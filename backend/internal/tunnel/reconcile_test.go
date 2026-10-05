package tunnel

import (
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"veilink/internal/model"
)

func persistentEcho(t *testing.T, port int) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	assertPersistentEcho(t, conn)
	return conn
}

func assertPersistentEcho(t *testing.T, conn net.Conn) {
	t.Helper()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte("still-alive")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len("still-alive"))
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "still-alive" {
		t.Fatalf("persistent connection lost: %q %v", buf, err)
	}
}

func TestMappingReconcilePreservesOtherFlows(t *testing.T) {
	for _, kind := range []string{"", "smux", "yamux", "h2mux"} {
		t.Run("mux="+kind, func(t *testing.T) {
			local := tlsFiles(t)
			s, c := fixtures(t, echoServer(t))
			s.Mappings[0].Mux, s.Mappings[0].MuxType = kind != "", kind
			other := s.Mappings[0]
			other.ID, other.Name, other.ListenPort = "other", "other", freePort(t)
			s.Mappings = append(s.Mappings, other)
			c.Mappings = append([]model.Mapping(nil), s.Mappings...)
			server, client := run(t, s, local), run(t, c, local)
			awaitEcho(t, other.ListenPort)
			conn := persistentEcho(t, other.ListenPort)
			serverChild, clientChild := testBindingService(server.instance, "one"), testBindingService(client.instance, "one")
			listener := serverChild.mappingListeners[other.ID]
			awaitSessions(t, serverChild, "one", 1)
			serverChild.mu.Lock()
			session := serverChild.sessions["one"][0]
			serverChild.mu.Unlock()
			s.Revision++
			s.Mappings[0].TargetPort = echoServer(t)
			c.Revision++
			c.Mappings = append([]model.Mapping(nil), s.Mappings...)
			// A client snapshot passed directly to Apply must retain its public template.
			c.Nodes = clone(*client.good).Nodes
			if err := server.Apply(s); err != nil {
				t.Fatal(err)
			}
			if err := client.Apply(c); err != nil {
				t.Fatal(err)
			}
			if testBindingService(server.instance, "one") != serverChild || testBindingService(client.instance, "one") != clientChild || serverChild.mappingListeners[other.ID] != listener || !session.alive() {
				t.Fatal("unrelated listener or session was replaced")
			}
			assertPersistentEcho(t, conn)
			awaitEcho(t, s.Mappings[0].ListenPort)
			s.Revision++
			s.Mappings[0].Enabled = false
			c.Revision++
			c.Mappings = append([]model.Mapping(nil), s.Mappings...)
			if err := server.Apply(s); err != nil {
				t.Fatal(err)
			}
			if err := client.Apply(c); err != nil {
				t.Fatal(err)
			}
			assertPersistentEcho(t, conn)
			assertBlocked(t, s.Mappings[0].ListenPort)
			if !session.alive() {
				t.Fatal("control session disconnected")
			}
		})
	}
}

func TestMappingReconcileDuringContinuousTraffic(t *testing.T) {
	local := tlsFiles(t)
	s, c := fixtures(t, echoServer(t))
	other := s.Mappings[0]
	other.ID, other.Name, other.ListenPort = "other", "other", freePort(t)
	s.Mappings = append(s.Mappings, other)
	c.Mappings = append([]model.Mapping(nil), s.Mappings...)
	server, client := run(t, s, local), run(t, c, local)
	awaitEcho(t, other.ListenPort)
	conn := persistentEcho(t, other.ListenPort)
	c = clone(*client.good)
	targets := []int{s.Mappings[0].TargetPort, echoServer(t)}
	done, cancel := make(chan struct{}), make(chan struct{})
	var applyErr error
	t.Cleanup(func() { close(cancel); <-done })
	go func() {
		defer close(done)
		for i := range 16 {
			select {
			case <-cancel:
				return
			default:
			}
			s.Revision++
			c.Revision++
			s.Mappings[0].TargetPort = targets[i%len(targets)]
			c.Mappings = append([]model.Mapping(nil), s.Mappings...)
			if err := client.Apply(c); err != nil {
				applyErr = err
				return
			}
			if err := server.Apply(s); err != nil {
				applyErr = err
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()
	for {
		select {
		case <-done:
			if applyErr != nil {
				t.Fatal(applyErr)
			}
			assertPersistentEcho(t, conn)
			return
		default:
			assertPersistentEcho(t, conn)
		}
	}
}

func TestBindingReconcilePreservesOtherClient(t *testing.T) {
	local := tlsFiles(t)
	s, first := fixtures(t, echoServer(t))
	b := model.Binding{ID: "two", ServerID: s.Node.ID, ClientID: "client-two", UUID: "e2587f5e-b746-4e68-a131-184984fa56a1", Domain: "two.reverse.test"}
	m := s.Mappings[0]
	m.ID, m.Name, m.BindingID, m.ListenPort = "two", "two", b.ID, freePort(t)
	s.Bindings = append(s.Bindings, b)
	s.Mappings = append(s.Mappings, m)
	second := clone(first)
	second.Node.ID, second.Bindings, second.Mappings = b.ClientID, []model.Binding{b}, []model.Mapping{m}
	server := run(t, s, local)
	run(t, first, local)
	run(t, second, local)
	awaitEcho(t, m.ListenPort)
	conn := persistentEcho(t, m.ListenPort)
	unchanged := testBindingService(server.instance, "two")
	// Pool changes preserve both this binding and the other client.
	s.Revision++
	s.Mappings[0].Pool = 2
	if err := server.Apply(s); err != nil {
		t.Fatal(err)
	}
	if testBindingService(server.instance, "two") != unchanged {
		t.Fatal("other client restarted")
	}
	assertPersistentEcho(t, conn)
	// Remove the first authorization without restarting the transport listener.
	s.Revision++
	s.Bindings, s.Mappings = []model.Binding{b}, []model.Mapping{m}
	if err := server.Apply(s); err != nil {
		t.Fatal(err)
	}
	assertPersistentEcho(t, conn)
	assertBlocked(t, first.Mappings[0].ListenPort)
}

func TestMappingReconcileFailureAndWithdrawal(t *testing.T) {
	local := tlsFiles(t)
	s, c := fixtures(t, echoServer(t))
	other := s.Mappings[0]
	other.ID, other.Name, other.ListenPort, other.TargetPort = "other", "other", freePort(t), echoServer(t)
	s.Mappings = append(s.Mappings, other)
	c.Mappings = append([]model.Mapping(nil), s.Mappings...)
	server, client := run(t, s, local), run(t, c, local)
	awaitEcho(t, other.ListenPort)
	conn := persistentEcho(t, other.ListenPort)
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	bad := clone(s)
	bad.Revision++
	bad.Mappings[0].ListenPort = busy.Addr().(*net.TCPAddr).Port
	if err := server.Apply(bad); err == nil {
		t.Fatal("occupied port accepted")
	}
	if server.Revision() != s.Revision {
		t.Fatal("failed apply advanced revision")
	}
	assertPersistentEcho(t, conn)
	awaitEcho(t, s.Mappings[0].ListenPort)
	withdrawn := persistentEcho(t, s.Mappings[0].ListenPort)
	updated := clone(*client.good)
	updated.Revision++
	updated.Mappings[0].TargetPort = echoServer(t)
	if err := client.Apply(updated); err != nil {
		t.Fatal(err)
	}
	assertPersistentEcho(t, conn)
	withdrawn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := withdrawn.Read(make([]byte, 1)); err == nil {
		t.Fatal("withdrawn target still open")
	} else if e, ok := err.(net.Error); ok && e.Timeout() {
		t.Fatal("withdrawn connection not closed")
	}
	assertBlocked(t, s.Mappings[0].ListenPort) // Stale server cannot request old target.
}

func TestUDPReconcilePreservesOtherAssociation(t *testing.T) {
	local := tlsFiles(t)
	s, c := fixtures(t, udpEchoServer(t))
	s.Mappings[0].Network, s.Mappings[0].ListenPort = "udp", freeUDPPort(t)
	other := s.Mappings[0]
	other.ID, other.Name, other.ListenPort = "other", "other", freeUDPPort(t)
	s.Mappings = append(s.Mappings, other)
	c.Mappings = append([]model.Mapping(nil), s.Mappings...)
	server, client := run(t, s, local), run(t, c, local)
	awaitUDPEcho(t, other.ListenPort)
	conn, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", other.ListenPort))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	assertPersistentEcho(t, conn)
	s.Revision++
	s.Mappings[0].TargetPort = udpEchoServer(t)
	updated := clone(*client.good)
	updated.Revision++
	updated.Mappings = append([]model.Mapping(nil), s.Mappings...)
	if err := server.Apply(s); err != nil {
		t.Fatal(err)
	}
	if err := client.Apply(updated); err != nil {
		t.Fatal(err)
	}
	assertPersistentEcho(t, conn)
	awaitUDPEcho(t, s.Mappings[0].ListenPort)
}

func TestMappingReconcileMovesBindingWithSamePort(t *testing.T) {
	local := tlsFiles(t)
	s, first := fixtures(t, echoServer(t))
	b := model.Binding{ID: "two", ServerID: s.Node.ID, ClientID: "client-two", UUID: "e2587f5e-b746-4e68-a131-184984fa56a1", Domain: "two.reverse.test"}
	other := s.Mappings[0]
	other.ID, other.Name, other.ListenPort = "other", "other", freePort(t)
	secondMapping := other
	secondMapping.ID, secondMapping.Name, secondMapping.ListenPort, secondMapping.BindingID = "second", "second", freePort(t), b.ID
	s.Bindings = append(s.Bindings, b)
	s.Mappings = append(s.Mappings, other, secondMapping)
	first.Mappings = []model.Mapping{s.Mappings[0], other}
	second := clone(first)
	second.Node.ID, second.Bindings, second.Mappings = b.ClientID, []model.Binding{b}, []model.Mapping{secondMapping}
	server, c1, c2 := run(t, s, local), run(t, first, local), run(t, second, local)
	awaitEcho(t, other.ListenPort)
	awaitEcho(t, secondMapping.ListenPort)
	conn1, conn2 := persistentEcho(t, other.ListenPort), persistentEcho(t, secondMapping.ListenPort)
	s.Revision++
	s.Mappings[0].BindingID = b.ID
	updated1, updated2 := clone(*c1.good), clone(*c2.good)
	updated1.Revision++
	updated2.Revision++
	updated1.Mappings = []model.Mapping{other}
	updated2.Mappings = []model.Mapping{s.Mappings[0], secondMapping}
	if err := c1.Apply(updated1); err != nil {
		t.Fatal(err)
	}
	if err := c2.Apply(updated2); err != nil {
		t.Fatal(err)
	}
	if err := server.Apply(s); err != nil {
		t.Fatal(err)
	}
	assertPersistentEcho(t, conn1)
	assertPersistentEcho(t, conn2)
	awaitEcho(t, s.Mappings[0].ListenPort)
}

func TestGatewayReconcilePreservesOtherServer(t *testing.T) {
	a, clientSnapshot := fixtures(t, echoServer(t))
	b := clone(a)
	b.Node.ID, b.Node.Port = "server-two", freePort(t)
	b.Node.Tunnel.ListenPort = b.Node.Port
	b.Bindings[0].ID, b.Bindings[0].ServerID, b.Bindings[0].Domain = "two", b.Node.ID, "two.reverse.test"
	b.Bindings[0].UUID = "e2587f5e-b746-4e68-a131-184984fa56a1"
	b.Mappings[0].ID, b.Mappings[0].Name, b.Mappings[0].BindingID, b.Mappings[0].ListenPort = "second", "second", "two", freePort(t)
	for _, snap := range []*model.Snapshot{&a, &b} {
		dec, _, _, _, err := GenerateVLESSEnc()
		if err != nil {
			t.Fatal(err)
		}
		snap.Node.Tunnel.TransportSecurity, snap.Node.Tunnel.Decryption = "plain", dec
	}
	server := run(t, a, model.LocalTLS{})
	run(t, b, model.LocalTLS{})
	clientSnapshot.Nodes = []model.Node{a.Node, b.Node}
	for i := range clientSnapshot.Nodes {
		peer, err := PublicPeerTunnel(clientSnapshot.Nodes[i].Tunnel, clientSnapshot.Nodes[i])
		if err != nil {
			t.Fatal(err)
		}
		clientSnapshot.Nodes[i].Tunnel = peer
	}
	clientSnapshot.Bindings = append(clientSnapshot.Bindings, b.Bindings...)
	clientSnapshot.Mappings = append(clientSnapshot.Mappings, b.Mappings...)
	client := run(t, clientSnapshot, model.LocalTLS{})
	awaitEcho(t, b.Mappings[0].ListenPort)
	conn := persistentEcho(t, b.Mappings[0].ListenPort)
	other := testBindingService(client.instance, "two")
	dec, _, _, _, err := GenerateVLESSEnc()
	if err != nil {
		t.Fatal(err)
	}
	a.Node.Tunnel.Decryption, a.Revision = dec, a.Revision+1
	clientSnapshot.Nodes[0].Tunnel, err = PublicPeerTunnel(a.Node.Tunnel, a.Node)
	if err != nil {
		t.Fatal(err)
	}
	clientSnapshot.Revision++
	if err := server.Apply(a); err != nil {
		t.Fatal(err)
	}
	if err := client.Apply(clientSnapshot); err != nil {
		t.Fatal(err)
	}
	if testBindingService(client.instance, "two") != other {
		t.Fatal("unrelated server binding replaced")
	}
	assertPersistentEcho(t, conn)
	awaitEcho(t, a.Mappings[0].ListenPort)
}
