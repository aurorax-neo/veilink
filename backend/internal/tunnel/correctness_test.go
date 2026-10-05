package tunnel

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"veilink/internal/model"
)

func TestEncryptionModesAndResumption(t *testing.T) {
	xd, xe, pd, pe, err := GenerateVLESSEnc()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"native", "xorpub", "random"} {
		for name, pair := range map[string][2]string{"x25519": {xd, xe}, "mlkem": {pd, pe}, "chain": {xd + "." + strings.Split(pd, ".")[3], xe + "." + strings.Split(pe, ".")[3]}} {
			t.Run(mode+"/"+name, func(t *testing.T) {
				dec := strings.Replace(pair[0], ".native.", "."+mode+".", 1)
				enc := strings.Replace(pair[1], ".native.", "."+mode+".", 1)
				// Deterministic single-fragment padding keeps the test bounded and quick.
				dec = strings.Replace(dec, ".600s.", ".600s.100-35-35.", 1)
				enc = strings.Replace(enc, ".0rtt.", ".0rtt.100-35-35.", 1)
				derived, err := DeriveClientTunnel(model.LocalTLS{}, model.LocalTLS{TransportSecurity: "plain", Decryption: dec}, model.Node{})
				if err != nil || derived.Encryption != enc {
					t.Fatalf("derivation mismatch: %v", err)
				}
				if model.DeriveVLESSEncryption(dec) != enc {
					t.Fatal("model/native derivation mismatch")
				}
				server, err := mustSpec(t, dec, false).newServer()
				if err != nil {
					t.Fatal(err)
				}
				defer server.Close()
				client, err := mustSpec(t, enc, true).newClient()
				if err != nil {
					t.Fatal(err)
				}
				// First connection issues a ticket; second must actually resume it.
				for attempt := 0; attempt < 2; attempt++ {
					encryptionExchange(t, server, client, attempt == 1)
				}
				if len(client.ticket) != 16 {
					t.Fatal("no resumption ticket")
				}
			})
		}
	}
}

func encryptionExchange(t *testing.T, server *encServer, client *encClient, resumed bool) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan error, 1)
	payload := bytes.Repeat([]byte("bounded-encryption"), 1500)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		defer raw.Close()
		_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
		conn, err := server.Handshake(raw)
		if err == nil {
			got := make([]byte, len(payload))
			_, err = io.ReadFull(conn, got)
			if err == nil && !bytes.Equal(got, payload) {
				err = fmt.Errorf("server payload mismatch")
			}
			if err == nil {
				_, err = conn.Write(got)
			}
		}
		done <- err
	}()
	raw, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
	conn, err := client.Handshake(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got := conn.(*recordConn).client != nil; got != resumed {
		t.Fatalf("resumed=%v want %v", got, resumed)
	}
	if _, err = conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err = io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("client payload mismatch")
	}
	select {
	case err = <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("server timed out")
	}
}

func TestEncryptionDerivationRejectsMalformed(t *testing.T) {
	dec, _, _, _, err := GenerateVLESSEnc()
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"secret", strings.Replace(dec, "600s", "-1s", 1), strings.Replace(dec, "600s", "600s.100-34-34", 1), strings.Replace(dec, "native", "unknown", 1)} {
		if _, err := DeriveClientTunnel(model.LocalTLS{}, model.LocalTLS{TransportSecurity: "tls", Decryption: bad}, model.Node{}); err == nil {
			t.Fatal("accepted malformed decryption")
		}
	}
	if _, err := DeriveClientTunnel(model.LocalTLS{Encryption: "none", Flow: "none"}, model.LocalTLS{TransportSecurity: "tls", Decryption: "bad", Flow: flowVision}, model.Node{}); err == nil {
		t.Fatal("client override accepted")
	}
}

func TestVisionTransportRestrictions(t *testing.T) {
	dec, enc, _, _, err := GenerateVLESSEnc()
	if err != nil {
		t.Fatal(err)
	}
	s, c := fixtures(t, 8080)
	for _, tc := range []struct {
		name     string
		snapshot model.Snapshot
		local    model.LocalTLS
	}{
		{"raw-server", s, model.LocalTLS{TransportSecurity: "plain", Flow: flowVision, Decryption: dec}},
		{"raw-client", c, model.LocalTLS{TransportSecurity: "plain", Flow: flowVision, Encryption: enc}},
		{"hy-server", s, model.LocalTLS{Flow: flowVision, CertPEM: "cert", KeyPEM: "key", Hysteria2: model.Hysteria2{Password: "x"}}},
		{"hy-client", c, model.LocalTLS{Flow: flowVision, CAPEM: "ca", Hysteria2: model.Hysteria2{Password: "x"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := CheckBootstrap(tc.snapshot.Node.Role, tc.local); err == nil {
				t.Fatal("bootstrap accepted unsupported Vision")
			}
			if _, err := Build(tc.snapshot, tc.local); err == nil {
				t.Fatal("validation accepted unsupported Vision")
			}
			if svc, err := start(tc.snapshot, tc.local); err == nil {
				svc.stop()
				t.Fatal("runtime accepted unsupported Vision")
			}
		})
	}
	for _, local := range []model.LocalTLS{{TransportSecurity: "tls", Flow: flowVision}, {TransportSecurity: "tls", Flow: flowVision, CAPEM: "ca", Encryption: enc}, {Flow: flowVision, Reality: model.Reality{PublicKey: "public"}}} {
		if err := checkVLESS("client", local); err != nil {
			t.Fatal(err)
		}
	}
}

func TestVisionCommands(t *testing.T) {
	var id [16]byte
	for _, cmd := range []byte{1, 2, 3} {
		c := newVision(nil, id)
		packet := append(append([]byte{}, id[:]...), cmd, 0, 1, 0, 0, 'x', 'y')
		var err error
		// Fragment every byte, including the UUID/header.
		for _, b := range packet {
			c.raw = append(c.raw, b)
			err = c.pull()
			if err != nil {
				break
			}
		}
		if cmd == 1 {
			if err != nil || !c.unpadded || string(c.plain) != "x" {
				t.Fatalf("padding end: %v", err)
			}
		} else if err == nil || len(c.plain) > 0 || c.unpadded {
			t.Fatal("unsupported command accepted or released data")
		}
	}
}

func TestMappingPoolAndRuntimeUpdate(t *testing.T) {
	mappings := []model.Mapping{{BindingID: "a", Enabled: true, Pool: 2}, {BindingID: "a", Enabled: true, Pool: 4}, {BindingID: "a", Enabled: false, Pool: 32}, {BindingID: "b", Enabled: true, Pool: 8}}
	if bindingPool(mappings, "a") != 4 || bindingPool(mappings, "b") != 8 || bindingPool(mappings, "c") != 1 || bindingPool(nil, "c") != 1 {
		t.Fatal("incorrect shared binding pool")
	}
	files := tlsFiles(t)
	s, c := fixtures(t, echoServer(t))
	for _, bad := range []int{-1, 0, 33} {
		invalid := clone(c)
		invalid.Mappings[0].Pool = bad
		if _, err := Build(invalid, files); err == nil {
			t.Fatal("invalid pool accepted")
		}
	}
	s.Mappings[0].Pool = 2
	server := run(t, s, files)
	c.Mappings[0].Pool = 2
	client := run(t, c, files)
	c.Nodes = clone(*client.good).Nodes
	awaitEcho(t, s.Mappings[0].ListenPort)
	awaitSessions(t, server.instance, s.Bindings[0].ID, 2)
	old := testBindingService(client.instance, s.Bindings[0].ID)
	c.Mappings[0].Pool = 3
	if err := client.Apply(c); err == nil {
		t.Fatal("pool changed under same revision")
	}
	c.Revision++
	s.Revision++
	s.Mappings[0].Pool = 3
	if err := server.Apply(s); err != nil {
		t.Fatal(err)
	}
	if err := client.Apply(c); err != nil {
		t.Fatal(err)
	}
	if testBindingService(client.instance, s.Bindings[0].ID) != old {
		t.Fatal("pool update replaced binding")
	}
	awaitSessions(t, server.instance, s.Bindings[0].ID, 3)
}

func awaitSessions(t *testing.T, s *service, binding string, n int) {
	t.Helper()
	s = testBindingService(s, binding)
	until := time.Now().Add(5 * time.Second)
	for time.Now().Before(until) {
		s.mu.Lock()
		got := len(s.sessions[binding])
		s.mu.Unlock()
		if got == n {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("binding did not reach %d sessions", n)
}

func TestMultipleGatewayEncryption(t *testing.T) {
	target := echoServer(t)
	a, c := fixtures(t, target)
	b, _ := fixtures(t, target)
	b.Node.ID = "server-two"
	b.Bindings[0].ID = "two"
	b.Bindings[0].ServerID = b.Node.ID
	b.Bindings[0].Domain = "two.reverse.test"
	b.Bindings[0].UUID = "a2587f5e-b746-4e68-a131-184984fa56a0"
	b.Mappings[0].ID = "echo-two"
	b.Mappings[0].Name = "echo-two"
	b.Mappings[0].BindingID = "two"
	for _, s := range []*model.Snapshot{&a, &b} {
		dec, _, _, _, err := GenerateVLESSEnc()
		if err != nil {
			t.Fatal(err)
		}
		s.Node.Tunnel.Decryption = dec
		s.Node.Tunnel.TransportSecurity = "plain"
		run(t, *s, model.LocalTLS{})
		peer, err := PublicPeerTunnel(s.Node.Tunnel, s.Node)
		if err != nil {
			t.Fatal(err)
		}
		if s.Node.ID == a.Node.ID {
			c.Nodes[0].Tunnel = peer
		} else {
			node := s.Node
			node.Tunnel = peer
			c.Nodes = append(c.Nodes, node)
		}
	}
	c.Bindings = append(c.Bindings, b.Bindings...)
	c.Mappings = append(c.Mappings, b.Mappings...)
	run(t, c, model.LocalTLS{})
	awaitEcho(t, a.Mappings[0].ListenPort)
	awaitEcho(t, b.Mappings[0].ListenPort)
}

func TestSnapshotMetadataAndOrderRetainActiveSession(t *testing.T) {
	files := tlsFiles(t)
	a, c := fixtures(t, echoServer(t))
	b := clone(a)
	b.Node.ID, b.Node.Port = "server-two", freePort(t)
	b.Node.Tunnel.ListenPort = b.Node.Port
	b.Bindings[0].ID, b.Bindings[0].ServerID = "two", b.Node.ID
	b.Bindings[0].Domain = "two.reverse.test"
	b.Bindings[0].UUID = "a2587f5e-b746-4e68-a131-184984fa56a0"
	b.Mappings[0].ID, b.Mappings[0].Name, b.Mappings[0].BindingID = "echo-two", "echo-two", "two"
	b.Mappings[0].ListenPort = freePort(t)
	c.Nodes = append(c.Nodes, b.Node)
	c.Bindings = append(c.Bindings, b.Bindings...)
	c.Mappings = append(c.Mappings, b.Mappings...)
	server := run(t, a, files)
	run(t, b, files)
	client := run(t, c, files)
	awaitEcho(t, a.Mappings[0].ListenPort)
	awaitEcho(t, b.Mappings[0].ListenPort)
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", a.Mappings[0].ListenPort))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	checkFlow := func() {
		t.Helper()
		if _, err := conn.Write([]byte("alive")); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, 5)
		if _, err := io.ReadFull(conn, got); err != nil || string(got) != "alive" {
			t.Fatalf("active flow interrupted: %q, %v", got, err)
		}
	}
	checkFlow()
	oldClient, oldServer := client.instance, server.instance
	updated := clone(c)
	slices.Reverse(updated.Nodes)
	slices.Reverse(updated.Bindings)
	slices.Reverse(updated.Mappings)
	metadata := func(n *model.Node) {
		n.Name = "renamed"
		n.DesiredRevision, n.AppliedRevision, n.LastSeen = 12, 11, 12345
		n.Error = "administrative status"
	}
	metadata(&updated.Node)
	for i := range updated.Nodes {
		metadata(&updated.Nodes[i])
	}
	metadata(&a.Node)
	for _, revision := range []int64{1, 2} {
		updated.Revision, a.Revision = revision, revision
		before := clone(updated)
		if err := client.Apply(updated); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(updated, before) {
			t.Fatal("Apply mutated caller's snapshot")
		}
		if err := server.Apply(a); err != nil {
			t.Fatal(err)
		}
		if client.instance != oldClient || server.instance != oldServer || client.Revision() != revision || server.Revision() != revision {
			t.Fatal("metadata/order update restarted service or lost revision")
		}
		checkFlow()
	}
	// Mapping names still undergo validation before the no-op fast path.
	invalid := clone(updated)
	invalid.Mappings[0].Name = invalid.Mappings[1].Name
	if err := client.Apply(invalid); err == nil {
		t.Fatal("duplicate mapping names accepted")
	}
}

func TestSameConfigurationPreservesMeaningfulChanges(t *testing.T) {
	_, base := fixtures(t, 8080)
	for name, change := range map[string]func(*model.Snapshot){
		"local encryption":    func(s *model.Snapshot) { s.Node.Tunnel.Encryption = "new-key" },
		"local decryption":    func(s *model.Snapshot) { s.Node.Tunnel.Decryption = "new-key" },
		"gateway encryption":  func(s *model.Snapshot) { s.Nodes[0].Tunnel.Encryption = "new-key" },
		"gateway reality key": func(s *model.Snapshot) { s.Nodes[0].Tunnel.Reality.PublicKey = "new-key" },
		"gateway transport":   func(s *model.Snapshot) { s.Nodes[0].Tunnel.TransportSecurity = "plain" },
		"gateway password":    func(s *model.Snapshot) { s.Nodes[0].Tunnel.Hysteria2.Password = "new-key" },
		"gateway address":     func(s *model.Snapshot) { s.Nodes[0].Address = "other.test" },
		"gateway port":        func(s *model.Snapshot) { s.Nodes[0].Port++ },
		"binding key":         func(s *model.Snapshot) { s.Bindings[0].UUID = "new-key" },
		"mapping pool":        func(s *model.Snapshot) { s.Mappings[0].Pool++ },
		"local CA":            func(s *model.Snapshot) { s.Node.Tunnel.CAPEM = "new-ca" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := clone(base)
			change(&changed)
			before := clone(changed)
			if sameConfiguration(base, changed) {
				t.Fatal("meaningful change ignored")
			}
			if !reflect.DeepEqual(changed, before) {
				t.Fatal("comparison mutated snapshot")
			}
		})
	}
}

func TestRuntimeEncryptionUpdate(t *testing.T) {
	s, c := fixtures(t, echoServer(t))
	dec, enc, _, _, err := GenerateVLESSEnc()
	if err != nil {
		t.Fatal(err)
	}
	s.Node.Tunnel.Decryption, c.Nodes[0].Tunnel.Encryption = dec, enc
	s.Node.Tunnel.TransportSecurity, c.Nodes[0].Tunnel.TransportSecurity = "plain", "plain"
	server := run(t, s, model.LocalTLS{})
	client := run(t, c, model.LocalTLS{})
	awaitEcho(t, s.Mappings[0].ListenPort)
	oldServer, oldClient := server.instance, testBindingService(client.instance, c.Bindings[0].ID)
	dec, enc, _, _, err = GenerateVLESSEnc()
	if err != nil {
		t.Fatal(err)
	}
	s.Node.Tunnel.Decryption, c.Nodes[0].Tunnel.Encryption = dec, enc
	if server.Apply(s) == nil || client.Apply(c) == nil {
		t.Fatal("key rotation accepted under same revision")
	}
	s.Revision++
	c.Revision++
	if err := server.Apply(s); err != nil {
		t.Fatal(err)
	}
	if err := client.Apply(c); err != nil {
		t.Fatal(err)
	}
	if server.instance == oldServer || testBindingService(client.instance, c.Bindings[0].ID) == oldClient {
		t.Fatal("key rotation did not replace runtime")
	}
	awaitEcho(t, s.Mappings[0].ListenPort)
}
