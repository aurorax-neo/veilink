package tunnel

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"veilink/internal/model"
)

type object = map[string]any

func tlsFiles(t *testing.T) model.LocalTLS {
	t.Helper()
	dir := t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "gateway.test"}, DNSNames: []string{"gateway.test"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kd, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	c := filepath.Join(dir, "cert.pem")
	k := filepath.Join(dir, "key.pem")
	if err = os.WriteFile(c, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(k, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd}), 0600); err != nil {
		t.Fatal(err)
	}
	certPEM, err := os.ReadFile(c)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := os.ReadFile(k)
	if err != nil {
		t.Fatal(err)
	}
	return model.LocalTLS{TransportSecurity: "tls", CertPEM: string(certPEM), KeyPEM: string(keyPEM), CAPEM: string(certPEM)}
}
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return p
}
func fixtures(t *testing.T, target int) (model.Snapshot, model.Snapshot) {
	t.Helper()
	port := freePort(t)
	n := model.Node{ID: "server", Role: "server", Address: "127.0.0.1", Port: port, Tunnel: model.LocalTLS{TransportSecurity: "tls", ListenPort: port}}
	b := model.Binding{ID: "one", ServerID: n.ID, ClientID: "client-one", UUID: "e2587f5e-b746-4e68-a131-184984fa56a0", Domain: "one.reverse.test"}
	m := model.Mapping{ID: "echo", Name: "echo", BindingID: b.ID, ListenPort: freePort(t), TargetHost: "127.0.0.1", TargetPort: target, Pool: 1, Enabled: true}
	s := model.Snapshot{Revision: 1, Node: n, Bindings: []model.Binding{b}, Mappings: []model.Mapping{m}}
	c := model.Snapshot{Revision: 1, Node: model.Node{ID: b.ClientID, Role: "client"}, Nodes: []model.Node{n}, Bindings: []model.Binding{b}, Mappings: []model.Mapping{m}}
	return s, c
}
func clone(s model.Snapshot) model.Snapshot {
	data, _ := json.Marshal(s)
	var out model.Snapshot
	_ = json.Unmarshal(data, &out)
	return out
}
func run(t *testing.T, s model.Snapshot, local model.LocalTLS) *Runtime {
	t.Helper()
	// Test settings describe an authoritative gateway template, never a local
	// client override. Populate the snapshot before creating the runtime.
	if s.Node.Role == "client" && local != (model.LocalTLS{}) {
		for i := range s.Nodes {
			s.Nodes[i].Tunnel = model.DeriveClientTunnel(local, s.Nodes[i])
		}
		local = model.LocalTLS{}
	}
	r := New(local)
	t.Cleanup(func() { _ = r.Close() })
	if err := r.Apply(s); err != nil {
		t.Fatal(err)
	}
	return r
}
func echoServer(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _ = c.SetDeadline(time.Now().Add(30 * time.Second)); _, _ = io.Copy(c, c) }()
		}
	}()
	return l.Addr().(*net.TCPAddr).Port
}
func exchange(port int, payload []byte, half bool) error {
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
	if err != nil {
		return err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	result := make(chan error, 1)
	go func() {
		_, err := c.Write(payload)
		if err == nil && half {
			err = c.(*net.TCPConn).CloseWrite()
		}
		result <- err
	}()
	got := make([]byte, len(payload))
	_, err = io.ReadFull(c, got)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if !bytes.Equal(payload, got) {
		return fmt.Errorf("payload mismatch")
	}
	if err := <-result; err != nil {
		return fmt.Errorf("write request/half-close: %w", err)
	}
	return nil
}
func awaitEcho(t *testing.T, port int) {
	t.Helper()
	until := time.Now().Add(15 * time.Second)
	var err error
	for time.Now().Before(until) {
		err = exchange(port, []byte("ready"), false)
		if err == nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("reverse did not become ready: %v", err)
}
func assertBlocked(t *testing.T, port int) {
	t.Helper()
	if err := exchange(port, []byte("must-not-pass"), false); err == nil {
		t.Fatal("unauthorized traffic succeeded")
	}
}

func TestBuildRules(t *testing.T) {
	s, c := fixtures(t, 8080)
	local := tlsFiles(t)
	local.ListenPort = s.Node.Tunnel.ListenPort
	for _, snapshot := range []model.Snapshot{s, c} {
		settings := local
		if snapshot.Node.Role == "client" {
			snapshot.Nodes[0].Tunnel = model.DeriveClientTunnel(local, snapshot.Nodes[0])
			settings = model.LocalTLS{}
		}
		doc, err := Build(snapshot, settings)
		if err != nil {
			t.Fatal(err)
		}

		var cfg struct {
			Inbounds  []object `json:"inbounds"`
			Outbounds []object `json:"outbounds"`
			Routing   struct {
				Rules []object `json:"rules"`
			} `json:"routing"`
		}
		if err = json.Unmarshal(doc, &cfg); err != nil {
			t.Fatal(err)
		}
		if cfg.Outbounds[0]["protocol"] != "blackhole" {
			t.Fatal("unsafe default")
		}
		r := cfg.Routing.Rules[0]
		for _, key := range []string{"inboundTag", "domain", "network", "port", "outboundTag"} {
			if r[key] == nil {
				t.Fatalf("missing AND constraint %s", key)
			}
		}
		if r["port"] != "0" || r["network"] != "tcp" {
			t.Fatal("reverse must use TCP port 0")
		}
		if snapshot.Node.Role == "server" && r["user"] == nil {
			t.Fatal("portal lacks authenticated identity")
		}
		if snapshot.Node.Role == "client" && (!bytes.Contains(doc, []byte(`"allowInsecure":false`)) || !bytes.Contains(doc, []byte(`"enabled":false`))) {
			t.Fatal("TLS verification or mux policy")
		}
		for _, in := range cfg.Inbounds {
			if in["listen"] != "127.0.0.1" {
				t.Fatal("listen is not loopback")
			}
		}
	}
}
func TestValidation(t *testing.T) {
	s, c := fixtures(t, 8080)
	local := tlsFiles(t)
	local.ListenPort = s.Node.Tunnel.ListenPort
	cases := map[string]func(*model.Snapshot){
		"role": func(s *model.Snapshot) { s.Node.Role = "master" }, "UUID": func(s *model.Snapshot) { s.Bindings[0].UUID = "bad" }, "foreign": func(s *model.Snapshot) { s.Bindings[0].ServerID = "other" }, "binding": func(s *model.Snapshot) { s.Mappings[0].BindingID = "absent" }, "port": func(s *model.Snapshot) { s.Mappings[0].TargetPort = 0 }, "target": func(s *model.Snapshot) { s.Mappings[0].TargetHost = "" }, "name": func(s *model.Snapshot) { s.Mappings[0].Name = "" }, "overlap": func(s *model.Snapshot) { s.Mappings[0].ListenPort = local.ListenPort }, "domain": func(s *model.Snapshot) { s.Bindings[0].Domain = "regexp:.*" }, "control-target": func(s *model.Snapshot) { s.Mappings[0].TargetHost = s.Bindings[0].Domain }, "revoked": func(s *model.Snapshot) { s.Node.Revoked = true },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			bad := clone(s)
			mutate(&bad)
			if _, err := Build(bad, local); err == nil {
				t.Fatal("accepted invalid snapshot")
			}
		})
	}
	c.Nodes = nil
	if _, err := Build(c, local); err == nil {
		t.Fatal("accepted absent trusted gateway")
	}
}
func TestEmptyAndRevision(t *testing.T) {
	s := model.Snapshot{Revision: 0, Node: model.Node{ID: "empty", Role: "client"}}
	r := run(t, s, model.LocalTLS{})
	if r.Revision() != 0 {
		t.Fatal(r.Revision())
	}
	old := r.instance
	if err := r.Apply(s); err != nil || r.instance != old {
		t.Fatal("non-idempotent", err)
	}
	s.Revision = 2
	if err := r.Apply(s); err != nil {
		t.Fatal(err)
	}
	s.Revision = 1
	if err := r.Apply(s); err == nil {
		t.Fatal("accepted stale revision")
	}
	s.Revision = 3
	s.Node.Role = "bad"
	if err := r.Apply(s); err == nil || r.Revision() != 2 {
		t.Fatal("invalid config changed revision")
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if r.Revision() != -1 {
		t.Fatal("closed runtime claims running revision")
	}
	if err := r.Apply(s); err == nil {
		t.Fatal("closed runtime accepted apply")
	}
}
func TestReverseTLS(t *testing.T) {
	local := tlsFiles(t)
	s, c := fixtures(t, echoServer(t))
	server := run(t, s, local)
	client := run(t, c, local)
	parent := t
	port := s.Mappings[0].ListenPort
	awaitEcho(t, port)
	t.Run("large-concurrent", func(t *testing.T) {
		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := exchange(port, bytes.Repeat([]byte("payload!"), 128*1024), false); err != nil {
					t.Error(err)
				}
			}()
		}
		wg.Wait()
	})
	t.Run("half-close", func(t *testing.T) {
		if err := exchange(port, bytes.Repeat([]byte("half-close"), 128*1024), true); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("prevalidation-and-rollback", func(t *testing.T) {
		bad := clone(s)
		bad.Revision++
		bad.Mappings[0].TargetHost = ""
		if err := server.Apply(bad); err == nil {
			t.Fatal("invalid accepted")
		}
		awaitEcho(t, port)
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		bad = clone(s)
		bad.Revision++
		bad.Mappings[0].ListenPort = l.Addr().(*net.TCPAddr).Port
		if err = server.Apply(bad); err == nil || !strings.Contains(err.Error(), "restored revision") {
			t.Fatalf("missing rollback: %v", err)
		}
		if server.Revision() != 1 {
			t.Fatal(server.Revision())
		}
		awaitEcho(t, port)
	})
	t.Run("reconnect", func(t *testing.T) {
		if err := client.Close(); err != nil {
			t.Fatal(err)
		}
		assertBlocked(t, port)
		client = run(parent, c, local)
		awaitEcho(t, port)
	})
	t.Run("unauthorized-target", func(t *testing.T) {
		bad := clone(s)
		bad.Revision = 2
		bad.Mappings[0].TargetPort = echoServer(t)
		if err := server.Apply(bad); err != nil {
			t.Fatal(err)
		}
		assertBlocked(t, port)
		s.Revision = 3
		if err := server.Apply(s); err != nil {
			t.Fatal(err)
		}
		awaitEcho(t, port)
	})
}
func TestTwoClientsIsolationAndImpersonation(t *testing.T) {
	local := tlsFiles(t)
	s, c1 := fixtures(t, echoServer(t))
	b2 := model.Binding{ID: "two", ServerID: s.Node.ID, ClientID: "client-two", UUID: "e2587f5e-b746-4e68-a131-184984fa56a1", Domain: "two.reverse.test"}
	m2 := s.Mappings[0]
	m2.ID = "echo-two"
	m2.Name = "echo-two"
	m2.BindingID = b2.ID
	m2.ListenPort = freePort(t)
	s.Bindings = append(s.Bindings, b2)
	s.Mappings = append(s.Mappings, m2)
	run(t, s, local)
	first := run(t, c1, local)
	awaitEcho(t, s.Mappings[0].ListenPort)
	c2 := clone(c1)
	c2.Node.ID = b2.ClientID
	c2.Bindings = []model.Binding{b2}
	c2.Mappings = []model.Mapping{m2}
	// Client one has a valid UUID but claims client two's reverse domain.
	attack := clone(c1)
	attack.Bindings[0].Domain = b2.Domain
	rogue := run(t, attack, local)
	assertBlocked(t, m2.ListenPort)
	_ = rogue.Close()
	// Correct portal domain but an unregistered UUID is also rejected.
	attack = clone(c2)
	attack.Bindings[0].UUID = "e2587f5e-b746-4e68-a131-184984fa56af"
	rogue = run(t, attack, local)
	assertBlocked(t, m2.ListenPort)
	_ = rogue.Close()
	// Same target host AND port must never cause cross-binding routing.
	run(t, c2, local)
	awaitEcho(t, m2.ListenPort)
	awaitEcho(t, s.Mappings[0].ListenPort)
	_ = first.Close()
	assertBlocked(t, s.Mappings[0].ListenPort)
	awaitEcho(t, m2.ListenPort)
}
func TestUntrustedTLS(t *testing.T) {
	local := tlsFiles(t)
	s, c := fixtures(t, echoServer(t))
	run(t, s, local)
	for _, mode := range []string{"wrong-name", "wrong-ca"} {
		t.Run(mode, func(t *testing.T) {
			bad := clone(c)
			trust := local
			if mode == "wrong-name" {
				bad.Nodes[0].Address = "localhost"
			} else {
				trust = tlsFiles(t)
			}
			r := run(t, bad, trust)
			assertBlocked(t, s.Mappings[0].ListenPort)
			_ = r.Close()
		})
	}
}
func camouflage(t *testing.T, certPEM, keyPEM string, largeChain ...bool) string {
	t.Helper()
	pair, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		t.Fatal(err)
	}
	if len(largeChain) > 0 && largeChain[0] {
		// REALITY mirrors the cover's certificate record size; ML-DSA needs
		// room for its 3309-byte extra signature, as with a real full chain.
		leaf := pair.Certificate[0]
		for i := 0; i < 10; i++ {
			pair.Certificate = append(pair.Certificate, leaf)
		}
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(io.Discard, c) }()
		}
	}()
	return ln.Addr().String()
}

func TestRealityReverse(t *testing.T) {
	files := tlsFiles(t)
	priv, pub, err := GenerateX25519()
	if err != nil {
		t.Fatal(err)
	}
	serverLocal := model.LocalTLS{Reality: model.Reality{Dest: camouflage(t, files.CertPEM, files.KeyPEM), PrivateKey: priv, ShortIDs: "0123456789abcdef", ServerNames: "first-cover.test,gateway.test"}}
	clientLocal := model.LocalTLS{Reality: model.Reality{PublicKey: pub, ShortID: "0123456789abcdef", ServerNames: "gateway.test"}}
	serverSnap, clientSnap := fixtures(t, echoServer(t))
	run(t, serverSnap, serverLocal)
	run(t, clientSnap, clientLocal)
	awaitEcho(t, serverSnap.Mappings[0].ListenPort)
}

func TestRealityMLDSA65(t *testing.T) {
	files := tlsFiles(t)
	priv, pub, err := GenerateX25519()
	if err != nil {
		t.Fatal(err)
	}
	seed, verify, err := GenerateMldsa65()
	if err != nil {
		t.Fatal(err)
	}
	serverLocal := model.LocalTLS{Reality: model.Reality{
		Dest:        camouflage(t, files.CertPEM, files.KeyPEM, true),
		PrivateKey:  priv,
		ShortIDs:    "0123456789abcdef",
		ServerNames: "first-cover.test,gateway.test",
		Mldsa65Seed: seed,
	}}
	clientLocal := model.LocalTLS{Reality: model.Reality{
		PublicKey:     pub,
		ShortID:       "0123456789abcdef",
		ServerNames:   "gateway.test",
		Mldsa65Verify: verify,
	}}
	serverSnap, clientSnap := fixtures(t, echoServer(t))
	run(t, serverSnap, serverLocal)
	run(t, clientSnap, clientLocal)
	awaitEcho(t, serverSnap.Mappings[0].ListenPort)
}

func TestRealityRejectsShortID(t *testing.T) {
	files := tlsFiles(t)
	priv, pub, err := GenerateX25519()
	if err != nil {
		t.Fatal(err)
	}
	serverLocal := model.LocalTLS{Reality: model.Reality{Dest: camouflage(t, files.CertPEM, files.KeyPEM), PrivateKey: priv, ShortIDs: "0123456789abcdef", ServerNames: "gateway.test"}}
	clientLocal := model.LocalTLS{Reality: model.Reality{PublicKey: pub, ShortID: "0000000000000000", ServerNames: "gateway.test"}}
	serverSnap, clientSnap := fixtures(t, echoServer(t))
	run(t, serverSnap, serverLocal)
	run(t, clientSnap, clientLocal)
	until := time.Now().Add(3 * time.Second)
	for time.Now().Before(until) {
		if exchange(serverSnap.Mappings[0].ListenPort, []byte("must-not-pass"), false) == nil {
			t.Fatal("REALITY accepted a short id that was not configured")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	l, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := l.LocalAddr().(*net.UDPAddr).Port
	_ = l.Close()
	return p
}

func udpEchoServer(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(buf[:n], addr)
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr).Port
}

func exchangeUDP(port int, payload []byte) error {
	c, err := net.DialTimeout("udp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
	if err != nil {
		return err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write(payload); err != nil {
		return err
	}
	got := make([]byte, len(payload)+64)
	n, err := c.Read(got)
	if err != nil {
		return err
	}
	if !bytes.Equal(payload, got[:n]) {
		return fmt.Errorf("payload mismatch: got %q, want %q", string(got[:n]), string(payload))
	}
	return nil
}

func awaitUDPEcho(t *testing.T, port int) {
	t.Helper()
	until := time.Now().Add(15 * time.Second)
	var err error
	for time.Now().Before(until) {
		err = exchangeUDP(port, []byte("ready-udp"))
		if err == nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("reverse UDP did not become ready: %v", err)
}

func TestUDPReverse(t *testing.T) {
	local := tlsFiles(t)
	targetPort := udpEchoServer(t)
	serverSnap, clientSnap := fixtures(t, targetPort)
	udpPort := freeUDPPort(t)
	serverSnap.Mappings[0].Network = "udp"
	serverSnap.Mappings[0].ListenPort = udpPort
	clientSnap.Mappings[0].Network = "udp"
	clientSnap.Mappings[0].ListenPort = udpPort

	run(t, serverSnap, local)
	run(t, clientSnap, local)
	awaitUDPEcho(t, udpPort)

	for i := 0; i < 5; i++ {
		msg := []byte(fmt.Sprintf("datagram-payload-%d", i))
		if err := exchangeUDP(udpPort, msg); err != nil {
			t.Fatalf("failed UDP exchange %d: %v", i, err)
		}
	}
}

func TestTCPAndUDPCoexist(t *testing.T) {
	local := tlsFiles(t)
	tcpTarget := echoServer(t)
	udpTarget := udpEchoServer(t)

	serverSnap, clientSnap := fixtures(t, tcpTarget)

	udpPort := freeUDPPort(t)
	udpMap := model.Mapping{
		ID:         "udp-echo",
		Name:       "udp-echo",
		BindingID:  serverSnap.Bindings[0].ID,
		ListenPort: udpPort,
		TargetHost: "127.0.0.1",
		TargetPort: udpTarget,
		Network:    "udp",
		Pool:       1,
		Enabled:    true,
	}
	serverSnap.Mappings = append(serverSnap.Mappings, udpMap)
	clientSnap.Mappings = append(clientSnap.Mappings, udpMap)

	run(t, serverSnap, local)
	run(t, clientSnap, local)

	awaitEcho(t, serverSnap.Mappings[0].ListenPort)
	awaitUDPEcho(t, udpPort)

	for i := 0; i < 3; i++ {
		if err := exchange(serverSnap.Mappings[0].ListenPort, []byte("hello-tcp"), false); err != nil {
			t.Fatalf("TCP exchange %d failed: %v", i, err)
		}
		if err := exchangeUDP(udpPort, []byte("hello-udp")); err != nil {
			t.Fatalf("UDP exchange %d failed: %v", i, err)
		}
	}
}
