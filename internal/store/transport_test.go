package store

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	"veilink/internal/model"
	"veilink/internal/tunnel"
)

func testPEM(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}))
}

func testTLS(t *testing.T) model.LocalTLS {
	t.Helper()
	cert, key := testPEM(t)
	return model.LocalTLS{TransportSecurity: "tls", CertPEM: cert, KeyPEM: key, ListenPort: 8444}
}

func TestPublicTunnelPreservesTransportAndCA(t *testing.T) {
	dec, _, _, _, err := tunnel.GenerateVLESSEnc()
	if err != nil {
		t.Fatal(err)
	}
	cert, key := testPEM(t)
	for _, tc := range []struct {
		name string
		tls  model.LocalTLS
		want string
	}{
		{"tls", model.LocalTLS{TransportSecurity: "tls", CertPEM: cert, KeyPEM: key, CAPEM: cert, Decryption: dec}, "tls"},
		{"plain", model.LocalTLS{TransportSecurity: "plain", Decryption: dec}, "plain"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			node := model.Node{Role: "server", Tunnel: tc.tls}
			node.ClientTunnel, err = clientTemplate(node)
			if err != nil {
				t.Fatal(err)
			}
			got, err := publicTunnel(node)
			if err != nil {
				t.Fatal(err)
			}
			if got.TransportSecurity != tc.want || got.CAPEM != tc.tls.CAPEM || got.CertPEM != "" || got.KeyPEM != "" || got.Decryption != "" || got.Encryption == "" {
				t.Fatal("invalid public transport, CA or private material")
			}
		})
	}
}

func TestSaveNodeReplacesRealityKey(t *testing.T) {
	const private = "4A39kZk0Nvd5uD3fXJbF2WvJqCq23xQ3_gL7_J0mE1s"
	cert, key := testPEM(t)
	for _, tc := range []struct {
		name    string
		tunnel  model.LocalTLS
		invalid bool
	}{
		{"no-private-key", model.LocalTLS{Reality: model.Reality{Dest: "example.com:443", ShortIDs: "aa"}}, true},
		{"certificate-tls", model.LocalTLS{TransportSecurity: "tls", CertPEM: cert, KeyPEM: key}, false},
		{"empty-reality", model.LocalTLS{TransportSecurity: "tls", ListenHost: "127.0.0.1"}, true},
		{"clear-keys", model.LocalTLS{}, false},
		{"hysteria2", model.LocalTLS{CertPEM: cert, KeyPEM: key, Hysteria2: model.Hysteria2{Password: "shared"}}, false},
		{"plain", model.LocalTLS{TransportSecurity: "plain"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _, _ := testStore(t)
			server := testNode(t, s, "server", "gateway")
			server.Tunnel = model.LocalTLS{Reality: model.Reality{PrivateKey: private, Dest: "example.com:443", ShortIDs: "aa", ServerNames: "example.com"}}
			server.ClientTunnel = nil
			var err error
			server, err = s.SaveNode(server)
			if err != nil {
				t.Fatal(err)
			}
			credential := testCredential(t, s, server.ID)
			server.Tunnel = tc.tunnel
			server.ClientTunnel = nil
			saved, err := s.SaveNode(server)
			if tc.invalid {
				if !errors.Is(err, ErrInvalid) {
					t.Fatal("incomplete replacement accepted", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if saved.Tunnel != tc.tunnel {
				t.Fatal("submitted tunnel was not a complete replacement")
			}
			snap, err := s.Snapshot(server.ID, credential)
			if err != nil {
				t.Fatal(err)
			}
			if snap.Node.Tunnel != tc.tunnel {
				t.Fatal("snapshot retained old private material")
			}
		})
	}
}

func TestPEMValidationPersistenceAndDistribution(t *testing.T) {
	s, db, keyPath := testStore(t)
	server := testNode(t, s, "server", "gateway")
	client := testNode(t, s, "client", "client")
	other := testNode(t, s, "client", "isolated")
	serverCredential := testCredential(t, s, server.ID)
	clientCredential := testCredential(t, s, client.ID)
	otherCredential := testCredential(t, s, other.ID)
	cert, key := testPEM(t)
	_, wrongKey := testPEM(t)
	before, err := s.load()
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []model.LocalTLS{
		{CertPEM: "/not/a/certificate", KeyPEM: "/not/a/key"},
		{CertPEM: cert}, {KeyPEM: key}, {CertPEM: cert, KeyPEM: wrongKey},
		{CAPEM: "not a CA"}, {CAPEM: key}, {Flow: "invalid"}, {Encryption: "private"},
		{CAPEM: cert + key}, {CAPEM: cert + "garbage"},
	} {
		server.Tunnel = bad
		server.Tunnel.TransportSecurity = "tls"
		if _, err := s.SaveNode(server); !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid server PEM/config accepted", err)
		}
	}
	for _, bad := range []model.LocalTLS{
		{CertPEM: cert, KeyPEM: key}, {CAPEM: "invalid"}, {Decryption: "none"},
		{CAPEM: cert + key}, {CAPEM: key + cert}, {CAPEM: cert + "garbage"},
		{Reality: model.Reality{PrivateKey: "secret"}}, {Reality: model.Reality{Dest: "server:443"}},
		{Hysteria2: model.Hysteria2{Password: "shared"}, Flow: "xtls-rprx-vision"},
		{Hysteria2: model.Hysteria2{Password: "shared"}, Reality: model.Reality{PublicKey: "key"}},
	} {
		client.Tunnel = bad
		if _, err := s.SaveNode(client); !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid client PEM/config accepted", err)
		}
	}
	after, err := s.load()
	if err != nil || after.Revision != before.Revision || after.Nodes[server.ID].Tunnel != before.Nodes[server.ID].Tunnel || after.Nodes[client.ID].Tunnel != before.Nodes[client.ID].Tunnel {
		t.Fatal("invalid PEM changed stored state", err)
	}
	server.Tunnel = model.LocalTLS{ListenPort: 8444, CertPEM: cert, KeyPEM: key, CAPEM: cert, TransportSecurity: "tls"}
	server.ClientTunnel = nil
	if _, err := s.SaveNode(server); err != nil {
		t.Fatal(err)
	}
	client.Tunnel = model.LocalTLS{}
	if _, err := s.SaveNode(client); err != nil {
		t.Fatal(err)
	}
	m := testMapping(server.ID, client.ID, 8080)
	m.Pool = 32
	if _, err := s.SaveMapping(m); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(db, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	serverSnap, err := s.Snapshot(server.ID, serverCredential)
	if err != nil || serverSnap.Node.Tunnel != server.Tunnel {
		t.Fatal("server PEM did not survive restart", err)
	}
	clientSnap, err := s.Snapshot(client.ID, clientCredential)
	if err != nil || len(clientSnap.Nodes) != 1 {
		t.Fatal("missing bound server", err)
	}
	peer := clientSnap.Nodes[0].Tunnel
	if clientSnap.Node.Tunnel != (model.LocalTLS{}) || clientSnap.Nodes[0].ClientTunnel != nil || peer.CAPEM != cert || peer.TransportSecurity != "tls" || peer.CertPEM != "" || peer.KeyPEM != "" || peer.Decryption != "" || peer.Reality.PrivateKey != "" {
		t.Fatal("CA distribution or private redaction failed")
	}
	rows, err := s.Mappings()
	if err != nil || len(rows) != 1 || rows[0].Pool != 32 || rows[0].ServerID != server.ID || rows[0].ClientID != client.ID || clientSnap.Mappings[0].Pool != 32 {
		t.Fatal("direct mapping did not survive restart", err)
	}
	isolated, err := s.Snapshot(other.ID, otherCredential)
	if err != nil || len(isolated.Nodes) != 0 {
		t.Fatal("unbound client received server data", err)
	}
}

func TestUnconfiguredServerEnrollmentAndMapping(t *testing.T) {
	s, _, _ := testStore(t)
	server, err := s.SaveNode(model.Node{Name: "unconfigured", Role: "server", Address: "localhost", Port: 8443})
	if err != nil {
		t.Fatal(err)
	}
	credential := testCredential(t, s, server.ID)
	snapshot, err := s.Snapshot(server.ID, credential)
	if err != nil {
		t.Fatal(err)
	}
	runtime := tunnel.New(model.LocalTLS{})
	defer runtime.Close()
	if err := runtime.Apply(snapshot); err != nil {
		t.Fatal("enrolled idle server failed", err)
	}
	if _, err := s.Heartbeat(server.ID, credential, runtime.Revision(), false); err != nil {
		t.Fatal(err)
	}
	node, found, err := s.FindNodeByName(server.Name)
	if err != nil || !found || node.Error != "" || node.LastSeen == 0 || node.AppliedRevision != snapshot.Revision {
		t.Fatal("idle enrollment did not report healthy", node, err)
	}
	if public, err := publicTunnel(server); err != nil || public != (model.LocalTLS{}) {
		t.Fatal("unconfigured public tunnel", public, err)
	}
	client := testNode(t, s, "client", "client")
	before, _ := s.load()
	for _, enabled := range []bool{false, true} {
		mapping := testMapping(server.ID, client.ID, 8080)
		mapping.Enabled = enabled
		if _, err := s.SaveMapping(mapping); !errors.Is(err, ErrInvalid) {
			t.Fatal("unconfigured server accepted mapping", err)
		}
	}
	after, _ := s.load()
	if before.Revision != after.Revision || len(after.Bindings) != 0 || len(after.Secrets) != 0 || len(after.Mappings) != 0 {
		t.Fatal("rejected mapping persisted state")
	}
	server.Tunnel = testTLS(t)
	if _, err := s.SaveNode(server); err != nil {
		t.Fatal(err)
	}
	mapping, err := s.SaveMapping(testMapping(server.ID, client.ID, 8080))
	if err != nil {
		t.Fatal(err)
	}
	server.Tunnel = model.LocalTLS{}
	if _, err := s.SaveNode(server); !errors.Is(err, ErrInvalid) {
		t.Fatal("cleared bound server settings", err)
	}
	if err := s.DeleteMapping(mapping.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SaveNode(server); err != nil {
		t.Fatal("unbound server cannot return to idle", err)
	}
}

func TestServerSettingsRequireCompleteExplicitSecurity(t *testing.T) {
	s, _, _ := testStore(t)
	server := testNode(t, s, "server", "gateway")
	cert, key := testPEM(t)
	reality := model.Reality{PrivateKey: "4A39kZk0Nvd5uD3fXJbF2WvJqCq23xQ3_gL7_J0mE1s", Dest: "example.com:443", ShortIDs: "aa"}
	for _, bad := range []model.LocalTLS{
		{TransportSecurity: "tls"},
		{TransportSecurity: "bogus"},
		{ListenHost: "127.0.0.1"},
		{Flow: "none"},
		{CertPEM: cert, KeyPEM: key}, // No legacy transport inference.
		{Reality: reality, CertPEM: cert, KeyPEM: key},
		{Reality: reality, Hysteria2: model.Hysteria2{Password: "shared"}},
		{Hysteria2: model.Hysteria2{Password: "shared"}},
		{Reality: model.Reality{PrivateKey: reality.PrivateKey, ShortIDs: "aa"}},
	} {
		server.Tunnel = bad
		if _, err := s.SaveNode(server); !errors.Is(err, ErrInvalid) {
			t.Fatal("incomplete or conflicting server settings accepted", err)
		}
	}
}
