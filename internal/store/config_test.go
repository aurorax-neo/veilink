package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"veilink/internal/model"
	"veilink/internal/tunnel"
)

func testStore(t *testing.T) (*Store, string, string) {
	t.Helper()
	dir := t.TempDir()
	db, key := filepath.Join(dir, "db"), filepath.Join(dir, "key")
	s, err := Open(db, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, db, key
}

func testNode(t *testing.T, s *Store, role, name string) model.Node {
	t.Helper()
	local := model.LocalTLS{}
	if role == "server" {
		local = testTLS(t)
	}
	n, err := s.SaveNode(model.Node{Name: name, Role: role, Address: "localhost", Port: 443, Tunnel: local})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func testCredential(t *testing.T, s *Store, id string) string {
	t.Helper()
	token, err := s.EnrollToken(id, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := s.Enroll(id, token)
	if err != nil {
		t.Fatal(err)
	}
	return credential
}

func testMapping(server, client string, port int) model.Mapping {
	return model.Mapping{Name: "route", ServerID: server, ClientID: client, Pool: 1, ListenHost: "0.0.0.0", ListenPort: port, TargetHost: "localhost", TargetPort: 80, Enabled: true}
}

func TestDirectMappingSessionsRollbackAndCleanup(t *testing.T) {
	s, db, key := testStore(t)
	server := testNode(t, s, "server", "gateway")
	second := testNode(t, s, "server", "second")
	client := testNode(t, s, "client", "client")
	credential := testCredential(t, s, client.ID)
	m, err := s.SaveMapping(testMapping(server.ID, client.ID, 8080))
	if err != nil || m.BindingID == "" || m.Pool != 1 || m.Network != "tcp" {
		t.Fatalf("direct mapping: %+v %v", m, err)
	}
	shared, err := s.SaveMapping(testMapping(server.ID, client.ID, 8081))
	if err != nil || shared.BindingID != m.BindingID {
		t.Fatalf("session reuse: %+v %v", shared, err)
	}
	before, _ := s.load()
	for _, change := range []func(*model.Mapping){
		func(m *model.Mapping) { m.Network = "sctp" },
		func(m *model.Mapping) { m.Pool = -1 },
		func(m *model.Mapping) { m.Pool = 0 },
		func(m *model.Mapping) { m.ServerID = "" },
		func(m *model.Mapping) { m.ClientID = "" },
		func(m *model.Mapping) { m.BindingID = shared.BindingID; m.ServerID = ""; m.ClientID = "" },
		func(m *model.Mapping) { m.Pool = 33 },
		func(m *model.Mapping) { m.ClientID = server.ID },
		func(m *model.Mapping) { m.ServerID = client.ID },
		func(m *model.Mapping) { m.ServerID = "missing" },
		func(m *model.Mapping) { m.BindingID = shared.BindingID; m.ServerID = second.ID },
		func(m *model.Mapping) { m.BindingID = "missing" },
	} {
		bad := testMapping(server.ID, client.ID, 8082)
		change(&bad)
		if _, err := s.SaveMapping(bad); !errors.Is(err, ErrInvalid) {
			t.Fatalf("accepted %+v: %v", bad, err)
		}
	}
	// Validation failure after creating a new session must not persist it.
	bad := testMapping(second.ID, client.ID, second.Tunnel.ListenPort)
	if _, err := s.SaveMapping(bad); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	after, _ := s.load()
	if !reflect.DeepEqual(before, after) {
		t.Fatal("failed save mutated state")
	}
	// Failure of the SQL audit write must roll back config and encrypted session.
	if _, err := s.db.Exec("CREATE TRIGGER fail_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT,'test rollback'); END"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SaveMapping(testMapping(second.ID, client.ID, 8090)); err == nil {
		t.Fatal("expected SQL failure")
	}
	if _, err := s.db.Exec("DROP TRIGGER fail_audit"); err != nil {
		t.Fatal(err)
	}
	after, _ = s.load()
	if !reflect.DeepEqual(before, after) {
		t.Fatal("SQL rollback failed")
	}
	snap, err := s.Snapshot(client.ID, credential)
	if err != nil {
		t.Fatal(err)
	}
	uuid := snap.Bindings[0].UUID
	data, _ := json.Marshal(after)
	if bytes.Contains(data, []byte(uuid)) {
		t.Fatal("plaintext UUID persisted")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(db, key)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	snap, err = s.Snapshot(client.ID, credential)
	if err != nil || snap.Bindings[0].UUID != uuid {
		t.Fatal("session not persistent", err)
	}
	m.BindingID, m.ServerID = "", second.ID
	m, err = s.SaveMapping(m)
	if err != nil {
		t.Fatal(err)
	}
	state, _ := s.load()
	if len(state.Bindings) != 2 {
		t.Fatal("removed referenced shared session")
	}
	if err := s.DeleteMapping(shared.ID); err != nil {
		t.Fatal(err)
	}
	state, _ = s.load()
	if len(state.Bindings) != 1 || len(state.Secrets) != 2 || state.Secrets[shared.BindingID] != nil || !bytes.Equal(state.Secrets[enrollmentCredentialKey(client.ID)], before.Secrets[enrollmentCredentialKey(client.ID)]) {
		t.Fatal("orphan session retained")
	}
	m.BindingID, m.ServerID = "", server.ID
	m, err = s.SaveMapping(m)
	if err != nil {
		t.Fatal(err)
	}
	state, _ = s.load()
	if len(state.Bindings) != 1 {
		t.Fatal("update retained orphan")
	}
	if err := s.DeleteMapping(m.ID); err != nil {
		t.Fatal(err)
	}
	state, _ = s.load()
	if len(state.Bindings) != 0 || len(state.Secrets) != 1 || !bytes.Equal(state.Secrets[enrollmentCredentialKey(client.ID)], before.Secrets[enrollmentCredentialKey(client.ID)]) {
		t.Fatal("delete retained orphan")
	}
	if err := s.RemoveNode(client.ID, false); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SaveMapping(testMapping(server.ID, client.ID, 8080)); !errors.Is(err, ErrInvalid) {
		t.Fatal("accepted revoked client")
	}
}

func TestGatewayDefaultsRemainLiveAndPrivate(t *testing.T) {
	s, _, _ := testStore(t)
	client := testNode(t, s, "client", "client")
	credential := testCredential(t, s, client.ID)
	private := "4A39kZk0Nvd5uD3fXJbF2WvJqCq23xQ3_gL7_J0mE1s"
	servers := []model.Node{testNode(t, s, "server", "one"), testNode(t, s, "server", "two")}
	for i := range servers {
		servers[i].ClientTunnel = nil
		servers[i].Tunnel = model.LocalTLS{Flow: "xtls-rprx-vision", ListenHost: "127.0.0.1", ListenPort: 8444, Decryption: "mlkem768x25519plus.native.600s." + private,
			Reality: model.Reality{PrivateKey: private, Dest: "secret-destination:443", ShortIDs: []string{"aa,bb", "cc,dd"}[i], ServerNames: servers[i].Name + ".example.com"}}
		var err error
		servers[i], err = s.SaveNode(servers[i])
		if err != nil {
			t.Fatal(err)
		}
		if _, err = s.SaveMapping(testMapping(servers[i].ID, client.ID, 8080)); err != nil {
			t.Fatal(err)
		}
	}
	check := func(expected map[string]string) {
		t.Helper()
		snap, err := s.Snapshot(client.ID, credential)
		if err != nil {
			t.Fatal(err)
		}
		if snap.Node.Tunnel != (model.LocalTLS{}) || snap.Node.ClientTunnel != nil || len(snap.Nodes) != 2 {
			t.Fatal("client configuration not authoritative or peers missing")
		}
		if len(snap.Nodes[0].ConnectEndpoints) == 0 {
			t.Fatal("client snapshot lost public connect endpoints")
		}
		for _, peer := range snap.Nodes {
			for _, server := range servers {
				if server.ID == peer.ID && (server.ClientTunnel == nil || peer.Tunnel != *server.ClientTunnel) {
					t.Fatal("mapped snapshot differs from derived stored template")
				}
			}
			if peer.Tunnel.ListenHost != "" || peer.Tunnel.ListenPort != 0 {
				t.Fatal("client snapshot leaked server local bind endpoint")
			}
			if peer.Tunnel.Reality.ShortID != expected[peer.ID] {
				t.Fatalf("wrong gateway defaults: %+v", peer)
			}
			if peer.Tunnel.Encryption == "" || peer.Tunnel.Encryption == servers[0].Tunnel.Decryption {
				t.Fatal("public encryption not derived")
			}
			data, _ := json.Marshal(peer)
			for _, secret := range []string{private, "/private/", "secret-destination", "600s"} {
				if bytes.Contains(data, []byte(secret)) {
					t.Fatalf("peer leaked %q", secret)
				}
			}
			if peer.ClientTunnel != nil {
				t.Fatal("nested server template leaked")
			}
		}
	}
	check(map[string]string{servers[0].ID: "aa", servers[1].ID: "cc"})
	servers[0].Tunnel.Reality.ShortIDs = "ee,ff"
	servers[0].ClientTunnel = nil
	var err error
	servers[0], err = s.SaveNode(servers[0])
	if err != nil {
		t.Fatal(err)
	}
	check(map[string]string{servers[0].ID: "ee", servers[1].ID: "cc"})
	client.Tunnel.Reality.ShortID = "ab"
	if _, err := s.SaveNode(client); !errors.Is(err, ErrInvalid) {
		t.Fatal("client override accepted", err)
	}
	check(map[string]string{servers[0].ID: "ee", servers[1].ID: "cc"})
}

func TestCredentialTTLRotationAndRevocation(t *testing.T) {
	s, _, _ := testStore(t)
	n := testNode(t, s, "client", "client")
	credential := testCredential(t, s, n.ID)
	var expires int64
	if err := s.db.QueryRow("SELECT expires FROM credentials WHERE node=?", n.ID).Scan(&expires); err != nil {
		t.Fatal(err)
	}
	if delta := expires - time.Now().Unix(); delta < int64((29*24*time.Hour)/time.Second) || delta > int64((30*24*time.Hour)/time.Second) {
		t.Fatal("credential not bounded", delta)
	}
	token, err := s.EnrollToken(n.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeEnrollToken(n.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Enroll(n.ID, token); !errors.Is(err, ErrAuth) {
		t.Fatal("revoked enrollment accepted")
	}
	if _, err := s.Snapshot(n.ID, credential); err != nil {
		t.Fatal("revocation affected active credential", err)
	}
	reused := testCredential(t, s, n.ID)
	if reused != credential {
		t.Fatal("new enrollment token changed an active credential")
	}
	if _, err := s.db.Exec("UPDATE credentials SET expires=? WHERE node=?", time.Now().Unix(), n.ID); err != nil {
		t.Fatal(err)
	}
	rotated := testCredential(t, s, n.ID)
	if rotated == credential {
		t.Fatal("expired credential was not replaced")
	}
	if _, err := s.Snapshot(n.ID, credential); !errors.Is(err, ErrAuth) {
		t.Fatal("expired credential revived")
	}
	if _, err := s.db.Exec("UPDATE credentials SET expires=?", time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Snapshot(n.ID, rotated); !errors.Is(err, ErrAuth) {
		t.Fatal("expired snapshot accepted")
	}
	if _, err := s.Heartbeat(n.ID, rotated, 0, false); !errors.Is(err, ErrAuth) {
		t.Fatal("expired heartbeat accepted")
	}
	if _, err := s.db.Exec("UPDATE credentials SET expires=0"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Snapshot(n.ID, rotated); !errors.Is(err, ErrAuth) {
		t.Fatal("zero-expiry credential accepted")
	}
	if _, err := s.Heartbeat(n.ID, rotated, 0, false); !errors.Is(err, ErrAuth) {
		t.Fatal("zero-expiry heartbeat accepted")
	}
}

func TestEncryptionAcrossTransportsAndFlowValidation(t *testing.T) {
	s, _, _ := testStore(t)
	dec, enc, pqDec, pqEnc, err := tunnel.GenerateVLESSEnc()
	if err != nil {
		t.Fatal(err)
	}
	for _, keys := range [][2]string{{dec, enc}, {pqDec, pqEnc}} {
		for _, transport := range []string{"raw", "tls", "reality", "hysteria2"} {
			t.Run(transport, func(t *testing.T) {
				cert, key := testPEM(t)
				server := testNode(t, s, "server", transport)
				client := testNode(t, s, "client", transport+"-client")
				server.Tunnel = model.LocalTLS{Protocol: "vless", ListenPort: 8444, Decryption: keys[0]}
				server.ClientTunnel = nil
				switch transport {
				case "raw":
					server.Tunnel.TransportSecurity = "plain"
				case "tls":
					server.Tunnel.TransportSecurity = "tls"
					server.Tunnel.CertPEM, server.Tunnel.KeyPEM = cert, key
				case "reality":
					server.Tunnel.Reality = model.Reality{PrivateKey: "4A39kZk0Nvd5uD3fXJbF2WvJqCq23xQ3_gL7_J0mE1s", Dest: "example.com:443", ShortIDs: "aa", ServerNames: "example.com"}
				case "hysteria2":
					server.Tunnel.CertPEM, server.Tunnel.KeyPEM = cert, key
					server.Tunnel.Hysteria2.Password = "shared-password"
					server.Tunnel.Protocol = "hysteria2"
					if _, err := s.SaveNode(server); !errors.Is(err, ErrInvalid) {
						t.Fatal("HY2 accepted VLESS Encryption", err)
					}
					server.Tunnel.Decryption = ""
				}
				server, err = s.SaveNode(server)
				if err != nil {
					t.Fatal("server encryption rejected", err)
				}
				if _, err := s.SaveNode(client); err != nil {
					t.Fatal("client encryption rejected", err)
				}
				if _, err := s.SaveMapping(testMapping(server.ID, client.ID, 8080)); err != nil {
					t.Fatal(err)
				}
				snap, err := s.Snapshot(client.ID, testCredential(t, s, client.ID))
				if err != nil {
					t.Fatal(err)
				}
				peer := snap.Nodes[0].Tunnel
				expectedEncryption := keys[1]
				if transport == "hysteria2" {
					expectedEncryption = ""
				}
				if peer.Protocol != server.Tunnel.Protocol || peer.Encryption != expectedEncryption || peer.Decryption != "" || peer.KeyPEM != "" || peer.CertPEM != "" || peer.Reality.PrivateKey != "" {
					t.Fatal("public crypto defaults or redaction incorrect")
				}
				if transport == "hysteria2" && peer.Hysteria2.Password != "shared-password" {
					t.Fatal("lost authorized HY2 credential")
				}
				server.Tunnel.Flow = "xtls-rprx-vision"
				server.ClientTunnel = nil
				_, err = s.SaveNode(server)
				if transport == "raw" || transport == "hysteria2" {
					if !errors.Is(err, ErrInvalid) {
						t.Fatal("invalid server flow accepted", err)
					}
				} else if err != nil {
					t.Fatal("TLS/REALITY flow rejected", err)
				}
				client.Tunnel.Flow = "xtls-rprx-vision"
				_, err = s.SaveNode(client)
				if !errors.Is(err, ErrInvalid) {
					t.Fatal("client flow override accepted", err)
				}
			})
		}
	}
}

func TestNativeCryptoValidationAndCorruptSnapshotFailure(t *testing.T) {
	s, _, _ := testStore(t)
	server := testNode(t, s, "server", "server")
	server.Tunnel.ListenPort = 8444
	client := testNode(t, s, "client", "client")
	dec, enc, _, _, err := tunnel.GenerateVLESSEnc()
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		strings.Replace(dec, ".600s.", ".invalid-ticket.", 1),
		strings.Replace(dec, ".600s.", ".600s.invalid-padding.", 1),
		"mlkem768x25519plus.native.600s.bad-key",
	} {
		server.Tunnel.Decryption = bad
		if _, err := s.SaveNode(server); !errors.Is(err, ErrInvalid) {
			t.Fatal("malformed private key accepted", err)
		}
	}
	for _, bad := range []string{
		strings.Replace(enc, ".0rtt.", ".invalid-ticket.", 1),
		strings.Replace(enc, ".0rtt.", ".0rtt.invalid-padding.", 1),
		"mlkem768x25519plus.native.0rtt.bad-key",
	} {
		client.Tunnel.Encryption = bad
		if _, err := s.SaveNode(client); !errors.Is(err, ErrInvalid) {
			t.Fatal("malformed public key accepted", err)
		}
	}
	if _, err := s.SaveMapping(testMapping(server.ID, client.ID, 8080)); err != nil {
		t.Fatal(err)
	}
	credential := testCredential(t, s, client.ID)
	if err := s.mutate("test.corrupt", server.ID, func(st *state) error {
		n := st.Nodes[server.ID]
		n.Tunnel.Decryption = "malformed-key"
		st.Nodes[server.ID] = n
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	snap, err := s.Snapshot(client.ID, credential)
	if !errors.Is(err, ErrInvalid) || len(snap.Nodes) != 0 {
		t.Fatal("invalid crypto silently downgraded", err)
	}
}

func TestClientTemplateReadOnlyAndLegacyFailure(t *testing.T) {
	s, _, _ := testStore(t)
	server := testNode(t, s, "server", "server")
	cert, key := testPEM(t)
	server.Tunnel = model.LocalTLS{TransportSecurity: "tls", CertPEM: cert, KeyPEM: key, CAPEM: cert}
	server.ClientTunnel = nil
	server, err := s.SaveNode(server)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SaveNode(server); err != nil {
		t.Fatal("identical derived roundtrip rejected", err)
	}
	for _, change := range []func(*model.LocalTLS){
		func(c *model.LocalTLS) { c.Reality.Fingerprint = "firefox" },
		func(c *model.LocalTLS) { c.Flow = "xtls-rprx-vision" },
		func(c *model.LocalTLS) { c.CAPEM = "" },
		func(c *model.LocalTLS) { *c = model.LocalTLS{} },
	} {
		candidate := server
		public := *server.ClientTunnel
		change(&public)
		candidate.ClientTunnel = &public
		if _, err := s.SaveNode(candidate); !errors.Is(err, ErrInvalid) {
			t.Fatal("custom template accepted", err)
		}
		if _, err := publicTunnel(candidate); !errors.Is(err, ErrInvalid) {
			t.Fatal("custom persisted template accepted", err)
		}
	}
	if err := s.mutate("test.legacy", server.ID, func(st *state) error {
		n := st.Nodes[server.ID]
		n.ClientTunnel.Reality.Fingerprint = "firefox"
		st.Nodes[server.ID] = n
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var before, after []byte
	if err := s.db.QueryRow("SELECT data FROM config WHERE id=1").Scan(&before); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Nodes(); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "unsupported persisted configuration") {
		t.Fatal("legacy override not explicitly rejected", err)
	}
	server.ClientTunnel = nil
	if _, err := s.SaveNode(server); !errors.Is(err, ErrInvalid) {
		t.Fatal("legacy override silently replaced", err)
	}
	if err := s.db.QueryRow("SELECT data FROM config WHERE id=1").Scan(&after); err != nil || !bytes.Equal(before, after) {
		t.Fatal("legacy data changed", err)
	}
}
