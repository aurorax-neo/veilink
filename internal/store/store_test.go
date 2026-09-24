package store

import (
	"bytes"
	"errors"
	"path/filepath"
	"testing"
	"time"
	"veilink/internal/model"
)

func TestPersistenceIsolationRevocation(t *testing.T) {
	dir := t.TempDir()
	db, key := filepath.Join(dir, "db"), filepath.Join(dir, "key")
	s, e := Open(db, key)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { s.Close() }()
	if e = s.InitAdmin("admin", "test password long"); e != nil {
		t.Fatal(e)
	}
	if !s.Login("admin", "test password long") || s.Login("admin", "wrong") {
		t.Fatal("login")
	}
	server, e := s.SaveNode(model.Node{Name: "gateway", Role: "server", Address: "localhost", ServerName: "localhost", Port: 443})
	if e != nil {
		t.Fatal(e)
	}
	client, e := s.SaveNode(model.Node{Name: "private", Role: "client"})
	if e != nil {
		t.Fatal(e)
	}
	other, e := s.SaveNode(model.Node{Name: "other", Role: "client"})
	if e != nil {
		t.Fatal(e)
	}
	creds := map[string]string{}
	for _, n := range []model.Node{server, client, other} {
		token, e := s.EnrollToken(n.ID, time.Hour)
		if e != nil {
			t.Fatal(e)
		}
		creds[n.ID], e = s.Enroll(n.ID, token)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = s.Enroll(n.ID, token); !errors.Is(e, ErrAuth) {
			t.Fatal("enrollment reused")
		}
	}
	expired, e := s.EnrollToken(other.ID, time.Hour)
	if e != nil {
		t.Fatal(e)
	}
	s.db.Exec("UPDATE enroll SET expires=0 WHERE node=?", other.ID)
	if _, e = s.Enroll(other.ID, expired); !errors.Is(e, ErrAuth) {
		t.Fatal("expired token accepted")
	}
	b, e := s.SaveBinding(model.Binding{ServerID: server.ID, ClientID: client.ID})
	if e != nil {
		t.Fatal(e)
	}
	m, e := s.SaveMapping(model.Mapping{Name: "test", BindingID: b.ID, ListenHost: "0.0.0.0", ListenPort: 10080, TargetHost: "127.0.0.1", TargetPort: 80, Enabled: true})
	if e != nil {
		t.Fatal(e)
	}
	m.ID = ""
	m.ListenHost = "127.0.0.1"
	if _, e = s.SaveMapping(m); e == nil {
		t.Fatal("wildcard conflict accepted")
	}
	snap, e := s.Snapshot(client.ID, creds[client.ID])
	if e != nil || len(snap.Bindings) != 1 || len(snap.Mappings) != 1 || snap.Bindings[0].UUID == "" {
		t.Fatal("snapshot", e)
	}
	uuid := snap.Bindings[0].UUID
	var data []byte
	s.db.QueryRow("SELECT data FROM config").Scan(&data)
	if bytes.Contains(data, []byte(uuid)) {
		t.Fatal("UUID stored plaintext")
	}
	bindings, _ := s.Bindings()
	if bindings[0].UUID != "" {
		t.Fatal("UUID leaked")
	}
	isolated, e := s.Snapshot(other.ID, creds[other.ID])
	if e != nil || len(isolated.Bindings) != 0 || len(isolated.Mappings) != 0 {
		t.Fatal("isolation")
	}
	if _, e = s.Snapshot(client.ID, creds[other.ID]); !errors.Is(e, ErrAuth) {
		t.Fatal("cross-node credential")
	}
	s.Close()
	s, e = Open(db, key)
	if e != nil {
		t.Fatal(e)
	}
	snap, e = s.Snapshot(client.ID, creds[client.ID])
	if e != nil || snap.Bindings[0].UUID != uuid {
		t.Fatal("persistence", e)
	}
	if e = s.RemoveNode(client.ID, false); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Snapshot(client.ID, creds[client.ID]); !errors.Is(e, ErrAuth) {
		t.Fatal("revoked pull")
	}
	if _, e = s.Heartbeat(client.ID, creds[client.ID], 0, false); !errors.Is(e, ErrAuth) {
		t.Fatal("revoked heartbeat")
	}
	snap, e = s.Snapshot(server.ID, creds[server.ID])
	if e != nil || len(snap.Bindings) != 0 || len(snap.Mappings) != 0 {
		t.Fatal("revoked peer routes retained")
	}
	if _, e = s.EnrollToken(client.ID, time.Hour); e == nil {
		t.Fatal("revoked enroll")
	}
	audit, e := s.Audit()
	if e != nil || len(audit) == 0 {
		t.Fatal("audit")
	}
}

func TestUDPMappingValidationAndPersistence(t *testing.T) {
	dir := t.TempDir()
	db, key := filepath.Join(dir, "db"), filepath.Join(dir, "key")
	s, err := Open(db, key)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if err = s.InitAdmin("admin", "test password long"); err != nil {
		t.Fatal(err)
	}

	server, err := s.SaveNode(model.Node{Name: "gw", Role: "server", Address: "localhost", ServerName: "localhost", Port: 8443})
	if err != nil {
		t.Fatal(err)
	}
	client, err := s.SaveNode(model.Node{Name: "cli", Role: "client"})
	if err != nil {
		t.Fatal(err)
	}
	binding, err := s.SaveBinding(model.Binding{ServerID: server.ID, ClientID: client.ID})
	if err != nil {
		t.Fatal(err)
	}

	// 1. TCP mapping on server.Port (8443) must be rejected
	tcpConflict := model.Mapping{
		Name:       "tcp-conflict",
		BindingID:  binding.ID,
		Network:    "tcp",
		ListenHost: "0.0.0.0",
		ListenPort: 8443,
		TargetHost: "127.0.0.1",
		TargetPort: 8080,
		Enabled:    true,
	}
	if _, err := s.SaveMapping(tcpConflict); !errors.Is(err, ErrInvalid) {
		t.Fatalf("expected ErrInvalid when TCP mapping uses server.Port, got %v", err)
	}

	// 2. UDP mapping on server.Port (8443) is allowed (UDP port != TCP transport port)
	// Also verify case-insensitive protocol normalization: "  UDP  " -> "udp"
	udpOnServerPort := model.Mapping{
		Name:       "udp-on-server-port",
		BindingID:  binding.ID,
		Network:    "  UDP  ",
		ListenHost: "0.0.0.0",
		ListenPort: 8443,
		TargetHost: "127.0.0.1",
		TargetPort: 5353,
		Enabled:    true,
	}
	savedUDP, err := s.SaveMapping(udpOnServerPort)
	if err != nil {
		t.Fatalf("saving UDP mapping on server port failed: %v", err)
	}
	if savedUDP.Network != "udp" {
		t.Fatalf("expected normalized network 'udp', got %q", savedUDP.Network)
	}

	// 3. UDP port collision: another UDP mapping on overlapping host and same port must fail
	udpCollision := model.Mapping{
		Name:       "udp-dup",
		BindingID:  binding.ID,
		Network:    "udp",
		ListenHost: "127.0.0.1",
		ListenPort: 8443,
		TargetHost: "127.0.0.1",
		TargetPort: 5354,
		Enabled:    true,
	}
	if _, err := s.SaveMapping(udpCollision); !errors.Is(err, ErrInvalid) {
		t.Fatalf("expected ErrInvalid on UDP port collision, got %v", err)
	}

	// 4. TCP and UDP coexistence: a TCP mapping on a non-server port (e.g. 9000)
	// and a UDP mapping on the same port (9000) must coexist without collision
	tcp9000 := model.Mapping{
		Name:       "tcp-9000",
		BindingID:  binding.ID,
		Network:    "tcp",
		ListenHost: "0.0.0.0",
		ListenPort: 9000,
		TargetHost: "127.0.0.1",
		TargetPort: 9001,
		Enabled:    true,
	}
	if _, err := s.SaveMapping(tcp9000); err != nil {
		t.Fatalf("saving TCP mapping on 9000 failed: %v", err)
	}

	udp9000 := model.Mapping{
		Name:       "udp-9000",
		BindingID:  binding.ID,
		Network:    "udp",
		ListenHost: "0.0.0.0",
		ListenPort: 9000,
		TargetHost: "127.0.0.1",
		TargetPort: 9002,
		Enabled:    true,
	}
	if _, err := s.SaveMapping(udp9000); err != nil {
		t.Fatalf("saving UDP mapping on same port 9000 as TCP mapping should succeed, got: %v", err)
	}

	// 5. Snapshot validation: verify client credential gets the UDP mapping with network="udp"
	tok, err := s.EnrollToken(client.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cred, err := s.Enroll(client.ID, tok)
	if err != nil {
		t.Fatal(err)
	}
	snap, err := s.Snapshot(client.ID, cred)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Mappings) != 3 {
		t.Fatalf("expected 3 mappings in snapshot, got %d", len(snap.Mappings))
	}
	var foundUDP8443, foundUDP9000, foundTCP9000 bool
	for _, m := range snap.Mappings {
		if m.ListenPort == 8443 && m.Network == "udp" {
			foundUDP8443 = true
		}
		if m.ListenPort == 9000 && m.Network == "udp" {
			foundUDP9000 = true
		}
		if m.ListenPort == 9000 && m.Network == "tcp" {
			foundTCP9000 = true
		}
	}
	if !foundUDP8443 || !foundUDP9000 || !foundTCP9000 {
		t.Fatalf("snapshot missing expected mappings: udp8443=%v, udp9000=%v, tcp9000=%v", foundUDP8443, foundUDP9000, foundTCP9000)
	}
}
func TestStoreHasAdminAndFindNodeByName(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "test.db"), filepath.Join(dir, "test.key"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	hasAdmin, err := s.HasAdmin()
	if err != nil {
		t.Fatal(err)
	}
	if hasAdmin {
		t.Fatalf("expected no admin, got true")
	}

	if err := s.InitAdmin("admin", "AdminSecret123!"); err != nil {
		t.Fatal(err)
	}

	hasAdmin, err = s.HasAdmin()
	if err != nil {
		t.Fatal(err)
	}
	if !hasAdmin {
		t.Fatalf("expected admin to exist, got false")
	}

	_, found, err := s.FindNodeByName("nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	if found {
		t.Fatalf("expected node to not be found")
	}

	node, err := s.SaveNode(model.Node{
		Name:       "server-local",
		Role:       "server",
		Address:    "127.0.0.1",
		Port:       8444,
		ServerName: "localhost",
	})
	if err != nil {
		t.Fatal(err)
	}

	foundNode, found, err := s.FindNodeByName("server-local")
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatalf("expected node to be found")
	}
	if foundNode.ID != node.ID || foundNode.Port != 8444 {
		t.Fatalf("unexpected node data: %+v", foundNode)
	}
}

func TestTunnelConfigPersistenceAndAutoDerivation(t *testing.T) {
	dir := t.TempDir()
	db, key := filepath.Join(dir, "db"), filepath.Join(dir, "key")
	s, err := Open(db, key)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// Test private key for X25519 (32 bytes base64url)
	testPriv := "4A39kZk0Nvd5uD3fXJbF2WvJqCq23xQ3_gL7_J0mE1s"
	expectedPub := model.DeriveX25519Public(testPriv)
	if expectedPub == "" {
		t.Fatal("failed to derive test public key")
	}

	server, err := s.SaveNode(model.Node{
		Name:       "gateway-reality",
		Role:       "server",
		Address:    "1.2.3.4",
		Port:       443,
		ServerName: "gateway.example.com",
		Tunnel: model.LocalTLS{
			Flow:       "xtls-rprx-vision",
			Decryption: "none",
			Reality: model.Reality{
				Dest:        "gateway.example.com:443",
				PrivateKey:  testPriv,
				ShortIDs:    "0123456789abcdef,fedcba9876543210",
				ServerNames: "gateway.example.com",
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if server.Tunnel.Reality.PublicKey != expectedPub {
		t.Fatalf("expected auto-derived public key %q, got %q", expectedPub, server.Tunnel.Reality.PublicKey)
	}

	client, err := s.SaveNode(model.Node{
		Name: "agent-1",
		Role: "client",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Enroll client & server
	tokenC, _ := s.EnrollToken(client.ID, time.Hour)
	credC, _ := s.Enroll(client.ID, tokenC)
	tokenS, _ := s.EnrollToken(server.ID, time.Hour)
	credS, _ := s.Enroll(server.ID, tokenS)

	// Create binding
	b, err := s.SaveBinding(model.Binding{
		ServerID: server.ID,
		ClientID: client.ID,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Verify client tunnel was auto-derived
	nodes, err := s.Nodes()
	if err != nil {
		t.Fatal(err)
	}
	var foundClient model.Node
	for _, n := range nodes {
		if n.ID == client.ID {
			foundClient = n
			break
		}
	}
	if foundClient.Tunnel.Flow != "xtls-rprx-vision" {
		t.Fatalf("expected client flow to be auto-derived, got %q", foundClient.Tunnel.Flow)
	}
	if foundClient.Tunnel.Encryption != "none" {
		t.Fatalf("expected client encryption 'none', got %q", foundClient.Tunnel.Encryption)
	}
	if foundClient.Tunnel.Reality.PublicKey != expectedPub {
		t.Fatalf("expected client public key %q, got %q", expectedPub, foundClient.Tunnel.Reality.PublicKey)
	}
	if foundClient.Tunnel.Reality.ShortID != "0123456789abcdef" {
		t.Fatalf("expected client short ID '0123456789abcdef', got %q", foundClient.Tunnel.Reality.ShortID)
	}
	if foundClient.Tunnel.Reality.Fingerprint != "chrome" {
		t.Fatalf("expected default fingerprint 'chrome', got %q", foundClient.Tunnel.Reality.Fingerprint)
	}

	// Verify snapshot redacts server private key for client
	clientSnap, err := s.Snapshot(client.ID, credC)
	if err != nil {
		t.Fatal(err)
	}
	if len(clientSnap.Nodes) != 1 {
		t.Fatalf("expected 1 peer gateway, got %d", len(clientSnap.Nodes))
	}
	if clientSnap.Nodes[0].Tunnel.Reality.PrivateKey != "" {
		t.Fatal("server private key leaked to client in snapshot!")
	}
	if clientSnap.Node.Tunnel.Reality.PublicKey != expectedPub {
		t.Fatalf("expected client snapshot public key %q, got %q", expectedPub, clientSnap.Node.Tunnel.Reality.PublicKey)
	}

	// Server snapshot should retain private key
	serverSnap, err := s.Snapshot(server.ID, credS)
	if err != nil {
		t.Fatal(err)
	}
	if serverSnap.Node.Tunnel.Reality.PrivateKey != testPriv {
		t.Fatal("server snapshot lost private key")
	}

	// Close and re-open store to verify SQLite persistence
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s2, err := Open(db, key)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()

	reloadedNodes, err := s2.Nodes()
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range reloadedNodes {
		if n.ID == server.ID {
			if n.Tunnel.Reality.PrivateKey != testPriv || n.Tunnel.Reality.PublicKey != expectedPub {
				t.Fatalf("server tunnel not persisted properly: %+v", n.Tunnel)
			}
		}
		if n.ID == client.ID {
			if n.Tunnel.Reality.PublicKey != expectedPub || n.Tunnel.Flow != "xtls-rprx-vision" {
				t.Fatalf("client tunnel not persisted properly: %+v", n.Tunnel)
			}
		}
	}

	// Test manual client override
	foundClient.Tunnel.Reality.ShortID = "customoverride123"
	foundClient.Tunnel.Pool = 8
	updatedClient, err := s2.SaveNode(foundClient)
	if err != nil {
		t.Fatal(err)
	}
	if updatedClient.Tunnel.Reality.ShortID != "customoverride123" || updatedClient.Tunnel.Pool != 8 {
		t.Fatalf("manual override failed: %+v", updatedClient.Tunnel)
	}
	_ = b
}
