package store

import (
	"testing"

	"veilink/internal/model"
	"veilink/internal/tunnel"
)

func TestOptionalEncryptionAndMLDSACanToggle(t *testing.T) {
	s, db, keyPath := testStore(t)
	server := testNode(t, s, "server", "gateway")
	client := testNode(t, s, "client", "inside")
	credential := testCredential(t, s, client.ID)
	private, _, err := tunnel.GenerateX25519()
	if err != nil {
		t.Fatal(err)
	}
	seed, verify, err := tunnel.GenerateMldsa65()
	if err != nil {
		t.Fatal(err)
	}
	dec, _, _, _, err := tunnel.GenerateVLESSEnc()
	if err != nil {
		t.Fatal(err)
	}
	for _, enabled := range []bool{true, false, true, false} {
		server.Tunnel = model.LocalTLS{ListenPort: 8444, Reality: model.Reality{PrivateKey: private, Dest: "example.com:443", ShortIDs: "aa", ServerNames: "example.com"}}
		if enabled {
			server.Tunnel.Decryption = dec
			server.Tunnel.Reality.Mldsa65Seed = seed
			server.Tunnel.Reality.Mldsa65Verify = verify
		}
		server.ClientTunnel = nil
		if err := tunnel.CheckBootstrap("server", server.Tunnel); err != nil {
			t.Fatalf("bootstrap enabled=%v: %v", enabled, err)
		}
		if _, err := tunnel.DeriveClientTunnel(model.LocalTLS{}, server.Tunnel, server); err != nil {
			t.Fatalf("derive enabled=%v: %v", enabled, err)
		}
		server, err = s.SaveNode(server)
		if err != nil {
			t.Fatalf("save enabled=%v: %v", enabled, err)
		}
		if (server.ClientTunnel.Encryption != "") != enabled || (server.ClientTunnel.Reality.Mldsa65Verify != "") != enabled {
			t.Fatal("public template retained disabled crypto or lost enabled crypto")
		}
		if server.ClientTunnel.Reality.Mldsa65Seed != "" || server.ClientTunnel.Decryption != "" {
			t.Fatal("server secret leaked to client template")
		}
	}
	if _, err := s.SaveMapping(testMapping(server.ID, client.ID, 8080)); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(db, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	snapshot, err := reopened.Snapshot(client.ID, credential)
	if err != nil || len(snapshot.Nodes) != 1 {
		t.Fatalf("client snapshot: %v", err)
	}
	peer := snapshot.Nodes[0].Tunnel
	if peer.Encryption != "" || peer.Decryption != "" || peer.Reality.Mldsa65Verify != "" || peer.Reality.Mldsa65Seed != "" {
		t.Fatal("disabled crypto returned after database restart")
	}
}
