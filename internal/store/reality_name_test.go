package store

import (
	"errors"
	"testing"
	"veilink/internal/model"
	"veilink/internal/tunnel"
)

func TestRealityFallbackNameValidatedBeforeSave(t *testing.T) {
	s, _, _ := testStore(t)
	private, _, err := tunnel.GenerateX25519()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"127.0.0.1", "localhost", "::1"} {
		n := model.Node{Name: "bad-reality", Role: "server", Address: "127.0.0.1", Port: 8444, ServerName: name, Tunnel: model.LocalTLS{Reality: model.Reality{PrivateKey: private, Dest: "cover.example:443", ShortIDs: "aa"}}}
		if _, err := s.SaveNode(n); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid fallback %q accepted: %v", name, err)
		}
		nodes, err := s.Nodes()
		if err != nil || len(nodes) != 0 {
			t.Fatalf("invalid server persisted: %v", err)
		}
	}
	n := model.Node{Name: "valid-reality", Role: "server", Address: "127.0.0.1", Port: 8444, ServerName: "localhost", Tunnel: model.LocalTLS{Reality: model.Reality{PrivateKey: private, Dest: "cover.example:443", ShortIDs: "aa", ServerNames: "cover.example"}}}
	saved, err := s.SaveNode(n)
	if err != nil {
		t.Fatal(err)
	}
	if saved.ClientTunnel == nil || saved.ClientTunnel.Reality.ServerNames != "cover.example" {
		t.Fatal("lost explicit cover name")
	}
}
