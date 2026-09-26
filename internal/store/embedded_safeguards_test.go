package store

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"veilink/internal/model"
)

func TestEmbeddedIdentitySafeguards(t *testing.T) {
	dir := t.TempDir()
	db, key := filepath.Join(dir, "db"), filepath.Join(dir, "key")
	s, err := Open(db, key)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { s.Close() }()
	seed := model.Node{Name: "embedded-server", Role: "server", Address: "localhost", Port: 8444}
	spoof := seed
	spoof.Embedded = true
	if _, err := s.SaveNode(spoof); !errors.Is(err, ErrInvalid) {
		t.Fatalf("embedded creation: %v", err)
	}
	external, err := s.SaveNode(seed)
	if err != nil {
		t.Fatal(err)
	}
	credential := testCredential(t, s, external.ID)
	external.Embedded = true
	if _, err := s.SaveNode(external); !errors.Is(err, ErrInvalid) {
		t.Fatalf("embedded promotion: %v", err)
	}
	seed.ID = external.ID // Even a supplied ID must not claim external credentials.
	embedded, err := s.EnsureEmbeddedNode(seed)
	if err != nil {
		t.Fatal(err)
	}
	if embedded.ID == external.ID || !embedded.Embedded {
		t.Fatal("adopted external identity")
	}
	if _, err := s.Snapshot(embedded.ID, credential); !errors.Is(err, ErrAuth) {
		t.Fatal("adopted external credential", err)
	}
	if snap, err := s.Snapshot(external.ID, credential); err != nil || snap.Node.Embedded {
		t.Fatal("changed external node", err)
	}
	embeddedCredential := testCredential(t, s, embedded.ID)
	pending, err := s.EnrollToken(embedded.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for _, remove := range []bool{false, true} {
		if err := s.RemoveNode(embedded.ID, remove); !errors.Is(err, ErrInvalid) {
			t.Fatalf("embedded remove=%t: %v", remove, err)
		}
	}
	if _, err := s.Snapshot(embedded.ID, embeddedCredential); err != nil {
		t.Fatal("removal changed credential", err)
	}
	if _, err := s.Enroll(embedded.ID, pending); err != nil {
		t.Fatal("removal changed pending token", err)
	}
	embedded.Name = "renamed"
	if _, err := s.SaveNode(embedded); err != nil {
		t.Fatal("roundtrip embedded flag", err)
	}
	embedded.Embedded = false
	if saved, err := s.SaveNode(embedded); err != nil || !saved.Embedded {
		t.Fatal("cleared embedded flag", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(db, key)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.EnsureEmbeddedNode(seed)
	if err != nil || got.ID != embedded.ID || got.Name != "renamed" || !got.Embedded {
		t.Fatal("identity lost across rename/reopen", got, err)
	}
	nodes, err := s.Nodes()
	if err != nil || len(nodes) != 2 {
		t.Fatal("unexpected nodes", nodes, err)
	}
	if err := s.RemoveNode(external.ID, false); err != nil {
		t.Fatal("ordinary revocation", err)
	}
	if _, err := s.Snapshot(external.ID, credential); !errors.Is(err, ErrAuth) {
		t.Fatal("ordinary credential not revoked", err)
	}
	if err := s.RemoveNode(external.ID, true); err != nil {
		t.Fatal("ordinary deletion", err)
	}
}
