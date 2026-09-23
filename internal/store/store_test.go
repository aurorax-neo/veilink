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
