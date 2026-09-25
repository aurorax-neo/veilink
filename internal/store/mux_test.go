package store

import (
	"path/filepath"
	"testing"
	"time"
	"veilink/internal/model"
)

func TestMappingMuxPersistenceAndSnapshot(t *testing.T) {
	dir := t.TempDir()
	db, key := filepath.Join(dir, "db"), filepath.Join(dir, "key")
	s, err := Open(db, key)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { s.Close() }()
	server, err := s.SaveNode(model.Node{Name: "gateway", Role: "server", Address: "localhost", ServerName: "localhost", Port: 443, Tunnel: testTLS(t)})
	if err != nil {
		t.Fatal(err)
	}
	client, err := s.SaveNode(model.Node{Name: "client", Role: "client"})
	if err != nil {
		t.Fatal(err)
	}
	token, err := s.EnrollToken(client.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := s.Enroll(client.ID, token)
	if err != nil {
		t.Fatal(err)
	}
	m := model.Mapping{Name: "mux-test", ServerID: server.ID, ClientID: client.ID, Pool: 1, ListenHost: "127.0.0.1", ListenPort: 19080, TargetHost: "localhost", TargetPort: 80, Enabled: true}
	var revision int64
	for _, mode := range []struct {
		enabled bool
		kind    string
	}{{false, ""}, {true, ""}, {true, model.MuxTypeSMux}, {true, model.MuxTypeYAMux}, {true, model.MuxTypeH2Mux}, {false, ""}} {
		m.Mux, m.MuxType = mode.enabled, mode.kind
		m.BindingID = ""
		m, err = s.SaveMapping(m)
		if err != nil {
			t.Fatal(err)
		}
		wantType := mode.kind
		if mode.enabled && wantType == "" {
			wantType = model.MuxTypeSMux
		}
		if m.MuxType != wantType {
			t.Fatalf("saved type: %q", m.MuxType)
		}
		s.Close()
		s, err = Open(db, key)
		if err != nil {
			t.Fatal(err)
		}
		rows, err := s.Mappings()
		if err != nil || len(rows) != 1 || rows[0].Mux != mode.enabled || rows[0].MuxType != wantType {
			t.Fatalf("persistence: %v %+v", err, rows)
		}
		snap, err := s.Snapshot(client.ID, credential)
		if err != nil || len(snap.Mappings) != 1 || snap.Mappings[0].Mux != mode.enabled || snap.Mappings[0].MuxType != wantType || snap.Revision <= revision {
			t.Fatalf("snapshot: %v %+v", err, snap)
		}
		revision = snap.Revision
		invalid := m
		invalid.BindingID = ""
		for _, invalidType := range []string{"unknown", "private-session"} {
			invalid.MuxType = invalidType
			if _, err := s.SaveMapping(invalid); err != ErrInvalid {
				t.Fatalf("invalid type %q accepted: %v", invalidType, err)
			}
		}
		after, err := s.Snapshot(client.ID, credential)
		if err != nil || after.Revision != revision {
			t.Fatalf("rejected save changed snapshot: %v", err)
		}
	}
}
