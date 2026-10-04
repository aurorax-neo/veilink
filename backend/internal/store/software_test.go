package store

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"veilink/internal/model"
)

func TestSoftwareReports(t *testing.T) {
	dir := t.TempDir()
	db, key := filepath.Join(dir, "db"), filepath.Join(dir, "key")
	s, err := Open(db, key)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { s.Close() }()
	n, err := s.SaveNode(model.Node{Name: "client", Role: "client"})
	if err != nil {
		t.Fatal(err)
	}
	token, err := s.EnrollToken(n.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := s.Enroll(n.ID, token)
	if err != nil {
		t.Fatal(err)
	}
	check := func(want SoftwareReport) {
		t.Helper()
		nodes, err := s.ReportedNodes()
		if err != nil || len(nodes) != 1 {
			t.Fatalf("nodes: %v %v", nodes, err)
		}
		if nodes[0].SoftwareReport != want {
			t.Fatalf("report: %+v want %+v", nodes[0].SoftwareReport, want)
		}
	}
	report := SoftwareReport{SoftwareVersion: "v1.2.3", SoftwareCommit: "abcdef"}
	check(SoftwareReport{})
	if _, err := s.HeartbeatSoftware(n.ID, "wrong", 0, false, report); !errors.Is(err, ErrAuth) {
		t.Fatal(err)
	}
	check(SoftwareReport{})
	rev, err := s.HeartbeatSoftware(n.ID, credential, 0, false, report)
	if err != nil {
		t.Fatal(err)
	}
	check(report)
	for _, bad := range []SoftwareReport{{SoftwareVersion: strings.Repeat("a", 129)}, {SoftwareCommit: "bad\nvalue"}} {
		if _, err := s.HeartbeatSoftware(n.ID, credential, 0, false, bad); !errors.Is(err, ErrInvalid) {
			t.Fatal(err)
		}
	}
	if _, err := s.HeartbeatSoftware(n.ID, credential, rev+1, false, SoftwareReport{}); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	check(report)
	snap, err := s.Snapshot(n.ID, credential)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Revision != rev || strings.Contains(string(b), "software_") {
		t.Fatalf("software changed snapshot: %s", b)
	}
	var persisted string
	if err := s.db.QueryRow("SELECT data FROM config WHERE id=1").Scan(&persisted); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(persisted, "software_") {
		t.Fatal("persisted software metadata")
	}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				if _, err := s.HeartbeatSoftware(n.ID, credential, 0, false, report); err != nil {
					t.Error(err)
				}
				if _, err := s.ReportedNodes(); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()
	if _, err := s.Heartbeat(n.ID, credential, 0, false); err != nil {
		t.Fatal(err)
	}
	check(SoftwareReport{})
	if _, err := s.HeartbeatSoftware(n.ID, credential, 0, false, report); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = Open(db, key)
	if err != nil {
		t.Fatal(err)
	}
	check(SoftwareReport{})
	if _, err := s.HeartbeatSoftware(n.ID, credential, 0, false, report); err != nil {
		t.Fatal(err)
	}
	check(report)
	if err := s.RemoveNode(n.ID, false); err != nil {
		t.Fatal(err)
	}
	check(SoftwareReport{})
	if _, err := s.HeartbeatSoftware(n.ID, credential, 0, false, report); !errors.Is(err, ErrAuth) {
		t.Fatal(err)
	}
}
