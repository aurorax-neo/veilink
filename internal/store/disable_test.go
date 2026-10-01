package store

import (
	"path/filepath"
	"testing"
	"time"

	"veilink/internal/model"
)

func TestDisabledNodeOmitsTunnelFromBothSnapshots(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "db"), filepath.Join(dir, "key"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	server, err := s.SaveNode(model.Node{Name: "gateway", Role: "server", Address: "203.0.113.10", Port: 20096, Tunnel: testTLS(t)})
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
	serverToken, err := s.EnrollToken(server.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	serverCredential, err := s.Enroll(server.ID, serverToken)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.SaveMapping(model.Mapping{Name: "web", ServerID: server.ID, ClientID: client.ID, Pool: 1, ListenHost: "127.0.0.1", ListenPort: 18080, TargetHost: "127.0.0.1", TargetPort: 80, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	before, err := s.Snapshot(client.ID, credential)
	if err != nil || len(before.Bindings) != 1 {
		t.Fatalf("enabled snapshot: %v %+v", err, before)
	}
	if err = s.SetNodeDisabled(server.ID, true); err != nil {
		t.Fatal(err)
	}
	stopped, err := s.Snapshot(client.ID, credential)
	if err != nil || len(stopped.Bindings) != 0 || len(stopped.Mappings) != 0 || stopped.Revision <= before.Revision {
		t.Fatalf("disabled server still dialable: %v %+v", err, stopped)
	}
	serverView, err := s.Snapshot(server.ID, serverCredential)
	if err != nil || len(serverView.Bindings) != 0 {
		t.Fatalf("disabled server still serves: %v %+v", err, serverView)
	}
	saved := server
	saved.Name = "renamed"
	saved, err = s.SaveNode(saved)
	if err != nil || !saved.Disabled {
		t.Fatalf("edit cleared disabled: %v %+v", err, saved)
	}
	if err = s.SetNodeDisabled(server.ID, false); err != nil {
		t.Fatal(err)
	}
	resumed, err := s.Snapshot(client.ID, credential)
	if err != nil || len(resumed.Bindings) != 1 {
		t.Fatalf("enable did not restore dial: %v %+v", err, resumed)
	}
	rows, err := s.Mappings()
	if err != nil || len(rows) != 1 || len(resumed.Bindings) != 1 {
		t.Fatalf("mapping lookup: %v %+v", err, rows)
	}
	if _, err = s.Heartbeat(server.ID, serverCredential, resumed.Revision, false); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Heartbeat(client.ID, credential, resumed.Revision, false); err != nil {
		t.Fatal(err)
	}
	if err = s.ReportLinks(server.ID, serverCredential, []string{resumed.Bindings[0].ID, "not-a-binding"}); err != nil {
		t.Fatal(err)
	}
	if err = s.ReportLinks(client.ID, credential, []string{resumed.Bindings[0].ID}); err != nil {
		t.Fatal(err)
	}
	linked, err := s.MappingStatuses()
	if err != nil || !linked[rows[0].ID].Server.Linked || !linked[rows[0].ID].Client.Linked {
		t.Fatalf("live sessions not reported: %v %+v", err, linked)
	}
	if err = s.ReportLinks(client.ID, credential, nil); err != nil {
		t.Fatal(err)
	}
	linked, err = s.MappingStatuses()
	if err != nil || linked[rows[0].ID].Client.Linked || !linked[rows[0].ID].Server.Linked {
		t.Fatalf("empty client report did not clear its link: %v %+v", err, linked)
	}
	if err = s.SetNodeDisabled(client.ID, true); err != nil {
		t.Fatal(err)
	}
	clientStopped, err := s.Snapshot(client.ID, credential)
	serverStopped, err2 := s.Snapshot(server.ID, serverCredential)
	if err != nil || err2 != nil || len(clientStopped.Bindings) != 0 || len(serverStopped.Bindings) != 0 {
		t.Fatalf("disabled client still linked: %v %v %+v %+v", err, err2, clientStopped, serverStopped)
	}
}
