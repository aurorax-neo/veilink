package store

import (
	"net"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"veilink/internal/model"
	"veilink/internal/tunnel"
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

func TestDisabledNodeClosesListeners(t *testing.T) {
	s, _, _ := testStore(t)
	tunnelPort := freeStorePort(t)
	publicPort := freeStorePort(t)
	local := testTLS(t)
	local.ListenHost = "127.0.0.1"
	local.ListenPort = tunnelPort
	server, err := s.SaveNode(model.Node{Name: "gateway", Role: "server", Address: "127.0.0.1", Port: tunnelPort, Tunnel: local})
	if err != nil {
		t.Fatal(err)
	}
	client := testNode(t, s, "client", "client")
	serverCredential := testCredential(t, s, server.ID)
	clientCredential := testCredential(t, s, client.ID)
	mapping := testMapping(server.ID, client.ID, publicPort)
	mapping.ListenHost = "127.0.0.1"
	mapping.TargetHost = "127.0.0.1"
	if _, err = s.SaveMapping(mapping); err != nil {
		t.Fatal(err)
	}
	serverSnap, err := s.Snapshot(server.ID, serverCredential)
	if err != nil {
		t.Fatal(err)
	}
	clientSnap, err := s.Snapshot(client.ID, clientCredential)
	if err != nil {
		t.Fatal(err)
	}
	serverRuntime := tunnel.New(model.LocalTLS{})
	clientRuntime := tunnel.New(model.LocalTLS{})
	t.Cleanup(func() { _ = serverRuntime.Close(); _ = clientRuntime.Close() })
	if err = serverRuntime.Apply(serverSnap); err != nil {
		t.Fatal(err)
	}
	if err = clientRuntime.Apply(clientSnap); err != nil {
		t.Fatal(err)
	}
	if !tcpOpen(tunnelPort) || !tcpOpen(publicPort) {
		t.Fatalf("enabled server is not listening tunnel=%v public=%v", tcpOpen(tunnelPort), tcpOpen(publicPort))
	}
	if err = s.SetNodeDisabled(server.ID, true); err != nil {
		t.Fatal(err)
	}
	stoppedServer, err := s.Snapshot(server.ID, serverCredential)
	stoppedClient, err2 := s.Snapshot(client.ID, clientCredential)
	if err != nil || err2 != nil {
		t.Fatal(err, err2)
	}
	if stoppedServer.Revision <= serverSnap.Revision || stoppedClient.Revision <= clientSnap.Revision {
		t.Fatalf("disable did not advance revisions server %d->%d client %d->%d", serverSnap.Revision, stoppedServer.Revision, clientSnap.Revision, stoppedClient.Revision)
	}
	if err = serverRuntime.Apply(stoppedServer); err != nil {
		t.Fatalf("disabled server apply: %v", err)
	}
	if err = clientRuntime.Apply(stoppedClient); err != nil {
		t.Fatalf("disabled server peer apply: %v", err)
	}
	if tcpOpen(tunnelPort) || tcpOpen(publicPort) {
		t.Fatalf("disabled server still listening tunnel=%v public=%v", tcpOpen(tunnelPort), tcpOpen(publicPort))
	}
	if err = s.SetNodeDisabled(server.ID, false); err != nil {
		t.Fatal(err)
	}
	resumed, err := s.Snapshot(server.ID, serverCredential)
	if err != nil {
		t.Fatal(err)
	}
	if err = serverRuntime.Apply(resumed); err != nil {
		t.Fatal(err)
	}
	if !tcpOpen(tunnelPort) || !tcpOpen(publicPort) {
		t.Fatal("enable did not restore listeners")
	}
	if err = s.SetNodeDisabled(client.ID, true); err != nil {
		t.Fatal(err)
	}
	afterClient, err := s.Snapshot(server.ID, serverCredential)
	clientStopped, err2 := s.Snapshot(client.ID, clientCredential)
	if err != nil || err2 != nil {
		t.Fatal(err, err2)
	}
	if err = serverRuntime.Apply(afterClient); err != nil {
		t.Fatalf("server apply after client disable: %v", err)
	}
	if err = clientRuntime.Apply(clientStopped); err != nil {
		t.Fatalf("disabled client apply: %v", err)
	}
	if tcpOpen(tunnelPort) || tcpOpen(publicPort) {
		t.Fatalf("disabled client left listeners tunnel=%v public=%v", tcpOpen(tunnelPort), tcpOpen(publicPort))
	}
}

func freeStorePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

func tcpOpen(port int) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 200*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
