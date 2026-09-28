package node

import (
	"context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"net"
	"path/filepath"
	"testing"
	"time"
	pb "veilink/api/control/v1"
	"veilink/internal/config"
	"veilink/internal/control"
	"veilink/internal/model"
	"veilink/internal/store"
)

func TestPushApplyAndManualReportWithoutHeartbeatWait(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Open(filepath.Join(dir, "db"), filepath.Join(dir, "key"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
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
	listener := bufconn.Listen(1 << 20)
	g := grpc.NewServer()
	pb.RegisterControlServer(g, &control.Service{Store: s})
	go g.Serve(listener)
	defer g.Stop()
	conn, err := grpc.NewClient("passthrough:///test", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runtime := &slowRuntime{release: make(chan struct{}), started: make(chan struct{})}
	close(runtime.release)
	state := newSyncState(ctx, runtime)
	st := diskState{NodeID: n.ID, Credential: credential}
	done := make(chan error, 1)
	go func() {
		done <- cycle(ctx, pb.NewControlClient(conn), config.Config{NodeID: n.ID}, "client", &st, state, filepath.Join(dir, "state.json"), nil, cycleTiming{time.Minute, time.Minute, time.Second})
	}()
	wait := func(check func() bool) {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			if check() {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
		t.Fatal("event-driven update exceeded 3 seconds (heartbeat is one minute)")
	}
	wait(func() bool {
		got, found, err := s.FindNodeByName(n.Name)
		return err == nil && found && got.AppliedRevision > 0 && got.AppliedRevision == got.DesiredRevision
	})
	n.Name = "changed"
	started := time.Now()
	if _, err = s.SaveNode(n); err != nil {
		t.Fatal(err)
	}
	wait(func() bool {
		got, found, err := s.FindNodeByName(n.Name)
		return err == nil && found && got.AppliedRevision == got.DesiredRevision && runtime.calls.Load() >= 2
	})
	t.Logf("save to applied report: %s", time.Since(started))
	// Clear only test software metadata through an authenticated report, then
	// request a new node report. It must arrive without waiting a minute.
	rev := runtime.Revision()
	if _, err = s.Heartbeat(n.ID, credential, rev, false); err != nil {
		t.Fatal(err)
	}
	if connected, err := s.RequestRefresh(n.ID); err != nil || !connected {
		t.Fatal("refresh", connected, err)
	}
	wait(func() bool {
		nodes, err := s.ReportedNodes()
		return err == nil && len(nodes) == 1 && nodes[0].SoftwareVersion != ""
	})
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cycle cancellation blocked")
	}
	wait(func() bool { connected, err := s.RequestRefresh(n.ID); return err == nil && !connected })
}
