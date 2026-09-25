package node

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	pb "veilink/api/control/v1"
	"veilink/internal/config"
	"veilink/internal/control"
	"veilink/internal/logring"
	"veilink/internal/model"
)

type testControl struct {
	pb.UnimplementedControlServer
	beats         atomic.Int64
	pulls         atomic.Int64
	rejectAfter   int64
	stallPull     bool
	stallEvents   bool
	failFirstPull bool
}

func (s *testControl) Events(stream grpc.BidiStreamingServer[structpb.Struct, structpb.Struct]) error {
	for {
		if _, err := stream.Recv(); err != nil {
			return err
		}
		n := s.beats.Add(1)
		if s.rejectAfter > 0 && n >= s.rejectAfter {
			return status.Error(codes.Unauthenticated, "revoked")
		}
		if s.stallEvents {
			<-stream.Context().Done()
			return stream.Context().Err()
		}
		out, _ := control.Envelope(map[string]any{"revision": 1})
		if err := stream.Send(out); err != nil {
			return err
		}
	}
}

func (s *testControl) Pull(ctx context.Context, req *structpb.Struct) (*structpb.Struct, error) {
	n := s.pulls.Add(1)
	if len(req.Fields) != 2 || req.Fields["node_id"] == nil || req.Fields["credential"] == nil {
		return nil, status.Error(codes.InvalidArgument, "Pull accepts identity only")
	}
	if s.failFirstPull && n == 1 {
		return nil, status.Error(codes.Unavailable, "transient transport failure")
	}
	if s.stallPull {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return control.Envelope(model.Snapshot{Revision: 1, Node: model.Node{ID: "node", Role: "client"}})
}

func testClient(t *testing.T, server *testControl) pb.ControlClient {
	t.Helper()
	listener := bufconn.Listen(1 << 20)
	g := grpc.NewServer()
	pb.RegisterControlServer(g, server)
	go g.Serve(listener)
	t.Cleanup(g.Stop)
	conn, err := grpc.NewClient("passthrough:///test", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return pb.NewControlClient(conn)
}

type slowRuntime struct {
	mu       sync.Mutex
	release  chan struct{}
	started  chan struct{}
	calls    atomic.Int64
	revision int64
	closed   atomic.Bool
}

func (r *slowRuntime) Apply(s model.Snapshot) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.calls.Add(1) == 1 {
		close(r.started)
	}
	<-r.release
	r.revision = s.Revision
	return nil
}
func (r *slowRuntime) Revision() int64 { r.mu.Lock(); defer r.mu.Unlock(); return r.revision }
func (r *slowRuntime) Close() error    { r.closed.Store(true); return nil }

func TestSlowApplyDoesNotBlockHeartbeatsOrRotation(t *testing.T) {
	server := &testControl{}
	client := testClient(t, server)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runtime := &slowRuntime{release: make(chan struct{}), started: make(chan struct{})}
	defer close(runtime.release)
	state := newSyncState(ctx, runtime)
	st := diskState{NodeID: "node", Credential: "credential"}
	path := filepath.Join(t.TempDir(), "state.json")
	timing := cycleTiming{100 * time.Millisecond, 5 * time.Millisecond, time.Second}
	for range 2 {
		if err := cycle(ctx, client, config.Config{NodeID: "node"}, "client", &st, state, path, nil, timing); err != nil {
			t.Fatal("routine rotation", err)
		}
	}
	if n := server.beats.Load(); n < 8 {
		t.Fatalf("heartbeats stalled during Apply: %d", n)
	}
	if n := runtime.calls.Load(); n != 1 {
		t.Fatalf("concurrent/duplicate Apply: %d", n)
	}
}

func TestRejectedHeartbeatInterruptsPullAndWipesState(t *testing.T) {
	server := &testControl{rejectAfter: 4, stallPull: true}
	client := testClient(t, server)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runtime := &slowRuntime{release: make(chan struct{}), started: make(chan struct{})}
	state := newSyncState(ctx, runtime)
	st := diskState{NodeID: "node", Credential: "secret", Snapshot: &model.Snapshot{}}
	path := filepath.Join(t.TempDir(), "state.json")
	if err := save(path, st); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	err := cycle(ctx, client, config.Config{NodeID: "node"}, "client", &st, state, path, nil, cycleTiming{time.Second, 5 * time.Millisecond, time.Second})
	if !rejected(err) {
		t.Fatalf("lost authentication status: %v", err)
	}
	if time.Since(start) > 500*time.Millisecond {
		t.Fatal("authentication waited for Pull timeout")
	}
	cancel()
	if err := wipeState(path, &st); err != nil {
		t.Fatal(err)
	}
	closeRuntime(runtime)
	if !runtime.closed.Load() || st.Credential != "" || st.Snapshot != nil {
		t.Fatal("runtime/credentials not cleared")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("state remains: %v", err)
	}
}

func TestRejectedHeartbeatDoesNotWaitForApply(t *testing.T) {
	server := &testControl{rejectAfter: 6}
	client := testClient(t, server)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runtime := &slowRuntime{release: make(chan struct{}), started: make(chan struct{})}
	defer close(runtime.release)
	state := newSyncState(ctx, runtime)
	st := diskState{NodeID: "node", Credential: "credential"}
	err := cycle(ctx, client, config.Config{NodeID: "node"}, "client", &st, state, filepath.Join(t.TempDir(), "state"), nil, cycleTiming{time.Second, 5 * time.Millisecond, time.Second})
	if !rejected(err) {
		t.Fatal(err)
	}
	select {
	case <-runtime.started:
	default:
		t.Fatal("Apply never started")
	}
}

func TestPullTimeoutAndHungStreamBounded(t *testing.T) {
	for _, stallPull := range []bool{true, false} {
		t.Run(map[bool]string{true: "pull", false: "stream"}[stallPull], func(t *testing.T) {
			server := &testControl{stallPull: stallPull, stallEvents: !stallPull}
			client := testClient(t, server)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			runtime := &slowRuntime{release: make(chan struct{}), started: make(chan struct{})}
			state := newSyncState(ctx, runtime)
			st := diskState{NodeID: "node", Credential: "credential"}
			err := cycle(ctx, client, config.Config{NodeID: "node"}, "client", &st, state, filepath.Join(t.TempDir(), "state"), nil, cycleTiming{100 * time.Millisecond, 5 * time.Millisecond, 30 * time.Millisecond})
			if stallPull && status.Code(err) != codes.DeadlineExceeded {
				t.Fatalf("Pull timeout: %v", err)
			}
			if !stallPull && err != nil {
				t.Fatalf("stream rotation: %v", err)
			}
		})
	}
}

func TestHeartbeatLogBudgetAndSingleDrain(t *testing.T) {
	ring := logring.New(200)
	ring.Append(logring.Entry{Message: strings.Repeat("x", 70<<10)})
	for range 100 {
		ring.Append(logring.Entry{At: 1, Level: "INFO", Message: strings.Repeat("x", 1024)})
	}
	m, err := heartbeatEnvelope("node", "credential", 4, false, ring)
	if err != nil {
		t.Fatal(err)
	}
	if proto.Size(m) > 64<<10 {
		t.Fatalf("oversized heartbeat: %d", proto.Size(m))
	}
	if len(m.Fields["logs"].GetListValue().Values) == 0 {
		t.Fatal("all logs discarded")
	}
	m, err = heartbeatEnvelope("node", "credential", 4, false, ring)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Fields["logs"].GetListValue().Values) != 0 {
		t.Fatal("logs duplicated")
	}
}

func TestIdentityOnlyPullsAcrossRotations(t *testing.T) {
	server := &testControl{}
	client := testClient(t, server)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runtime := &slowRuntime{release: make(chan struct{}), started: make(chan struct{})}
	close(runtime.release)
	state := newSyncState(ctx, runtime)
	st := diskState{NodeID: "node", Credential: "credential"}
	path := filepath.Join(t.TempDir(), "state.json")
	for range 2 {
		if err := cycle(ctx, client, config.Config{NodeID: "node"}, "client", &st, state, path, nil, cycleTiming{100 * time.Millisecond, 5 * time.Millisecond, time.Second}); err != nil {
			t.Fatal(err)
		}
	}
	if server.pulls.Load() != 2 {
		t.Fatalf("pulls=%d", server.pulls.Load())
	}
	if st.Snapshot == nil || st.Snapshot.Revision != 1 || state.revision.Load() != 1 {
		t.Fatal("applied revision/cache not updated")
	}
}

func TestRetriesAfterPullTransportFailure(t *testing.T) {
	server := &testControl{failFirstPull: true}
	client := testClient(t, server)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runtime := &slowRuntime{release: make(chan struct{}), started: make(chan struct{})}
	close(runtime.release)
	state := newSyncState(ctx, runtime)
	st := diskState{NodeID: "node", Credential: "credential"}
	path := filepath.Join(t.TempDir(), "state.json")
	c := config.Config{NodeID: "node"}
	timing := cycleTiming{100 * time.Millisecond, 5 * time.Millisecond, time.Second}
	if err := cycle(ctx, client, c, "client", &st, state, path, nil, timing); status.Code(err) != codes.Unavailable {
		t.Fatalf("expected transient Pull failure: %v", err)
	}
	if runtime.calls.Load() != 0 {
		t.Fatal("failed Pull applied a snapshot")
	}
	for range 2 {
		if err := cycle(ctx, client, c, "client", &st, state, path, nil, timing); err != nil {
			t.Fatal(err)
		}
	}
	if server.pulls.Load() != 3 {
		t.Fatalf("pulls=%d", server.pulls.Load())
	}
	if st.Snapshot == nil || st.Snapshot.Revision != 1 || state.revision.Load() != 1 {
		t.Fatal("retry did not apply and cache the snapshot")
	}
}

func TestRunRejectedCredentialRemovesDiskState(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	g := grpc.NewServer()
	pb.RegisterControlServer(g, &testControl{rejectAfter: 1})
	go g.Serve(listener)
	defer g.Stop()
	d := t.TempDir()
	path := filepath.Join(d, "state.json")
	st := diskState{NodeID: "node", Master: listener.Addr().String(), Credential: "rejected"}
	if err := save(path, st); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err = Run(ctx, config.Config{NodeID: st.NodeID, MasterAddr: st.Master, StateDir: d}, "client")
	if err == nil || !strings.Contains(err.Error(), "local state wiped") {
		t.Fatalf("unexpected Run result: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("rejected credential remains: %v", err)
	}
}
