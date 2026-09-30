package node

import (
	"context"
	crand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	"log/slog"
	"math/rand/v2"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"
	pb "veilink/api/control/v1"
	"veilink/internal/buildinfo"
	"veilink/internal/config"
	"veilink/internal/control"
	"veilink/internal/logring"
	"veilink/internal/model"
	"veilink/internal/tunnel"
)

// ErrCredentialRejected is returned only after an authentication rejection and
// successful removal of the local credential/snapshot. Ordinary nodes still
// require administrator enrollment; the owning master may recover its node.
var ErrCredentialRejected = errors.New("node credential rejected; local state wiped; administrator must re-enroll")

type diskState struct {
	NodeID     string          `json:"node_id"`
	Master     string          `json:"master"`
	Credential string          `json:"credential"`
	Snapshot   *model.Snapshot `json:"snapshot,omitempty"`
}

func save(path string, s diskState) error {
	b, e := json.Marshal(s)
	if e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".state-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	if e = os.Rename(f.Name(), path); e != nil {
		return e
	}
	d, e := os.Open(filepath.Dir(path))
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}
func tlsConfig(c config.Config) (*tls.Config, error) {
	tc := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: c.ControlServerName}
	if c.ControlCA != "" {
		pem, e := os.ReadFile(c.ControlCA)
		if e != nil {
			return nil, e
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("invalid control CA")
		}
		tc.RootCAs = pool
	}
	return tc, nil
}
func Run(ctx context.Context, c config.Config, role string) error {
	return RunWithLogger(ctx, c, role, nil)
}

// RunWithLogger keeps the embedded node from replacing the Master's process-wide logger.
func RunWithLogger(ctx context.Context, c config.Config, role string, logger *slog.Logger) error {
	if e := c.Validate(role); e != nil {
		return e
	}
	var ring *logring.Ring
	if logger == nil {
		ring = logring.New(1000)
		logger = slog.New(logring.NewHandler(ring, "node", slog.NewTextHandler(os.Stderr, nil)))
	}
	logger.Info("node starting", "role", role, "node_id", c.NodeID)
	tc, e := tlsConfig(c)
	if e != nil {
		return e
	}
	if e = os.MkdirAll(c.StateDir, 0700); e != nil {
		return e
	}
	if e = os.Chmod(c.StateDir, 0700); e != nil {
		return e
	}
	path := filepath.Join(c.StateDir, "state.json")
	st := diskState{NodeID: c.NodeID, Master: c.MasterAddr}
	if b, er := os.ReadFile(path); er == nil {
		if json.Unmarshal(b, &st) != nil || st.NodeID != c.NodeID || st.Master != c.MasterAddr {
			return errors.New("local state identity mismatch or corruption")
		}
		if e = os.Chmod(path, 0600); e != nil {
			return e
		}
	} else if !os.IsNotExist(er) {
		return er
	}
	// Only authenticated database snapshots configure the tunnel runtime.
	runtime := tunnel.New(model.LocalTLS{})
	if role == "client" {
		runtime.SetDialLogger(logger)
	}
	runCtx, stopRuntime := context.WithCancel(ctx)
	defer func() { stopRuntime(); closeRuntime(runtime) }()
	state := newSyncState(runCtx, runtime)
	if role == "server" {
		var epoch [16]byte
		if _, err := crand.Read(epoch[:]); err != nil {
			return err
		}
		state.traffic, state.trafficEpoch = runtime.Traffic(), hex.EncodeToString(epoch[:])
	}
	if st.Snapshot != nil {
		if st.Snapshot.Node.ID != c.NodeID || st.Snapshot.Node.Role != role {
			return errors.New("cached node identity mismatch")
		}
		state.restore(*st.Snapshot)
	}
	var dialOpts []grpc.DialOption
	if c.ControlCA == "" && c.ControlServerName == "" {
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(credentials.NewTLS(tc)))
	}
	dialOpts = append(dialOpts, grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(4<<20), grpc.MaxCallSendMsgSize(64<<10)))
	conn, e := grpc.NewClient(c.MasterAddr, dialOpts...)
	if e != nil {
		return e
	}
	defer conn.Close()
	client := pb.NewControlClient(conn)
	backoff := time.Second
	for ctx.Err() == nil {
		if st.Credential == "" {
			if c.EnrollToken == "" {
				return errors.New("enrollment token required for first start")
			}
			call, cancel := context.WithTimeout(ctx, 10*time.Second)
			in, _ := control.Envelope(map[string]any{"node_id": c.NodeID, "token": c.EnrollToken})
			out, er := client.Enroll(call, in)
			cancel()
			e = er
			if e == nil {
				st.Credential = control.String(out, "credential")
				if st.Credential == "" {
					return errors.New("empty enrollment credential")
				}
				if e = save(path, st); e != nil {
					return errors.New("cannot persist node credential")
				}
				logger.Info("node enrolled; credential saved", "role", role, "node_id", c.NodeID)
			}
		} else {
			e = nil
		}
		if e == nil {
			e = cycle(ctx, client, c, role, &st, state, path, ring, defaultCycleTiming, logger)
		}
		if rejected(e) {
			stopRuntime()
			if er := wipeState(path, &st); er != nil {
				return er
			}
			return ErrCredentialRejected
		}
		if ctx.Err() != nil {
			return nil
		}
		if e == nil || errors.Is(e, context.DeadlineExceeded) || errors.Is(e, context.Canceled) {
			backoff = time.Second
			continue
		}
		state.connected.Store(false)
		logger.Warn("control connection unavailable; retaining last successful configuration", "role", role, "err", e)
		delay := backoff + time.Duration(rand.Int64N(int64(backoff/2)+1))
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(delay):
		}
		if backoff < 30*time.Second {
			backoff *= 2
			if backoff > 30*time.Second {
				backoff = 30 * time.Second
			}
		}
	}
	return nil
}

// runtimeDriver permits deterministic slow-apply tests without real listeners.
type runtimeDriver interface {
	Apply(model.Snapshot) error
	Revision() int64
	Close() error
}

type applyResult struct {
	snapshot model.Snapshot
	revision int64
	err      error
}

// One worker survives stream rotations. It never touches credentials or disk,
// and no second Apply is started while the first is outstanding.
type syncState struct {
	ctx          context.Context
	jobs         chan model.Snapshot
	results      chan applyResult
	busy         bool // control-loop owned
	revision     atomic.Int64
	failed       atomic.Bool
	connected    atomic.Bool
	traffic      *tunnel.Traffic
	trafficEpoch string
	trafficSeq   atomic.Uint64
}

func newSyncState(ctx context.Context, runtime runtimeDriver) *syncState {
	s := &syncState{ctx: ctx, jobs: make(chan model.Snapshot, 1), results: make(chan applyResult, 1)}
	s.revision.Store(-1)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case snap := <-s.jobs:
				if ctx.Err() != nil {
					return
				}
				var err error
				if cancellable, ok := runtime.(interface {
					ApplyContext(context.Context, model.Snapshot) error
				}); ok {
					err = cancellable.ApplyContext(ctx, snap)
				} else {
					err = runtime.Apply(snap)
				}
				if ctx.Err() != nil {
					return
				}
				r := applyResult{snapshot: snap, revision: runtime.Revision(), err: err}
				select {
				case s.results <- r:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return s
}

func (s *syncState) restore(snap model.Snapshot) {
	s.busy = true
	s.jobs <- snap
}

func closeRuntime(runtime runtimeDriver) {
	done := make(chan struct{})
	go func() { _ = runtime.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		// Legacy Apply is not cancellable. Do not hold credential cleanup hostage.
	}
}

func rejected(err error) bool {
	return status.Code(err) == codes.Unauthenticated || status.Code(err) == codes.PermissionDenied
}

func wipeState(path string, st *diskState) error {
	st.Credential, st.Snapshot = "", nil
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return errors.New("credential rejected; local state removal failed")
	}
	return nil
}

type cycleTiming struct{ lifetime, heartbeat, pull time.Duration }

var defaultCycleTiming = cycleTiming{2 * time.Minute, 10 * time.Second, 10 * time.Second}

// heartbeatEnvelope drains exactly once. Oversized entries/batches are dropped,
// not retried or re-drained; the complete protobuf stays within the RPC limit.
func heartbeatEnvelope(id, credential string, revision int64, failed bool, ring *logring.Ring) (*structpb.Struct, error) {
	errText := ""
	if failed {
		errText = "apply failed"
	}
	if revision < 0 {
		revision = 0
	}
	m, err := control.Envelope(map[string]any{"node_id": id, "credential": credential, "applied_revision": revision, "error": errText, "logs": []any{}, "software_version": buildinfo.Version, "software_commit": buildinfo.Commit})
	if err != nil {
		return nil, err
	}
	logs := m.Fields["logs"].GetListValue()
	if ring != nil {
		for _, entry := range ring.Drain() {
			item, err := structpb.NewStruct(map[string]any{"at": float64(entry.At), "level": entry.Level, "message": entry.Message})
			if err != nil {
				continue
			}
			logs.Values = append(logs.Values, structpb.NewStructValue(item))
			if proto.Size(m) > 64<<10 {
				logs.Values = logs.Values[:len(logs.Values)-1]
			}
		}
	}
	if proto.Size(m) > 64<<10 {
		return nil, errors.New("heartbeat identity exceeds RPC size limit")
	}
	return m, nil
}

func heartbeat(ctx context.Context, client pb.ControlClient, id, credential string, state *syncState, ring *logring.Ring, interval time.Duration, revisions chan int64, report chan struct{}) error {
	stream, err := client.Events(ctx)
	if err != nil {
		return err
	}
	type response struct {
		message *structpb.Struct
		err     error
	}
	received := make(chan response, 1)
	go func() {
		for {
			out, err := stream.Recv()
			select {
			case received <- response{out, err}:
			case <-ctx.Done():
				return
			}
			if err != nil {
				return
			}
		}
	}()
	send := func() error {
		in, err := heartbeatEnvelope(id, credential, state.revision.Load(), state.failed.Load(), ring)
		if err != nil {
			return err
		}
		if state.traffic != nil {
			totals := state.traffic.Snapshot()
			if len(totals) <= 128 {
				entries := make(map[string]any, len(totals))
				for mappingID, v := range totals {
					entries[mappingID] = map[string]any{"up": v.Up, "down": v.Down}
				}
				traffic, buildErr := structpb.NewStruct(entries)
				if buildErr != nil {
					return buildErr
				}
				in.Fields["traffic"] = structpb.NewStructValue(traffic)
				in.Fields["traffic_epoch"] = structpb.NewStringValue(state.trafficEpoch)
				in.Fields["traffic_seq"] = structpb.NewNumberValue(float64(state.trafficSeq.Add(1)))
				logs := in.Fields["logs"].GetListValue()
				for proto.Size(in) > 64<<10 && len(logs.Values) > 0 {
					logs.Values = logs.Values[:len(logs.Values)-1]
				}
				if proto.Size(in) > 64<<10 {
					return errors.New("traffic report exceeds RPC size limit")
				}
			}
		}
		if err = stream.Send(in); err != nil {
			select {
			case out := <-received:
				if out.err != nil {
					return out.err
				}
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return err
	}
	if err := send(); err != nil {
		return err
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := send(); err != nil {
				return err
			}
		case <-report:
			if err := send(); err != nil {
				return err
			}
		case out := <-received:
			if out.err != nil {
				return out.err
			}
			v := out.message.GetFields()["revision"].GetNumberValue()
			if v < 0 || v > 9007199254740991 || v != float64(int64(v)) {
				return errors.New("invalid desired revision")
			}
			select {
			case <-revisions:
			default:
			}
			revisions <- int64(v)
			if out.message.GetFields()["refresh"].GetBoolValue() {
				select {
				case report <- struct{}{}:
				default:
				}
			}
		}
	}
}

// Heartbeats never call Runtime.Revision (which locks behind Apply). Disk state
// and scheduling belong exclusively to this loop; the apply worker is serialized.
func cycle(ctx context.Context, client pb.ControlClient, c config.Config, role string, st *diskState, state *syncState, path string, ring *logring.Ring, timing cycleTiming, loggers ...*slog.Logger) (err error) {
	logger := slog.Default()
	if len(loggers) > 0 && loggers[0] != nil {
		logger = loggers[0]
	}
	streamCtx, cancel := context.WithTimeout(ctx, timing.lifetime)
	deadline, _ := streamCtx.Deadline()
	defer cancel()
	revisions := make(chan int64, 1)
	report := make(chan struct{}, 1)
	terminal := make(chan error, 1)
	go func() {
		err := heartbeat(streamCtx, client, c.NodeID, st.Credential, state, ring, timing.heartbeat, revisions, report)
		terminal <- err
		cancel() // interrupts an outstanding Pull immediately on rejection
	}()
	defer func() {
		cancel()
		// gRPC Send/Recv honor cancellation; join before diskState may be wiped.
		heartbeatErr := <-terminal
		if rejected(heartbeatErr) {
			err = heartbeatErr
			return
		}
		if err == nil && ctx.Err() != nil {
			err = ctx.Err()
		}
		// A routine two-minute rotation is not a transport failure/backoff.
		// The server's propagated gRPC deadline can fire just before the local
		// timer; our explicit cancel must not turn that rotation into a failure.
		rotated := errors.Is(streamCtx.Err(), context.DeadlineExceeded) ||
			(status.Code(heartbeatErr) == codes.DeadlineExceeded && time.Until(deadline) <= 10*time.Millisecond)
		if ctx.Err() == nil && rotated && !rejected(err) {
			err = nil
		} else if err == nil && heartbeatErr != nil {
			err = heartbeatErr
		}
	}()
	first := true
	for {
		select {
		case <-streamCtx.Done():
			return nil
		case result := <-state.results:
			state.busy = false
			previous, wasFailed := state.revision.Load(), state.failed.Load()
			state.revision.Store(result.revision)
			state.failed.Store(result.err != nil)
			if result.err != nil {
				logger.Warn("runtime configuration apply failed", "role", role, "revision", result.snapshot.Revision, "err", result.err)
			} else if streamCtx.Err() == nil && state.ctx.Err() == nil {
				st.Snapshot = &result.snapshot
				if err := save(path, *st); err != nil {
					state.failed.Store(true)
					return errors.New("cannot persist runtime cache")
				}
				if previous != result.revision || wasFailed {
					logger.Info("runtime configuration applied", "role", role, "revision", result.snapshot.Revision)
				}
				select {
				case report <- struct{}{}:
				default:
				}
			}
		case desired := <-revisions:
			if state.busy || (!first && desired <= state.revision.Load() && !state.failed.Load()) {
				continue
			}
			first = false
			request := map[string]any{"node_id": c.NodeID, "credential": st.Credential}
			req, err := control.Envelope(request)
			if err != nil {
				return err
			}
			call, stop := context.WithTimeout(streamCtx, timing.pull)
			response, err := client.Pull(call, req)
			stop()
			if err != nil {
				return err
			}
			b, err := json.Marshal(response.AsMap())
			if err != nil {
				return err
			}
			var snap model.Snapshot
			if err = json.Unmarshal(b, &snap); err != nil {
				return err
			}
			if snap.Node.ID != c.NodeID || snap.Node.Role != role || snap.Node.Revoked {
				return status.Error(codes.PermissionDenied, "node identity rejected")
			}
			if snap.Revision < state.revision.Load() {
				return errors.New("stale snapshot")
			}
			if streamCtx.Err() != nil {
				return nil
			}
			if !state.connected.Swap(true) {
				logger.Info("control connection established", "role", role, "node_id", c.NodeID)
			}
			state.restore(snap)
		}
	}
}
