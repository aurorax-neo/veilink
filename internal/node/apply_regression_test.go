package node

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"veilink/internal/config"
	"veilink/internal/model"
)

type regressionRuntime struct {
	fail     atomic.Bool
	revision atomic.Int64
}

func (r *regressionRuntime) Apply(s model.Snapshot) error {
	if r.fail.Load() {
		return errors.New("injected Apply failure")
	}
	r.revision.Store(s.Revision)
	return nil
}
func (r *regressionRuntime) Revision() int64 { return r.revision.Load() }
func (r *regressionRuntime) Close() error    { return nil }

func TestApplyFailureRetainsSnapshotAndReportsRecovery(t *testing.T) {
	client := testClient(t, &testControl{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runtime := &regressionRuntime{}
	runtime.fail.Store(true)
	state := newSyncState(ctx, runtime)
	state.revision.Store(0)
	st := diskState{NodeID: "node", Credential: "test-credential", Snapshot: &model.Snapshot{Revision: 0, Node: model.Node{ID: "node", Role: "client"}}}
	path := filepath.Join(t.TempDir(), "state.json")
	if err := save(path, st); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	timing := cycleTiming{100 * time.Millisecond, 5 * time.Millisecond, time.Second}
	if err := cycle(ctx, client, config.Config{NodeID: "node"}, "client", &st, state, path, nil, timing); err != nil {
		t.Fatal(err)
	}
	if !state.failed.Load() || state.revision.Load() != 0 || st.Snapshot.Revision != 0 {
		t.Fatal("failed Apply advanced revision or snapshot")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("failed Apply overwrote persisted snapshot", err)
	}
	beat, err := heartbeatEnvelope(st.NodeID, st.Credential, state.revision.Load(), state.failed.Load(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if beat.Fields["applied_revision"].GetNumberValue() != 0 || beat.Fields["error"].GetStringValue() == "" {
		t.Fatal("failed Apply heartbeat claims success")
	}
	runtime.fail.Store(false)
	for range 3 {
		if err := cycle(ctx, client, config.Config{NodeID: "node"}, "client", &st, state, path, nil, timing); err != nil {
			t.Fatal(err)
		}
		if !state.failed.Load() && state.revision.Load() == 1 {
			break
		}
	}
	if state.failed.Load() || state.revision.Load() != 1 || st.Snapshot.Revision != 1 {
		t.Fatal("recovery did not apply snapshot")
	}
	after, err = os.ReadFile(path)
	if err != nil || bytes.Equal(before, after) {
		t.Fatal("successful recovery not persisted", err)
	}
	beat, err = heartbeatEnvelope(st.NodeID, st.Credential, state.revision.Load(), state.failed.Load(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if beat.Fields["applied_revision"].GetNumberValue() != 1 || beat.Fields["error"].GetStringValue() != "" {
		t.Fatal("recovery heartbeat incorrect")
	}
}
