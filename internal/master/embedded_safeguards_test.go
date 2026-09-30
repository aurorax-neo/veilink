package master

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"veilink/internal/config"
	"veilink/internal/model"
	"veilink/internal/node"
	"veilink/internal/store"
)

func TestEmbeddedExpiredCredentialRecovery(t *testing.T) {
	dir := t.TempDir()
	c := config.Config{Database: filepath.Join(dir, "db"), DeploymentKey: filepath.Join(dir, "key"), ListenAddr: freeMasterAddress(t), Scheme: "http", StateDir: dir, EmbeddedServer: config.EmbeddedServerConfig{Enabled: true}}
	s, err := store.Open(c.Database, c.DeploymentKey)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	n, err := embeddedNode(c, s)
	if err != nil {
		t.Fatal(err)
	}
	n.Name = "renamed-before-expiry"
	if _, err := s.SaveNode(n); err != nil {
		t.Fatal(err)
	}
	token, err := s.EnrollToken(n.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	expired, err := s.Enroll(n.ID, token)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := s.Snapshot(n.ID, expired)
	if err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(dir, "embedded-server", "state.json")
	if err := os.MkdirAll(filepath.Dir(statePath), 0700); err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string]any{"node_id": n.ID, "master": c.ListenAddr, "credential": expired, "snapshot": snapshot})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, body, 0600); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", c.Database)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec("UPDATE credentials SET expires=? WHERE node=?", time.Now().Add(-time.Hour).Unix(), n.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Snapshot(n.ID, expired); !errors.Is(err, store.ErrAuth) {
		t.Fatal("credential not expired", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, c) }()
	stopped := false
	defer func() {
		if stopped {
			return
		}
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(7 * time.Second):
			t.Error("master shutdown hung")
		}
	}()
	var cached struct {
		NodeID     string `json:"node_id"`
		Master     string `json:"master"`
		Credential string `json:"credential"`
	}
	recovered := false
	deadline := time.Now().Add(7 * time.Second)
	for time.Now().Before(deadline) {
		body, err := os.ReadFile(statePath)
		if err == nil && json.Unmarshal(body, &cached) == nil && cached.Credential != "" && cached.Credential != expired {
			recovered = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !recovered {
		t.Fatal("expired cached credential was not re-enrolled")
	}
	if cached.NodeID != n.ID || cached.Master != c.ListenAddr {
		t.Fatal("recovery changed identity")
	}
	got, err := s.Snapshot(n.ID, cached.Credential)
	if err != nil || got.Node.Name != n.Name || !got.Node.Embedded {
		t.Fatal("recovery lost database identity/settings", err)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
		stopped = true
	case <-time.After(7 * time.Second):
		t.Fatal("embedded recovery shutdown hung")
	}
	nodes, err := s.Nodes()
	if err != nil || len(nodes) != 1 {
		t.Fatal("recovery duplicated node", err)
	}
	var pending int
	if err := db.QueryRow("SELECT count(*) FROM enroll WHERE node=?", n.ID).Scan(&pending); err != nil || pending != 0 {
		t.Fatal("internal token not consumed", err)
	}
}

func TestEmbeddedRecoveryRejectsIdentityMismatch(t *testing.T) {
	for _, field := range []string{"node_id", "master", "snapshot"} {
		t.Run(field, func(t *testing.T) {
			dir := t.TempDir()
			s, err := store.Open(filepath.Join(dir, "db"), filepath.Join(dir, "key"))
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			c := config.Config{ListenAddr: "127.0.0.1:8443", Scheme: "http", StateDir: dir}
			n, err := embeddedNode(c, s)
			if err != nil {
				t.Fatal(err)
			}
			cached := map[string]any{"node_id": n.ID, "master": c.ListenAddr, "credential": "expired"}
			if field == "snapshot" {
				cached[field] = model.Snapshot{Node: model.Node{ID: "external", Role: "server"}}
			} else {
				cached[field] = "external"
			}
			body, err := json.Marshal(cached)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "embedded-server", "state.json")
			if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, body, 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if err := runEmbeddedAttempt(ctx, c, s, n); err == nil {
				t.Fatal("identity mismatch accepted")
			}
			after, err := os.ReadFile(path)
			if err != nil || string(after) != string(body) {
				t.Fatal("mismatched cache modified", err)
			}
		})
	}
}

func TestEmbeddedLiveCredentialExpiry(t *testing.T) {
	dir := t.TempDir()
	c := config.Config{Database: filepath.Join(dir, "db"), DeploymentKey: filepath.Join(dir, "key"), ListenAddr: freeMasterAddress(t), Scheme: "http", StateDir: dir, EmbeddedServer: config.EmbeddedServerConfig{Enabled: true}}
	s, err := store.Open(c.Database, c.DeploymentKey)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, c) }()
	defer func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(7 * time.Second):
			t.Error("master shutdown hung")
		}
	}()
	var cached struct {
		NodeID     string `json:"node_id"`
		Credential string `json:"credential"`
	}
	path := filepath.Join(dir, "embedded-server", "state.json")
	wait := func(predicate func() bool) {
		t.Helper()
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) {
			if predicate() {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatal("embedded heartbeat/recovery timed out")
	}
	wait(func() bool {
		body, err := os.ReadFile(path)
		if err != nil || json.Unmarshal(body, &cached) != nil || cached.Credential == "" {
			return false
		}
		snap, err := s.Snapshot(cached.NodeID, cached.Credential)
		return err == nil && snap.Node.LastSeen > 0
	})
	beforeExpiry := time.Now().Unix()
	id, old := cached.NodeID, cached.Credential
	db, err := sql.Open("sqlite", c.Database)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// This independent test connection races with the embedded node heartbeat.
	// Match the store's busy timeout instead of failing on a transient WAL writer.
	db.SetMaxOpenConns(1)
	if _, err := db.Exec("PRAGMA busy_timeout=5000"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("UPDATE credentials SET expires=0 WHERE node=?", id); err != nil {
		t.Fatal(err)
	}
	wait(func() bool {
		body, err := os.ReadFile(path)
		if err != nil || json.Unmarshal(body, &cached) != nil || cached.Credential == "" || cached.Credential == old {
			return false
		}
		snap, err := s.Snapshot(id, cached.Credential)
		return err == nil && snap.Node.LastSeen > beforeExpiry
	})
	if cached.NodeID != id {
		t.Fatal("live recovery changed identity")
	}
	nodes, err := s.Nodes()
	if err != nil || len(nodes) != 1 || !nodes[0].Embedded {
		t.Fatal("live recovery changed nodes", err)
	}
	client := &http.Client{Timeout: time.Second}
	response, err := client.Get("http://" + c.ListenAddr + "/healthz")
	if err != nil {
		t.Fatal("master stopped during recovery", err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatal(response.Status)
	}
	if _, err := s.Snapshot(id, old); !errors.Is(err, store.ErrAuth) {
		t.Fatal("expired credential still accepted", err)
	}
}

func TestEmbeddedSupervisorBoundedAndCancelAware(t *testing.T) {
	calls := 0
	start := time.Now()
	err := superviseEmbedded(context.Background(), func() error {
		calls++
		return node.ErrCredentialRejected
	}, time.Millisecond)
	if !errors.Is(err, node.ErrCredentialRejected) || calls != 4 || time.Since(start) < 7*time.Millisecond {
		t.Fatal("unbounded or busy-loop recovery", calls, err)
	}
	runtimeErr := errors.New("disk/runtime failure")
	calls = 0
	err = superviseEmbedded(context.Background(), func() error { calls++; return runtimeErr }, time.Millisecond)
	if !errors.Is(err, runtimeErr) || calls != 1 {
		t.Fatal("arbitrary failure retried", calls, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	time.AfterFunc(20*time.Millisecond, cancel)
	start = time.Now()
	err = superviseEmbedded(ctx, func() error { return node.ErrCredentialRejected }, time.Hour)
	if err != nil || time.Since(start) > time.Second {
		t.Fatal("backoff not cancel-aware", err)
	}
}

func TestEmbeddedRetryRejectsChangedDatabaseIdentity(t *testing.T) {
	for _, change := range []string{"revoked", "role", "missing", "flag", "duplicate", "corrupt"} {
		t.Run(change, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "db")
			s, err := store.Open(path, filepath.Join(dir, "key"))
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			c := config.Config{ListenAddr: "127.0.0.1:8443", Scheme: "http", StateDir: dir}
			n, err := embeddedNode(c, s)
			if err != nil {
				t.Fatal(err)
			}
			db, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			var body []byte
			if err := db.QueryRow("SELECT data FROM config WHERE id=1").Scan(&body); err != nil {
				t.Fatal(err)
			}
			var document map[string]json.RawMessage
			if err := json.Unmarshal(body, &document); err != nil {
				t.Fatal(err)
			}
			var nodes map[string]model.Node
			if err := json.Unmarshal(document["Nodes"], &nodes); err != nil {
				t.Fatal(err)
			}
			changed := nodes[n.ID]
			switch change {
			case "revoked":
				changed.Revoked = true
			case "role":
				changed.Role = "client"
			case "flag":
				changed.Embedded = false
			case "duplicate":
				duplicate := changed
				duplicate.ID = "duplicate"
				nodes[duplicate.ID] = duplicate
			}
			nodes[n.ID] = changed
			if change == "missing" {
				delete(nodes, n.ID)
			}
			document["Nodes"], err = json.Marshal(nodes)
			if err != nil {
				t.Fatal(err)
			}
			if change == "corrupt" {
				document["Nodes"] = json.RawMessage(`"invalid"`)
			}
			body, err = json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec("UPDATE config SET data=? WHERE id=1", body); err != nil {
				t.Fatal(err)
			}
			calls := 0
			err = superviseEmbedded(context.Background(), func() error {
				calls++
				if calls == 1 {
					return node.ErrCredentialRejected
				}
				return runEmbeddedAttempt(context.Background(), c, s, n)
			}, time.Millisecond)
			if err == nil || calls != 2 {
				t.Fatal("changed identity did not fail closed", calls, err)
			}
			var after []byte
			if err := db.QueryRow("SELECT data FROM config WHERE id=1").Scan(&after); err != nil || string(after) != string(body) {
				t.Fatal("identity silently repaired", err)
			}
			var tokens int
			if err := db.QueryRow("SELECT count(*) FROM enroll").Scan(&tokens); err != nil || tokens != 0 {
				t.Fatal("invalid identity received enrollment", err)
			}
		})
	}
}
