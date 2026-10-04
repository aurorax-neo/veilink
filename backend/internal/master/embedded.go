package master

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"time"

	"veilink/internal/config"
	"veilink/internal/logring"
	"veilink/internal/model"
	"veilink/internal/node"
	"veilink/internal/store"
)

func embeddedNode(c config.Config, s *store.Store) (model.Node, error) {
	name := c.EmbeddedServer.Name
	if name == "" {
		name = "default"
	}
	port := c.EmbeddedServer.Port
	if port == 0 {
		port = 8444
	}
	addr := c.EmbeddedServer.Address
	if addr == "" {
		addr, _, _ = net.SplitHostPort(c.ListenAddr)
		if addr == "" || addr == "0.0.0.0" || addr == "::" {
			addr = "127.0.0.1"
		}
	}
	n, err := s.EnsureEmbeddedNode(model.Node{
		Name: name, Role: "server", Address: addr, Port: port,
		Tunnel:           model.LocalTLS{ListenPort: port},
		ConnectEndpoints: []model.ConnectEndpoint{{ID: "primary", Name: "启动参数默认接入", Host: addr, Port: port, Enabled: true}},
	})
	if err != nil {
		return n, fmt.Errorf("failed to auto-register embedded server node: %w", err)
	}
	slog.Info("registered embedded server node", "node_id", n.ID, "name", n.Name, "port", n.Port)
	return n, nil
}

func embeddedConfig(c config.Config, n model.Node) config.Config {
	masterAddr := c.ListenAddr
	bindHost, bindPortStr, err := net.SplitHostPort(c.ListenAddr)
	if err == nil {
		if bindHost == "" || bindHost == "0.0.0.0" {
			masterAddr = net.JoinHostPort("127.0.0.1", bindPortStr)
		} else if bindHost == "::" {
			masterAddr = net.JoinHostPort("::1", bindPortStr)
		}
	}
	var controlCA, controlSNI string
	if c.Scheme == "https" {
		controlCA = c.ControlCA
		if controlCA == "" {
			controlCA = c.CertFile
		}
		controlSNI = c.ControlServerName
		// An empty SNI lets TLS verify the actual dial host, not forced localhost.
	}
	stateDir := c.EmbeddedServer.StateDir
	if stateDir == "" {
		stateDir = filepath.Join(c.StateDir, "embedded-server")
	}
	return config.Config{
		MasterAddr: masterAddr,
		ControlCA:  controlCA, ControlServerName: controlSNI,
		NodeID: n.ID, StateDir: stateDir,
	}
}

func runEmbeddedServer(ctx context.Context, c config.Config, s *store.Store, rings ...*logring.Ring) error {
	n, err := embeddedNode(c, s)
	if err != nil {
		return err
	}
	return superviseEmbedded(ctx, func() error {
		return runEmbeddedAttempt(ctx, c, s, n, rings...)
	}, time.Second)
}

// Retry only explicit authentication rejection, at most three times per minute.
// Long-lived sessions get a fresh budget so future credential expirations recover.
func superviseEmbedded(ctx context.Context, run func() error, delay time.Duration) error {
	window := time.Now()
	retries := 0
	for {
		if ctx.Err() != nil {
			return nil
		}
		err := run()
		if ctx.Err() != nil {
			return nil
		}
		if !errors.Is(err, node.ErrCredentialRejected) {
			return err
		}
		if time.Since(window) >= time.Minute {
			window, retries = time.Now(), 0
		}
		if retries >= 3 {
			return fmt.Errorf("embedded authentication recovery exhausted: %w", err)
		}
		slog.Warn("embedded credential rejected; retrying internal enrollment", "attempt", retries+1)
		timer := time.NewTimer(delay * time.Duration(1<<retries))
		retries++
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}

func runEmbeddedAttempt(ctx context.Context, c config.Config, s *store.Store, n model.Node, rings ...*logring.Ring) error {
	// Never re-register here: missing/revoked/corrupt identities must fail closed,
	// not create a replacement node or adopt a different embedded identity.
	nodes, err := s.Nodes()
	if err != nil {
		return err
	}
	count := 0
	for _, current := range nodes {
		if current.Embedded {
			if current.ID != n.ID || current.Role != "server" || current.Revoked {
				return fmt.Errorf("embedded database identity mismatch or revocation")
			}
			count++
		}
	}
	if count != 1 {
		return fmt.Errorf("embedded database identity missing or ambiguous")
	}
	srvConfig := embeddedConfig(c, n)
	// Keep a valid cached credential; expired credentials need internal enrollment
	// before node.Run, which deliberately fails closed on rejected credentials.
	var cached struct {
		NodeID     string          `json:"node_id"`
		Master     string          `json:"master"`
		Credential string          `json:"credential"`
		Snapshot   *model.Snapshot `json:"snapshot,omitempty"`
	}
	statePath := filepath.Join(srvConfig.StateDir, "state.json")
	body, err := os.ReadFile(statePath)
	if err == nil {
		if json.Unmarshal(body, &cached) != nil || cached.NodeID != n.ID || cached.Master != srvConfig.MasterAddr {
			return fmt.Errorf("embedded node state identity mismatch or corruption")
		}
		if cached.Snapshot != nil && (cached.Snapshot.Node.ID != n.ID || cached.Snapshot.Node.Role != "server") {
			return fmt.Errorf("embedded cached node identity mismatch")
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("cannot read embedded node state: %w", err)
	}
	if cached.Credential != "" {
		if _, err := s.Snapshot(n.ID, cached.Credential); err != nil {
			if !errors.Is(err, store.ErrAuth) {
				return fmt.Errorf("cannot validate embedded credential: %w", err)
			}
			// Preserve the verified local identity, but never restore a snapshot
			// authenticated with an expired or otherwise invalid credential.
			cached.Credential, cached.Snapshot = "", nil
			body, err = json.Marshal(cached)
			if err != nil {
				return err
			}
			if err := saveEmbeddedState(statePath, body); err != nil {
				return fmt.Errorf("cannot reset expired embedded credential: %w", err)
			}
		}
	}
	if cached.Credential == "" {
		token, err := s.EnrollToken(n.ID, 24*time.Hour)
		if err != nil {
			return fmt.Errorf("failed to issue enrollment token for embedded server: %w", err)
		}
		srvConfig.EnrollToken = token
		defer s.RevokeEnrollToken(n.ID)
	}
	if len(rings) > 0 && rings[0] != nil {
		logger := slog.New(logring.NewNodeHandler(rings[0], n.ID, slog.NewTextHandler(os.Stderr, nil)))
		return node.RunWithLogger(ctx, srvConfig, "server", logger)
	}
	return node.Run(ctx, srvConfig, "server")
}

// Atomically replace only the local authentication cache, never the database.
func saveEmbeddedState(path string, body []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".state-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(body); err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(f.Name(), path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
