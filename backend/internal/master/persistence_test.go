package master

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"veilink/internal/config"
	"veilink/internal/model"
	"veilink/internal/store"
)

func TestEmbeddedNodePreservesDatabaseSettings(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Open(filepath.Join(dir, "db"), filepath.Join(dir, "key"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	c := config.Config{ListenAddr: "gateway.example.com:8443", CertFile: "master-cert.pem", KeyFile: "master-key.pem"}
	n, err := embeddedNode(c, s)
	if err != nil {
		t.Fatal(err)
	}
	if !n.Embedded || n.ClientTunnel != nil || n.Address != "gateway.example.com" || n.Tunnel != (model.LocalTLS{ListenPort: 8444}) {
		t.Fatal("registration must seed only the explicit local listen port, never master certificates")
	}
	n.Address, n.Port = "updated.example.com", 9999
	n.Name, n.Embedded = "renamed-in-web", false // API cannot clear master metadata.
	cert, key := writeCert(t, dir)
	certPEM, err := os.ReadFile(cert)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := os.ReadFile(key)
	if err != nil {
		t.Fatal(err)
	}
	n.Tunnel = model.LocalTLS{ListenPort: 9999, TransportSecurity: "tls", CertPEM: string(certPEM), KeyPEM: string(keyPEM)}
	if _, err := s.SaveNode(n); err != nil {
		t.Fatal(err)
	}
	next, err := embeddedNode(c, s)
	if err != nil {
		t.Fatal(err)
	}
	if !next.Embedded || next.ID != n.ID || next.Name != n.Name || next.ClientTunnel == nil || next.Address != n.Address || next.Port != n.Port || next.Tunnel != n.Tunnel {
		t.Fatal("registration reset administrative settings")
	}
	for _, remove := range []bool{false, true} {
		if err := s.RemoveNode(n.ID, remove); err == nil {
			t.Fatal("embedded node removal accepted")
		}
	}
	c.EmbeddedServer.Name = "client-name"
	if _, err := s.SaveNode(model.Node{Name: c.EmbeddedServer.Name, Role: "client"}); err != nil {
		t.Fatal(err)
	}
	if got, err := embeddedNode(c, s); err != nil || got.ID != n.ID {
		t.Fatal("display-name collision changed embedded identity", err)
	}
}

func TestEmbeddedControlTransport(t *testing.T) {
	c := config.Config{ListenAddr: "0.0.0.0:8443", Scheme: "http", ControlCA: "unused", ControlServerName: "unused", CertFile: "cert", KeyFile: "key"}
	n := model.Node{ID: "node", Tunnel: model.LocalTLS{ListenHost: "127.0.0.1"}}
	got := embeddedConfig(c, n)
	if got.ControlCA != "" || got.ControlServerName != "" || got.MasterAddr != "127.0.0.1:8443" || got.CertFile != "" || got.KeyFile != "" {
		t.Fatal("HTTP embedded control must be insecure and DB tunnel authoritative")
	}
	c.Scheme, c.ControlCA, c.ControlServerName = "https", "", ""
	got = embeddedConfig(c, n)
	if got.ControlCA != "cert" || got.ControlServerName != "" {
		t.Fatal("HTTPS should trust local cert without forcing localhost SNI")
	}
}

func TestEmbeddedHTTPRestartKeepsCredential(t *testing.T) {
	dir := t.TempDir()
	c := config.Config{Database: filepath.Join(dir, "db"), DeploymentKey: filepath.Join(dir, "key"), ListenAddr: "127.0.0.1:0", Scheme: "http", StateDir: dir, EmbeddedServer: config.EmbeddedServerConfig{Enabled: true}}
	// The embedded node can enroll and idle without any tunnel certificates.
	// Use a stable address across both runs so the local auth cache identity stays stable.
	c.ListenAddr = freeMasterAddress(t)
	var firstCredential string
	for iteration := 0; iteration < 2; iteration++ {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- Run(ctx, c) }()
		var cached struct {
			Credential string `json:"credential"`
		}
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			body, err := os.ReadFile(filepath.Join(dir, "embedded-server", "state.json"))
			if err == nil && json.Unmarshal(body, &cached) == nil && cached.Credential != "" {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		if cached.Credential == "" {
			cancel()
			t.Fatal("HTTP embedded enrollment failed")
		}
		if iteration == 0 {
			firstCredential = cached.Credential
		} else if cached.Credential != firstCredential {
			cancel()
			t.Fatal("credential rotated on restart")
		}
		// Allow the second run to finish startup and contact the master.
		time.Sleep(100 * time.Millisecond)
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(7 * time.Second):
			t.Fatal("embedded shutdown hung")
		}
		body, err := os.ReadFile(filepath.Join(dir, "embedded-server", "state.json"))
		if err != nil || json.Unmarshal(body, &cached) != nil || cached.Credential != firstCredential {
			t.Fatal("stable credential not retained after shutdown")
		}
	}
}

func freeMasterAddress(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

func TestFailedMasterStartupDoesNotPersistOverrides(t *testing.T) {
	for _, seeded := range []bool{false, true} {
		t.Run(fmt.Sprintf("seeded=%t", seeded), func(t *testing.T) {
			dir := t.TempDir()
			cert, key := writeCert(t, dir)
			database := filepath.Join(dir, "db")
			bootstrap := []string{"-database", database, "-deployment-key", filepath.Join(dir, "key")}
			settings := []string{"-listen-addr", freeMasterAddress(t), "-scheme=https", "-cert-file", cert, "-key-file", key}
			load := func(extra ...string) config.Config {
				t.Helper()
				c, err := config.ParseFlags("master", append(append([]string{}, bootstrap...), extra...))
				if err != nil {
					t.Fatal(err)
				}
				return c
			}
			run := func(c config.Config) error {
				// A cancelled context still executes startup, then shuts down promptly.
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return Run(ctx, c)
			}
			if seeded {
				if err := run(load(settings...)); err != nil {
					t.Fatal(err)
				}
			}
			occupied, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer occupied.Close()
			badCert := filepath.Join(dir, "invalid.pem")
			if err := os.WriteFile(badCert, []byte("not a certificate"), 0600); err != nil {
				t.Fatal(err)
			}
			var baseline string
			readDocument := func() string {
				t.Helper()
				db, err := sql.Open("sqlite", database)
				if err != nil {
					t.Fatal(err)
				}
				defer db.Close()
				var body string
				err = db.QueryRow("SELECT data FROM master_config WHERE id=1").Scan(&body)
				if err != nil && err != sql.ErrNoRows {
					t.Fatal(err)
				}
				return body
			}
			if seeded {
				baseline = readDocument()
			}
			for _, tc := range []struct{ name, flag, value string }{
				{"missing certificate", "-cert-file", filepath.Join(dir, "missing.pem")},
				{"invalid certificate", "-cert-file", badCert},
				{"bad port", "-listen-addr", "127.0.0.1:65536"},
				{"nonnumeric port", "-listen-addr", "127.0.0.1:not-a-port"},
				{"occupied port", "-listen-addr", occupied.Addr().String()},
			} {
				t.Run(tc.name, func(t *testing.T) {
					flags := []string{tc.flag, tc.value}
					if !seeded {
						flags = append(append([]string{}, settings...), flags...)
					}
					if err := run(load(flags...)); err == nil {
						t.Fatal("invalid startup succeeded")
					}
					if readDocument() != baseline {
						t.Fatal("failed startup changed persisted settings")
					}
				})
			}
			finalFlags := []string{}
			if !seeded {
				finalFlags = settings
			}
			if err := run(load(finalFlags...)); err != nil {
				t.Fatalf("restart after removing override failed: %v", err)
			}
			if seeded && readDocument() != baseline {
				t.Fatal("restart lost prior settings")
			}
			if !seeded && readDocument() == "" {
				t.Fatal("successful first startup did not seed settings")
			}
		})
	}
}

func TestMasterConfigCommitRejectsConcurrentChange(t *testing.T) {
	for _, seeded := range []bool{false, true} {
		t.Run(fmt.Sprintf("seeded=%t", seeded), func(t *testing.T) {
			dir := t.TempDir()
			c := config.Config{Database: filepath.Join(dir, "db"), DeploymentKey: filepath.Join(dir, "key"), ListenAddr: "127.0.0.1:0", Scheme: "http"}
			if seeded {
				if _, err := config.PersistMaster(c); err != nil {
					t.Fatal(err)
				}
			}
			_, staleCommit, err := config.ResolveMaster(c)
			if err != nil {
				t.Fatal(err)
			}
			c.StateDir = "newer-settings"
			if _, err := config.PersistMaster(c); err != nil {
				t.Fatal(err)
			}
			if err := staleCommit(); err == nil {
				t.Fatal("stale commit overwrote concurrent update")
			}
			local, err := config.ParseFlags("master", []string{"-database", c.Database, "-deployment-key", c.DeploymentKey})
			if err != nil {
				t.Fatal(err)
			}
			got, _, err := config.ResolveMaster(local)
			if err != nil || got.StateDir != "newer-settings" {
				t.Fatal("concurrent settings lost")
			}
		})
	}
}

func TestLegacyAdminPasswordIgnored(t *testing.T) {
	t.Setenv("VEILINK_INIT_ADMIN_PASSWORD", "")
	t.Setenv("VEILINK_ADMIN_PASSWORD", "legacy-password-must-not-work")
	dir := t.TempDir()
	c := config.Config{Database: filepath.Join(dir, "db"), DeploymentKey: filepath.Join(dir, "key"), ListenAddr: "127.0.0.1:0", Scheme: "http"}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Run(ctx, c); err != nil {
		t.Fatal(err)
	}
	s, err := store.Open(c.Database, c.DeploymentKey)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	hasAdmin, err := s.HasAdmin()
	if err != nil || hasAdmin {
		t.Fatal("legacy password initialized administrator", err)
	}
}
