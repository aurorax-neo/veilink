package config

import (
	"database/sql"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestMasterPersistenceRedeployAndOverrides(t *testing.T) {
	dir := t.TempDir()
	database := filepath.Join(dir, "master.db")
	bootstrap := []string{"-database", database, "-deployment-key", filepath.Join(dir, "master.key")}
	load := func(flags ...string) Config {
		t.Helper()
		c, err := ParseFlags("master", append(append([]string{}, bootstrap...), flags...))
		if err != nil {
			t.Fatal(err)
		}
		c, err = PersistMaster(c)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	first := load("-listen-addr=0.0.0.0:9443", "-state-dir=durable-state", "-scheme=http", "-cert-file=/local/cert.pem", "-key-file=/local/key.pem", "-embedded-server-enabled", "-embedded-server-address=gateway.example.com", "-embedded-server-port=9444")
	second := load()
	if second.ListenAddr != first.ListenAddr || second.StateDir != first.StateDir || second.EmbeddedServer != first.EmbeddedServer || second.CertFile != first.CertFile || second.Scheme != "http" {
		t.Fatal("redeploy defaults replaced persisted settings")
	}
	if second.EnrollToken != "" {
		t.Fatal("enrollment token persisted")
	}
	// Explicit false and nested leaves override without resetting omitted siblings.
	third := load("-embedded-server-enabled=false", "-embedded-server-address=updated.example.com", "-cert-file=")
	if third.EmbeddedServer.Enabled || third.EmbeddedServer.Port != 9444 || third.EmbeddedServer.Address != "updated.example.com" {
		t.Fatal("nested override lost settings")
	}
	t.Setenv("VEILINK_LISTEN_ADDR", "0.0.0.0:10443")
	t.Setenv("VEILINK_EMBEDDED_SERVER_ENABLED", "true")
	last := load()
	if last.ListenAddr != "0.0.0.0:9443" || last.EmbeddedServer.Enabled || last.CertFile != "" {
		t.Fatal("environment override or explicit empty ignored")
	}
	updated := load("-listen-addr=0.0.0.0:10443", "-embedded-server-enabled=true")
	if updated.ListenAddr != "0.0.0.0:10443" || !updated.EmbeddedServer.Enabled {
		t.Fatal("explicit CLI override ignored")
	}
	db, err := sql.Open("sqlite", database)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var raw string
	if err := db.QueryRow("SELECT data FROM master_config WHERE id=1").Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"Database", "DeploymentKey", "EnrollToken"} {
		if _, ok := doc[field]; ok {
			t.Errorf("bootstrap/transient field %s persisted", field)
		}
	}
	if strings.Contains(raw, "BEGIN CERTIFICATE") {
		t.Fatal("transient secret or certificate bytes persisted")
	}
}

func TestMasterPersistenceRejectsInvalidUpdate(t *testing.T) {
	dir := t.TempDir()
	c := Defaults()
	c.Database, c.DeploymentKey = filepath.Join(dir, "db"), filepath.Join(dir, "key")
	if _, err := PersistMaster(c); err != nil {
		t.Fatal(err)
	}
	c.ListenAddr = "invalid"
	c.explicit["listen_addr"] = true
	if _, err := PersistMaster(c); err == nil {
		t.Fatal("invalid config accepted")
	}
	delete(c.explicit, "listen_addr")
	c, err := PersistMaster(c)
	if err != nil || c.ListenAddr != "127.0.0.1:8443" {
		t.Fatal("invalid update replaced saved config")
	}
}

func TestMasterPersistenceRejectsRemovedFields(t *testing.T) {
	for _, document := range []string{`{"BindAddr":"localhost:8443"}`, `{"TLSMode":"http"}`, `{"ControlCert":"cert"}`, `{"ControlKey":"key"}`, `{"TLS":{}}`, `{"Pool":2}`, `{"EmbeddedServer":{"TLS":{}}}`, `{} {}`} {
		t.Run(document, func(t *testing.T) {
			c := Defaults()
			dir := t.TempDir()
			c.Database, c.DeploymentKey = filepath.Join(dir, "db"), filepath.Join(dir, "key")
			if _, err := PersistMaster(c); err != nil {
				t.Fatal(err)
			}
			db, err := sql.Open("sqlite", c.Database)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			if _, err := db.Exec("UPDATE master_config SET data=? WHERE id=1", document); err != nil {
				t.Fatal(err)
			}
			if _, err := PersistMaster(c); err == nil {
				t.Fatal("removed persisted schema accepted")
			}
			var after string
			if err := db.QueryRow("SELECT data FROM master_config WHERE id=1").Scan(&after); err != nil {
				t.Fatal(err)
			}
			if after != document {
				t.Fatal("invalid persisted schema migrated")
			}
		})
	}
}

func TestMasterExplicitEmptySchemeDoesNotCommit(t *testing.T) {
	dir := t.TempDir()
	base := []string{"-database", filepath.Join(dir, "db"), "-deployment-key", filepath.Join(dir, "key")}
	for _, seed := range []bool{false, true} {
		if seed {
			c, err := ParseFlags("master", base)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = PersistMaster(c); err != nil {
				t.Fatal(err)
			}
		}
		c, err := ParseFlags("master", append(append([]string{}, base...), "-scheme="))
		if err != nil {
			t.Fatal(err)
		}
		if _, err = PersistMaster(c); err == nil {
			t.Fatal("explicit empty scheme accepted")
		}
	}
}
