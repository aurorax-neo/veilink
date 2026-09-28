package config

import (
	"path/filepath"
	"testing"
)

func TestDefaultsAndFlags(t *testing.T) {
	c := Defaults()
	if !c.EmbeddedServer.Enabled || c.Database != "/data/veilink.db" || c.DeploymentKey != "/data/veilink.key" || c.StateDir != "/data/state" || c.ListenAddr != "127.0.0.1:8443" || c.Scheme != "http" {
		t.Fatalf("defaults: %+v", c)
	}
	t.Setenv("VEILINK_CONFIG", filepath.Join(t.TempDir(), "missing.yaml"))
	t.Setenv("VEILINK_SCHEME", "https")
	t.Setenv("VEILINK_LISTEN_ADDR", "0.0.0.0:65536")
	t.Setenv("VEILINK_ENROLL_TOKEN", "ignored")
	c, err := ParseFlags("master", nil)
	if err != nil || c.Scheme != "http" || c.ListenAddr != "127.0.0.1:8443" {
		t.Fatal(c, err)
	}
	c, err = ParseFlags("master", []string{"-listen-addr", "127.0.0.1:9443", "-control-server-name", "panel.example.com", "-control-ca", "/config/master-ca.pem", "-embedded-server-enabled", "-embedded-server-port", "9999", "-embedded-server-name", "gateway", "-embedded-server-address", "127.0.0.1", "-embedded-server-state-dir", "/tmp/gateway"})
	if err != nil || c.Validate("master") != nil || c.ControlServerName != "panel.example.com" || c.ControlCA != "/config/master-ca.pem" || !c.EmbeddedServer.Enabled || c.EmbeddedServer.Port != 9999 || c.EmbeddedServer.Name != "gateway" || c.EmbeddedServer.StateDir != "/tmp/gateway" {
		t.Fatal(c, err)
	}
	node, err := ParseFlags("client", []string{"-master-addr", "localhost:8443", "-node-id", "node", "-enroll-token", "secret", "-state-dir", "/tmp/node", "-control-ca", "/tmp/ca", "-control-server-name", "localhost"})
	if err != nil || node.Validate("client") != nil || node.EnrollToken != "secret" || node.ControlCA != "/tmp/ca" || node.ControlServerName != "localhost" {
		t.Fatal(node, err)
	}
	node, err = ParseFlags("server", []string{"-master-addr", "localhost:8443", "-node-id", "node"})
	if err != nil || node.EnrollToken != "" || node.StateDir != "/data/state" {
		t.Fatal(node, err)
	}
}

func TestRemovedAndWrongRoleFlags(t *testing.T) {
	for _, tc := range []struct {
		role string
		args []string
	}{
		{"master", []string{"-config", "old.yaml"}}, {"client", []string{"-config=old.yaml"}}, {"init-admin", []string{"-config", "old.yaml"}},
		{"master", []string{"-embedded-server-server-name=localhost"}},
		{"server", []string{"-database", "db"}}, {"client", []string{"-cert-file", "cert"}}, {"master", []string{"-enroll-token", "secret"}},
		{"master", []string{"-embedded-server-port", "bad"}}, {"master", []string{"-embedded-server-enabled=bad"}}, {"master", []string{"stray"}},
	} {
		if _, err := ParseFlags(tc.role, tc.args); err == nil {
			t.Errorf("%s %v accepted", tc.role, tc.args)
		}
	}
}

func TestSchemeExplicitAndValidated(t *testing.T) {
	for _, scheme := range []string{"http", "https", "HTTPS", "auto", "ftp", ""} {
		c, err := ParseFlags("master", []string{"-scheme=" + scheme, "-cert-file=cert", "-key-file=key"})
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Validate("master"); (err == nil) != (scheme == "http" || scheme == "https") {
			t.Fatalf("scheme %q: %v", scheme, err)
		}
	}
	c, _ := ParseFlags("master", []string{"-scheme=https"})
	if c.Validate("master") == nil {
		t.Fatal("HTTPS without certificate accepted")
	}
}
