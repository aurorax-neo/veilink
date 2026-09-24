package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStrictAndEnv(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yaml")
	os.WriteFile(p, []byte("unknown: true\n"), 0600)
	if _, e := Load(p); e == nil {
		t.Fatal("unknown field accepted")
	}
	os.WriteFile(p, []byte("node_id: test\nmaster_addr: localhost:8443\n"), 0600)
	t.Setenv("VEILINK_NODE_ID", "override")
	c, e := Load(p)
	if e != nil || c.NodeID != "override" {
		t.Fatal(c, e)
	}
	if e = c.Validate("client"); e != nil {
		t.Fatal(e)
	}
	c.ControlCert = "cert"
	c.ControlKey = "key"
	if e = c.Validate("master"); e != nil {
		t.Fatal(e)
	}
	c.Pool = 4
	if c.Validate("master") == nil {
		t.Fatal("server pool accepted")
	}
	c.Pool = 0
	if e = c.Validate("client"); e != nil {
		t.Fatal(e)
	}
	c.Pool = 64
	if c.Validate("client") == nil {
		t.Fatal("oversized pool accepted")
	}
}
func TestEmbeddedServerEnvOverrides(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yaml")
	os.WriteFile(p, []byte("bind_addr: 127.0.0.1:8443\ncontrol_cert: cert.pem\ncontrol_key: key.pem\n"), 0600)
	t.Setenv("VEILINK_EMBEDDED_SERVER_ENABLED", "true")
	t.Setenv("VEILINK_EMBEDDED_SERVER_NAME", "my-gateway")
	t.Setenv("VEILINK_EMBEDDED_SERVER_PORT", "9999")
	t.Setenv("VEILINK_EMBEDDED_SERVER_ADDRESS", "192.168.1.100")
	t.Setenv("VEILINK_EMBEDDED_SERVER_SERVER_NAME", "gateway.example.com")

	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if !c.EmbeddedServer.Enabled {
		t.Errorf("expected Enabled to be true, got %v", c.EmbeddedServer.Enabled)
	}
	if c.EmbeddedServer.Name != "my-gateway" {
		t.Errorf("expected Name to be my-gateway, got %q", c.EmbeddedServer.Name)
	}
	if c.EmbeddedServer.Port != 9999 {
		t.Errorf("expected Port to be 9999, got %d", c.EmbeddedServer.Port)
	}
	if c.EmbeddedServer.Address != "192.168.1.100" {
		t.Errorf("expected Address to be 192.168.1.100, got %q", c.EmbeddedServer.Address)
	}
	if c.EmbeddedServer.ServerName != "gateway.example.com" {
		t.Errorf("expected ServerName to be gateway.example.com, got %q", c.EmbeddedServer.ServerName)
	}
}

func TestEffectiveTLSMode(t *testing.T) {
	tests := []struct{ mode, cert, key, want string }{
		{"", "", "", "http"},
		{"", "c.pem", "k.pem", "https"},
		{"http", "c.pem", "k.pem", "http"},
		{"https", "c.pem", "k.pem", "https"},
		{"HTTPS", "", "", "https"},
	}
	for _, tt := range tests {
		c := Config{TLSMode: tt.mode, ControlCert: tt.cert, ControlKey: tt.key}
		if got := c.EffectiveTLSMode(); got != tt.want {
			t.Errorf("TLSMode=%q cert=%q key=%q: got %q want %q", tt.mode, tt.cert, tt.key, got, tt.want)
		}
	}
}
