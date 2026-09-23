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
	if c.Validate("master") == nil {
		t.Fatal("implicit HTTP accepted")
	}
	c.InsecureLoopbackHTTP = true
	if e = c.Validate("master"); e != nil {
		t.Fatal(e)
	}
	c.HTTPAddr = "0.0.0.0:8080"
	if c.Validate("master") == nil {
		t.Fatal("nonloopback dev mode accepted")
	}
}
