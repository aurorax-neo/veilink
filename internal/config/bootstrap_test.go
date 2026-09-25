package config

import "testing"

func TestDatabaseOnlyNodeConfiguration(t *testing.T) {
	for _, role := range []string{"server", "client"} {
		c := Config{MasterAddr: "127.0.0.1:8443", NodeID: "node", StateDir: t.TempDir(), ControlCA: "master-ca.pem", ControlServerName: "master.example.com"}
		if err := c.Validate(role); err != nil {
			t.Fatalf("%s cannot fetch database tunnel config: %v", role, err)
		}
		for _, field := range []string{"cert_file", "key_file"} {
			bad := c
			bad.explicit = map[string]bool{field: true}
			if bad.Validate(role) == nil {
				t.Fatalf("%s accepted master field %s", role, field)
			}
		}
		c.CertFile = "cert.pem"
		if c.Validate(role) == nil {
			t.Fatalf("%s accepted master certificate", role)
		}
		c.CertFile, c.KeyFile = "", "key.pem"
		if c.Validate(role) == nil {
			t.Fatalf("%s accepted master key", role)
		}
	}
}
