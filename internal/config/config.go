package config

import (
	"errors"
	"flag"
	"net"
	"os"
	"path/filepath"
	"strconv"
)

type EmbeddedServerConfig struct {
	Enabled    bool
	Name       string
	Address    string
	Port       int
	ServerName string
	StateDir   string
}

type Config struct {
	Database          string
	DeploymentKey     string
	ListenAddr        string
	HTMLDir           string
	CertFile          string
	KeyFile           string
	Scheme            string
	ControlCA         string
	ControlServerName string
	MasterAddr        string
	NodeID            string
	EnrollToken       string
	StateDir          string
	EmbeddedServer    EmbeddedServerConfig

	// explicit tracks visited CLI flags; defaults never overwrite stored settings.
	explicit map[string]bool
}

func Defaults() Config {
	return Config{Database: "/data/veilink.db", DeploymentKey: "/data/veilink.key", ListenAddr: "127.0.0.1:8443", Scheme: "http", StateDir: "/data/state", explicit: make(map[string]bool)}
}

// ParseFlags accepts only flags belonging to the requested role. Visited flags,
// including false and empty values, take precedence over persisted master settings.
func ParseFlags(role string, args []string) (Config, error) {
	c := Defaults()
	f := flag.NewFlagSet(role, flag.ContinueOnError)
	f.Usage = func() {
		_, _ = f.Output().Write([]byte("Usage: veilink " + role + " [flags]\nTunnel settings are managed in the Master Web UI, not local flags: TLS needs matching certificate/CA/SNI; plain requires VLESS Encryption; REALITY needs matching public key/Short ID/name; Hysteria2 needs UDP, TLS and a shared password. Vision requires TCP + TLS/REALITY and may use encrypted fallback. -control-ca trusts Master HTTPS only, not tunnel TLS.\n"))
		f.PrintDefaults()
	}
	fields := make(map[string]string)
	stringFlag := func(name, field string, dst *string) {
		f.StringVar(dst, name, *dst, "")
		fields[name] = field
	}
	switch role {
	case "master":
		stringFlag("database", "database", &c.Database)
		stringFlag("deployment-key", "deployment_key", &c.DeploymentKey)
		stringFlag("listen-addr", "listen_addr", &c.ListenAddr)
		stringFlag("scheme", "scheme", &c.Scheme)
		stringFlag("cert-file", "cert_file", &c.CertFile)
		stringFlag("key-file", "key_file", &c.KeyFile)
		stringFlag("html-dir", "html_dir", &c.HTMLDir)
		stringFlag("state-dir", "state_dir", &c.StateDir)
		stringFlag("control-ca", "control_ca", &c.ControlCA)
		stringFlag("control-server-name", "control_server_name", &c.ControlServerName)
		f.BoolVar(&c.EmbeddedServer.Enabled, "embedded-server-enabled", c.EmbeddedServer.Enabled, "")
		fields["embedded-server-enabled"] = "embedded_server.enabled"
		stringFlag("embedded-server-name", "embedded_server.name", &c.EmbeddedServer.Name)
		stringFlag("embedded-server-address", "embedded_server.address", &c.EmbeddedServer.Address)
		f.IntVar(&c.EmbeddedServer.Port, "embedded-server-port", c.EmbeddedServer.Port, "")
		fields["embedded-server-port"] = "embedded_server.port"
		stringFlag("embedded-server-server-name", "embedded_server.server_name", &c.EmbeddedServer.ServerName)
		stringFlag("embedded-server-state-dir", "embedded_server.state_dir", &c.EmbeddedServer.StateDir)
	case "server", "client":
		stringFlag("master-addr", "master_addr", &c.MasterAddr)
		stringFlag("node-id", "node_id", &c.NodeID)
		stringFlag("enroll-token", "enroll_token", &c.EnrollToken)
		stringFlag("state-dir", "state_dir", &c.StateDir)
		stringFlag("control-ca", "control_ca", &c.ControlCA)
		stringFlag("control-server-name", "control_server_name", &c.ControlServerName)
	default:
		return c, errors.New("unknown command")
	}
	if err := f.Parse(args); err != nil {
		return c, err
	}
	if f.NArg() != 0 {
		return c, errors.New("unexpected positional arguments")
	}
	f.Visit(func(v *flag.Flag) { c.explicit[fields[v.Name]] = true })
	return c, nil
}

func (c Config) Validate(role string) error {
	if (c.Scheme == "" && c.explicit["scheme"]) || (c.Scheme != "" && c.Scheme != "http" && c.Scheme != "https") {
		return errors.New("scheme must be http or https")
	}
	if role == "master" {
		if c.Database == "" || c.DeploymentKey == "" {
			return errors.New("database and deployment_key bootstrap paths required")
		}
		if c.Scheme == "https" && (c.CertFile == "" || c.KeyFile == "") {
			return errors.New("HTTPS cert_file and key_file required")
		}
		_, listenPortStr, e := net.SplitHostPort(c.ListenAddr)
		if e != nil {
			return e
		}
		listenPort, e := strconv.Atoi(listenPortStr)
		if e != nil || listenPort < 0 || listenPort > 65535 {
			return errors.New("master listen_addr must have a numeric port from 0 to 65535")
		}
		if c.HTMLDir != "" {
			info, e := os.Stat(filepath.Join(c.HTMLDir, "index.html"))
			if e != nil || info.IsDir() {
				return errors.New("html_dir must contain index.html")
			}
		}
		if c.EmbeddedServer.Enabled {
			if c.EmbeddedServer.Port < 0 || c.EmbeddedServer.Port > 65535 {
				return errors.New("embedded_server port out of range")
			}
			srvPort := c.EmbeddedServer.Port
			if srvPort == 0 {
				srvPort = 8444
			}
			if srvPort == listenPort {
				return errors.New("embedded_server port collides with master listen_addr")
			}
		}
		return nil
	}
	if role != "server" && role != "client" {
		return errors.New("invalid role")
	}
	if c.MasterAddr == "" || c.NodeID == "" || c.StateDir == "" {
		return errors.New("master_addr, node_id and state_dir required")
	}
	if c.CertFile != "" || c.KeyFile != "" || c.explicit["cert_file"] || c.explicit["key_file"] {
		return errors.New("cert_file and key_file are master-only; configure tunnel certificates in Web")
	}
	return nil
}
