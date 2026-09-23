package config

import (
	"errors"
	"gopkg.in/yaml.v3"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"veilink/internal/model"
	"veilink/internal/tunnel"
)

type EmbeddedServerConfig struct {
	Enabled    bool           `yaml:"enabled"`
	Name       string         `yaml:"name"`
	Address    string         `yaml:"address"`
	Port       int            `yaml:"port"`
	ServerName string         `yaml:"server_name"`
	StateDir   string         `yaml:"state_dir"`
	TLS        model.LocalTLS `yaml:"tls"`
}

type Config struct {
	Database          string               `yaml:"database"`
	DeploymentKey     string               `yaml:"deployment_key"`
	BindAddr          string               `yaml:"bind_addr"`
	HTMLDir           string               `yaml:"html_dir"`
	ControlCert       string               `yaml:"control_cert"`
	ControlKey        string               `yaml:"control_key"`
	ControlCA         string               `yaml:"control_ca"`
	ControlServerName string               `yaml:"control_server_name"`
	MasterAddr        string               `yaml:"master_addr"`
	NodeID            string               `yaml:"node_id"`
	EnrollToken       string               `yaml:"enroll_token"`
	StateDir          string               `yaml:"state_dir"`
	Pool              int                  `yaml:"pool"`
	TLS               model.LocalTLS       `yaml:"tls"`
	EmbeddedServer    EmbeddedServerConfig `yaml:"embedded_server"`
}

func Load(path string) (Config, error) {
	c := Config{Database: "veilink.db", DeploymentKey: "veilink.key", BindAddr: "127.0.0.1:8443", StateDir: "state"}
	if path == "" {
		if e := env(reflect.ValueOf(&c).Elem(), "VEILINK_"); e != nil {
			return c, e
		}
		return c, nil
	}
	f, e := os.Open(path)
	if e != nil {
		if os.IsNotExist(e) && path == "veilink.yaml" {
			if e := env(reflect.ValueOf(&c).Elem(), "VEILINK_"); e != nil {
				return c, e
			}
			return c, nil
		}
		return c, e
	}
	defer f.Close()
	d := yaml.NewDecoder(io.LimitReader(f, 1<<20))
	d.KnownFields(true)
	if e = d.Decode(&c); e != nil {
		return c, e
	}
	var extra any
	if e = d.Decode(&extra); e != io.EOF {
		return c, errors.New("configuration must contain one YAML document")
	}
	if e = env(reflect.ValueOf(&c).Elem(), "VEILINK_"); e != nil {
		return c, e
	}
	return c, nil
}
func env(v reflect.Value, prefix string) error {
	t := v.Type()
	for i := 0; i < v.NumField(); i++ {
		f := v.Field(i)
		key := prefix + strings.ToUpper(t.Field(i).Tag.Get("yaml"))
		if f.Kind() == reflect.Struct {
			if e := env(f, key+"_"); e != nil {
				return e
			}
			continue
		}
		if value, ok := os.LookupEnv(key); ok {
			switch f.Kind() {
			case reflect.Bool:
				b, e := strconv.ParseBool(value)
				if e != nil {
					return errors.New("invalid boolean environment override")
				}
				f.SetBool(b)
			case reflect.Int, reflect.Int64:
				n, e := strconv.ParseInt(value, 10, 64)
				if e != nil {
					return errors.New("invalid integer environment override")
				}
				f.SetInt(n)
			default:
				f.SetString(value)
			}
		}
	}
	return nil
}
func (c Config) Validate(role string) error {
	if role != "client" && c.Pool != 0 {
		return errors.New("pool is client-only")
	}
	if c.Pool < 0 || c.Pool > 32 {
		return errors.New("pool must be from 1 to 32")
	}
	if role == "master" {
		if c.ControlCert == "" || c.ControlKey == "" {
			return errors.New("control TLS certificate and key required")
		}
		bindHost, bindPortStr, e := net.SplitHostPort(c.BindAddr)
		if e != nil {
			return e
		}
		bindPort, _ := strconv.Atoi(bindPortStr)
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
			srvHost := c.EmbeddedServer.TLS.ListenHost
			if srvHost == "" {
				srvHost = "0.0.0.0"
			}
			if srvPort == bindPort && (bindHost == "" || bindHost == "0.0.0.0" || srvHost == "0.0.0.0" || bindHost == srvHost) {
				return errors.New("embedded_server port collides with master bind_addr")
			}
			srvTLS := c.EmbeddedServer.TLS
			if srvTLS.CertFile != "" || srvTLS.Reality.Enabled() || srvTLS.Hysteria2.Enabled() {
				if err := tunnel.CheckBootstrap("server", srvTLS); err != nil {
					return err
				}
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
	if role == "server" || role == "client" {
		if e := tunnel.CheckBootstrap(role, c.TLS); e != nil {
			return e
		}
	}
	return nil

}
