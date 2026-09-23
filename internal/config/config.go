package config

import (
	"errors"
	"gopkg.in/yaml.v3"
	"io"
	"net"
	"os"
	"reflect"
	"strconv"
	"strings"
	"veilink/internal/model"
)

type Config struct {
	Database             string         `yaml:"database"`
	DeploymentKey        string         `yaml:"deployment_key"`
	HTTPAddr             string         `yaml:"http_addr"`
	HTTPCert             string         `yaml:"http_cert"`
	HTTPKey              string         `yaml:"http_key"`
	InsecureLoopbackHTTP bool           `yaml:"insecure_loopback_http"`
	TrustedProxy         bool           `yaml:"trusted_proxy"`
	ControlAddr          string         `yaml:"control_addr"`
	ControlCert          string         `yaml:"control_cert"`
	ControlKey           string         `yaml:"control_key"`
	ControlCA            string         `yaml:"control_ca"`
	ControlServerName    string         `yaml:"control_server_name"`
	MasterAddr           string         `yaml:"master_addr"`
	NodeID               string         `yaml:"node_id"`
	EnrollToken          string         `yaml:"enroll_token"`
	StateDir             string         `yaml:"state_dir"`
	TLS                  model.LocalTLS `yaml:"tls"`
}

func Load(path string) (Config, error) {
	c := Config{Database: "veilink.db", DeploymentKey: "veilink.key", HTTPAddr: "127.0.0.1:8080", ControlAddr: "127.0.0.1:8443", StateDir: "state"}
	f, e := os.Open(path)
	if e != nil {
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
			if f.Kind() == reflect.Bool {
				b, e := strconv.ParseBool(value)
				if e != nil {
					return errors.New("invalid boolean environment override")
				}
				f.SetBool(b)
			} else {
				f.SetString(value)
			}
		}
	}
	return nil
}
func (c Config) Validate(role string) error {
	if role == "master" {
		if c.ControlCert == "" || c.ControlKey == "" {
			return errors.New("control TLS certificate and key required")
		}
		if (c.HTTPCert == "") != (c.HTTPKey == "") {
			return errors.New("HTTP certificate and key must be paired")
		}
		h, _, e := net.SplitHostPort(c.HTTPAddr)
		if e != nil {
			return e
		}
		loop := net.ParseIP(h) != nil && net.ParseIP(h).IsLoopback()
		if c.InsecureLoopbackHTTP && !loop {
			return errors.New("insecure HTTP only permits literal loopback addresses")
		}
		if c.HTTPCert == "" && !c.TrustedProxy && !(loop && c.InsecureLoopbackHTTP) {
			return errors.New("HTTP requires TLS, trusted proxy or explicit loopback development mode")
		}
		return nil
	}
	if role != "server" && role != "client" {
		return errors.New("invalid role")
	}
	if c.MasterAddr == "" || c.NodeID == "" || c.StateDir == "" {
		return errors.New("master_addr, node_id and state_dir required")
	}
	if role == "server" && (c.TLS.CertFile == "" || c.TLS.KeyFile == "") {
		return errors.New("server data TLS certificate and key required")
	}
	return nil
}
