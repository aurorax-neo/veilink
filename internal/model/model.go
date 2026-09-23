// Package model defines the control-plane snapshot consumed by the tunnel runtime.
package model

import "strings"

// Node contains administrative metadata, never reusable secrets.
type Node struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Role            string `json:"role"`
	Address         string `json:"address"` // server dial hostname or IP
	Port            int    `json:"port"`
	ServerName      string `json:"server_name"`
	Revoked         bool   `json:"revoked"`
	DesiredRevision int64  `json:"desired_revision"`
	AppliedRevision int64  `json:"applied_revision"`
	LastSeen        int64  `json:"last_seen"`
	Error           string `json:"error"`
}

type Binding struct {
	ID       string `json:"id"`
	ServerID string `json:"server_id"`
	ClientID string `json:"client_id"`
	UUID     string `json:"uuid,omitempty"` // secret: snapshots only; redact admin responses
	Domain   string `json:"domain"`
}

type Mapping struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	BindingID  string `json:"binding_id"`
	ListenHost string `json:"listen_host"`
	ListenPort int    `json:"listen_port"`
	TargetHost string `json:"target_host"`
	TargetPort int    `json:"target_port"`
	Network    string `json:"network,omitempty"`
	Enabled    bool   `json:"enabled"`
}

// Snapshot is an authorized per-node view. Nodes includes only related gateways.
type Snapshot struct {
	Revision int64     `json:"revision"`
	Node     Node      `json:"node"`
	Nodes    []Node    `json:"nodes"`
	Bindings []Binding `json:"bindings"`
	Mappings []Mapping `json:"mappings"`
}

// LocalTLS paths are local bootstrap settings, never supplied by the master.
// Flow and VLESS encryption are optional. Empty flow is ordinary VLESS. Empty
// decryption/encryption means "none". Private decryption keys stay on the server.
type LocalTLS struct {
	CertFile   string    `json:"cert_file" yaml:"cert_file"`
	KeyFile    string    `json:"key_file" yaml:"key_file"`
	CAFile     string    `json:"ca_file" yaml:"ca_file"`
	ListenHost string    `json:"listen_host" yaml:"listen_host"`
	Flow       string    `json:"flow" yaml:"flow"`
	Decryption string    `json:"decryption" yaml:"decryption"`
	Encryption string    `json:"encryption" yaml:"encryption"`
	Pool       int       `json:"pool,omitempty" yaml:"-"`
	Reality    Reality   `json:"reality" yaml:"reality"`
	Hysteria2  Hysteria2 `json:"hysteria2" yaml:"hysteria2"`
}

// Reality is optional camouflage for the data plane. Private keys stay on the
// server; the master never distributes them. An empty value keeps certificate TLS.
type Reality struct {
	Dest        string `json:"dest" yaml:"dest"`
	PrivateKey  string `json:"private_key" yaml:"private_key"`
	PublicKey   string `json:"public_key" yaml:"public_key"`
	ShortID     string `json:"short_id" yaml:"short_id"`
	ShortIDs    string `json:"short_ids" yaml:"short_ids"`
	ServerNames string `json:"server_names" yaml:"server_names"`
	Fingerprint string `json:"fingerprint" yaml:"fingerprint"`
	MaxTimeDiff string `json:"max_time_diff" yaml:"max_time_diff"`
}

// Enabled reports whether any REALITY setting is present.
func (r Reality) Enabled() bool {
	return strings.TrimSpace(r.Dest) != "" || strings.TrimSpace(r.PrivateKey) != "" || strings.TrimSpace(r.PublicKey) != "" || strings.TrimSpace(r.ShortID) != "" || strings.TrimSpace(r.ShortIDs) != "" || strings.TrimSpace(r.ServerNames) != ""
}

// Hysteria2 is an optional QUIC transport for the client-to-server data plane.
// It uses the certificate files for QUIC TLS and cannot be combined with REALITY.
type Hysteria2 struct {
	Password string `json:"password" yaml:"password"`
}

// Enabled reports whether a Hysteria2 password is configured.
func (h Hysteria2) Enabled() bool { return strings.TrimSpace(h.Password) != "" }
