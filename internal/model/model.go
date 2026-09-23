// Package model defines the control-plane snapshot consumed by the tunnel runtime.
package model

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
type LocalTLS struct {
	CertFile   string `json:"cert_file" yaml:"cert_file"`
	KeyFile    string `json:"key_file" yaml:"key_file"`
	CAFile     string `json:"ca_file" yaml:"ca_file"`
	ListenHost string `json:"listen_host" yaml:"listen_host"`
}
