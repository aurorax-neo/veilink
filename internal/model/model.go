// Package model defines the control-plane snapshot consumed by the tunnel runtime.
package model

import (
	"crypto/ecdh"
	"encoding/base64"
	"strings"
)

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
	Tunnel          LocalTLS `json:"tunnel"`
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
	Pool       int       `json:"pool,omitempty" yaml:"pool,omitempty"`
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

// Merge returns a new LocalTLS taking non-empty values from override over base.
func (base LocalTLS) Merge(override LocalTLS) LocalTLS {
	res := base
	if override.CertFile != "" {
		res.CertFile = override.CertFile
	}
	if override.KeyFile != "" {
		res.KeyFile = override.KeyFile
	}
	if override.CAFile != "" {
		res.CAFile = override.CAFile
	}
	if override.ListenHost != "" {
		res.ListenHost = override.ListenHost
	}
	if override.Flow != "" {
		res.Flow = override.Flow
	}
	if override.Decryption != "" {
		res.Decryption = override.Decryption
	}
	if override.Encryption != "" {
		res.Encryption = override.Encryption
	}
	if override.Pool > 0 {
		res.Pool = override.Pool
	}
	if override.Reality.Dest != "" {
		res.Reality.Dest = override.Reality.Dest
	}
	if override.Reality.PrivateKey != "" {
		res.Reality.PrivateKey = override.Reality.PrivateKey
	}
	if override.Reality.PublicKey != "" {
		res.Reality.PublicKey = override.Reality.PublicKey
	}
	if override.Reality.ShortID != "" {
		res.Reality.ShortID = override.Reality.ShortID
	}
	if override.Reality.ShortIDs != "" {
		res.Reality.ShortIDs = override.Reality.ShortIDs
	}
	if override.Reality.ServerNames != "" {
		res.Reality.ServerNames = override.Reality.ServerNames
	}
	if override.Reality.Fingerprint != "" {
		res.Reality.Fingerprint = override.Reality.Fingerprint
	}
	if override.Reality.MaxTimeDiff != "" {
		res.Reality.MaxTimeDiff = override.Reality.MaxTimeDiff
	}
	if override.Hysteria2.Password != "" {
		res.Hysteria2.Password = override.Hysteria2.Password
	}
	return res
}

// DeriveX25519Public computes the base64 raw URL encoded X25519 public key from a private key.
func DeriveX25519Public(privateKey string) string {
	s := strings.TrimSpace(privateKey)
	if s == "" {
		return ""
	}
	enc := base64.RawURLEncoding
	if strings.ContainsAny(s, "+/=") {
		enc = base64.StdEncoding
	}
	b, err := enc.DecodeString(s)
	if err != nil || len(b) != 32 {
		return ""
	}
	k, err := ecdh.X25519().NewPrivateKey(b)
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(k.PublicKey().Bytes())
}

// DeriveClientTunnel generates client tunnel settings from a server's tunnel settings and node metadata,
// preserving any manual overrides already configured on the client.
func DeriveClientTunnel(clientTunnel LocalTLS, serverTunnel LocalTLS, serverNode Node) LocalTLS {
	res := clientTunnel
	// 1. Flow
	if res.Flow == "" && serverTunnel.Flow != "" {
		res.Flow = serverTunnel.Flow
	}
	// 2. Encryption / Decryption
	if res.Encryption == "" && serverTunnel.Decryption != "" {
		res.Encryption = serverTunnel.Decryption
	}
	// 3. REALITY
	if serverTunnel.Reality.Enabled() {
		pubKey := serverTunnel.Reality.PublicKey
		if pubKey == "" && serverTunnel.Reality.PrivateKey != "" {
			pubKey = DeriveX25519Public(serverTunnel.Reality.PrivateKey)
		}
		if res.Reality.PublicKey == "" {
			res.Reality.PublicKey = pubKey
		}
		if res.Reality.ShortID == "" {
			ids := strings.Split(serverTunnel.Reality.ShortIDs, ",")
			if len(ids) > 0 && strings.TrimSpace(ids[0]) != "" {
				res.Reality.ShortID = strings.TrimSpace(ids[0])
			} else if serverTunnel.Reality.ShortID != "" {
				res.Reality.ShortID = serverTunnel.Reality.ShortID
			}
		}
		if res.Reality.ServerNames == "" {
			names := strings.Split(serverTunnel.Reality.ServerNames, ",")
			if len(names) > 0 && strings.TrimSpace(names[0]) != "" {
				res.Reality.ServerNames = strings.TrimSpace(names[0])
			} else if serverNode.ServerName != "" {
				res.Reality.ServerNames = serverNode.ServerName
			}
		}
		if res.Reality.Fingerprint == "" {
			if serverTunnel.Reality.Fingerprint != "" {
				res.Reality.Fingerprint = serverTunnel.Reality.Fingerprint
			} else {
				res.Reality.Fingerprint = "chrome"
			}
		}
		if res.Reality.MaxTimeDiff == "" && serverTunnel.Reality.MaxTimeDiff != "" {
			res.Reality.MaxTimeDiff = serverTunnel.Reality.MaxTimeDiff
		}
	}
	// 4. Hysteria2
	if serverTunnel.Hysteria2.Enabled() {
		if res.Hysteria2.Password == "" {
			res.Hysteria2.Password = serverTunnel.Hysteria2.Password
		}
	}
	// 5. CAFile
	if res.CAFile == "" && serverTunnel.CAFile != "" {
		res.CAFile = serverTunnel.CAFile
	}
	return res
}
