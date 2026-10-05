package store

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"strings"

	"veilink/internal/auth"
	"veilink/internal/model"
	"veilink/internal/tunnel"
)

// RevokeEnrollToken invalidates enrollment reuse, not an active node credential.
func (s *Store) RevokeEnrollToken(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec("DELETE FROM enroll WHERE node=?", id)
	return err
}

// validateTunnel checks structure and native crypto syntax without filesystem
// access or runtime startup. Client validation is for server-owned templates only.
func validateTunnel(role string, local model.LocalTLS) error {
	if role != "server" && role != "client" {
		return ErrInvalid
	}
	// Enrollment may precede data-plane security configuration. A server may
	// already reserve its private bind endpoint without being runnable.
	unconfigured := local
	unconfigured.ListenHost, unconfigured.ListenPort = "", 0
	if unconfigured == (model.LocalTLS{}) {
		return nil
	}
	switch strings.TrimSpace(local.Flow) {
	case "", "none", "xtls-rprx-vision", "xtls-rprx-vision-udp443":
	default:
		return ErrInvalid
	}
	if len(local.CertPEM) > 64<<10 || len(local.KeyPEM) > 64<<10 || len(local.CAPEM) > 64<<10 {
		return ErrInvalid
	}
	if local.CertPEM != "" || local.KeyPEM != "" {
		if _, err := tls.X509KeyPair([]byte(local.CertPEM), []byte(local.KeyPEM)); err != nil {
			return ErrInvalid
		}
	}
	if local.CAPEM != "" {
		if !x509.NewCertPool().AppendCertsFromPEM([]byte(local.CAPEM)) {
			return ErrInvalid
		}
		// CA bundles are distributed to clients: never accept hidden private-key
		// blocks or ignored trailing material alongside a valid certificate.
		remaining := strings.TrimSpace(local.CAPEM)
		for remaining != "" {
			if !strings.HasPrefix(remaining, "-----BEGIN CERTIFICATE-----") {
				return ErrInvalid
			}
			// Decode only the first delimited block: pem.Decode otherwise skips
			// malformed prefixes and can hide private material before a valid CA.
			const begin, end = "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----"
			endAt := strings.Index(remaining, end)
			if endAt < 0 {
				return ErrInvalid
			}
			endAt += len(end)
			first := remaining[:endAt]
			if strings.Contains(first[len(begin):], "-----BEGIN") {
				return ErrInvalid
			}
			block, rest := pem.Decode([]byte(first))
			if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(strings.TrimSpace(string(rest))) != 0 {
				return ErrInvalid
			}
			if _, err := x509.ParseCertificate(block.Bytes); err != nil {
				return ErrInvalid
			}
			remaining = strings.TrimSpace(remaining[endAt:])
		}
	}
	if role == "client" && (local.Decryption != "" || local.KeyPEM != "" || local.CertPEM != "" || local.ListenHost != "" || local.ListenPort != 0 || local.Reality.PrivateKey != "" || local.Reality.Dest != "" || local.Reality.ShortIDs != "") {
		return ErrInvalid
	}
	if role == "server" && local.Encryption != "" && local.Encryption != "none" {
		return ErrInvalid
	}
	if local.ListenHost != "" && net.ParseIP(local.ListenHost) == nil {
		return ErrInvalid
	}
	if local.ListenPort < 0 || local.ListenPort > 65535 {
		return ErrInvalid
	}
	var err error
	if role == "server" {
		if err := tunnel.CheckBootstrap(role, local); err != nil {
			return ErrInvalid
		}
		_, err = tunnel.DeriveClientTunnel(model.LocalTLS{}, local, model.Node{})
	} else {
		err = tunnel.ValidateClientTemplate(local)
	}
	if err != nil {
		return ErrInvalid
	}
	if local.Reality.PrivateKey != "" && model.DeriveX25519Public(local.Reality.PrivateKey) == "" {
		return ErrInvalid
	}
	flow := strings.TrimSpace(local.Flow)
	if local.Hysteria2.Enabled() && (local.Reality.Enabled() || (flow != "" && flow != "none")) {
		return ErrInvalid
	}
	if role == "server" && flow != "" && flow != "none" && !local.Reality.Enabled() && (local.CertPEM == "" || local.KeyPEM == "") {
		return ErrInvalid
	}
	return nil
}

// clientTemplate derives the read-only public settings solely from server.Tunnel.
// Existing objects may roundtrip only when their template is exactly derived.
func clientTemplate(server model.Node) (*model.LocalTLS, error) {
	unconfigured := server.Tunnel
	unconfigured.ListenHost, unconfigured.ListenPort = "", 0
	if unconfigured == (model.LocalTLS{}) {
		if server.ClientTunnel != nil {
			return nil, ErrInvalid
		}
		return nil, nil
	}
	if server.Tunnel.XHTTP.DownloadEndpointID != "" {
		mode := server.Tunnel.XHTTP.Mode
		if mode != "" && mode != "packet-up" && mode != "auto" && mode != "stream-up" {
			return nil, ErrInvalid
		}
		if !validEndpointSelection(server, server.Tunnel.XHTTP.DownloadEndpointID) {
			return nil, ErrInvalid
		}
	}
	if err := validateTunnel("server", server.Tunnel); err != nil {
		return nil, err
	}
	derived, err := tunnel.DeriveClientTunnel(model.LocalTLS{}, server.Tunnel, server)
	if err != nil {
		return nil, ErrInvalid
	}
	if server.Tunnel.Reality.PrivateKey != "" && derived.Reality.PublicKey != model.DeriveX25519Public(server.Tunnel.Reality.PrivateKey) {
		return nil, ErrInvalid
	}
	paired := derived
	if server.ClientTunnel != nil && *server.ClientTunnel != derived {
		return nil, fmt.Errorf("client_tunnel is read-only and must equal the derived configuration: %w", ErrInvalid)
	}
	if err := validateTunnel("client", paired); err != nil {
		return nil, err
	}
	if derived.Reality.Enabled() {
		// Validate the effective server allowlist, including metadata fallback,
		// with the same rules used by the REALITY listener at runtime.
		effective := server.Tunnel
		if strings.TrimSpace(effective.Reality.ServerNames) == "" {
			effective.Reality.ServerNames = server.Address
		}
		if err := tunnel.CheckBootstrap("server", effective); err != nil {
			return nil, ErrInvalid
		}
		ids := server.Tunnel.Reality.ShortIDs
		if server.Tunnel.Reality.ShortID != "" {
			ids += "," + server.Tunnel.Reality.ShortID
		}
		if !listed(paired.Reality.ShortID, ids) {
			return nil, ErrInvalid
		}
		names := server.Tunnel.Reality.ServerNames
		if strings.TrimSpace(names) == "" {
			names = server.Address
		}
		for _, name := range strings.Split(paired.Reality.ServerNames, ",") {
			if !listed(name, names) {
				return nil, ErrInvalid
			}
		}
	}
	return &paired, nil
}

func listed(value, list string) bool {
	for _, item := range strings.Split(list, ",") {
		if strings.EqualFold(strings.TrimSpace(value), strings.TrimSpace(item)) {
			return true
		}
	}
	return false
}

// Snapshots use the stored public template, failing closed on corrupt or unpaired
// data rather than silently deriving a different configuration at delivery time.
func publicTunnel(server model.Node) (model.LocalTLS, error) {
	validated, err := clientTemplate(server)
	if err != nil {
		return model.LocalTLS{}, err
	}
	if validated == nil && server.ClientTunnel == nil {
		return model.LocalTLS{}, nil
	}
	if server.ClientTunnel == nil || validated == nil || *validated != *server.ClientTunnel {
		return model.LocalTLS{}, ErrInvalid
	}
	return *server.ClientTunnel, nil
}

func validPair(st *state, serverID, clientID string) bool {
	server, sok := st.Nodes[serverID]
	client, cok := st.Nodes[clientID]
	return sok && cok && server.Role == "server" && client.Role == "client" && !server.Revoked && !client.Revoked
}

func (s *Store) createBinding(st *state, serverID, clientID, endpointID string) (model.Binding, error) {
	b := model.Binding{ID: auth.Token(), ServerID: serverID, ClientID: clientID, ConnectEndpointID: endpointID}
	b.Domain = "b-" + strings.ToLower(auth.Hash(b.ID)[:24]) + ".veilink.internal"
	u := make([]byte, 16)
	if _, err := rand.Read(u); err != nil {
		return b, err
	}
	u[6] = (u[6] & 15) | 64
	u[8] = (u[8] & 63) | 128
	uuid := fmt.Sprintf("%x-%x-%x-%x-%x", u[:4], u[4:6], u[6:8], u[8:10], u[10:])
	secret, err := auth.Seal(s.key, uuid)
	if err != nil {
		return b, err
	}
	st.Bindings[b.ID], st.Secrets[b.ID] = b, secret
	return b, nil
}

func cleanupBinding(st *state, id string) {
	for _, m := range st.Mappings {
		if m.BindingID == id {
			return
		}
	}
	delete(st.Bindings, id)
	delete(st.Secrets, id)
}
