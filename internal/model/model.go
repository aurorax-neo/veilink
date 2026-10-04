// Package model defines the control-plane snapshot consumed by the tunnel runtime.
package model

import (
	"bytes"
	"crypto/ecdh"
	"crypto/mlkem"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
)

// ConnectEndpoint is a public Client dial candidate for a Server. Host and Port
// are the Client dial address, independent of the Server's local listen address.
// Host is also the certificate verification name; candidates retain list order.
type ConnectEndpoint struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Enabled bool   `json:"enabled"`
}

// Node contains master-managed metadata and role-scoped tunnel configuration.
type Node struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	Role             string            `json:"role"`
	Address          string            `json:"address"` // compatibility/default connect endpoint
	Port             int               `json:"port"`
	ConnectEndpoints []ConnectEndpoint `json:"connect_endpoints,omitempty"`
	Revoked          bool              `json:"revoked"`
	Disabled         bool              `json:"disabled,omitempty"` // administrative stop; absent means enabled
	DesiredRevision  int64             `json:"desired_revision"`
	AppliedRevision  int64             `json:"applied_revision"`
	LastSeen         int64             `json:"last_seen"`
	Error            string            `json:"error"`
	Tunnel           LocalTLS          `json:"tunnel"`
	// ClientTunnel is the persisted, public client template owned by a server.
	ClientTunnel *LocalTLS `json:"client_tunnel,omitempty"`
	Embedded     bool      `json:"embedded"` // master-owned registration metadata
}

// UnmarshalJSON rejects obsolete/unknown fields even in cached and gRPC snapshots.
func (n *Node) UnmarshalJSON(data []byte) error {
	type wire Node
	var value wire
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&value); err != nil {
		return err
	}
	*n = Node(value)
	return nil
}

func (e *ConnectEndpoint) UnmarshalJSON(data []byte) error {
	type wire ConnectEndpoint
	var value wire
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&value); err != nil {
		return err
	}
	*e = ConnectEndpoint(value)
	return nil
}

type Binding struct {
	ID                string `json:"id"`
	ServerID          string `json:"server_id"`
	ClientID          string `json:"client_id"`
	ConnectEndpointID string `json:"connect_endpoint_id,omitempty"`
	UUID              string `json:"uuid,omitempty"` // secret: snapshots only; redact admin responses
	Domain            string `json:"domain"`
}

type Mapping struct {
	ID                string `json:"id"`
	Name              string `json:"name"`
	BindingID         string `json:"binding_id,omitempty"`
	ServerID          string `json:"server_id"`
	ClientID          string `json:"client_id"`
	ConnectEndpointID string `json:"connect_endpoint_id,omitempty"`
	ListenHost        string `json:"listen_host"`
	ListenPort        int    `json:"listen_port"`
	TargetHost        string `json:"target_host"`
	TargetPort        int    `json:"target_port"`
	Network           string `json:"network,omitempty"`
	Pool              int    `json:"pool"`               // 1..32: shared sessions per binding (maximum of enabled mappings)
	Mux               bool   `json:"mux"`                // TCP stream multiplexing; disabled by default
	MuxType           string `json:"mux_type,omitempty"` // extensible implementation selector; ignored when mux is off
	Enabled           bool   `json:"enabled"`
}

// Snapshot is an authorized per-node view. Nodes includes only related gateways.
type Snapshot struct {
	Revision int64     `json:"revision"`
	Node     Node      `json:"node"`
	Nodes    []Node    `json:"nodes"`
	Bindings []Binding `json:"bindings"`
	Mappings []Mapping `json:"mappings"`
}

// LocalTLS contains Web-managed data-plane settings distributed in authorized snapshots.
// Server Tunnel holds private settings; its ClientTunnel holds the paired public
// settings. Client nodes have an empty Tunnel and consume their related servers.
type LocalTLS struct {
	Protocol          string    `json:"protocol,omitempty"`           // vless or hysteria2
	TransportSecurity string    `json:"transport_security,omitempty"` // tls or plain; empty clients inherit
	CertPEM           string    `json:"cert_pem"`
	KeyPEM            string    `json:"key_pem"`
	CAPEM             string    `json:"ca_pem"`
	ListenHost        string    `json:"listen_host"`
	ListenPort        int       `json:"listen_port"`
	Flow              string    `json:"flow"`
	Decryption        string    `json:"decryption"`
	Encryption        string    `json:"encryption"`
	Reality           Reality   `json:"reality"`
	Hysteria2         Hysteria2 `json:"hysteria2"`
	XHTTP             XHTTP     `json:"xhttp,omitempty"`
}

// XHTTP configures Veilink's native HTTP transport. TLS selects HTTPS at the
// Client dial candidate; TransportSecurity independently selects the origin listener.
// Unsupported reference settings are not accepted as no-op configuration.
type XHTTPXmux struct {
	MaxConcurrency   int `json:"max_concurrency,omitempty"`
	MaxConnections   int `json:"max_connections,omitempty"`
	CMaxReuseTimes   int `json:"c_max_reuse_times,omitempty"`
	HMaxRequestTimes int `json:"h_max_request_times,omitempty"`
	HMaxReusableSecs int `json:"h_max_reusable_secs,omitempty"`
	KeepAlivePeriod  int `json:"keep_alive_period,omitempty"`
}

type XHTTP struct {
	Xmux                  XHTTPXmux    `json:"xmux,omitempty"`
	Host                  string       `json:"host,omitempty"`    // HTTP Host only; TLS identity stays at the dial endpoint
	Headers               XHTTPHeaders `json:"headers,omitempty"` // canonical bounded safe header object
	Path                  string       `json:"path"`
	Mode                  string       `json:"mode"`
	TLS                   bool         `json:"tls"`
	HTTPVersion           string       `json:"http_version,omitempty"`            // empty = existing HTTP negotiation; 3 = QUIC/HTTP3
	MaxEachPostBytes      int          `json:"max_each_post_bytes,omitempty"`     // 0 = 32 KiB
	PostBytesMax          int          `json:"post_bytes_max,omitempty"`          // 0 = fixed at MaxEachPostBytes
	RequestTimeoutSeconds int          `json:"request_timeout_seconds,omitempty"` // 0 = 15 s
	PaddingBytes          int          `json:"padding_bytes,omitempty"`           // 0 = 100; minimum or fixed length
	PaddingMaxBytes       int          `json:"padding_max_bytes,omitempty"`       // 0 = fixed at PaddingBytes
	PaddingObfsMode       bool         `json:"padding_obfs_mode,omitempty"`
	PaddingPlacement      string       `json:"padding_placement,omitempty"`
	PaddingKey            string       `json:"padding_key,omitempty"`
	PaddingHeader         string       `json:"padding_header,omitempty"`
	PaddingMethod         string       `json:"padding_method,omitempty"`
	NoGRPCHeader          bool         `json:"no_grpc_header,omitempty"`            // streaming POST without application/grpc
	NoSSEHeader           bool         `json:"no_sse_header,omitempty"`             // download without text/event-stream
	ServerMaxHeaderBytes  int          `json:"server_max_header_bytes,omitempty"`   // 0 = 8 KiB; bounded to 8-32 KiB
	UplinkHTTPMethod      string       `json:"uplink_http_method,omitempty"`        // empty = POST; PUT also permitted
	MinPostsIntervalMs    int          `json:"min_posts_interval_ms,omitempty"`     // 0 = no pacing; packet-up only
	MaxPostsIntervalMs    int          `json:"max_posts_interval_ms,omitempty"`     // 0 = fixed at min; packet-up only
	MaxBufferedPosts      int          `json:"max_buffered_posts,omitempty"`        // 0 = legacy ordered backpressure; 1-32 buffered posts
	MaxConcurrentPosts    int          `json:"max_concurrent_posts,omitempty"`      // 0 = one request; 1-8, bounded by buffering
	StreamUpServerSecs    int          `json:"stream_up_server_secs,omitempty"`     // 0 = random 20-80 s; stream-up response padding
	StreamUpServerMaxSecs int          `json:"stream_up_server_max_secs,omitempty"` // 0 = fixed at explicit minimum
	DownloadEndpointID    string       `json:"download_endpoint_id,omitempty"`      // authorized Server endpoint for packet-up downlink
	UplinkDataPlacement   string       `json:"uplink_data_placement,omitempty"`     // body (default), header or cookie
	UplinkDataKey         string       `json:"uplink_data_key,omitempty"`           // private header/cookie base name
	UplinkChunkSize       int          `json:"uplink_chunk_size,omitempty"`         // encoded block size, 64-8192
	SessionIDPlacement    string       `json:"session_id_placement,omitempty"`
	SessionIDKey          string       `json:"session_id_key,omitempty"`
	SeqPlacement          string       `json:"seq_placement,omitempty"`
	SeqKey                string       `json:"seq_key,omitempty"`
	SessionIDTable        string       `json:"session_id_table,omitempty"`
	SessionIDLength       int          `json:"session_id_length,omitempty"`
}

func (x XHTTP) Enabled() bool {
	if x.MaxBufferedPosts != 0 || x.MaxConcurrentPosts != 0 || x.StreamUpServerSecs != 0 || x.StreamUpServerMaxSecs != 0 || x.DownloadEndpointID != "" || x.UplinkDataPlacement != "" || x.UplinkDataKey != "" || x.UplinkChunkSize != 0 || x.Xmux != (XHTTPXmux{}) {
		return true
	}
	return x.Path != "" || x.Host != "" || x.Headers != "" || x.Mode != "" || x.TLS || x.HTTPVersion != "" || x.MaxEachPostBytes != 0 || x.PostBytesMax != 0 || x.RequestTimeoutSeconds != 0 || x.PaddingBytes != 0 || x.PaddingMaxBytes != 0 || x.PaddingObfsMode || x.PaddingPlacement != "" || x.PaddingKey != "" || x.PaddingHeader != "" || x.PaddingMethod != "" || x.NoGRPCHeader || x.NoSSEHeader || x.ServerMaxHeaderBytes != 0 || x.UplinkHTTPMethod != "" || x.MinPostsIntervalMs != 0 || x.MaxPostsIntervalMs != 0 || x.SessionIDPlacement != "" || x.SessionIDKey != "" || x.SeqPlacement != "" || x.SeqKey != "" || x.SessionIDTable != "" || x.SessionIDLength != 0 || x.DownloadEndpointID != "" || x.UplinkDataPlacement != "" || x.UplinkDataKey != "" || x.UplinkChunkSize != 0 || x.Xmux != (XHTTPXmux{})
}

// Reality is optional camouflage for the data plane. Private keys stay on the
// server; the master never distributes them. An empty value keeps certificate TLS.
type Reality struct {
	Dest        string `json:"dest"`
	PrivateKey  string `json:"private_key"`
	PublicKey   string `json:"public_key"`
	ShortID     string `json:"short_id"`
	ShortIDs    string `json:"short_ids"`
	ServerNames string `json:"server_names"`
	Fingerprint string `json:"fingerprint"`
	MaxTimeDiff string `json:"max_time_diff"`
	SpiderX     string `json:"spider_x,omitempty"`
	SpiderY     string `json:"spider_y,omitempty"`
	// ML-DSA-65 后量子证书额外验证公钥（base64，可选，对齐 Xray-core）
	Mldsa65Verify string `json:"mldsa65_verify,omitempty"`
}

// Enabled reports whether any REALITY setting is present.
func (r Reality) Enabled() bool {
	return strings.TrimSpace(r.Dest) != "" || strings.TrimSpace(r.PrivateKey) != "" || strings.TrimSpace(r.PublicKey) != "" || strings.TrimSpace(r.ShortID) != "" || strings.TrimSpace(r.ShortIDs) != "" || strings.TrimSpace(r.ServerNames) != ""
}

// Hysteria2 configures the QUIC/TLS sibling protocol, not a VLESS transport.
// Password currently enables and validates the HY2 configuration, not enrollment.
// Each authorized Binding UUID is the standard Hysteria-Auth password.
type Hysteria2 struct {
	Password string `json:"password"`
}

// Enabled reports whether a Hysteria2 password is configured.
func (h Hysteria2) Enabled() bool { return strings.TrimSpace(h.Password) != "" }

// EffectiveProtocol preserves empty-field JSON defaults. Explicit values are
// validated by the tunnel boundary, never inferred from other fields.
func (c LocalTLS) EffectiveProtocol() string {
	if c.Protocol != "" {
		return c.Protocol
	}
	if c.Hysteria2.Enabled() {
		return "hysteria2"
	}
	return "vless"
}

// Merge returns a new LocalTLS taking non-empty values from override over base.
func (base LocalTLS) Merge(override LocalTLS) LocalTLS {
	res := base
	if override.Protocol != "" {
		res.Protocol = override.Protocol
	}
	if override.TransportSecurity != "" {
		res.TransportSecurity = override.TransportSecurity
	}
	if override.CertPEM != "" {
		res.CertPEM = override.CertPEM
	}
	if override.KeyPEM != "" {
		res.KeyPEM = override.KeyPEM
	}
	if override.CAPEM != "" {
		res.CAPEM = override.CAPEM
	}
	if override.ListenHost != "" {
		res.ListenHost = override.ListenHost
	}
	if override.ListenPort != 0 {
		res.ListenPort = override.ListenPort
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
	if override.XHTTP.Enabled() {
		res.XHTTP = override.XHTTP
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

// DeriveClientTunnel generates public settings solely from the authoritative
// server configuration. Template customization and validation are separate.
func DeriveClientTunnel(serverTunnel LocalTLS, serverNode Node) LocalTLS {
	res := LocalTLS{
		Protocol:          serverTunnel.Protocol,
		TransportSecurity: serverTunnel.TransportSecurity,
		Flow:              serverTunnel.Flow,
		CAPEM:             serverTunnel.CAPEM,
		Hysteria2:         serverTunnel.Hysteria2,
		XHTTP:             serverTunnel.XHTTP,
		Encryption:        serverTunnel.Encryption,
	}
	if serverTunnel.Decryption != "" {
		res.Encryption = DeriveVLESSEncryption(serverTunnel.Decryption)
	}
	if r := serverTunnel.Reality; r.Enabled() {
		res.Reality.PublicKey = r.PublicKey
		if r.PublicKey == "" && r.PrivateKey != "" {
			res.Reality.PublicKey = DeriveX25519Public(r.PrivateKey)
		}
		res.Reality.ShortID = strings.TrimSpace(strings.Split(r.ShortIDs, ",")[0])
		if res.Reality.ShortID == "" {
			res.Reality.ShortID = r.ShortID
		}
		res.Reality.ServerNames = strings.TrimSpace(strings.Split(r.ServerNames, ",")[0])
		if res.Reality.ServerNames == "" {
			res.Reality.ServerNames = serverNode.Address
		}
		res.Reality.Fingerprint = r.Fingerprint
		if res.Reality.Fingerprint == "" {
			res.Reality.Fingerprint = "chrome"
		}
		res.Reality.MaxTimeDiff = r.MaxTimeDiff
	}
	// Trust is explicit: never promote the server's leaf certificate to a CA.
	return res
}

// DeriveVLESSEncryption converts server key material to client public keys without
// importing the tunnel runtime. Invalid keys or lifetimes produce no configuration.
// Callers requiring full protocol/padding validation should use the error-returning
// tunnel.DeriveClientTunnel helper. Ticket lifetimes become 0rtt or 1rtt.
func DeriveVLESSEncryption(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "none" {
		return raw
	}
	parts := strings.Split(raw, ".")
	if len(parts) < 4 || parts[0] != "mlkem768x25519plus" {
		return ""
	}
	switch parts[1] {
	case "native", "xorpub", "random":
	default:
		return ""
	}
	// Protocol validation is performed by the native tunnel parser. Only public
	// keys are ever emitted here, including for chained X25519/ML-KEM keys.
	span := strings.SplitN(strings.TrimSuffix(parts[2], "s"), "-", 2)
	from, err := strconv.ParseInt(span[0], 10, 64)
	if err != nil || from < 0 {
		return ""
	}
	to := from
	if len(span) == 2 {
		to, err = strconv.ParseInt(span[1], 10, 64)
		if err != nil || to < from {
			return ""
		}
	}
	parts[2] = "0rtt"
	if from == 0 && to == 0 {
		parts[2] = "1rtt"
	}
	keys := 0
	for i := 3; i < len(parts); i++ {
		if len(parts[i]) < 20 && keys == 0 {
			continue // optional padding parameters, before the keys only
		}
		rawKey, err := base64.RawURLEncoding.DecodeString(parts[i])
		if err != nil {
			return ""
		}
		var public []byte
		switch len(rawKey) {
		case 32:
			key, err := ecdh.X25519().NewPrivateKey(rawKey)
			if err != nil {
				return ""
			}
			public = key.PublicKey().Bytes()
		case 64:
			key, err := mlkem.NewDecapsulationKey768(rawKey)
			if err != nil {
				return ""
			}
			public = key.EncapsulationKey().Bytes()
		default:
			return ""
		}
		parts[i] = base64.RawURLEncoding.EncodeToString(public)
		keys++
	}
	if keys == 0 {
		return ""
	}
	return strings.Join(parts, ".")
}

// PublicPeerTunnel exposes only public client-facing settings. It excludes local
// certificate PEM, private keys, server-only fields, and the shared Hysteria2 password.
// Authorized Hysteria2 snapshots must supply that credential separately; this
// public view alone cannot describe or authenticate a Hysteria2 connection.
func PublicPeerTunnel(serverTunnel LocalTLS, serverNode Node) LocalTLS {
	peer := DeriveClientTunnel(serverTunnel, serverNode)
	peer.CertPEM, peer.KeyPEM = "", ""
	peer.Hysteria2 = Hysteria2{}
	return peer
}
