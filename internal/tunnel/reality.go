package tunnel

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
	"github.com/xtls/reality"
	"golang.org/x/crypto/hkdf"

	"veilink/internal/model"
)

// CheckBootstrap validates data-plane settings before the runtime starts.
// REALITY replaces the certificate on that hop; control-plane TLS is unchanged.
func CheckBootstrap(role string, local model.LocalTLS) error {
	if err := checkExclusive(role, local); err != nil {
		return err
	}
	if err := checkVLESS(role, local); err != nil {
		return err
	}
	switch role {
	case "server":
		if local.Reality.Enabled() {
			return checkRealityServer(local.Reality, "")
		}
		if !local.Hysteria2.Enabled() && local.TransportSecurity == "plain" {
			return nil
		}
		if local.CertPEM == "" || local.KeyPEM == "" {
			return errors.New("server data TLS certificate and key required")
		}
	case "client":
		if local.Reality.Enabled() {
			return checkRealityClient(local.Reality)
		}
	}
	return nil
}

func checkRealityServer(r model.Reality, fallback string) error {
	if err := checkDest(r.Dest); err != nil {
		return err
	}
	if _, err := decodeKey(r.PrivateKey); err != nil {
		return fmt.Errorf("REALITY private key: %w", err)
	}
	if _, err := parseShortIDs(r.ShortID, r.ShortIDs); err != nil {
		return err
	}
	if _, err := timeDiff(r.MaxTimeDiff); err != nil {
		return err
	}
	if strings.TrimSpace(r.ServerNames) == "" && strings.TrimSpace(fallback) == "" {
		return nil
	}
	_, err := realityNames(r, fallback)
	return err
}

func checkRealityClient(r model.Reality) error {
	if strings.TrimSpace(r.PrivateKey) != "" || strings.TrimSpace(r.Dest) != "" || strings.TrimSpace(r.ShortIDs) != "" {
		return errors.New("client REALITY accepts public_key, short_id and fingerprint only")
	}
	if _, err := decodeKey(r.PublicKey); err != nil {
		return fmt.Errorf("REALITY public key: %w", err)
	}
	if _, err := parseShortIDs(r.ShortID, ""); err != nil {
		return err
	}
	_, err := fingerprint(r.Fingerprint)
	return err
}

func (s *service) prepareReality() error {
	if s.snapshot.Node.Role != "server" || !s.local.Reality.Enabled() {
		return nil
	}
	cfg, err := newRealityConfig(s.local.Reality, s.snapshot.Node.Address)
	if err != nil {
		return err
	}
	s.reality = cfg
	return nil
}

func (s *service) acceptOne(conn net.Conn) {
	raw := conn
	defer s.untrack(raw)
	_ = raw.SetDeadline(time.Now().Add(15 * time.Second))
	gate := &recordBoundaryConn{Conn: raw, ordinary: s.local.Flow != flowVision && s.reality == nil}
	if s.reality != nil {
		wrapped, err := reality.Server(s.ctx, gate, s.reality)
		if err != nil {
			raw.Close()
			return
		}
		conn = ownTLS(wrapped, gate)
	} else if s.tlsConfig != nil {
		wrapped := tls.Server(gate, s.tlsConfig)
		if err := wrapped.HandshakeContext(s.ctx); err != nil {
			raw.Close()
			return
		}
		conn = ownTLS(wrapped, gate)
	}
	if conn != raw {
		if !s.track(conn) {
			conn.Close()
			return
		}
		s.untrack(raw)
	}
	s.authenticate(conn)
}

func enabledEndpoints(gateway model.Node) []model.ConnectEndpoint {
	endpoints := append([]model.ConnectEndpoint(nil), gateway.ConnectEndpoints...)
	if len(endpoints) == 0 && gateway.Address != "" && gateway.Port > 0 {
		endpoints = []model.ConnectEndpoint{{ID: "primary", Name: "primary", Host: gateway.Address, Port: gateway.Port, Enabled: true}}
	}
	out := endpoints[:0]
	for _, ep := range endpoints {
		if ep.Enabled && hostOK(ep.Host) && portOK(ep.Port) {
			out = append(out, ep)
		}
	}
	return out
}

// bindingGateway restricts every protocol/session dial to the chosen candidate.
// Never turn a stale or disabled explicit selection into automatic failover.
func bindingGateway(gateway model.Node, b model.Binding) (model.Node, error) {
	if gateway.ID != b.ServerID {
		return model.Node{}, errors.New("binding references a foreign gateway")
	}
	if b.ConnectEndpointID == "" {
		return gateway, nil
	}
	endpoints := gateway.ConnectEndpoints
	if len(endpoints) == 0 {
		endpoints = enabledEndpoints(gateway)
	}
	var selected model.ConnectEndpoint
	matches := 0
	for _, ep := range endpoints {
		if ep.ID == b.ConnectEndpointID {
			selected = ep
			matches++
		}
	}
	if matches != 1 || !selected.Enabled || !hostOK(selected.Host) || !portOK(selected.Port) {
		return model.Node{}, errors.New("binding connect endpoint is missing, disabled or invalid")
	}
	gateway.ConnectEndpoints = []model.ConnectEndpoint{selected}
	return gateway, nil
}

func (s *service) dialGateway(gateway model.Node, peer *clientGateway) (net.Conn, error) {
	local := peer.local
	if err := checkVLESS("client", local); err != nil {
		return nil, err
	}
	var last error
	for _, endpoint := range enabledEndpoints(gateway) {
		addr := net.JoinHostPort(endpoint.Host, strconv.Itoa(endpoint.Port))
		serverName := endpoint.Host
		if local.XHTTP.Enabled() {
			dial := func(ctx context.Context) (net.Conn, error) {
				return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", addr)
			}
			if local.Reality.Enabled() {
				dial = func(ctx context.Context) (net.Conn, error) { return dialReality(ctx, addr, serverName, local.Reality) }
			}
			if conn, err := dialXHTTPWithDialer(s.ctx, addr, serverName, local, dial); err == nil {
				return conn, nil
			} else {
				last = err
			}
			continue
		}
		if local.EffectiveProtocol() == "hysteria2" {
			return nil, errors.New("Hysteria2 requires an authorized protocol session")
		}
		if local.Reality.Enabled() {
			if conn, err := dialReality(s.ctx, addr, serverName, local.Reality); err == nil {
				return conn, nil
			} else {
				last = err
			}
			continue
		}
		if local.TransportSecurity == "plain" {
			if conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(s.ctx, "tcp", addr); err == nil {
				return conn, nil
			} else {
				last = err
			}
			continue
		}
		min := uint16(tls.VersionTLS12)
		if peer.flow != "" {
			min = tls.VersionTLS13
		}
		pool, err := roots(local.CAPEM)
		if err != nil {
			return nil, err
		}
		raw, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(s.ctx, "tcp", addr)
		if err != nil {
			last = err
			continue
		}
		gate := &recordBoundaryConn{Conn: raw, ordinary: peer.flow != flowVision}
		conn := tls.Client(gate, &tls.Config{MinVersion: min, ServerName: serverName, RootCAs: pool, SessionTicketsDisabled: true})
		ctx, cancel := context.WithTimeout(s.ctx, 15*time.Second)
		err = conn.HandshakeContext(ctx)
		cancel()
		if err != nil {
			raw.Close()
			last = err
			continue
		}
		return ownTLS(conn, gate), nil
	}
	if last == nil {
		last = errors.New("gateway has no enabled connect endpoint")
	}
	return nil, last
}

func newRealityConfig(r model.Reality, fallback string) (*reality.Config, error) {
	if err := checkRealityServer(r, fallback); err != nil {
		return nil, err
	}
	names, err := realityNames(r, fallback)
	if err != nil {
		return nil, err
	}
	priv, err := decodeKey(r.PrivateKey)
	if err != nil {
		return nil, err
	}
	ids, err := parseShortIDs(r.ShortID, r.ShortIDs)
	if err != nil {
		return nil, err
	}
	diff, err := timeDiff(r.MaxTimeDiff)
	if err != nil {
		return nil, err
	}
	cfg := &reality.Config{
		DialContext:            (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		Type:                   "tcp",
		Dest:                   strings.TrimSpace(r.Dest),
		PrivateKey:             priv,
		ServerNames:            map[string]bool{},
		ShortIds:               map[[8]byte]bool{},
		MaxTimeDiff:            diff,
		SessionTicketsDisabled: true,
	}
	for _, name := range names {
		cfg.ServerNames[name] = true
	}
	for _, id := range ids {
		cfg.ShortIds[id] = true
	}
	reality.DetectPostHandshakeRecordsLens(cfg)
	return cfg, nil
}

func dialReality(ctx context.Context, addr, serverName string, r model.Reality) (net.Conn, error) {
	if err := checkRealityClient(r); err != nil {
		return nil, err
	}
	// The authoritative public template may select a cover name unrelated to
	// gateway metadata. Use that same name when building the authenticated hello.
	names, err := realityNames(r, serverName)
	if err != nil {
		return nil, err
	}
	serverName = names[0]
	pub, err := decodeKey(r.PublicKey)
	if err != nil {
		return nil, err
	}
	ids, err := parseShortIDs(r.ShortID, "")
	if err != nil {
		return nil, err
	}
	helloID, err := fingerprint(r.Fingerprint)
	if err != nil {
		return nil, err
	}
	raw, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	gate := &recordBoundaryConn{Conn: raw}
	verified := false
	var authKey []byte
	uconn := utls.UClient(gate, &utls.Config{
		ServerName:             serverName,
		InsecureSkipVerify:     true,
		SessionTicketsDisabled: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if !realityCertificate(authKey, rawCerts) {
				return errors.New("REALITY certificate authentication failed")
			}
			verified = true
			return nil
		},
	}, helloID)
	if err = uconn.BuildHandshakeState(); err != nil {
		_ = raw.Close()
		return nil, err
	}
	hello := uconn.HandshakeState.Hello
	keys := uconn.HandshakeState.State13.KeyShareKeys
	var ecdhe *ecdh.PrivateKey
	if keys != nil {
		ecdhe = keys.Ecdhe
		if ecdhe == nil {
			ecdhe = keys.MlkemEcdhe
		}
	}
	if hello == nil || ecdhe == nil || len(hello.Raw) < 71 || hello.Raw[38] != 32 || len(hello.Random) < 32 {
		_ = raw.Close()
		return nil, errors.New("REALITY fingerprint has no compatible key share or session id")
	}
	authKey, err = realityAuthKey(ecdhe, pub, hello.Random[:20])
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	if err = sealSessionID(authKey, hello, ids[0]); err != nil {
		_ = raw.Close()
		return nil, err
	}
	if err = uconn.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, err
	}
	if !verified {
		_ = uconn.Close()
		return nil, errors.New("REALITY certificate was not authenticated")
	}
	return ownTLS(uconn, gate), nil
}

func realityAuthKey(local *ecdh.PrivateKey, peer, salt []byte) ([]byte, error) {
	pub, err := ecdh.X25519().NewPublicKey(peer)
	if err != nil {
		return nil, err
	}
	shared, err := local.ECDH(pub)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 32)
	if _, err = hkdf.New(sha256.New, shared, salt, []byte("REALITY")).Read(out); err != nil {
		return nil, err
	}
	return out, nil
}

func sealSessionID(authKey []byte, hello *utls.PubClientHelloMsg, shortID [8]byte) error {
	block, err := aes.NewCipher(authKey)
	if err != nil {
		return err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	// HandshakeContext remarshals from SessionId. The server opens the seal with
	// the wire ClientHello after clearing that field, so the ciphertext has to be
	// in SessionId and the AAD must be this raw hello with those bytes zeroed.
	hello.SessionId = make([]byte, 32)
	copy(hello.Raw[39:], hello.SessionId)
	binary.BigEndian.PutUint32(hello.SessionId[4:], uint32(time.Now().Unix()))
	copy(hello.SessionId[8:], shortID[:])
	sealed := aead.Seal(hello.SessionId[:0], hello.Random[20:], hello.SessionId[:16], hello.Raw)
	if len(sealed) != 32 {
		return errors.New("REALITY session seal has unexpected length")
	}
	hello.SessionId = sealed
	copy(hello.Raw[39:], hello.SessionId)
	return nil
}

func realityCertificate(authKey []byte, rawCerts [][]byte) bool {
	if len(authKey) == 0 || len(rawCerts) == 0 {
		return false
	}
	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return false
	}
	pub, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return false
	}
	mac := hmac.New(sha512.New, authKey)
	_, _ = mac.Write(pub)
	return hmac.Equal(mac.Sum(nil), cert.Signature)
}

func decodeKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("missing X25519 key")
	}
	enc := base64.RawURLEncoding
	if strings.ContainsAny(s, "+/=") {
		enc = base64.StdEncoding
	}
	b, err := enc.DecodeString(s)
	if err != nil || len(b) != 32 {
		return nil, errors.New("X25519 key must be 32 bytes in base64")
	}
	return b, nil
}

func parseShortIDs(single, list string) ([][8]byte, error) {
	var parts []string
	if strings.TrimSpace(list) != "" {
		parts = append(parts, strings.Split(list, ",")...)
	}
	if strings.TrimSpace(single) != "" {
		parts = append(parts, single)
	}
	if len(parts) == 0 {
		return nil, errors.New("REALITY short id required")
	}
	var out [][8]byte
	seen := map[[8]byte]bool{}
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if len(p) > 16 || len(p)%2 != 0 {
			return nil, fmt.Errorf("REALITY short id %q must be 0 to 16 hex characters", p)
		}
		raw, err := hex.DecodeString(p)
		if err != nil {
			return nil, fmt.Errorf("REALITY short id %q must be hex", p)
		}
		var id [8]byte
		copy(id[:], raw)
		if seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out, nil
}

func realityNames(r model.Reality, fallback string) ([]string, error) {
	var parts []string
	if strings.TrimSpace(r.ServerNames) != "" {
		parts = strings.Split(r.ServerNames, ",")
	} else if strings.TrimSpace(fallback) != "" {
		parts = []string{fallback}
	}
	var out []string
	seen := map[string]bool{}
	for _, p := range parts {
		p = strings.ToLower(strings.TrimSpace(p))
		if !hostOK(p) || net.ParseIP(p) != nil || !strings.Contains(p, ".") {
			return nil, fmt.Errorf("REALITY server name %q is invalid", p)
		}
		if seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	if len(out) == 0 {
		return nil, errors.New("REALITY server name required")
	}
	return out, nil
}

func checkDest(dest string) error {
	host, port, err := net.SplitHostPort(strings.TrimSpace(dest))
	if err != nil || host == "" {
		return errors.New("REALITY dest must be host:port")
	}
	n, err := net.LookupPort("tcp", port)
	if err != nil || !portOK(n) {
		return errors.New("REALITY dest must be host:port")
	}
	return nil
}

func timeDiff(s string) (time.Duration, error) {
	if strings.TrimSpace(s) == "" {
		return time.Minute, nil
	}
	d, err := time.ParseDuration(strings.TrimSpace(s))
	if err != nil || d < 0 {
		return 0, errors.New("REALITY max_time_diff must be a non-negative duration")
	}
	return d, nil
}

func fingerprint(name string) (utls.ClientHelloID, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "chrome":
		return utls.HelloChrome_Auto, nil
	case "firefox":
		return utls.HelloFirefox_Auto, nil
	case "safari":
		return utls.HelloSafari_Auto, nil
	case "ios":
		return utls.HelloIOS_Auto, nil
	case "edge":
		return utls.HelloEdge_Auto, nil
	default:
		return utls.ClientHelloID{}, fmt.Errorf("unsupported REALITY fingerprint %q", name)
	}
}

// GenerateX25519 returns a REALITY private/public key pair, base64 raw URL encoded.
func GenerateX25519() (string, string, error) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return base64.RawURLEncoding.EncodeToString(key.Bytes()), base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), nil
}
