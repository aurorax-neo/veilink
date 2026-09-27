package tunnel

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"lukechampine.com/blake3"

	"veilink/internal/model"
)

const (
	flowVision       = "xtls-rprx-vision"
	vlessScheme      = "mlkem768x25519plus"
	vlessPlain       = "none"
	visionChunkLimit = 8192 - 21
)

var maxNonce = bytes.Repeat([]byte{255}, 12)

func normalizeFlow(raw string) (string, error) {
	switch strings.TrimSpace(raw) {
	case "", vlessPlain:
		return "", nil
	case flowVision, flowVision + "-udp443":
		return flowVision, nil
	default:
		return "", fmt.Errorf("unsupported VLESS flow %q", strings.TrimSpace(raw))
	}
}

func decryptionEnabled(raw string) bool {
	text := strings.TrimSpace(raw)
	return text != "" && text != vlessPlain
}

func checkVLESS(role string, local model.LocalTLS) error {
	if err := checkTransportSecurity(local); err != nil {
		return err
	}
	if role == "server" {
		if err := requireTransportSecurity(local); err != nil {
			return err
		}
	}
	if local.TransportSecurity == "plain" {
		if role == "server" && (local.CertPEM != "" || local.KeyPEM != "") {
			return errors.New("plain transport_security cannot use server TLS certificate PEM")
		}
		if (role == "server" && !decryptionEnabled(local.Decryption)) || (role == "client" && !decryptionEnabled(local.Encryption)) {
			return errors.New("plain transport_security requires VLESS encryption")
		}
	}
	if local.XHTTP.Enabled() && !local.XHTTP.TLS && ((role == "server" && !decryptionEnabled(local.Decryption)) || (role == "client" && !decryptionEnabled(local.Encryption))) {
		return errors.New("xhttp HTTP dial candidates require VLESS encryption")
	}
	flow, err := normalizeFlow(local.Flow)
	if err != nil {
		return err
	}
	if flow != "" {
		if local.Hysteria2.Enabled() {
			return errors.New("Vision requires TCP TLS or REALITY, not Hysteria2")
		}
		if !local.Reality.Enabled() && local.TransportSecurity == "plain" {
			return errors.New("Vision requires TCP TLS or REALITY, not raw TCP encryption")
		}
	}
	if decryptionEnabled(local.Decryption) && decryptionEnabled(local.Encryption) {
		return errors.New("decryption and encryption cannot both be set")
	}
	switch role {
	case "server":
		if decryptionEnabled(local.Encryption) {
			return errors.New("server accepts decryption, not encryption")
		}
		_, err := parseDecryption(local.Decryption)
		return err
	case "client":
		if decryptionEnabled(local.Decryption) {
			return errors.New("client accepts encryption, not decryption")
		}
		_, err := parseEncryption(local.Encryption)
		return err
	default:
		return nil
	}
}

func (s *service) prepareCrypto() error {
	if idleServer(s.snapshot, s.local) {
		return nil
	}
	if err := checkVLESS(s.snapshot.Node.Role, s.local); err != nil {
		return err
	}
	flow, err := normalizeFlow(s.local.Flow)
	if err != nil {
		return err
	}
	s.flow = flow
	if s.snapshot.Node.Role == "server" {
		spec, err := parseDecryption(s.local.Decryption)
		if err != nil || spec == nil {
			return err
		}
		s.inbound, err = spec.newServer()
		return err
	}
	return nil // Client cryptographic state is isolated per gateway, not per node.
}

// GenerateVLESSEnc prints the same two authentication choices as Xray's vlessenc.
func GenerateVLESSEnc() (xDec, xEnc, pqDec, pqEnc string, err error) {
	var priv *ecdh.PrivateKey
	for range 8 {
		priv, err = ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return "", "", "", "", err
		}
		if priv.PublicKey().Bytes()[31] <= 127 {
			break
		}
		priv = nil
	}
	if priv == nil {
		return "", "", "", "", errors.New("VLESS encryption could not generate an X25519 key")
	}
	xDec = vlessDot("native", "600s", priv.Bytes())
	xEnc = vlessDot("native", "0rtt", priv.PublicKey().Bytes())
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		return "", "", "", "", err
	}
	pqDec = vlessDot("native", "600s", dk.Bytes())
	pqEnc = vlessDot("native", "0rtt", dk.EncapsulationKey().Bytes())
	return xDec, xEnc, pqDec, pqEnc, nil
}

func vlessDot(mode, ticket string, key []byte) string {
	return vlessScheme + "." + mode + "." + ticket + "." + base64.RawURLEncoding.EncodeToString(key)
}

// DeriveClientTunnel derives public settings using native encryption validation.
// The client argument must be empty: client-local overrides are rejected.
// Server-owned public template edits use ValidateClientTemplate, not derivation.
func DeriveClientTunnel(client, server model.LocalTLS, node model.Node) (model.LocalTLS, error) {
	if err := requireTransportSecurity(server); err != nil {
		return model.LocalTLS{}, err
	}
	if client != (model.LocalTLS{}) {
		return model.LocalTLS{}, errors.New("client-local tunnel overrides are not allowed")
	}
	result := model.DeriveClientTunnel(server, node)
	if server.Decryption != "" {
		spec, err := parseDecryption(server.Decryption)
		if err != nil {
			return model.LocalTLS{}, err
		}
		if spec != nil {
			ticket := "1rtt"
			if spec.from > 0 || spec.to > 0 {
				ticket = "0rtt"
			}
			// Derivation needs key constructors, not ticket-reaper goroutines.
			spec.from, spec.to = 0, 0
			keys, err := spec.newServer()
			if err != nil {
				return model.LocalTLS{}, err
			}
			defer keys.Close()
			mode := []string{"native", "xorpub", "random"}[spec.xor]
			parts := []string{vlessScheme, mode, ticket}
			if spec.padding != "" {
				parts = append(parts, spec.padding)
			}
			for _, key := range keys.keys {
				parts = append(parts, base64.RawURLEncoding.EncodeToString(key.pub))
			}
			result.Encryption = strings.Join(parts, ".")
		} else {
			result.Encryption = strings.TrimSpace(server.Decryption)
		}
	}
	if err := ValidateClientTemplate(result); err != nil {
		return model.LocalTLS{}, err
	}
	return result, nil
}

// ValidateClientTemplate validates public template fields without deriving,
// merging or replacing them. Store pairing and runtime completeness are separate.
func ValidateClientTemplate(result model.LocalTLS) error {
	if result.CertPEM != "" || result.KeyPEM != "" || result.ListenHost != "" || result.Decryption != "" || result.Reality.PrivateKey != "" || result.Reality.Dest != "" || result.Reality.ShortIDs != "" {
		return errors.New("client template contains server-only settings")
	}
	if err := CheckBootstrap("client", result); err != nil {
		return err
	}
	if spec, err := parseEncryption(result.Encryption); err != nil {
		return err
	} else if spec != nil {
		if _, err = spec.newClient(); err != nil {
			return err
		}
	}
	return nil
}

// PublicPeerTunnel returns a validated, public-only gateway view. Hysteria2's
// shared password is deliberately omitted; authorized snapshots need it separately.
func PublicPeerTunnel(server model.LocalTLS, node model.Node) (model.LocalTLS, error) {
	peer, err := DeriveClientTunnel(model.LocalTLS{}, server, node)
	peer.CertPEM, peer.KeyPEM = "", ""
	peer.Hysteria2 = model.Hysteria2{}
	return peer, err
}

type cryptSpec struct {
	xor     uint32
	from    int64
	to      int64
	seconds uint32
	padding string
	keys    [][]byte
}

func parseDecryption(raw string) (*cryptSpec, error) { return parseVLESSKey(raw, false) }
func parseEncryption(raw string) (*cryptSpec, error) { return parseVLESSKey(raw, true) }

func parseVLESSKey(raw string, client bool) (*cryptSpec, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == vlessPlain {
		return nil, nil
	}
	label := "decryption"
	if client {
		label = "encryption"
	}
	bad := fmt.Errorf("unsupported VLESS %s", label)
	parts := strings.Split(raw, ".")
	if len(parts) < 4 || parts[0] != vlessScheme {
		return nil, bad
	}
	spec := &cryptSpec{}
	switch parts[1] {
	case "native":
	case "xorpub":
		spec.xor = 1
	case "random":
		spec.xor = 2
	default:
		return nil, bad
	}
	if client {
		switch parts[2] {
		case "1rtt":
		case "0rtt":
			spec.seconds = 1
		default:
			return nil, bad
		}
	} else {
		span := strings.SplitN(strings.TrimSuffix(parts[2], "s"), "-", 2)
		from, err := strconv.Atoi(span[0])
		if err != nil || from < 0 {
			return nil, bad
		}
		spec.from = int64(from)
		if len(span) == 2 {
			to, err := strconv.Atoi(span[1])
			if err != nil || to < from {
				return nil, bad
			}
			spec.to = int64(to)
		}
	}
	for _, part := range parts[3:] {
		if len(part) < 20 {
			if len(spec.keys) > 0 {
				return nil, bad
			}
			if spec.padding != "" {
				spec.padding += "."
			}
			spec.padding += part
			continue
		}
		key, err := base64.RawURLEncoding.DecodeString(part)
		if err != nil {
			return nil, bad
		}
		if (client && len(key) != 32 && len(key) != 1184) || (!client && len(key) != 32 && len(key) != 64) {
			return nil, bad
		}
		spec.keys = append(spec.keys, key)
	}
	if len(spec.keys) == 0 {
		return nil, bad
	}
	if _, _, err := parsePadding(spec.padding); err != nil {
		return nil, err
	}
	return spec, nil
}

func parsePadding(padding string) (lens, gaps [][3]int, err error) {
	if padding == "" {
		return nil, nil, nil
	}
	total := 0
	for i, piece := range strings.Split(padding, ".") {
		item := strings.Split(piece, "-")
		if len(item) != 3 {
			return nil, nil, errors.New("invalid VLESS padding")
		}
		var y [3]int
		for n := range y {
			y[n], err = strconv.Atoi(item[n])
			if err != nil || y[n] < 0 {
				return nil, nil, errors.New("invalid VLESS padding")
			}
		}
		if y[1] > y[2] {
			return nil, nil, errors.New("invalid VLESS padding")
		}
		if i == 0 && (y[0] < 100 || y[1] < 35 || y[2] < 35) {
			return nil, nil, errors.New("invalid VLESS padding")
		}
		if i%2 == 0 {
			lens = append(lens, y)
			total += y[2]
		} else {
			gaps = append(gaps, y)
		}
	}
	if total > 18+65535 {
		return nil, nil, errors.New("invalid VLESS padding")
	}
	return lens, gaps, nil
}

func makePadding(lens, gaps [][3]int) (int, []int, []time.Duration) {
	if len(lens) == 0 {
		lens = [][3]int{{100, 111, 1111}, {50, 0, 3333}}
		gaps = [][3]int{{75, 0, 111}}
	}
	var sizes []int
	total := 0
	for _, y := range lens {
		n := 0
		if y[0] >= int(randBetween(0, 100)) {
			n = int(randBetween(int64(y[1]), int64(y[2])))
		}
		sizes = append(sizes, n)
		total += n
	}
	var waits []time.Duration
	for _, y := range gaps {
		n := 0
		if y[0] >= int(randBetween(0, 100)) {
			n = int(randBetween(int64(y[1]), int64(y[2])))
		}
		waits = append(waits, time.Duration(n)*time.Millisecond)
	}
	if total < 35 {
		sizes[0] += 35 - total
		total = 35
	}
	return total, sizes, waits
}

type nfsPriv struct {
	key  any
	pub  []byte
	hash [32]byte
	span int
}

type encSession struct {
	pfs []byte
	nfs sync.Map
}

type encServer struct {
	keys   []nfsPriv
	relays int
	xor    uint32
	from   int64
	to     int64
	lens   [][3]int
	gaps   [][3]int

	mu       sync.RWMutex
	closed   bool
	stop     chan struct{}
	lasts    map[int64][16]byte
	tickets  [][16]byte
	sessions map[[16]byte]*encSession
}

func (spec *cryptSpec) newServer() (*encServer, error) {
	out := &encServer{
		xor: spec.xor, from: spec.from, to: spec.to,
		lasts: map[int64][16]byte{}, sessions: map[[16]byte]*encSession{},
	}
	var err error
	if out.lens, out.gaps, err = parsePadding(spec.padding); err != nil {
		return nil, err
	}
	for _, raw := range spec.keys {
		item := nfsPriv{}
		if len(raw) == 32 {
			key, err := ecdh.X25519().NewPrivateKey(raw)
			if err != nil {
				return nil, err
			}
			item.key, item.pub, item.span = key, key.PublicKey().Bytes(), 32
		} else {
			key, err := mlkem.NewDecapsulationKey768(raw)
			if err != nil {
				return nil, fmt.Errorf("VLESS decryption: %w", err)
			}
			item.key, item.pub, item.span = key, key.EncapsulationKey().Bytes(), 1088
		}
		item.hash = blake3.Sum256(item.pub)
		out.relays += item.span + 32
		out.keys = append(out.keys, item)
	}
	out.relays -= 32
	if out.from > 0 || out.to > 0 {
		out.stop = make(chan struct{})
		go out.reap(out.stop)
	}
	return out, nil
}

func (s *encServer) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	if s.stop != nil {
		close(s.stop)
	}
}

func (s *encServer) reap(stop <-chan struct{}) {
	timer := time.NewTimer(time.Minute)
	defer timer.Stop()
	for {
		select {
		case <-stop:
			return
		case <-timer.C:
			s.mu.Lock()
			minute := time.Now().Unix() / 60
			last := s.lasts[minute]
			delete(s.lasts, minute)
			delete(s.lasts, minute-1)
			if last != [16]byte{} {
				for i, ticket := range s.tickets {
					delete(s.sessions, ticket)
					if ticket == last {
						s.tickets = s.tickets[i+1:]
						break
					}
				}
			}
			closed := s.closed
			s.mu.Unlock()
			if closed {
				return
			}
			timer.Reset(time.Minute)
		}
	}
}

func (s *encServer) Handshake(conn net.Conn) (net.Conn, error) {
	if len(s.keys) == 0 {
		return nil, errors.New("VLESS decryption is not initialized")
	}
	c := &recordConn{Conn: conn, aes: true}
	head := make([]byte, 16+s.relays)
	if _, err := io.ReadFull(conn, head); err != nil {
		return nil, err
	}
	iv := append([]byte{}, head[:16]...)
	relays := head[16:]
	var nfsKey []byte
	var last cipher.Stream
	for j, key := range s.keys {
		if last != nil {
			relays = xorSlice(last, relays, 32)
		}
		if s.xor > 0 {
			relays = xorSlice(newCTR(key.pub, iv), relays, key.span)
		}
		shared, err := s.share(key, relays[:key.span])
		if err != nil {
			return nil, err
		}
		nfsKey = shared
		if j == len(s.keys)-1 {
			break
		}
		relays = relays[key.span:]
		last = newCTR(nfsKey, iv)
		relays = xorSlice(last, relays, 32)
		if !bytes.Equal(relays[:32], s.keys[j+1].hash[:]) {
			return nil, errors.New("VLESS encryption authentication failed")
		}
		relays = relays[32:]
	}
	blob := make([]byte, 18)
	if _, err := io.ReadFull(conn, blob); err != nil {
		return nil, err
	}
	nfs := newBox(iv, nfsKey, true)
	plain, err := nfs.open(nil, nil, blob, nil)
	if err != nil {
		nfs = newBox(iv, nfsKey, false)
		c.aes = false
		plain, err = nfs.open(nil, nil, blob, nil)
		if err != nil {
			return nil, err
		}
	}
	length := decodeLen(plain)
	if length == 32 {
		return s.resume(conn, c, nfs, nfsKey, iv)
	}
	if length < 1184+32+16 {
		return nil, errors.New("VLESS encryption handshake is too short")
	}
	sealed := make([]byte, length)
	if _, err = io.ReadFull(conn, sealed); err != nil {
		return nil, err
	}
	pfsPub, err := nfs.open(nil, nil, sealed, nil)
	if err != nil {
		return nil, err
	}
	if len(pfsPub) < 1184+32 {
		return nil, errors.New("VLESS encryption handshake is too short")
	}
	ek, err := mlkem.NewEncapsulationKey768(pfsPub[:1184])
	if err != nil {
		return nil, err
	}
	mlkemKey, encapsulated := ek.Encapsulate()
	peer, err := ecdh.X25519().NewPublicKey(pfsPub[1184 : 1184+32])
	if err != nil {
		return nil, err
	}
	local, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	xKey, err := local.ECDH(peer)
	if err != nil {
		return nil, err
	}
	pfsKey := make([]byte, 64)
	copy(pfsKey, mlkemKey)
	copy(pfsKey[32:], xKey)
	serverPub := append(encapsulated, local.PublicKey().Bytes()...)
	c.united = append(append([]byte{}, pfsKey...), nfsKey...)
	c.out = newBox(serverPub, c.united, c.aes)
	c.peer = newBox(append([]byte{}, pfsPub[:1184+32]...), c.united, c.aes)
	ticket := make([]byte, 16)
	if _, err = rand.Read(ticket); err != nil {
		return nil, err
	}
	seconds := s.from * randBetween(50, 100) / 100
	if s.to > 0 {
		seconds = randBetween(s.from, s.to)
	}
	copy(ticket, encodeLen(int(seconds)))
	if seconds > 0 {
		s.remember(ticket, pfsKey)
	}
	if err = s.writeHello(conn, nfs, c, serverPub, ticket); err != nil {
		return nil, err
	}
	if err = readPadding(conn, nfs); err != nil {
		return nil, err
	}
	if s.xor == 2 {
		c.Conn = newXor(conn, newCTR(c.united, ticket), newCTR(c.united, iv), 0, 0)
	}
	return c, nil
}

func (s *encServer) share(key nfsPriv, raw []byte) ([]byte, error) {
	switch priv := key.key.(type) {
	case *ecdh.PrivateKey:
		if raw[len(raw)-1] > 127 {
			return nil, errors.New("VLESS encryption rejected an X25519 public key")
		}
		pub, err := ecdh.X25519().NewPublicKey(raw)
		if err != nil {
			return nil, err
		}
		return priv.ECDH(pub)
	case *mlkem.DecapsulationKey768:
		return priv.Decapsulate(raw)
	default:
		return nil, errors.New("VLESS decryption key is unusable")
	}
}

func (s *encServer) remember(ticket, pfs []byte) {
	var key [16]byte
	copy(key[:], ticket[:16])
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.lasts[(time.Now().Unix()+max(s.from, s.to))/60+2] = key
	s.tickets = append(s.tickets, key)
	s.sessions[key] = &encSession{pfs: append([]byte{}, pfs...)}
}

func (s *encServer) resume(conn net.Conn, c *recordConn, nfs *aeadBox, nfsKey, iv []byte) (net.Conn, error) {
	if s.from == 0 && s.to == 0 {
		return nil, errors.New("VLESS encryption 0-RTT is not allowed")
	}
	blob := make([]byte, 32)
	if _, err := io.ReadFull(conn, blob); err != nil {
		return nil, err
	}
	ticket, err := nfs.open(nil, nil, blob, nil)
	if err != nil || len(ticket) < 16 {
		return nil, errors.New("VLESS encryption ticket is invalid")
	}
	var key [16]byte
	copy(key[:], ticket[:16])
	s.mu.RLock()
	session := s.sessions[key]
	s.mu.RUnlock()
	if session == nil {
		noise := make([]byte, 1280)
		_, _ = rand.Read(noise)
		_, _ = conn.Write(noise)
		return nil, errors.New("VLESS encryption ticket expired")
	}
	if len(nfsKey) != 32 {
		return nil, errors.New("VLESS encryption key is invalid")
	}
	var id [32]byte
	copy(id[:], nfsKey)
	if _, loaded := session.nfs.LoadOrStore(id, true); loaded {
		return nil, errors.New("VLESS encryption ticket was replayed")
	}
	c.united = append(append([]byte{}, session.pfs...), nfsKey...)
	c.pre = make([]byte, 16)
	if _, err = rand.Read(c.pre); err != nil {
		return nil, err
	}
	c.out = newBox(c.pre, c.united, c.aes)
	c.peer = newBox(blob, c.united, c.aes)
	if s.xor == 2 {
		c.Conn = newXor(conn, newCTR(c.united, c.pre), newCTR(c.united, iv), 16, 0)
	}
	return c, nil
}

func (s *encServer) writeHello(conn net.Conn, nfs *aeadBox, c *recordConn, serverPub, ticket []byte) error {
	padLen, sizes, gaps := makePadding(s.lens, s.gaps)
	body := make([]byte, len(serverPub)+16+32+padLen)
	nfs.seal(body[:0], maxNonce, serverPub, nil)
	c.out.seal(body[:len(serverPub)+16], nil, ticket, nil)
	pad := body[len(serverPub)+16+32:]
	c.out.seal(pad[:0], nil, encodeLen(padLen-18), nil)
	c.out.seal(pad[:18], nil, pad[18:padLen-16], nil)
	sizes[0] += len(serverPub) + 16 + 32
	return writeFragments(conn, body, sizes, gaps)
}

func readPadding(conn net.Conn, box *aeadBox) error {
	header := make([]byte, 18)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}
	plain, err := box.open(nil, nil, header, nil)
	if err != nil {
		return err
	}
	body := make([]byte, decodeLen(plain))
	if _, err = io.ReadFull(conn, body); err != nil {
		return err
	}
	_, err = box.open(nil, nil, body, nil)
	return err
}

type nfsClientKey struct {
	key  any
	raw  []byte
	hash [32]byte
	span int
}

type encClient struct {
	keys    []nfsClientKey
	relays  int
	xor     uint32
	seconds uint32
	lens    [][3]int
	gaps    [][3]int

	mu     sync.RWMutex
	expire time.Time
	pfs    []byte
	ticket []byte
}

func (spec *cryptSpec) newClient() (*encClient, error) {
	out := &encClient{xor: spec.xor, seconds: spec.seconds}
	var err error
	if out.lens, out.gaps, err = parsePadding(spec.padding); err != nil {
		return nil, err
	}
	for _, raw := range spec.keys {
		item := nfsClientKey{raw: append([]byte{}, raw...)}
		if len(raw) == 32 {
			key, err := ecdh.X25519().NewPublicKey(raw)
			if err != nil {
				return nil, err
			}
			item.key, item.span = key, 32
		} else {
			key, err := mlkem.NewEncapsulationKey768(raw)
			if err != nil {
				return nil, fmt.Errorf("VLESS encryption: %w", err)
			}
			item.key, item.span = key, 1088
		}
		item.hash = blake3.Sum256(raw)
		out.relays += item.span + 32
		out.keys = append(out.keys, item)
	}
	out.relays -= 32
	return out, nil
}

func (i *encClient) Handshake(conn net.Conn) (net.Conn, error) {
	if len(i.keys) == 0 {
		return nil, errors.New("VLESS encryption is not initialized")
	}
	c := &recordConn{Conn: conn, aes: true}
	ivAndRelays := 16 + i.relays
	const pfsLen = 18 + 1184 + 32 + 16
	padLen, sizes, gaps := makePadding(i.lens, i.gaps)
	hello := make([]byte, ivAndRelays+pfsLen+padLen)
	if _, err := rand.Read(hello[:16]); err != nil {
		return nil, err
	}
	iv := append([]byte{}, hello[:16]...)
	relays := hello[16:ivAndRelays]
	var nfsKey []byte
	var last cipher.Stream
	for j, key := range i.keys {
		shared, err := clientShare(relays[:key.span], key)
		if err != nil {
			return nil, err
		}
		if i.xor > 0 {
			xorFrom(newCTR(key.raw, iv), relays[:key.span], relays[:key.span])
		}
		if last != nil {
			xorFrom(last, relays[:32], relays[:32])
		}
		nfsKey = shared
		if j == len(i.keys)-1 {
			break
		}
		last = newCTR(nfsKey, iv)
		xorFrom(last, relays[key.span:key.span+32], i.keys[j+1].hash[:])
		relays = relays[key.span+32:]
	}
	nfs := newBox(iv, nfsKey, true)
	if done, err := i.resume(c, conn, hello, iv, ivAndRelays, nfs, nfsKey); done || err != nil {
		if err != nil {
			return nil, err
		}
		return c, nil
	}
	pfs := hello[ivAndRelays : ivAndRelays+pfsLen]
	nfs.seal(pfs[:0], nil, encodeLen(pfsLen-18), nil)
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, err
	}
	xPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	pfsPub := append(dk.EncapsulationKey().Bytes(), xPriv.PublicKey().Bytes()...)
	nfs.seal(pfs[:18], nil, pfsPub, nil)
	padding := hello[ivAndRelays+pfsLen:]
	nfs.seal(padding[:0], nil, encodeLen(padLen-18), nil)
	nfs.seal(padding[:18], nil, padding[18:padLen-16], nil)
	sizes[0] += ivAndRelays + pfsLen
	if err = writeFragments(conn, hello, sizes, gaps); err != nil {
		return nil, err
	}
	sealed := make([]byte, 1088+32+16)
	if _, err = io.ReadFull(conn, sealed); err != nil {
		return nil, err
	}
	serverPub, err := nfs.open(nil, maxNonce, sealed, nil)
	if err != nil {
		return nil, err
	}
	mlkemKey, err := dk.Decapsulate(serverPub[:1088])
	if err != nil {
		return nil, err
	}
	peer, err := ecdh.X25519().NewPublicKey(serverPub[1088 : 1088+32])
	if err != nil {
		return nil, err
	}
	xKey, err := xPriv.ECDH(peer)
	if err != nil {
		return nil, err
	}
	pfsKey := make([]byte, 64)
	copy(pfsKey, mlkemKey)
	copy(pfsKey[32:], xKey)
	c.united = append(append([]byte{}, pfsKey...), nfsKey...)
	c.out = newBox(pfsPub, c.united, true)
	c.peer = newBox(serverPub[:1088+32], c.united, true)
	sealedTicket := make([]byte, 32)
	if _, err = io.ReadFull(conn, sealedTicket); err != nil {
		return nil, err
	}
	ticket, err := c.peer.open(nil, nil, sealedTicket, nil)
	if err != nil || len(ticket) < 16 {
		return nil, errors.New("VLESS encryption ticket is invalid")
	}
	seconds := decodeLen(ticket)
	if i.seconds > 0 && seconds > 0 {
		i.mu.Lock()
		i.expire = time.Now().Add(time.Duration(seconds) * time.Second)
		i.pfs = append([]byte{}, pfsKey...)
		i.ticket = append([]byte{}, ticket[:16]...)
		i.mu.Unlock()
	}
	sealedLen := make([]byte, 18)
	if _, err = io.ReadFull(conn, sealedLen); err != nil {
		return nil, err
	}
	length, err := c.peer.open(nil, nil, sealedLen, nil)
	if err != nil {
		return nil, err
	}
	c.peerPad = make([]byte, decodeLen(length))
	if i.xor == 2 {
		c.Conn = newXor(conn, newCTR(c.united, iv), newCTR(c.united, ticket[:16]), 0, len(c.peerPad))
	}
	return c, nil
}

func (i *encClient) resume(c *recordConn, conn net.Conn, hello, iv []byte, ivAndRelays int, nfs *aeadBox, nfsKey []byte) (bool, error) {
	if i.seconds == 0 {
		return false, nil
	}
	i.mu.RLock()
	defer i.mu.RUnlock()
	if !time.Now().Before(i.expire) || len(i.ticket) != 16 || len(i.pfs) != 64 {
		return false, nil
	}
	c.united = append(append([]byte{}, i.pfs...), nfsKey...)
	nfs.seal(hello[:ivAndRelays], nil, encodeLen(32), nil)
	nfs.seal(hello[:ivAndRelays+18], nil, i.ticket, nil)
	c.pre = append([]byte{}, hello[:ivAndRelays+18+32]...)
	c.out = newBox(hello[ivAndRelays+18:ivAndRelays+18+32], c.united, true)
	c.client = i
	if i.xor == 2 {
		c.Conn = newXor(conn, newCTR(c.united, iv), nil, len(c.pre), 16)
	}
	return true, nil
}

func clientShare(dst []byte, key nfsClientKey) ([]byte, error) {
	switch pub := key.key.(type) {
	case *ecdh.PublicKey:
		priv, err := ephemeralX25519()
		if err != nil {
			return nil, err
		}
		copy(dst, priv.PublicKey().Bytes())
		return priv.ECDH(pub)
	case *mlkem.EncapsulationKey768:
		shared, ciphertext := pub.Encapsulate()
		copy(dst, ciphertext)
		return shared, nil
	default:
		return nil, errors.New("VLESS encryption key is unusable")
	}
}

func ephemeralX25519() (*ecdh.PrivateKey, error) {
	for range 8 {
		key, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		if key.PublicKey().Bytes()[31] <= 127 {
			return key, nil
		}
	}
	return nil, errors.New("VLESS encryption could not generate an X25519 key")
}

func writeFragments(conn net.Conn, body []byte, sizes []int, gaps []time.Duration) error {
	for n, size := range sizes {
		if size > 0 {
			if size > len(body) {
				size = len(body)
			}
			if _, err := conn.Write(body[:size]); err != nil {
				return err
			}
			body = body[size:]
		}
		if n < len(gaps) {
			time.Sleep(gaps[n])
		}
	}
	if len(body) == 0 {
		return nil
	}
	_, err := conn.Write(body)
	return err
}

type aeadBox struct {
	cipher.AEAD
	nonce [12]byte
}

func newBox(ctx, key []byte, useAES bool) *aeadBox {
	derived := make([]byte, 32)
	blake3.DeriveKey(derived, string(ctx), key)
	var aead cipher.AEAD
	var err error
	if useAES {
		block, blockErr := aes.NewCipher(derived)
		if blockErr != nil {
			panic(blockErr)
		}
		aead, err = cipher.NewGCM(block)
	} else {
		aead, err = chacha20poly1305.New(derived)
	}
	if err != nil {
		panic(err)
	}
	return &aeadBox{AEAD: aead}
}

func (a *aeadBox) seal(dst, nonce, plain, extra []byte) []byte {
	if nonce == nil {
		nonce = bumpNonce(a.nonce[:])
	}
	return a.Seal(dst, nonce, plain, extra)
}

func (a *aeadBox) open(dst, nonce, ciphertext, extra []byte) ([]byte, error) {
	if nonce == nil {
		nonce = bumpNonce(a.nonce[:])
	}
	return a.Open(dst, nonce, ciphertext, extra)
}

func bumpNonce(nonce []byte) []byte {
	for i := range 12 {
		nonce[11-i]++
		if nonce[11-i] != 0 {
			break
		}
	}
	return nonce
}

func encodeLen(n int) []byte { return []byte{byte(n >> 8), byte(n)} }

func decodeLen(b []byte) int { return int(b[0])<<8 | int(b[1]) }

func encodeHeader(h []byte, n int) {
	h[0], h[1], h[2], h[3], h[4] = 23, 3, 3, byte(n>>8), byte(n)
}

func decodeHeader(h []byte) (int, error) {
	n := int(h[3])<<8 | int(h[4])
	if h[0] != 23 || h[1] != 3 || h[2] != 3 || n < 17 || n > 16640 {
		return 0, fmt.Errorf("invalid header: %v", h[:5])
	}
	return n, nil
}

type recordConn struct {
	net.Conn
	aes         bool
	ticketMu    sync.Mutex // protects client across concurrent Read/Write errors
	client      *encClient
	united      []byte
	pre         []byte
	out         *aeadBox
	peer        *aeadBox
	peerPad     []byte
	pending     bytes.Reader
	writeMu     sync.Mutex
	writeClosed bool
}

// CloseWrite preserves the independent read-side AEAD/XOR state. All records
// (including deferred handshake bytes) are flushed before the transport FIN or
// TLS close_notify; no raw bypass of the encryption wrapper is permitted.
func (c *recordConn) CloseWrite() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeClosed {
		return nil
	}
	c.writeClosed = true
	if len(c.pre) > 0 {
		if err := writeAll(c.Conn, c.pre); err != nil {
			return err
		}
		c.pre = nil
	}
	if w, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return w.CloseWrite()
	}
	return errors.New("encryption transport does not support half-close")
}

func (c *recordConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeClosed {
		return 0, net.ErrClosed
	}
	if len(p) == 0 {
		return 0, nil
	}
	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > 8192 {
			chunk = chunk[:8192]
		}
		p = p[len(chunk):]
		total += len(chunk)
		packet := make([]byte, 5+len(chunk)+16)
		encodeHeader(packet, len(chunk)+16)
		rekey := bytes.Equal(c.out.nonce[:], maxNonce)
		c.out.seal(packet[:5], nil, chunk, packet[:5])
		if rekey {
			c.out = newBox(packet, c.united, c.aes)
		}
		if c.pre != nil {
			packet = append(append([]byte{}, c.pre...), packet...)
			c.pre = nil
		}
		if _, err := c.Conn.Write(packet); err != nil {
			c.expireTicket()
			return 0, err
		}
	}
	return total, nil
}

func (c *recordConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if c.pending.Len() > 0 {
		return c.pending.Read(p)
	}
	if c.peer == nil {
		random := make([]byte, 16)
		if _, err := io.ReadFull(c.Conn, random); err != nil {
			return 0, err
		}
		c.peer = newBox(random, c.united, c.aes)
		if wrapped, ok := c.Conn.(*xorConn); ok {
			wrapped.peer = newCTR(c.united, random)
		}
	}
	if c.peerPad != nil {
		if _, err := io.ReadFull(c.Conn, c.peerPad); err != nil {
			return 0, err
		}
		if _, err := c.peer.open(nil, nil, c.peerPad, nil); err != nil {
			return 0, err
		}
		c.peerPad = nil
	}
	header := make([]byte, 5)
	if _, err := io.ReadFull(c.Conn, header); err != nil {
		return 0, err
	}
	n, err := decodeHeader(header)
	if err != nil {
		if strings.Contains(err.Error(), "invalid header: ") && c.expireTicket() {
			return 0, errors.New("new handshake needed")
		}
		return 0, err
	}
	c.ticketMu.Lock()
	c.client = nil
	c.ticketMu.Unlock()
	blob := make([]byte, n)
	if _, err = io.ReadFull(c.Conn, blob); err != nil {
		return 0, err
	}
	var next *aeadBox
	if bytes.Equal(c.peer.nonce[:], maxNonce) {
		next = newBox(append(append([]byte{}, header...), blob...), c.united, c.aes)
	}
	plain, err := c.peer.open(nil, nil, blob, header)
	if next != nil {
		c.peer = next
	}
	if err != nil {
		return 0, err
	}
	copied := copy(p, plain)
	if copied < len(plain) {
		c.pending.Reset(plain[copied:])
	}
	return copied, nil
}

func (c *recordConn) expireTicket() bool {
	c.ticketMu.Lock()
	defer c.ticketMu.Unlock()
	if c.client == nil {
		return false
	}
	c.client.mu.Lock()
	c.client.expire = time.Now()
	c.client.mu.Unlock()
	c.client = nil
	return true
}

func newCTR(key, iv []byte) cipher.Stream {
	derived := make([]byte, 32)
	blake3.DeriveKey(derived, "VLESS", key)
	block, err := aes.NewCipher(derived)
	if err != nil {
		panic(err)
	}
	nonce := make([]byte, 16)
	copy(nonce, iv)
	return cipher.NewCTR(block, nonce)
}

func xorFrom(stream cipher.Stream, dst, src []byte) {
	tmp := append([]byte{}, src...)
	stream.XORKeyStream(dst[:len(tmp)], tmp)
}

func xorSlice(stream cipher.Stream, src []byte, n int) []byte {
	out := append([]byte{}, src...)
	tmp := append([]byte{}, out[:n]...)
	stream.XORKeyStream(out[:n], tmp)
	return out
}

type xorConn struct {
	net.Conn
	out     cipher.Stream
	peer    cipher.Stream
	outSkip int
	outHead []byte
	inSkip  int
	inHead  []byte
}

func newXor(conn net.Conn, out, peer cipher.Stream, outSkip, inSkip int) *xorConn {
	return &xorConn{Conn: conn, out: out, peer: peer, outSkip: outSkip, inSkip: inSkip, outHead: make([]byte, 0, 5), inHead: make([]byte, 0, 5)}
}

func (c *xorConn) CloseWrite() error {
	if w, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return w.CloseWrite()
	}
	return errors.New("XOR transport does not support half-close")
}

func (c *xorConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for buf := p; ; {
		if len(buf) <= c.outSkip {
			c.outSkip -= len(buf)
			break
		}
		buf = buf[c.outSkip:]
		c.outSkip = 0
		need := 5 - len(c.outHead)
		if len(buf) < need {
			c.outHead = append(c.outHead, buf...)
			xorFrom(c.out, buf, buf)
			break
		}
		header := append(append([]byte{}, c.outHead...), buf[:need]...)
		c.outSkip, _ = decodeHeader(header)
		c.outHead = c.outHead[:0]
		xorFrom(c.out, buf[:need], buf[:need])
		buf = buf[need:]
	}
	if _, err := c.Conn.Write(p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *xorConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	n, err := c.Conn.Read(p)
	for buf := p[:n]; ; {
		if len(buf) <= c.inSkip {
			c.inSkip -= len(buf)
			break
		}
		buf = buf[c.inSkip:]
		c.inSkip = 0
		need := 5 - len(c.inHead)
		if len(buf) < need {
			xorFrom(c.peer, buf, buf)
			c.inHead = append(c.inHead, buf...)
			break
		}
		xorFrom(c.peer, buf[:need], buf[:need])
		c.inSkip, _ = decodeHeader(append(append([]byte{}, c.inHead...), buf[:need]...))
		c.inHead = c.inHead[:0]
		buf = buf[need:]
	}
	return n, err
}

func randBetween(from, to int64) int64 {
	if from > to {
		from, to = to, from
	}
	if to-from <= 1 {
		return from
	}
	n, err := rand.Int(rand.Reader, big.NewInt(to-from))
	if err != nil {
		return from
	}
	return from + n.Int64()
}
