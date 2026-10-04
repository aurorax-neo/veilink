package tunnel

import (
	"bytes"
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
	"io"
	"math/big"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
	"github.com/xtls/reality"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/net/http2"

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
	allEndpoints := enabledEndpoints(gateway)
	endpoints := gateway.ConnectEndpoints
	if len(endpoints) == 0 {
		endpoints = allEndpoints
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
	if gateway.Tunnel.XHTTP.DownloadEndpointID != "" {
		for _, ep := range allEndpoints {
			if ep.ID == gateway.Tunnel.XHTTP.DownloadEndpointID && ep.ID != selected.ID {
				gateway.ConnectEndpoints = append(gateway.ConnectEndpoints, ep)
				break
			}
		}
	}
	return gateway, nil
}

func (s *service) dialGateway(gateway model.Node, peer *clientGateway) (net.Conn, error) {
	local := peer.local
	if err := checkVLESS("client", local); err != nil {
		return nil, err
	}
	endpoints := enabledEndpoints(gateway)
	var downEndpoint *model.ConnectEndpoint
	if local.XHTTP.Enabled() && local.XHTTP.DownloadEndpointID != "" {
		for i := range endpoints {
			if endpoints[i].ID == local.XHTTP.DownloadEndpointID {
				selected := endpoints[i]
				downEndpoint = &selected
				break
			}
		}
		if downEndpoint == nil {
			return nil, errors.New("xhttp download endpoint is missing, disabled or invalid")
		}
	}
	var last error
	for _, endpoint := range endpoints {
		addr := net.JoinHostPort(endpoint.Host, strconv.Itoa(endpoint.Port))
		serverName := endpoint.Host
		if local.XHTTP.Enabled() {
			dial := func(ctx context.Context) (net.Conn, error) {
				return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", addr)
			}
			if local.Reality.Enabled() {
				dial = func(ctx context.Context) (net.Conn, error) { return dialReality(ctx, addr, serverName, local.Reality) }
			}
			var downDial func(context.Context) (net.Conn, error)
			downAddr := ""
			if downEndpoint != nil {
				downAddr = net.JoinHostPort(downEndpoint.Host, strconv.Itoa(downEndpoint.Port))
				downServerName := downEndpoint.Host
				if local.Reality.Enabled() {
					downDial = func(ctx context.Context) (net.Conn, error) {
						return dialReality(ctx, downAddr, downServerName, local.Reality)
					}
				} else {
					downDial = func(ctx context.Context) (net.Conn, error) {
						return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", downAddr)
					}
				}
			}
			if conn, err := dialXHTTPWithDownDialer(s.ctx, addr, serverName, local, dial, downDial, downAddr); err == nil {
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
	// ML-DSA-65 后量子签名密钥（服务端）
	var mldsa65Key []byte
	if r.Mldsa65Seed != "" {
		mldsa65Key, err = base64.RawURLEncoding.DecodeString(r.Mldsa65Seed)
		if err != nil {
			mldsa65Key, err = base64.StdEncoding.DecodeString(r.Mldsa65Seed)
			if err != nil {
				return nil, err
			}
		}
	}
	cfg := &reality.Config{
		DialContext:            (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		Type:                   "tcp",
		Dest:                   strings.TrimSpace(r.Dest),
		Mldsa65Key:             mldsa65Key,
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
	var uconn *utls.UConn
	uconn = utls.UClient(gate, &utls.Config{
		ServerName:             serverName,
		InsecureSkipVerify:     true,
		SessionTicketsDisabled: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if !realityCertificate(authKey, rawCerts) {
				return errors.New("REALITY certificate authentication failed")
			}
			// 对齐 Xray-core：如配置了 mldsa65_verify，做后量子额外验证
			if r.Mldsa65Verify != "" {
				if !realityMldsa65Verify(authKey, rawCerts, r.Mldsa65Verify, uconn) {
					return errors.New("REALITY ML-DSA-65 verification failed")
				}
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
		// 对齐 Xray-core：验证失败时伪装成正常浏览器爬目标站（反探测），而非直接断开
		camouflageBrowse(uconn, serverName, r.SpiderX, r.SpiderY)
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
	// 对齐 Xray-core：SessionId[0:4] 填版本号 [26, 9, 30, 0]，留零会成为可观测指纹差异
	hello.SessionId[0] = 26
	hello.SessionId[1] = 9
	hello.SessionId[2] = 30
	hello.SessionId[3] = 0 // reserved
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

// realityMldsa65Verify 对齐 Xray-core 的 ML-DSA-65 后量子额外验证
func realityMldsa65Verify(authKey []byte, rawCerts [][]byte, mldsa65VerifyB64 string, uconn *utls.UConn) bool {
	if len(rawCerts) == 0 || mldsa65VerifyB64 == "" || uconn == nil {
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
	if len(cert.Extensions) == 0 {
		return false
	}
	// 解码 ML-DSA-65 公钥
	pubKeyBytes, err := base64.RawURLEncoding.DecodeString(mldsa65VerifyB64)
	if err != nil {
		// 尝试标准 base64
		pubKeyBytes, err = base64.StdEncoding.DecodeString(mldsa65VerifyB64)
		if err != nil {
			return false
		}
	}
	verifyKey, err := mldsa65.Scheme().UnmarshalBinaryPublicKey(pubKeyBytes)
	if err != nil {
		return false
	}
	// 构造待验证消息：HMAC(pub) + Hello.Raw + ServerHello.Raw
	mac := hmac.New(sha512.New, authKey)
	_, _ = mac.Write(pub)
	h := mac.Sum(nil)
	state := uconn.HandshakeState
	if state.Hello == nil || state.ServerHello == nil {
		return false
	}
	h = append(h, state.Hello.Raw...)
	h = append(h, state.ServerHello.Raw...)
	// 验证证书第一个扩展中的签名
	return mldsa65.Verify(verifyKey.(*mldsa65.PublicKey), h, nil, cert.Extensions[0].Value)
}

// spiderPathCache 缓存每个目标站点的已发现路径（对齐 Xray-core maps）
var spiderPathCache struct {
	sync.Mutex
	maps map[string]map[string]struct{}
}

var spiderHrefRe = regexp.MustCompile(`href="([/h].*?)"`)
var spiderDot = []byte(".")

func spiderGetPathLocked(paths map[string]struct{}) string {
	if len(paths) == 0 {
		return "/"
	}
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(paths))))
	stopAt := int(n.Int64())
	i := 0
	for s := range paths {
		if i == stopAt {
			return s
		}
		i++
	}
	return "/"
}

func spiderRandBetween(min, max int64) int64 {
	if max <= min {
		return min
	}
	n, _ := rand.Int(rand.Reader, big.NewInt(max-min+1))
	return min + n.Int64()
}

// parseSpiderY 解析 spider_y 配置（10 个整数），缺省用 Xray-core 常用值
func parseSpiderY(s string) [10]int64 {
	// 默认值：padding 32-64，并发 1-2，每路径请求 1-3，间隔 0-100ms，返回前等待 0-50ms
	def := [10]int64{32, 64, 1, 2, 1, 3, 0, 100, 0, 50}
	if strings.TrimSpace(s) == "" {
		return def
	}
	parts := strings.Split(s, ",")
	for i := 0; i < 10 && i < len(parts); i++ {
		if v, err := strconv.ParseInt(strings.TrimSpace(parts[i]), 10, 64); err == nil {
			def[i] = v
		}
	}
	return def
}

// camouflageBrowse 对齐 Xray-core：证书验证失败时，像正常浏览器一样爬目标站
// （反探测设计，缺失后失败连接模式更易被区分）
// generateSpiderX 生成随机的伪装爬取起点路径（避免所有用户都用 "/" 形成指纹）
func generateSpiderX() (string, error) {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	for i := range b {
		b[i] = chars[int(b[i])%len(chars)]
	}
	return "/" + string(b), nil
}

func camouflageBrowse(conn net.Conn, serverName, spiderX, spiderY string) {
	spiderYVals := parseSpiderY(spiderY)
	if spiderX == "" {
		// 不固定用 "/"，随机生成避免指纹
		var err error
		spiderX, err = generateSpiderX()
		if err != nil {
			spiderX = "/"
		}
	}
	go func() {
		client := &http.Client{
			Transport: &http2.Transport{
				DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
					return conn, nil
				},
			},
		}
		prefix := []byte("https://" + serverName)
		spiderPathCache.Lock()
		if spiderPathCache.maps == nil {
			spiderPathCache.maps = make(map[string]map[string]struct{})
		}
		paths := spiderPathCache.maps[serverName]
		if paths == nil {
			paths = make(map[string]struct{})
			paths[spiderX] = struct{}{}
			spiderPathCache.maps[serverName] = paths
		}
		firstURL := string(prefix) + spiderGetPathLocked(paths)
		spiderPathCache.Unlock()
		get := func(first bool) {
			var req *http.Request
			if first {
				req, _ = http.NewRequest("GET", firstURL, nil)
			} else {
				spiderPathCache.Lock()
				req, _ = http.NewRequest("GET", string(prefix)+spiderGetPathLocked(paths), nil)
				spiderPathCache.Unlock()
			}
			if req == nil {
				return
			}
			// 模拟浏览器默认头
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
			req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
			req.Header.Set("Accept-Language", "en-US,en;q=0.9")
			times := 1
			if !first {
				times = int(spiderRandBetween(spiderYVals[4], spiderYVals[5]))
			}
			for j := 0; j < times; j++ {
				if !first && j == 0 {
					req.Header.Set("Referer", firstURL)
				}
				req.AddCookie(&http.Cookie{Name: "padding", Value: strings.Repeat("0", int(spiderRandBetween(spiderYVals[0], spiderYVals[1])))})
				resp, err := client.Do(req)
				if err != nil {
					break
				}
				func() {
					defer resp.Body.Close()
					req.Header.Set("Referer", req.URL.String())
					body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
					if err != nil {
						return
					}
					spiderPathCache.Lock()
					for _, m := range spiderHrefRe.FindAllSubmatch(body, -1) {
						m[1] = bytes.TrimPrefix(m[1], prefix)
						if !bytes.Contains(m[1], spiderDot) {
							paths[string(m[1])] = struct{}{}
						}
					}
					req.URL.Path = spiderGetPathLocked(paths)
					spiderPathCache.Unlock()
				}()
				if !first {
					time.Sleep(time.Duration(spiderRandBetween(spiderYVals[6], spiderYVals[7])) * time.Millisecond)
				}
			}
		}
		get(true)
		concurrency := int(spiderRandBetween(spiderYVals[2], spiderYVals[3]))
		for i := 0; i < concurrency; i++ {
			go get(false)
		}
		// 不关闭连接，留给对端
	}()
	time.Sleep(time.Duration(spiderRandBetween(spiderYVals[8], spiderYVals[9])) * time.Millisecond)
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

// GenerateMldsa65 生成 ML-DSA-65 后量子密钥对（对齐 Xray-core）
func GenerateMldsa65() (string, string, error) {
	pub, priv, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	pubBytes, err := pub.MarshalBinary()
	if err != nil {
		return "", "", err
	}
	privBytes, err := priv.MarshalBinary()
	if err != nil {
		return "", "", err
	}
	return base64.RawURLEncoding.EncodeToString(privBytes), base64.RawURLEncoding.EncodeToString(pubBytes), nil
}
