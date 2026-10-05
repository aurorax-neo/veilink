package tunnel

// Native packet-up transport, independently implemented from protocol behavior
// documented by Xray's splithttp reference (no MPL source incorporated).
// GET path/<session> opens the download; sequenced POSTs send the upload.
// The private X-Veilink-EOF extension preserves upload half-close for native peers.
// This is not an Xray interoperability guarantee.
// Reverse proxies must stream responses, disable buffering, and preserve paths.
import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2/hpack"

	"veilink/internal/model"
)

const (
	xhttpChunk    = 32 << 10
	xhttpSessions = 128
	xhttpTimeout  = 15 * time.Second
)

func xhttpServerHeaderLimit(x model.XHTTP) int {
	if x.ServerMaxHeaderBytes > 0 {
		return x.ServerMaxHeaderBytes
	}
	return 8 << 10
}

func xhttpClientALPN(version string) []string {
	if version == "1.1" {
		return []string{"http/1.1"}
	}
	return []string{"h2", "http/1.1"}
}

// REALITY dialers/listeners already provide authenticated TLS connections.
// Use HTTP/2 prior knowledge inside them without adding a second TLS layer.
func xhttpPriorHTTP2(local model.LocalTLS) bool {
	return !local.XHTTP.TLS && (local.XHTTP.HTTPVersion == "2" ||
		(local.Reality.Enabled() && xhttpEffectiveMode(local.XHTTP, true) != "packet-up"))
}

// xhttpEffectiveMode 对齐 Xray-core dialer.go:332-341 的 auto 协商逻辑：
// auto/空 + 无 REALITY → packet-up
// auto/空 + REALITY（无 downloadSettings）→ stream-one
// auto/空 + REALITY（有 downloadSettings）→ stream-up
// 纯客户端本地决定，无需服务端握手。
func xhttpEffectiveMode(x model.XHTTP, realityEnabled bool) string {
	mode := x.Mode
	if mode == "" || mode == "auto" {
		mode = "packet-up"
		if realityEnabled {
			mode = "stream-one"
			if x.DownloadEndpointID != "" {
				mode = "stream-up"
			}
		}
	}
	return mode
}

func xhttpUplinkMethod(x model.XHTTP) string {
	if x.UplinkHTTPMethod == "" {
		return http.MethodPost
	}
	return x.UplinkHTTPMethod
}

func xhttpPostSize(x model.XHTTP) int {
	if x.MaxEachPostBytes > 0 {
		return x.MaxEachPostBytes
	}
	return xhttpChunk
}
func xhttpPostMaximum(x model.XHTTP) int {
	if x.PostBytesMax > 0 {
		return x.PostBytesMax
	}
	return xhttpPostSize(x)
}
func xhttpRequestTimeout(x model.XHTTP) time.Duration {
	if x.RequestTimeoutSeconds > 0 {
		return time.Duration(x.RequestTimeoutSeconds) * time.Second
	}
	return xhttpTimeout
}

func xhttpPaddingMinimum(x model.XHTTP) int {
	if x.PaddingBytes > 0 {
		return x.PaddingBytes
	}
	return 100
}
func xhttpPaddingMaximum(x model.XHTTP) int {
	if x.PaddingMaxBytes > 0 {
		return x.PaddingMaxBytes
	}
	return xhttpPaddingMinimum(x)
}
func xhttpPaddingSize(x model.XHTTP) int {
	min, max := xhttpPaddingMinimum(x), xhttpPaddingMaximum(x)
	if max <= min {
		return min
	}
	return min + mrand.IntN(max-min+1)
}

// Non-obfuscated XHTTP padding travels in Referer's query and X-Padding.
func xhttpPadRequest(req *http.Request, size int) {
	u := *req.URL
	u.RawQuery = "x_padding=" + strings.Repeat("X", size)
	req.Header.Set("Referer", u.String())
}

func xhttpApplyHeaders(req *http.Request, headers http.Header) {
	for key, values := range headers {
		req.Header.Set(key, values[0])
	}
}

func xhttpValidPadding(r *http.Request, size int) bool {
	return xhttpValidPaddingRange(r, size, size)
}
func xhttpValidPaddingRange(r *http.Request, min, max int) bool {
	values := r.Header.Values("Referer")
	if len(values) != 1 {
		return false
	}
	referer := values[0]
	if referer == "" {
		return false
	}
	u, err := url.Parse(referer)
	if err != nil || u.Path != r.URL.Path {
		return false
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil || len(q) != 1 || len(q["x_padding"]) != 1 {
		return false
	}
	p := q["x_padding"][0]
	return len(p) >= min && len(p) <= max && strings.Trim(p, "X") == ""
}

func xhttpPaddingPlacement(x model.XHTTP) string {
	if x.PaddingPlacement == "" {
		return "query_in_header"
	}
	return x.PaddingPlacement
}
func xhttpPaddingKey(x model.XHTTP) string {
	if x.PaddingKey == "" {
		return "x_padding"
	}
	return x.PaddingKey
}
func xhttpPaddingHeader(x model.XHTTP) string {
	if x.PaddingHeader != "" {
		return x.PaddingHeader
	}
	if xhttpPaddingPlacement(x) == "query_in_header" {
		return "Referer"
	}
	return "X-Padding"
}
func checkXHTTPPadding(x model.XHTTP) error {
	if !x.PaddingObfsMode {
		if x.PaddingPlacement != "" || x.PaddingKey != "" || x.PaddingHeader != "" || x.PaddingMethod != "" {
			return errors.New("xhttp padding options require padding_obfs_mode")
		}
		return nil
	}
	p := xhttpPaddingPlacement(x)
	switch p {
	case "query_in_header", "query", "header", "cookie":
	default:
		return errors.New("invalid xhttp padding_placement")
	}
	if x.PaddingMethod != "" && x.PaddingMethod != "repeat-x" && x.PaddingMethod != "tokenish" {
		return errors.New("invalid xhttp padding_method")
	}
	if x.PaddingKey != "" && p != "query_in_header" && p != "query" && p != "cookie" {
		return errors.New("xhttp padding_key not used by placement")
	}
	if x.PaddingHeader != "" && p != "query_in_header" && p != "header" {
		return errors.New("xhttp padding_header not used by placement")
	}
	key := xhttpPaddingKey(x)
	if p == "cookie" {
		if key != "x_padding" && !safeXHTTPMetaCookieKey(key) {
			return errors.New("invalid private xhttp padding cookie key")
		}
	} else if (p == "query" || p == "query_in_header") && !safeXHTTPMetaQueryKey(key) && key != "x_padding" {
		return errors.New("invalid xhttp padding query key")
	}
	if p == "query" || p == "cookie" || p == "query_in_header" {
		for _, field := range []struct{ placement, key string }{{x.SessionIDPlacement, xhttpSessionKey(x)}, {x.SeqPlacement, xhttpSequenceKey(x)}} {
			if field.key == key && (p == "query_in_header" || p == field.placement) {
				return errors.New("xhttp padding key collides with metadata")
			}
		}
	}
	if p == "header" || p == "query_in_header" {
		header := xhttpPaddingHeader(x)
		lower := strings.ToLower(header)
		if !((p == "query_in_header" && lower == "referer") || lower == "x-padding" || (strings.HasPrefix(lower, "x-custom-") && len(lower) > len("x-custom-"))) || !httpgutsValidHeaderName(header) {
			return errors.New("invalid or reserved xhttp padding header")
		}
		for _, key := range []string{xhttpSessionKey(x), xhttpSequenceKey(x)} {
			if strings.EqualFold(header, key) {
				return errors.New("xhttp padding header collides with metadata")
			}
		}
		headers, err := x.Headers.Entries()
		if err != nil {
			return err
		}
		if len(headers.Values(header)) != 0 {
			return errors.New("xhttp padding header collides with custom headers")
		}
	}
	return nil
}

func httpgutsValidHeaderName(name string) bool {
	if len(name) > 64 {
		return false
	}
	for i := range name {
		c := name[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

const xhttpBase62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

func xhttpPaddingValue(x model.XHTTP) (string, error) {
	target := xhttpPaddingSize(x)
	if !x.PaddingObfsMode || x.PaddingMethod != "tokenish" {
		return strings.Repeat("X", target), nil
	}
	// Rejection sampling avoids modulo bias; HPACK's byte count is the wire target.
	buf := make([]byte, 4096)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	value := make([]byte, 0, target*2+8)
	pos := 0
	for len(value) < 3000 {
		if pos == len(buf) {
			if _, err := rand.Read(buf); err != nil {
				return "", err
			}
			pos = 0
		}
		b := buf[pos]
		pos++
		if b >= 248 {
			continue
		}
		value = append(value, xhttpBase62[int(b)%62])
		length := int(hpack.HuffmanEncodeLength(string(value)))
		if length >= target-2 && length <= target+2 {
			return string(value), nil
		}
	}
	return "", errors.New("xhttp tokenish padding exceeds header budget")
}

func xhttpPaddingValidValue(value string, x model.XHTTP) bool {
	if value == "" || len(value) > 3000 {
		return false
	}
	if !x.PaddingObfsMode || x.PaddingMethod != "tokenish" {
		return len(value) >= xhttpPaddingMinimum(x) && len(value) <= xhttpPaddingMaximum(x) && strings.Trim(value, "X") == ""
	}
	for i := range value {
		if !strings.ContainsRune(xhttpBase62, rune(value[i])) {
			return false
		}
	}
	length := int(hpack.HuffmanEncodeLength(value))
	return length >= xhttpPaddingMinimum(x)-2 && length <= xhttpPaddingMaximum(x)+2
}

func xhttpSetPadding(req *http.Request, x model.XHTTP) error {
	value, err := xhttpPaddingValue(x)
	if err != nil {
		return err
	}
	if !x.PaddingObfsMode {
		xhttpPadRequest(req, len(value))
		return nil
	}
	switch xhttpPaddingPlacement(x) {
	case "query_in_header":
		u := *req.URL
		u.Host = req.Host
		u.RawQuery = url.Values{xhttpPaddingKey(x): {value}}.Encode()
		req.Header.Set(xhttpPaddingHeader(x), u.String())
	case "query":
		q := req.URL.Query()
		q.Set(xhttpPaddingKey(x), value)
		req.URL.RawQuery = q.Encode()
	case "header":
		req.Header.Set(xhttpPaddingHeader(x), value)
	case "cookie":
		req.AddCookie(&http.Cookie{Name: xhttpPaddingKey(x), Value: value})
	}
	return nil
}

func xhttpCheckRequestPadding(req *http.Request, x model.XHTTP) bool {
	if !x.PaddingObfsMode {
		return xhttpValidPaddingRange(req, xhttpPaddingMinimum(x), xhttpPaddingMaximum(x))
	}
	switch xhttpPaddingPlacement(x) {
	case "query_in_header":
		values := req.Header.Values(xhttpPaddingHeader(x))
		if len(values) != 1 {
			return false
		}
		u, err := url.Parse(values[0])
		if err != nil || u.Path != req.URL.Path || u.Fragment != "" || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host != req.Host {
			return false
		}
		q, err := url.ParseQuery(u.RawQuery)
		return err == nil && len(q) == 1 && len(q[xhttpPaddingKey(x)]) == 1 && xhttpPaddingValidValue(q[xhttpPaddingKey(x)][0], x)
	case "query":
		q, err := url.ParseQuery(req.URL.RawQuery)
		return err == nil && len(q[xhttpPaddingKey(x)]) == 1 && (x.Mode != "stream-one" || len(q) == 1) && xhttpPaddingValidValue(q[xhttpPaddingKey(x)][0], x)
	case "header":
		values := req.Header.Values(xhttpPaddingHeader(x))
		return len(values) == 1 && xhttpPaddingValidValue(values[0], x)
	case "cookie":
		values := req.Header.Values("Cookie")
		if len(values) != 1 {
			return false
		}
		cookies := req.Cookies()
		if len(cookies) != len(strings.Split(values[0], ";")) {
			return false
		}
		found := 0
		for _, c := range cookies {
			if c.Name == xhttpPaddingKey(x) {
				found++
				if !xhttpPaddingValidValue(c.Value, x) {
					return false
				}
			}
		}
		return found == 1
	}
	return false
}

func xhttpSetResponsePadding(w http.ResponseWriter, req *http.Request, x model.XHTTP) error {
	value, err := xhttpPaddingValue(x)
	if err != nil {
		return err
	}
	if !x.PaddingObfsMode {
		w.Header().Set("X-Padding", value)
		return nil
	}
	switch xhttpPaddingPlacement(x) {
	case "query_in_header", "header":
		w.Header().Set(xhttpPaddingHeader(x), value)
	case "query":
		w.Header().Set("X-Padding", value)
	case "cookie":
		http.SetCookie(w, &http.Cookie{Name: xhttpPaddingKey(x), Value: value, Path: "/", HttpOnly: true, Secure: req.TLS != nil})
	}
	return nil
}

func xhttpCheckResponsePadding(resp *http.Response, x model.XHTTP) bool {
	header := "X-Padding"
	if x.PaddingObfsMode {
		switch xhttpPaddingPlacement(x) {
		case "query_in_header", "header":
			header = xhttpPaddingHeader(x)
		case "cookie":
			values := resp.Header.Values("Set-Cookie")
			if len(values) != 1 {
				return false
			}
			cookies := resp.Cookies()
			return len(cookies) == 1 && cookies[0].Name == xhttpPaddingKey(x) && xhttpPaddingValidValue(cookies[0].Value, x)
		}
	}
	values := resp.Header.Values(header)
	return len(values) == 1 && xhttpPaddingValidValue(values[0], x)
}

// XHTTP's default session path is a UUID; reject noncanonical spellings.
func newXHTTPSessionID() (string, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", err
	}
	id[6] = id[6]&0x0f | 0x40
	id[8] = id[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", id[:4], id[4:6], id[6:8], id[8:10], id[10:]), nil
}

func validXHTTPSessionID(id string) bool {
	if len(id) != 36 || id[8] != '-' || id[13] != '-' || id[18] != '-' || id[23] != '-' {
		return false
	}
	compact := id[:8] + id[9:13] + id[14:18] + id[19:23] + id[24:]
	decoded, err := hex.DecodeString(compact)
	return err == nil && hex.EncodeToString(decoded) == compact
}

// Two independent pipes preserve EOF in one direction without closing the other.
// Pipe deadlines are real, mutable net.Conn deadlines, including blocked calls.
type xhttpStream struct{ r, w net.Conn }

func xhttpPair() (*xhttpStream, *xhttpStream) {
	ar, bw := net.Pipe()
	br, aw := net.Pipe()
	return &xhttpStream{ar, aw}, &xhttpStream{br, bw}
}
func (c *xhttpStream) Read(p []byte) (int, error)         { return c.r.Read(p) }
func (c *xhttpStream) Write(p []byte) (int, error)        { return c.w.Write(p) }
func (c *xhttpStream) CloseWrite() error                  { return c.w.Close() }
func (c *xhttpStream) Close() error                       { _ = c.r.Close(); return c.w.Close() }
func (c *xhttpStream) LocalAddr() net.Addr                { return c.r.LocalAddr() }
func (c *xhttpStream) RemoteAddr() net.Addr               { return c.r.RemoteAddr() }
func (c *xhttpStream) SetReadDeadline(t time.Time) error  { return c.r.SetReadDeadline(t) }
func (c *xhttpStream) SetWriteDeadline(t time.Time) error { return c.w.SetWriteDeadline(t) }
func (c *xhttpStream) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}

type xhttpSession struct {
	wire, app *xhttpStream
	mu        sync.Mutex
	next      uint64
	uploading bool
	eof       bool
	buffer    *xhttpBufferedState
}
type xhttpHandler struct {
	path                      string
	host                      string
	headers                   http.Header
	settings                  model.XHTTP
	mode                      string
	version                   string
	uplinkMethod              string
	noGRPCHeader, noSSEHeader bool
	accept                    func(net.Conn)
	mu                        sync.Mutex
	sessions                  map[string]*xhttpSession
	streams                   map[*xhttpStream]struct{}
	closed                    bool
	slots                     chan struct{}
	timeout                   time.Duration
	maxPost                   int
	padding, paddingMax       int
}

func newXHTTPHandler(path string, accept func(net.Conn)) *xhttpHandler {
	return &xhttpHandler{path: path, mode: "packet-up", uplinkMethod: http.MethodPost, accept: accept, sessions: make(map[string]*xhttpSession), streams: make(map[*xhttpStream]struct{}), slots: make(chan struct{}, 2*xhttpSessions), timeout: xhttpTimeout, maxPost: xhttpChunk, padding: 100, paddingMax: 100}
}
func (h *xhttpHandler) Close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.closed = true
	for _, s := range h.sessions {
		_ = s.wire.Close()
		_ = s.app.Close()
	}
	for c := range h.streams {
		_ = c.Close()
	}
}
func (h *xhttpHandler) settingsWithPadding() model.XHTTP {
	x := h.settings
	if x.PaddingBytes == 0 && h.padding != 100 {
		x.PaddingBytes = h.padding
	}
	if x.PaddingMaxBytes == 0 && h.paddingMax != 100 {
		x.PaddingMaxBytes = h.paddingMax
	}
	return x
}

func (h *xhttpHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	select {
	case h.slots <- struct{}{}:
		defer func() { <-h.slots }()
	default:
		http.Error(w, "busy", 503)
		return
	}
	if h.host != "" && r.Host != h.host {
		http.NotFound(w, r)
		return
	}
	for key, values := range h.headers {
		got := r.Header.Values(key)
		if len(got) != 1 || got[0] != values[0] {
			http.Error(w, "invalid request headers", http.StatusBadRequest)
			return
		}
	}
	if (h.mode == "stream-one" && r.URL.RawQuery != "" && !(h.settings.PaddingObfsMode && h.settings.PaddingPlacement == "query")) || r.URL.RawPath != "" || !strings.HasPrefix(r.URL.Path, h.path) {
		http.NotFound(w, r)
		return
	}
	if !xhttpCheckRequestPadding(r, h.settingsWithPadding()) {
		http.Error(w, "invalid padding", http.StatusBadRequest)
		return
	}
	if err := xhttpSetResponsePadding(w, r, h.settingsWithPadding()); err != nil {
		http.Error(w, "padding unavailable", http.StatusInternalServerError)
		return
	}
	if h.mode == "stream-one" {
		h.streamOne(w, r)
		return
	}
	withSeq := h.mode == "packet-up" && r.Method == h.uplinkMethod
	id, seqText, metaErr := xhttpGetMeta(r, h.settings, h.path, withSeq)
	if metaErr != nil {
		http.Error(w, "invalid session metadata", http.StatusBadRequest)
		return
	}
	if r.Method == http.MethodGet && (r.ContentLength == 0 || (r.ProtoMajor == 3 && r.ContentLength == -1)) {
		if h.mode == "stream-up" && r.ProtoMajor != h.streamHTTPMajor() {
			http.Error(w, "HTTP/2 required", http.StatusBadRequest)
			return
		}
		h.download(w, r, id)
		return
	}
	if h.mode == "stream-up" && r.Method == h.uplinkMethod {
		h.streamUpload(w, r, id)
		return
	}
	if r.Method != h.uplinkMethod || h.mode != "packet-up" {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	seq, _ := strconv.ParseUint(seqText, 10, 64)
	h.mu.Lock()
	s := h.sessions[id]
	h.mu.Unlock()
	if s == nil {
		http.Error(w, "unknown session", 404)
		return
	}
	if h.settings.MaxBufferedPosts != 0 || h.settings.MaxConcurrentPosts != 0 {
		h.bufferedUpload(w, r, s, seq)
		return
	}
	if !s.mu.TryLock() {
		http.Error(w, "concurrent upload", 409)
		return
	}
	defer s.mu.Unlock()
	if s.eof || seq != s.next {
		http.Error(w, "unexpected sequence", 409)
		return
	}
	rc := http.NewResponseController(w)
	if err := rc.SetReadDeadline(time.Now().Add(h.timeout)); err != nil {
		http.Error(w, "deadline unavailable", 500)
		return
	}
	defer rc.SetReadDeadline(time.Time{})
	body, err := xhttpReadData(r, h.settings, h.maxPost)
	if err != nil {
		http.Error(w, "invalid body", 400)
		return
	}
	if len(body) > h.maxPost {
		http.Error(w, "body too large", 413)
		return
	}
	eof := r.Header.Get("X-Veilink-EOF")
	if len(r.Header.Values("X-Veilink-EOF")) > 1 || (eof != "" && eof != "1") || (eof == "1" && len(body) != 0) || (eof == "" && len(body) == 0) {
		http.Error(w, "invalid EOF", 400)
		return
	}
	if eof == "1" {
		s.eof = true
		_ = s.wire.CloseWrite()
	} else {
		_ = s.wire.SetWriteDeadline(time.Now().Add(h.timeout))
		if _, err = s.wire.Write(body); err != nil {
			_ = s.wire.Close()
			http.Error(w, "upload closed", 410)
			return
		}
	}
	s.next++
	w.WriteHeader(http.StatusOK)
}
func (h *xhttpHandler) download(w http.ResponseWriter, r *http.Request, id string) {
	h.mu.Lock()
	if h.closed || len(h.sessions)+len(h.streams) >= xhttpSessions {
		h.mu.Unlock()
		http.Error(w, "session limit", 503)
		return
	}
	if h.sessions[id] != nil {
		h.mu.Unlock()
		http.Error(w, "duplicate session", 409)
		return
	}
	app, wire := xhttpPair()
	s := &xhttpSession{wire: wire, app: app}
	h.sessions[id] = s
	h.mu.Unlock()
	cleanEOF := false
	defer func() {
		if !cleanEOF {
			_ = wire.Close()
			_ = app.Close()
		}
	}()
	stop := context.AfterFunc(r.Context(), func() { _ = wire.Close(); _ = app.Close() })
	defer stop()
	// Keep upload alive after download EOF until the application finishes.
	go func() {
		defer func() { _ = wire.Close(); _ = app.Close(); h.mu.Lock(); delete(h.sessions, id); h.mu.Unlock() }()
		h.accept(app)
	}()
	if !h.noSSEHeader {
		w.Header().Set("Content-Type", "text/event-stream")
	} else {
		w.Header()["Content-Type"] = nil // suppress net/http's content sniffing
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	rc := http.NewResponseController(w)
	if err := rc.SetWriteDeadline(time.Now().Add(h.timeout)); err != nil {
		return
	}
	if err := rc.Flush(); err != nil {
		return
	}
	buf := make([]byte, xhttpChunk)
	for {
		_ = wire.SetReadDeadline(time.Now().Add(90 * time.Second))
		n, err := wire.Read(buf)
		if n > 0 {
			if rc.SetWriteDeadline(time.Now().Add(h.timeout)) != nil {
				return
			}
			if _, e := w.Write(buf[:n]); e != nil {
				return
			}
			if rc.Flush() != nil {
				return
			}
		}
		if err != nil {
			cleanEOF = err == io.EOF
			if cleanEOF {
				// The GET context ends here, so bound the remaining upload
				// lifetime explicitly even if the peer never sends EOF.
				_ = app.SetReadDeadline(time.Now().Add(90 * time.Second))
				stop() // A clean download EOF must not cancel remaining upload POSTs.
			}
			return
		}
	}
}

// Bound accepted TCP connections as well as sessions and handlers, including
// peers that stall before sending headers. net/http closes them on timeout.
type xhttpListener struct {
	net.Listener
	slots chan struct{}
}
type xhttpSocket struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *xhttpSocket) Close() error { err := c.Conn.Close(); c.once.Do(c.release); return err }
func (l *xhttpListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		select {
		case l.slots <- struct{}{}:
			return &xhttpSocket{Conn: c, release: func() { <-l.slots }}, nil
		default:
			_ = c.Close()
		}
	}
}
func (s *service) serveXHTTP(ln net.Listener) {
	h := newXHTTPHandler(s.local.XHTTP.Path, func(c net.Conn) {
		if !s.track(c) {
			_ = c.Close()
			return
		}
		s.authenticate(c)
	})
	h.mode = xhttpEffectiveMode(s.local.XHTTP, s.local.Reality.Enabled())
	h.settings = s.local.XHTTP
	h.host = s.local.XHTTP.Host
	h.headers, _ = s.local.XHTTP.Headers.Entries()
	h.version = s.local.XHTTP.HTTPVersion
	h.uplinkMethod = xhttpUplinkMethod(s.local.XHTTP)
	h.noGRPCHeader, h.noSSEHeader = s.local.XHTTP.NoGRPCHeader, s.local.XHTTP.NoSSEHeader
	h.timeout = xhttpRequestTimeout(s.local.XHTTP)
	h.padding, h.paddingMax = xhttpPaddingMinimum(s.local.XHTTP), xhttpPaddingMaximum(s.local.XHTTP)
	h.maxPost = xhttpPostMaximum(s.local.XHTTP)
	server := &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: xhttpServerHeaderLimit(s.local.XHTTP), BaseContext: func(net.Listener) context.Context { return s.ctx }}
	if xhttpPriorHTTP2(s.local) {
		protocols := new(http.Protocols)
		protocols.SetUnencryptedHTTP2(true)
		server.Protocols = protocols // prior knowledge only; no implicit HTTP/1.1 fallback
	}
	s.xhttpClose = func() { h.Close(); _ = server.Close() }
	ln = &xhttpListener{Listener: ln, slots: make(chan struct{}, 2*xhttpSessions)}
	if s.tlsConfig != nil {
		cfg := s.tlsConfig.Clone()
		cfg.NextProtos = []string{"h2", "http/1.1"}
		ln = tls.NewListener(ln, cfg)
	}
	go func() { _ = server.Serve(ln) }()
}

type xhttpClientConn struct {
	*xhttpStream
	cancel            context.CancelFunc
	transport         xhttpCloser
	writeMu           sync.Mutex
	ack               net.Conn
	postSize, postMax int
}

// A successful Write acknowledges delivery, not merely staging in a pipe;
// callers may immediately Close after their final response.
func (c *xhttpClientConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	total := 0
	for len(p) > 0 {
		limit := c.postSize
		if limit == 0 {
			limit = xhttpChunk
		}
		if c.postMax > limit {
			limit += mrand.IntN(c.postMax - limit + 1)
		}
		n := len(p)
		if n > limit {
			n = limit
		}
		if _, err := c.xhttpStream.Write(p[:n]); err != nil {
			return total, err
		}
		var ack [1]byte
		if _, err := io.ReadFull(c.ack, ack[:]); err != nil {
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
}
func (c *xhttpClientConn) SetWriteDeadline(t time.Time) error {
	_ = c.ack.SetReadDeadline(t)
	return c.xhttpStream.SetWriteDeadline(t)
}
func (c *xhttpClientConn) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}
func (c *xhttpClientConn) Close() error {
	c.cancel()
	_ = c.ack.Close()
	closeXHTTPTransport(c.transport)
	return c.xhttpStream.Close()
}
func dialXHTTP(ctx context.Context, addr, serverName string, local model.LocalTLS) (net.Conn, error) {
	return dialXHTTPWithDialer(ctx, addr, serverName, local, func(ctx context.Context) (net.Conn, error) {
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", addr)
	})
}
func DialXHTTP(ctx context.Context, addr, serverName string, local model.LocalTLS) (net.Conn, error) {
	return dialXHTTP(ctx, addr, serverName, local)
}

func dialXHTTPWithDialer(ctx context.Context, addr, serverName string, local model.LocalTLS, dial func(context.Context) (net.Conn, error)) (net.Conn, error) {
	return dialXHTTPWithDownDialer(ctx, addr, serverName, local, dial, nil, "")
}

func dialXHTTPWithDownDialer(ctx context.Context, addr, serverName string, local model.LocalTLS, dial func(context.Context) (net.Conn, error), downDial func(context.Context) (net.Conn, error), downAddr string) (net.Conn, error) {
	headers, err := local.XHTTP.Headers.Entries()
	if err != nil {
		return nil, err
	}
	if err := checkXHTTPMeta(local.XHTTP, xhttpEffectiveMode(local.XHTTP, local.Reality.Enabled())); err != nil {
		return nil, err
	}
	if err := checkXHTTPPadding(local.XHTTP); err != nil {
		return nil, err
	}
	if err := checkXHTTPBuffer(local.XHTTP, xhttpEffectiveMode(local.XHTTP, local.Reality.Enabled())); err != nil {
		return nil, err
	}
	if err := checkXHTTPData(local.XHTTP, xhttpEffectiveMode(local.XHTTP, local.Reality.Enabled())); err != nil {
		return nil, err
	}
	if err := checkXHTTPMux(local.XHTTP); err != nil {
		return nil, err
	}
	if local.XHTTP.DownloadEndpointID != "" && downAddr == "" {
		return nil, errors.New("xhttp download endpoint requires an authorized downlink dialer")
	}
	pool, err := roots(local.CAPEM)
	if err != nil {
		return nil, err
	}
	timeout := xhttpRequestTimeout(local.XHTTP)
	createTransport := func(dialer func(context.Context) (net.Conn, error), tlsName string) (xhttpCloser, error) {
		if local.XHTTP.HTTPVersion == "3" {
			return newXHTTP3ClientTransport(pool, tlsName, time.Duration(local.XHTTP.Xmux.KeepAlivePeriod)*time.Second), nil
		}
		if xhttpPriorHTTP2(local) {
			protocols := new(http.Protocols)
			protocols.SetUnencryptedHTTP2(true)
			return &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return dialer(ctx) }, Protocols: protocols, HTTP2: xhttpHTTP2Config(local.XHTTP.Xmux.KeepAlivePeriod), MaxIdleConnsPerHost: 8, IdleConnTimeout: 30 * time.Second, ResponseHeaderTimeout: timeout, MaxResponseHeaderBytes: 8 << 10, DisableCompression: true}, nil
		}
		return &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return dialer(ctx) }, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, ServerName: tlsName, NextProtos: xhttpClientALPN(local.XHTTP.HTTPVersion)}, ForceAttemptHTTP2: local.XHTTP.TLS && !local.Reality.Enabled() && local.XHTTP.HTTPVersion != "1.1", TLSNextProto: xhttpTLSNextProto(local.XHTTP.HTTPVersion), HTTP2: xhttpHTTP2Config(local.XHTTP.Xmux.KeepAlivePeriod), MaxConnsPerHost: 0, MaxIdleConnsPerHost: 8, IdleConnTimeout: 30 * time.Second, TLSHandshakeTimeout: timeout, ResponseHeaderTimeout: timeout, MaxResponseHeaderBytes: 8 << 10, DisableCompression: true}, nil
	}
	var tr xhttpCloser
	if local.XHTTP.Xmux != (model.XHTTPXmux{}) {
		lease, e := globalXHTTPMuxPool.acquire(ctx, xhttpMuxKey(addr, serverName, local), local.XHTTP, func() (xhttpCloser, error) { return createTransport(dial, serverName) })
		if e != nil {
			return nil, e
		}
		tr = lease
	} else {
		tr, err = createTransport(dial, serverName)
		if err != nil {
			return nil, err
		}
	}
	downTr := tr
	downAddrActual := addr
	downName := serverName
	downDialActual := dial
	if local.XHTTP.DownloadEndpointID != "" {
		if downDial == nil || downAddr == "" {
			closeXHTTPTransport(tr)
			return nil, errors.New("xhttp authorized downlink transport unavailable")
		}
		downAddrActual = downAddr
		if host, _, e := net.SplitHostPort(downAddr); e == nil {
			downName = host
		}
		downDialActual = downDial
		if local.XHTTP.Xmux != (model.XHTTPXmux{}) {
			lease, e := globalXHTTPMuxPool.acquire(ctx, xhttpMuxKey(downAddrActual, downName, local), local.XHTTP, func() (xhttpCloser, error) { return createTransport(downDialActual, downName) })
			if e != nil {
				closeXHTTPTransport(tr)
				return nil, e
			}
			downTr = lease
		} else {
			downTr, err = createTransport(downDialActual, downName)
			if err != nil {
				closeXHTTPTransport(tr)
				return nil, err
			}
		}
	}
	client := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("xhttp redirects forbidden") }}
	downClient := client
	if downTr != tr {
		downClient = &http.Client{Transport: downTr, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("xhttp redirects forbidden") }}
	}
	ctx, cancel := context.WithCancel(ctx)
	fail := func(err error) (net.Conn, error) {
		cancel()
		closeXHTTPTransport(&xhttpTransportPair{up: tr, down: downTr})
		return nil, err
	}
	id, err := newXHTTPSessionIDFor(local.XHTTP)
	if err != nil {
		return fail(err)
	}
	base := "http://" + addr
	if local.XHTTP.TLS {
		base = "https://" + addr
	}
	downBase := "http://" + downAddrActual
	if local.XHTTP.TLS {
		downBase = "https://" + downAddrActual
	}
	if xhttpEffectiveMode(local.XHTTP, local.Reality.Enabled()) == "stream-one" || xhttpEffectiveMode(local.XHTTP, local.Reality.Enabled()) == "stream-up" {
		return dialXHTTPStream(ctx, client, downClient, &xhttpTransportPair{up: tr, down: downTr}, base+local.XHTTP.Path, downBase+local.XHTTP.Path, local.XHTTP, local.Reality.Enabled(), headers, cancel)
	}
	url := xhttpMetaPath(downBase+local.XHTTP.Path, local.XHTTP, id, "")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fail(err)
	}
	if local.XHTTP.Host != "" {
		req.Host = local.XHTTP.Host
	}
	xhttpApplyHeaders(req, headers)
	xhttpSetMeta(req, local.XHTTP, id, "")
	if err := xhttpSetPadding(req, local.XHTTP); err != nil {
		return fail(err)
	}
	// Bound the initial GET response headers (including HTTP/3, which has no
	// ResponseHeaderTimeout). Stop the timer once the streaming body is open.
	setupTimer := time.AfterFunc(timeout, cancel)
	resp, err := downClient.Do(req)
	if err != nil {
		return fail(err)
	}
	if resp.StatusCode != 200 || !xhttpCheckResponsePadding(resp, local.XHTTP) || (local.XHTTP.HTTPVersion == "2" && resp.ProtoMajor != 2) || (local.XHTTP.HTTPVersion == "3" && resp.ProtoMajor != 3) || (local.XHTTP.HTTPVersion == "1.1" && resp.ProtoMajor != 1) {
		_ = resp.Body.Close()
		return fail(fmt.Errorf("xhttp GET status %d", resp.StatusCode))
	}
	if !setupTimer.Stop() {
		_ = resp.Body.Close()
		return fail(context.DeadlineExceeded)
	}
	app, wire := xhttpPair()
	ack, ackWriter := net.Pipe()
	postMax := xhttpUploadLimit(local.XHTTP)
	postSize := min(xhttpPostSize(local.XHTTP), postMax)
	c := &xhttpClientConn{xhttpStream: app, cancel: cancel, transport: &xhttpTransportPair{up: tr, down: downTr}, ack: ack, postSize: postSize, postMax: postMax}
	context.AfterFunc(ctx, func() {
		_ = ack.Close()
		_ = ackWriter.Close()
		_ = app.Close()
		_ = wire.Close()
		_ = resp.Body.Close()
		closeXHTTPTransport(&xhttpTransportPair{up: tr, down: downTr})
	})
	go func() {
		defer resp.Body.Close()
		_, err := io.Copy(wire, resp.Body)
		if err != nil {
			_ = c.Close()
		} else {
			_ = wire.CloseWrite()
		}
	}()
	if local.XHTTP.MaxBufferedPosts != 0 || local.XHTTP.MaxConcurrentPosts != 0 {
		_ = ackWriter.Close()
		_ = wire.r.Close()
		return &xhttpBufferedClient{xhttpClientConn: c, client: client, ctx: ctx, base: base + local.XHTTP.Path, id: id, settings: local.XHTTP, headers: headers}, nil
	}
	go func() {
		defer wire.r.Close()
		defer ackWriter.Close()
		var seq uint64
		var lastPost time.Time
		buf := make([]byte, postMax)
		for {
			n, readErr := wire.Read(buf)
			if readErr != nil && readErr != io.EOF {
				return
			}
			if n == 0 && readErr == nil {
				continue
			}
			if !lastPost.IsZero() && local.XHTTP.MinPostsIntervalMs > 0 {
				interval := local.XHTTP.MinPostsIntervalMs
				if local.XHTTP.MaxPostsIntervalMs > interval {
					interval += mrand.IntN(local.XHTTP.MaxPostsIntervalMs - interval + 1)
				}
				if delay := time.Until(lastPost.Add(time.Duration(interval) * time.Millisecond)); delay > 0 {
					timer := time.NewTimer(delay)
					select {
					case <-timer.C:
					case <-ctx.Done():
						timer.Stop()
						return
					}
				}
			}
			lastPost = time.Now()
			postCtx, postCancel := context.WithTimeout(ctx, timeout)
			seqText := strconv.FormatUint(seq, 10)
			req, e := http.NewRequestWithContext(postCtx, xhttpUplinkMethod(local.XHTTP), xhttpMetaPath(base+local.XHTTP.Path, local.XHTTP, id, seqText), bytes.NewReader(buf[:n]))
			if e == nil {
				if xhttpDataPlacement(local.XHTTP) != "body" {
					e = xhttpEncodeData(req, buf[:n], local.XHTTP)
				}
				if local.XHTTP.Host != "" {
					req.Host = local.XHTTP.Host
				}
				xhttpApplyHeaders(req, headers)
				xhttpSetMeta(req, local.XHTTP, id, seqText)
				if e == nil {
					e = xhttpSetPadding(req, local.XHTTP)
				}
			}
			if e == nil {
				if readErr == io.EOF {
					req.Header.Set("X-Veilink-EOF", "1")
				}
				var reply *http.Response
				reply, e = client.Do(req)
				if e == nil {
					if reply.StatusCode != http.StatusOK || !xhttpCheckResponsePadding(reply, local.XHTTP) {
						e = fmt.Errorf("xhttp POST status %d", reply.StatusCode)
					}
					_ = reply.Body.Close()
				}
			}
			postCancel()
			if e != nil {
				_ = c.Close()
				return
			}
			seq++
			if readErr == io.EOF {
				return
			}
			if _, err := ackWriter.Write([]byte{1}); err != nil {
				return
			}
		}
	}()
	return c, nil
}
