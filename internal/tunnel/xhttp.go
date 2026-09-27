package tunnel

// Native, private packet-up transport, independently implemented from behavioral
// semantics only (the reference splithttp implementation is MPL-2.0; no source
// is incorporated). HTTP/1.1 only; not an Xray interoperability promise.
// GET path/<random session> establishes download before any upload. POST
// path/<session>/<decimal sequence> sends <=32 KiB in exact order. The private
// X-Veilink-EOF: 1 extension on an empty sequenced POST half-closes upload.
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
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"veilink/internal/model"
)

const (
	xhttpChunk    = 32 << 10
	xhttpSessions = 128
	xhttpTimeout  = 15 * time.Second
)

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
	eof       bool
}
type xhttpHandler struct {
	path     string
	accept   func(net.Conn)
	mu       sync.Mutex
	sessions map[string]*xhttpSession
	closed   bool
	slots    chan struct{}
}

func newXHTTPHandler(path string, accept func(net.Conn)) *xhttpHandler {
	return &xhttpHandler{path: path, accept: accept, sessions: make(map[string]*xhttpSession), slots: make(chan struct{}, 2*xhttpSessions)}
}
func (h *xhttpHandler) Close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.closed = true
	for _, s := range h.sessions {
		_ = s.wire.Close()
		_ = s.app.Close()
	}
}
func (h *xhttpHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	select {
	case h.slots <- struct{}{}:
		defer func() { <-h.slots }()
	default:
		http.Error(w, "busy", 503)
		return
	}
	if r.ProtoMajor != 1 || r.URL.RawQuery != "" || r.URL.RawPath != "" || !strings.HasPrefix(r.URL.Path, h.path) {
		http.NotFound(w, r)
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, h.path), "/")
	id, err := hex.DecodeString(parts[0])
	if err != nil || len(id) != 32 || parts[0] != hex.EncodeToString(id) {
		http.Error(w, "invalid session", 400)
		return
	}
	if r.Method == http.MethodGet && len(parts) == 1 && r.ContentLength == 0 {
		h.download(w, r, parts[0])
		return
	}
	if r.Method != http.MethodPost || len(parts) != 2 {
		http.Error(w, "invalid request", 400)
		return
	}
	seq, err := strconv.ParseUint(parts[1], 10, 64)
	if err != nil || strconv.FormatUint(seq, 10) != parts[1] {
		http.Error(w, "invalid sequence", 400)
		return
	}
	h.mu.Lock()
	s := h.sessions[parts[0]]
	h.mu.Unlock()
	if s == nil {
		http.Error(w, "unknown session", 404)
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
	if err := rc.SetReadDeadline(time.Now().Add(xhttpTimeout)); err != nil {
		http.Error(w, "deadline unavailable", 500)
		return
	}
	defer rc.SetReadDeadline(time.Time{})
	body, err := io.ReadAll(io.LimitReader(r.Body, xhttpChunk+1))
	if err != nil {
		http.Error(w, "invalid body", 400)
		return
	}
	if len(body) > xhttpChunk {
		http.Error(w, "body too large", 413)
		return
	}
	eof := r.Header.Get("X-Veilink-EOF")
	if (eof != "" && eof != "1") || (eof == "1" && len(body) != 0) || (eof == "" && len(body) == 0) {
		http.Error(w, "invalid EOF", 400)
		return
	}
	if eof == "1" {
		s.eof = true
		_ = s.wire.CloseWrite()
	} else {
		_ = s.wire.SetWriteDeadline(time.Now().Add(xhttpTimeout))
		if _, err = s.wire.Write(body); err != nil {
			_ = s.wire.Close()
			http.Error(w, "upload closed", 410)
			return
		}
	}
	s.next++
	w.WriteHeader(http.StatusNoContent)
}
func (h *xhttpHandler) download(w http.ResponseWriter, r *http.Request, id string) {
	h.mu.Lock()
	if h.closed || len(h.sessions) >= xhttpSessions {
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
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	rc := http.NewResponseController(w)
	if err := rc.SetWriteDeadline(time.Now().Add(xhttpTimeout)); err != nil {
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
			if rc.SetWriteDeadline(time.Now().Add(xhttpTimeout)) != nil {
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
	server := &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8 << 10, BaseContext: func(net.Listener) context.Context { return s.ctx }}
	s.xhttpClose = func() { h.Close(); _ = server.Close() }
	ln = &xhttpListener{Listener: ln, slots: make(chan struct{}, 2*xhttpSessions)}
	if s.tlsConfig != nil {
		cfg := s.tlsConfig.Clone()
		cfg.NextProtos = []string{"http/1.1"}
		ln = tls.NewListener(ln, cfg)
	}
	go func() { _ = server.Serve(ln) }()
}

type xhttpClientConn struct {
	*xhttpStream
	cancel    context.CancelFunc
	transport *http.Transport
	writeMu   sync.Mutex
	ack       net.Conn
}

// A successful Write acknowledges delivery, not merely staging in a pipe;
// callers may immediately Close after their final response.
func (c *xhttpClientConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > xhttpChunk {
			n = xhttpChunk
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
	c.transport.CloseIdleConnections()
	return c.xhttpStream.Close()
}
func dialXHTTP(ctx context.Context, addr, serverName string, local model.LocalTLS) (net.Conn, error) {
	pool, err := roots(local.CAPEM)
	if err != nil {
		return nil, err
	}
	tr := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, ServerName: serverName, NextProtos: []string{"http/1.1"}},
		TLSNextProto:    map[string]func(string, *tls.Conn) http.RoundTripper{}, ForceAttemptHTTP2: false,
		MaxConnsPerHost: 2, MaxIdleConnsPerHost: 2, IdleConnTimeout: 30 * time.Second, TLSHandshakeTimeout: xhttpTimeout, ResponseHeaderTimeout: xhttpTimeout, MaxResponseHeaderBytes: 8 << 10, DisableCompression: true}
	client := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("xhttp redirects forbidden") }}
	ctx, cancel := context.WithCancel(ctx)
	fail := func(err error) (net.Conn, error) { cancel(); tr.CloseIdleConnections(); return nil, err }
	var id [32]byte
	if _, err = rand.Read(id[:]); err != nil {
		return fail(err)
	}
	scheme := "http"
	if local.XHTTP.TLS {
		scheme = "https"
	}
	url := scheme + "://" + addr + local.XHTTP.Path + hex.EncodeToString(id[:])
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fail(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fail(err)
	}
	if resp.StatusCode != 200 {
		_ = resp.Body.Close()
		return fail(fmt.Errorf("xhttp GET status %d", resp.StatusCode))
	}
	app, wire := xhttpPair()
	ack, ackWriter := net.Pipe()
	c := &xhttpClientConn{xhttpStream: app, cancel: cancel, transport: tr, ack: ack}
	context.AfterFunc(ctx, func() {
		_ = ack.Close()
		_ = ackWriter.Close()
		_ = app.Close()
		_ = wire.Close()
		_ = resp.Body.Close()
		tr.CloseIdleConnections()
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
	go func() {
		defer wire.r.Close()
		defer ackWriter.Close()
		var seq uint64
		buf := make([]byte, xhttpChunk)
		for {
			n, readErr := wire.Read(buf)
			if readErr != nil && readErr != io.EOF {
				return
			}
			if n == 0 && readErr == nil {
				continue
			}
			postCtx, postCancel := context.WithTimeout(ctx, xhttpTimeout)
			req, e := http.NewRequestWithContext(postCtx, http.MethodPost, url+"/"+strconv.FormatUint(seq, 10), bytes.NewReader(buf[:n]))
			if e == nil {
				if readErr == io.EOF {
					req.Header.Set("X-Veilink-EOF", "1")
				}
				var reply *http.Response
				reply, e = client.Do(req)
				if e == nil {
					if reply.StatusCode != 204 {
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
