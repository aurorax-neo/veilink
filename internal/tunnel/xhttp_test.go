package tunnel

import (
	"bytes"
	"context"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"testing"
	"time"

	"veilink/internal/model"
)

func xhttpTestDial(t *testing.T, ctx context.Context, s *httptest.Server, secure bool) (net.Conn, error) {
	t.Helper()
	u, _ := url.Parse(s.URL)
	host, _, _ := net.SplitHostPort(u.Host)
	local := model.LocalTLS{XHTTP: model.XHTTP{Path: "/packet/", Mode: "packet-up", TLS: secure}}
	if secure {
		local.CAPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw}))
	}
	return dialXHTTP(ctx, u.Host, host, local)
}
func TestXHTTPRoundtrip(t *testing.T) {
	for _, mode := range []string{"plain", "tls", "proxy"} {
		t.Run(mode, func(t *testing.T) {
			h := newXHTTPHandler("/packet/", func(c net.Conn) {
				defer c.Close()
				b, e := io.ReadAll(c)
				if e == nil {
					_, _ = c.Write(b)
				}
			})
			defer h.Close()
			var s *httptest.Server
			if mode == "tls" {
				s = httptest.NewTLSServer(h)
			} else {
				s = httptest.NewServer(h)
			}
			defer s.Close()
			if mode == "proxy" {
				u, _ := url.Parse(s.URL)
				p := httputil.NewSingleHostReverseProxy(u)
				p.FlushInterval = -1
				edge := httptest.NewTLSServer(p)
				defer edge.Close()
				s = edge
			}
			c, e := xhttpTestDial(t, context.Background(), s, mode != "plain")
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			want := bytes.Repeat([]byte("packet-up"), 10000)
			if _, e = c.Write(want); e != nil {
				t.Fatal(e)
			}
			if e = c.(interface{ CloseWrite() error }).CloseWrite(); e != nil {
				t.Fatal(e)
			}
			got, e := io.ReadAll(c)
			if e != nil {
				t.Fatal(e)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("got %d bytes want %d", len(got), len(want))
			}
		})
	}
}
func TestXHTTPUntrusted(t *testing.T) {
	h := newXHTTPHandler("/packet/", func(c net.Conn) { _ = c.Close() })
	defer h.Close()
	s := httptest.NewTLSServer(h)
	defer s.Close()
	u, _ := url.Parse(s.URL)
	host, _, _ := net.SplitHostPort(u.Host)
	c, e := dialXHTTP(context.Background(), u.Host, host, model.LocalTLS{XHTTP: model.XHTTP{Path: "/packet/", Mode: "packet-up", TLS: true}})
	if e == nil {
		c.Close()
		t.Fatal("accepted untrusted certificate")
	}
}
func TestXHTTPDeadlineCancellation(t *testing.T) {
	done := make(chan struct{})
	h := newXHTTPHandler("/packet/", func(c net.Conn) { defer close(done); defer c.Close(); _, _ = io.Copy(io.Discard, c) })
	defer h.Close()
	s := httptest.NewServer(h)
	defer s.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c, e := xhttpTestDial(t, ctx, s, false)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	_, e = c.Read(make([]byte, 1))
	if ne, ok := e.(net.Error); !ok || !ne.Timeout() {
		t.Fatalf("deadline: %v", e)
	}
	_ = c.SetReadDeadline(time.Time{})
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("server not canceled")
	}
	_, e = c.Read(make([]byte, 1))
	if e == nil {
		t.Fatal("read after cancel")
	}
}
func TestXHTTPRejects(t *testing.T) {
	h := newXHTTPHandler("/packet/", func(c net.Conn) { defer c.Close(); _, _ = io.Copy(io.Discard, c) })
	defer h.Close()
	s := httptest.NewServer(h)
	defer s.Close()
	id := strings.Repeat("a", 64)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", s.URL+"/packet/"+id, nil)
	down, e := s.Client().Do(req)
	if e != nil {
		t.Fatal(e)
	}
	defer down.Body.Close()
	cases := []struct {
		path, body string
		status     int
	}{
		{id + "/0", "a", 204}, {id + "/0", "a", 409}, {id + "/2", "a", 409},
		{id + "/01", "a", 400}, {"bad/0", "a", 400}, {strings.Repeat("b", 64) + "/0", "a", 404},
		{id + "/1", strings.Repeat("x", xhttpChunk+1), 413}, {id + "/1", "", 400},
	}
	for _, tt := range cases {
		r, e := s.Client().Post(s.URL+"/packet/"+tt.path, "application/octet-stream", strings.NewReader(tt.body))
		if e != nil {
			t.Fatal(e)
		}
		_ = r.Body.Close()
		if r.StatusCode != tt.status {
			t.Fatalf("%s: %d want %d", tt.path, r.StatusCode, tt.status)
		}
	}
	r, e := s.Client().Get(s.URL + "/packet/" + id)
	if e != nil {
		t.Fatal(e)
	}
	r.Body.Close()
	if r.StatusCode != 409 {
		t.Fatal(r.StatusCode)
	}
}
func TestXHTTPSessionLimit(t *testing.T) {
	h := newXHTTPHandler("/packet/", func(c net.Conn) { defer c.Close(); _, _ = io.Copy(io.Discard, c) })
	defer h.Close()
	s := httptest.NewServer(h)
	defer s.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for i := 0; i < xhttpSessions; i++ {
		req, _ := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/packet/%064x", s.URL, i), nil)
		r, e := s.Client().Do(req)
		if e != nil {
			t.Fatal(e)
		}
		defer r.Body.Close()
		if r.StatusCode != 200 {
			t.Fatal(r.StatusCode)
		}
	}
	r, e := s.Client().Get(fmt.Sprintf("%s/packet/%064x", s.URL, xhttpSessions))
	if e != nil {
		t.Fatal(e)
	}
	r.Body.Close()
	if r.StatusCode != 503 {
		t.Fatal(r.StatusCode)
	}
}
func TestXHTTPWriteDeadline(t *testing.T) {
	a, b := xhttpPair()
	defer a.Close()
	defer b.Close()
	done := make(chan error, 1)
	go func() { _, e := a.Write([]byte("blocked")); done <- e }()
	_ = a.SetWriteDeadline(time.Now().Add(20 * time.Millisecond))
	select {
	case e := <-done:
		if ne, ok := e.(net.Error); !ok || !ne.Timeout() {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("ignored write deadline")
	}
}
