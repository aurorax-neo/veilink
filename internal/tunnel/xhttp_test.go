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
	"sync"
	"testing"
	"time"

	"veilink/internal/model"
)

const xhttpTestSession = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"

func TestXHTTPSessionID(t *testing.T) {
	first, err := newXHTTPSessionID()
	if err != nil || !validXHTTPSessionID(first) || first[14] != '4' || !strings.ContainsRune("89ab", rune(first[19])) {
		t.Fatalf("invalid generated UUID %q: %v", first, err)
	}
	second, err := newXHTTPSessionID()
	if err != nil || first == second || !validXHTTPSessionID(second) {
		t.Fatalf("duplicate or invalid generated UUID %q: %v", second, err)
	}
	for _, invalid := range []string{"", strings.Repeat("a", 64), strings.ToUpper(first), first[:8] + "_" + first[9:], first[:35] + "g"} {
		if validXHTTPSessionID(invalid) {
			t.Fatalf("accepted noncanonical session ID %q", invalid)
		}
	}
}

func xhttpTestDial(t *testing.T, ctx context.Context, s *httptest.Server, secure bool, settings ...model.XHTTP) (net.Conn, error) {
	t.Helper()
	u, _ := url.Parse(s.URL)
	host, _, _ := net.SplitHostPort(u.Host)
	x := model.XHTTP{Path: "/packet/", Mode: "packet-up", TLS: secure}
	if len(settings) > 0 {
		x = settings[0]
	}
	local := model.LocalTLS{XHTTP: x}
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

func TestXHTTPCustomPostSizeAndTimeoutRoundtrip(t *testing.T) {
	h := newXHTTPHandler("/packet/", func(c net.Conn) {
		defer c.Close()
		b, err := io.ReadAll(c)
		if err == nil {
			_, _ = c.Write(b)
		}
	})
	h.timeout = 5 * time.Second
	defer h.Close()
	var mu sync.Mutex
	var posts []int64
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			mu.Lock()
			posts = append(posts, r.ContentLength)
			mu.Unlock()
		}
		h.ServeHTTP(w, r)
	}))
	defer s.Close()
	c, err := xhttpTestDial(t, context.Background(), s, false, model.XHTTP{Path: "/packet/", Mode: "packet-up", MaxEachPostBytes: 1024, RequestTimeoutSeconds: 5})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	want := bytes.Repeat([]byte("a"), 4096)
	if _, err = c.Write(want); err != nil {
		t.Fatal(err)
	}
	if err = c.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(c)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("roundtrip: %d bytes, %v", len(got), err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(posts) < 5 {
		t.Fatalf("expected four chunks and EOF, got %v", posts)
	}
	for _, size := range posts {
		if size > 1024 {
			t.Fatalf("oversized POST: %d", size)
		}
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
	id := xhttpTestSession
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", s.URL+"/packet/"+id, nil)
	xhttpPadRequest(req, 100)
	down, e := s.Client().Do(req)
	if e != nil {
		t.Fatal(e)
	}
	defer down.Body.Close()
	cases := []struct {
		path, body string
		status     int
	}{
		{id + "/0", "a", 200}, {id + "/0", "a", 409}, {id + "/2", "a", 409},
		{id + "/01", "a", 400}, {"bad/0", "a", 400}, {"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb/0", "a", 404},
		{id + "/1", strings.Repeat("x", xhttpChunk+1), 413}, {id + "/1", "", 400},
	}
	for _, tt := range cases {
		r, e := xhttpPostTest(s.Client(), s.URL+"/packet/"+tt.path, tt.body)
		if e != nil {
			t.Fatal(e)
		}
		_ = r.Body.Close()
		if r.StatusCode != tt.status {
			t.Fatalf("%s: %d want %d", tt.path, r.StatusCode, tt.status)
		}
	}
	r, e := xhttpGetTest(s.Client(), s.URL+"/packet/"+id)
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
		req, _ := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/packet/%08x-aaaa-4aaa-8aaa-aaaaaaaaaaaa", s.URL, i), nil)
		xhttpPadRequest(req, 100)
		r, e := s.Client().Do(req)
		if e != nil {
			t.Fatal(e)
		}
		defer r.Body.Close()
		if r.StatusCode != 200 {
			t.Fatal(r.StatusCode)
		}
	}
	r, e := xhttpGetTest(s.Client(), fmt.Sprintf("%s/packet/%08x-aaaa-4aaa-8aaa-aaaaaaaaaaaa", s.URL, xhttpSessions))
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

func TestXHTTPServerCustomChunkLimitAndDownloadHalfClose(t *testing.T) {
	done := make(chan string, 1)
	h := newXHTTPHandler("/packet/", func(c net.Conn) {
		defer c.Close()
		_, _ = c.Write([]byte("ok"))
		if cw, ok := c.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		buf := make([]byte, 3)
		_, err := io.ReadFull(c, buf)
		if err != nil {
			done <- err.Error()
			return
		}
		done <- string(buf)
	})
	h.maxPost = 1024
	defer h.Close()
	s := httptest.NewServer(h)
	defer s.Close()
	c, err := xhttpTestDial(t, context.Background(), s, false, model.XHTTP{Path: "/packet/", Mode: "packet-up", MaxEachPostBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 2)
	if _, err = io.ReadFull(c, buf); err != nil || string(buf) != "ok" {
		t.Fatalf("download: %q %v", buf, err)
	}
	_, _ = io.ReadAll(c) // Confirm GET EOF before POST upload.
	if _, err = c.Write([]byte("up!")); err != nil {
		t.Fatal("upload after GET EOF:", err)
	}
	select {
	case got := <-done:
		if got != "up!" {
			t.Fatal(got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("upload stalled")
	}
	// The server rejects oversized direct peers regardless of Client chunk settings.
	id := xhttpTestSession
	get, err := xhttpGetTest(s.Client(), s.URL+"/packet/"+id)
	if err != nil {
		t.Fatal(err)
	}
	defer get.Body.Close()
	request, err := http.NewRequest(http.MethodPost, s.URL+"/packet/"+id+"/0", bytes.NewReader(make([]byte, 1025)))
	if err != nil {
		t.Fatal(err)
	}
	xhttpPadRequest(request, 100)
	resp, err := s.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("unexpected status %d", resp.StatusCode)
	}
}

func xhttpGetTest(client *http.Client, target string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	xhttpPadRequest(req, 100)
	return client.Do(req)
}

func xhttpPostTest(client *http.Client, target, body string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodPost, target, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	xhttpPadRequest(req, 100)
	return client.Do(req)
}

func TestXHTTPPaddingAndHTTP2(t *testing.T) {
	h := newXHTTPHandler("/packet/", func(c net.Conn) { defer c.Close(); _, _ = io.Copy(io.Discard, c) })
	h.padding, h.paddingMax = 256, 256
	defer h.Close()
	proto := make(chan int, 2)
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Referer") != "" {
			select {
			case proto <- r.ProtoMajor:
			default:
			}
			if !xhttpValidPadding(r, 256) {
				t.Errorf("invalid request padding")
			}
		}
		h.ServeHTTP(w, r)
	}))
	s.EnableHTTP2 = true
	s.StartTLS()
	defer s.Close()
	u, _ := url.Parse(s.URL)
	host, _, _ := net.SplitHostPort(u.Host)
	local := model.LocalTLS{CAPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw})), XHTTP: model.XHTTP{Path: "/packet/", Mode: "packet-up", TLS: true, PaddingBytes: 256}}
	c, err := dialXHTTP(context.Background(), u.Host, host, local)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if got := <-proto; got != 2 {
		t.Fatalf("expected HTTP/2, got %d", got)
	}
	bad, _ := http.NewRequest(http.MethodGet, s.URL+"/packet/"+xhttpTestSession, nil)
	response, err := s.Client().Do(bad)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("missing padding: %d", response.StatusCode)
	}
}

func TestXHTTPPaddingRangeRoundtrip(t *testing.T) {
	h := newXHTTPHandler("/packet/", func(c net.Conn) {
		defer c.Close()
		data, err := io.ReadAll(c)
		if err == nil {
			_, _ = c.Write(data)
		}
	})
	h.padding, h.paddingMax = 120, 450
	defer h.Close()
	s := httptest.NewServer(h)
	defer s.Close()
	for _, size := range []int{119, 120, 450, 451} {
		r, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/packet/%08x-aaaa-4aaa-8aaa-aaaaaaaaaaaa", s.URL, size), nil)
		if err != nil {
			t.Fatal(err)
		}
		xhttpPadRequest(r, size)
		response, err := s.Client().Do(r)
		if err != nil {
			t.Fatal(err)
		}
		if size >= 120 && size <= 450 {
			if response.StatusCode != http.StatusOK {
				t.Fatalf("size %d: %d", size, response.StatusCode)
			}
			if length := len(response.Header.Get("X-Padding")); length < 120 || length > 450 {
				t.Fatalf("response padding: %d", length)
			}
		} else if response.StatusCode != http.StatusBadRequest {
			t.Fatalf("size %d accepted: %d", size, response.StatusCode)
		}
		response.Body.Close()
	}
	settings := model.XHTTP{Path: "/packet/", Mode: "packet-up", PaddingBytes: 120, PaddingMaxBytes: 450}
	c, err := xhttpTestDial(t, context.Background(), s, false, settings)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err = c.Write([]byte("range")); err != nil {
		t.Fatal(err)
	}
	if err = c.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if got, err := io.ReadAll(c); err != nil || string(got) != "range" {
		t.Fatalf("roundtrip: %q %v", got, err)
	}
	seen := map[int]bool{}
	for i := 0; i < 50; i++ {
		size := xhttpPaddingSize(settings)
		if size < 120 || size > 450 {
			t.Fatalf("generated size %d", size)
		}
		seen[size] = true
	}
	if len(seen) < 2 {
		t.Fatal("configured range did not vary")
	}
}
