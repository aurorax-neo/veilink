package tunnel

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"veilink/internal/model"
)

func streamTestServer(t *testing.T, mode string, accept func(net.Conn)) (*httptest.Server, *xhttpHandler) {
	t.Helper()
	h := newXHTTPHandler("/packet/", accept)
	h.mode = mode
	s := httptest.NewUnstartedServer(h)
	s.EnableHTTP2 = true
	s.StartTLS()
	t.Cleanup(func() { h.Close(); s.Close() })
	return s, h
}

func streamTestDial(t *testing.T, ctx context.Context, s *httptest.Server, mode string, padding ...int) (net.Conn, error) {
	t.Helper()
	u, _ := url.Parse(s.URL)
	host, _, _ := net.SplitHostPort(u.Host)
	x := model.XHTTP{Path: "/packet/", Mode: mode, TLS: true}
	if len(padding) == 2 {
		x.PaddingBytes, x.PaddingMaxBytes = padding[0], padding[1]
	}
	local := model.LocalTLS{TransportSecurity: "tls", CAPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw})), XHTTP: x}
	return dialXHTTP(ctx, u.Host, host, local)
}

func TestXHTTPStreamModesRoundtripAndHalfClose(t *testing.T) {
	for _, mode := range []string{"stream-up", "stream-one"} {
		t.Run(mode, func(t *testing.T) {
			server, _ := streamTestServer(t, mode, func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				data, err := io.ReadAll(c)
				if err == nil {
					_, _ = c.Write(data)
				}
			})
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			conn, err := streamTestDial(t, ctx, server, mode)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(6 * time.Second))
			payload := bytes.Repeat([]byte("stream-test-"), 5000)
			if _, err := conn.Write(payload); err != nil {
				t.Fatal(err)
			}
			if err := conn.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(conn)
			if err != nil || !bytes.Equal(got, payload) {
				t.Fatalf("response %d bytes: %v", len(got), err)
			}
		})
	}
}

func TestXHTTPStreamAutoRealityDownloadUsesStreamUp(t *testing.T) {
	server, _ := streamTestServer(t, "stream-up", func(c net.Conn) {
		defer c.Close()
		_, _ = io.Copy(io.Discard, c)
	})
	u, _ := url.Parse(server.URL)
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	host, _, _ := net.SplitHostPort(u.Host)
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: host}, ForceAttemptHTTP2: true}
	client := &http.Client{Transport: tr}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	settings := model.XHTTP{Path: "/packet/", Mode: "auto", DownloadEndpointID: "download", TLS: true, RequestTimeoutSeconds: 1}
	conn, err := dialXHTTPStream(ctx, client, tr, "https://"+u.Host+settings.Path, settings, true, nil, cancel)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
}

func TestXHTTPStreamModesRequireHTTP2AndRejectInvalidRequests(t *testing.T) {
	for _, mode := range []string{"stream-up", "stream-one"} {
		t.Run(mode, func(t *testing.T) {
			server, handler := streamTestServer(t, mode, func(c net.Conn) { defer c.Close(); _, _ = io.Copy(io.Discard, c) })
			// A TLS HTTP/1.1 peer is not a permitted streaming transport.
			noH2 := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("hello"))
			}))
			defer noH2.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if c, err := streamTestDial(t, ctx, noH2, mode); err == nil {
				c.Close()
				t.Fatal("HTTP/1.1 accepted")
			}
			path := "/packet/"
			if mode == "stream-up" {
				path += xhttpTestSession
			}
			req, _ := http.NewRequest(http.MethodPost, server.URL+path, strings.NewReader("payload"))
			xhttpPadRequest(req, 100)
			resp, err := server.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("missing grpc header: %d", resp.StatusCode)
			}
			if mode == "stream-up" {
				get, _ := http.NewRequest(http.MethodGet, server.URL+path, nil)
				xhttpPadRequest(get, 100)
				plain := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}}}} // test-only; production TLS verifies CA
				plain.Transport.(*http.Transport).TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
				response, err := plain.Do(get)
				if err != nil {
					t.Fatal(err)
				}
				response.Body.Close()
				if response.StatusCode != http.StatusBadRequest {
					t.Fatalf("HTTP/1.1 GET accepted: %d", response.StatusCode)
				}
			}
			handler.mu.Lock()
			count := len(handler.sessions) + len(handler.streams)
			handler.mu.Unlock()
			if count != 0 {
				t.Fatalf("invalid requests created sessions: %d", count)
			}
		})
	}
}

func TestXHTTPStreamCancelStopsBothDirections(t *testing.T) {
	for _, mode := range []string{"stream-up", "stream-one"} {
		t.Run(mode, func(t *testing.T) {
			finished := make(chan struct{})
			s, _ := streamTestServer(t, mode, func(c net.Conn) {
				defer close(finished)
				defer c.Close()
				_, _ = io.Copy(io.Discard, c)
			})
			ctx, cancel := context.WithCancel(context.Background())
			c, err := streamTestDial(t, ctx, s, mode)
			if err != nil {
				cancel()
				t.Fatal(err)
			}
			cancel()
			_ = c.SetReadDeadline(time.Now().Add(time.Second))
			if _, err := c.Read(make([]byte, 1)); err == nil {
				t.Fatal("read survived cancel")
			}
			select {
			case <-finished:
			case <-time.After(2 * time.Second):
				t.Fatal("server stream survived cancel")
			}
			_ = c.Close()
		})
	}
}

func TestXHTTPStreamUpSetupTimeout(t *testing.T) {
	s, _ := streamTestServer(t, "stream-up", func(c net.Conn) { _ = c.Close() })
	// The GET headers never arrive. The setup timeout must cancel this request,
	// rather than waiting indefinitely for a response header.
	blocked := make(chan struct{})
	tr := &http.Transport{}
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		close(blocked)
		<-r.Context().Done()
		return nil, r.Context().Err()
	})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	start := time.Now()
	_, err := dialXHTTPStream(ctx, client, tr, s.URL+"/packet/", model.XHTTP{Mode: "stream-up", RequestTimeoutSeconds: 1}, false, nil, cancel)
	if err == nil || time.Since(start) > 3*time.Second {
		t.Fatalf("stalled GET did not time out: %v (%v)", err, time.Since(start))
	}
	select {
	case <-blocked:
	default:
		t.Fatal("GET not attempted")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestXHTTPStreamCloseReleasesSession(t *testing.T) {
	for _, mode := range []string{"stream-up", "stream-one"} {
		t.Run(mode, func(t *testing.T) {
			finished := make(chan struct{})
			s, h := streamTestServer(t, mode, func(c net.Conn) {
				defer close(finished)
				defer c.Close()
				_, _ = io.Copy(io.Discard, c)
			})
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			c, err := streamTestDial(t, ctx, s, mode)
			if err != nil {
				t.Fatal(err)
			}
			if err := c.Close(); err != nil {
				t.Fatal(err)
			}
			if err := c.Close(); err != nil {
				t.Fatalf("repeated close: %v", err)
			}
			select {
			case <-finished:
			case <-time.After(2 * time.Second):
				t.Fatal("accepted connection survived close")
			}
			deadline := time.Now().Add(2 * time.Second)
			for {
				h.mu.Lock()
				remaining := len(h.sessions) + len(h.streams)
				h.mu.Unlock()
				if remaining == 0 {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("session survived close: %d", remaining)
				}
				time.Sleep(10 * time.Millisecond)
			}
		})
	}
}

func TestXHTTPStreamUpRejectsRepeatedUpload(t *testing.T) {
	h := newXHTTPHandler("/packet/", func(net.Conn) {})
	h.mode = "stream-up"
	defer h.Close()
	app, wire := xhttpPair()
	defer app.Close()
	defer wire.Close()
	id := xhttpTestSession
	s := &xhttpSession{app: app, wire: wire}
	h.mu.Lock()
	h.sessions[id] = s
	h.mu.Unlock()
	s.mu.Lock()
	s.eof = true
	s.mu.Unlock()
	req := httptest.NewRequest(http.MethodPost, "https://example.test/packet/"+id, strings.NewReader("second"))
	req.ProtoMajor = 2
	req.Header.Set("Content-Type", "application/grpc")
	xhttpPadRequest(req, h.padding)
	recorder := httptest.NewRecorder()
	h.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("repeated upload status %d", recorder.Code)
	}
}

func TestXHTTPStreamRequestShapes(t *testing.T) {
	for _, mode := range []string{"stream-up", "stream-one"} {
		t.Run(mode, func(t *testing.T) {
			h := newXHTTPHandler("/packet/", func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(io.Discard, c)
			})
			h.mode = mode
			type requestShape struct {
				method, path, contentType, referer string
				version                            int
				length                             int64
				padding                            string
				query                              string
			}
			seen := make(chan requestShape, 2)
			s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seen <- requestShape{method: r.Method, path: r.URL.Path, contentType: r.Header.Get("Content-Type"), referer: r.Header.Get("Referer"), version: r.ProtoMajor, length: r.ContentLength, padding: r.Header.Get("X-Padding"), query: r.URL.RawQuery}
				h.ServeHTTP(w, r)
			}))
			s.EnableHTTP2 = true
			s.StartTLS()
			t.Cleanup(func() { h.Close(); s.Close() })
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			c, err := streamTestDial(t, ctx, s, mode)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			want := []string{http.MethodPost}
			if mode == "stream-up" {
				want = []string{http.MethodGet, http.MethodPost}
			}
			var sessionPath string
			for _, method := range want {
				select {
				case got := <-seen:
					if got.method != method || got.version != 2 || got.query != "" || got.padding != "" || !strings.Contains(got.referer, "x_padding="+strings.Repeat("X", 100)) {
						t.Fatalf("unexpected %s request: %+v", mode, got)
					}
					if mode == "stream-one" {
						if got.path != "/packet/" {
							t.Fatalf("stream-one path: %q", got.path)
						}
					} else if sessionPath == "" {
						sessionPath = got.path
						if !strings.HasPrefix(sessionPath, "/packet/") || !validXHTTPSessionID(strings.TrimPrefix(sessionPath, "/packet/")) {
							t.Fatalf("stream-up session path: %q", sessionPath)
						}
					} else if got.path != sessionPath {
						t.Fatalf("different session paths: %q and %q", sessionPath, got.path)
					}
					if method == http.MethodPost && (got.contentType != "application/grpc" || got.length != -1) {
						t.Fatalf("non-streaming POST: %+v", got)
					}
				case <-ctx.Done():
					t.Fatal("request did not arrive")
				}
			}
		})
	}
}

func TestXHTTPStreamPaddingRangeRoundtrip(t *testing.T) {
	for _, mode := range []string{"stream-up", "stream-one"} {
		t.Run(mode, func(t *testing.T) {
			s, h := streamTestServer(t, mode, func(c net.Conn) {
				defer c.Close()
				data, err := io.ReadAll(c)
				if err == nil {
					_, _ = c.Write(data)
				}
			})
			h.padding, h.paddingMax = 120, 450
			ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
			defer cancel()
			c, err := streamTestDial(t, ctx, s, mode, 120, 450)
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
			if data, err := io.ReadAll(c); err != nil || string(data) != "range" {
				t.Fatalf("roundtrip: %q %v", data, err)
			}
		})
	}
}

func TestXHTTPStreamUpRejectsMissingUploadConfirmation(t *testing.T) {
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Padding", strings.Repeat("X", 100))
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusOK)
			_ = http.NewResponseController(w).Flush()
			<-r.Context().Done()
			return
		}
		w.WriteHeader(http.StatusOK) // Pretend success without consuming POST or marking completion.
	}))
	s.EnableHTTP2 = true
	s.StartTLS()
	defer s.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	c, err := streamTestDial(t, ctx, s, "stream-up")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.(interface{ CloseWrite() error }).CloseWrite(); err == nil {
		t.Fatal("early 200 without upload confirmation accepted")
	}
}
