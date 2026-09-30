package tunnel

import (
	"bytes"
	"context"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"veilink/internal/model"
)

func TestXHTTPOptionalStreamingHeaders(t *testing.T) {
	for _, mode := range []string{"stream-up", "stream-one"} {
		for _, omit := range []bool{false, true} {
			t.Run(mode+map[bool]string{false: "/default", true: "/omitted"}[omit], func(t *testing.T) {
				h := newXHTTPHandler("/packet/", func(c net.Conn) {
					defer c.Close()
					b, err := io.ReadAll(c)
					if err == nil {
						_, _ = c.Write(b)
					}
				})
				h.mode, h.noGRPCHeader, h.noSSEHeader = mode, omit, omit
				type headers struct{ method, request, response string }
				seen := make(chan headers, 2)
				s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					captured := r.Header.Get("Content-Type")
					w = &captureXHTTPHeaders{ResponseWriter: w, done: func(ct string) { seen <- headers{r.Method, captured, ct} }}
					h.ServeHTTP(w, r)
				}))
				s.EnableHTTP2 = true
				s.StartTLS()
				t.Cleanup(func() { h.Close(); s.Close() })
				u, _ := url.Parse(s.URL)
				host, _, _ := net.SplitHostPort(u.Host)
				local := model.LocalTLS{TransportSecurity: "tls", CAPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw})), XHTTP: model.XHTTP{Path: "/packet/", Mode: mode, TLS: true, NoGRPCHeader: omit, NoSSEHeader: omit}}
				ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
				defer cancel()
				c, err := dialXHTTP(ctx, u.Host, host, local)
				if err != nil {
					t.Fatal(err)
				}
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				want := bytes.Repeat([]byte("headers"), 2000)
				if _, err = c.Write(want); err != nil {
					t.Fatal(err)
				}
				if err = c.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
					t.Fatal(err)
				}
				got, err := io.ReadAll(c)
				if err != nil || !bytes.Equal(got, want) {
					t.Fatalf("roundtrip: %d bytes: %v", len(got), err)
				}
				count := 1
				if mode == "stream-up" {
					count = 2
				}
				for i := 0; i < count; i++ {
					select {
					case shape := <-seen:
						if shape.method == http.MethodPost {
							expected := "application/grpc"
							if omit {
								expected = ""
							}
							if shape.request != expected {
								t.Fatalf("POST Content-Type = %q, want %q", shape.request, expected)
							}
						}
						if shape.method == http.MethodGet || mode == "stream-one" {
							expected := "text/event-stream"
							if omit {
								expected = ""
							}
							if shape.response != expected {
								t.Fatalf("download Content-Type = %q, want %q", shape.response, expected)
							}
						}
					case <-ctx.Done():
						t.Fatal("missing captured request")
					}
				}
			})
		}
	}
}

// Observe the headers at first flush without affecting the handler's streaming behavior.
type captureXHTTPHeaders struct {
	http.ResponseWriter
	done     func(string)
	captured bool
}

func (w *captureXHTTPHeaders) Flush() {
	if !w.captured {
		w.captured = true
		w.done(w.Header().Get("Content-Type"))
	}
	w.ResponseWriter.(http.Flusher).Flush()
}
func (w *captureXHTTPHeaders) Write(p []byte) (int, error) { return w.ResponseWriter.Write(p) }
func (w *captureXHTTPHeaders) WriteHeader(status int)      { w.ResponseWriter.WriteHeader(status) }
func (w *captureXHTTPHeaders) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// Inspect the response actually serialized by net/http, not only Handler.Header.
func TestXHTTPNoSSEHeaderOnWire(t *testing.T) {
	for _, mode := range []string{"packet-up", "stream-up", "stream-one"} {
		for _, omit := range []bool{false, true} {
			t.Run(mode+map[bool]string{false: "/default", true: "/omitted"}[omit], func(t *testing.T) {
				h := newXHTTPHandler("/packet/", func(c net.Conn) {
					defer c.Close()
					_, _ = io.Copy(io.Discard, c)
				})
				h.mode, h.noSSEHeader = mode, omit
				s := httptest.NewUnstartedServer(h)
				s.EnableHTTP2 = true
				s.StartTLS()
				t.Cleanup(func() { h.Close(); s.Close() })
				method, path := http.MethodGet, "/packet/"+xhttpTestSession
				var body io.Reader
				if mode == "stream-one" {
					method, path, body = http.MethodPost, "/packet/", bytes.NewReader([]byte("a"))
				}
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				req, err := http.NewRequestWithContext(ctx, method, s.URL+path, body)
				if err != nil {
					t.Fatal(err)
				}
				if mode == "stream-one" {
					req.Header.Set("Content-Type", "application/grpc")
				}
				xhttpPadRequest(req, 100)
				client := s.Client()
				client.Transport.(*http.Transport).ForceAttemptHTTP2 = true
				resp, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				defer resp.Body.Close()
				if resp.StatusCode != http.StatusOK || resp.ProtoMajor != 2 {
					t.Fatalf("response %d HTTP/%d", resp.StatusCode, resp.ProtoMajor)
				}
				_, exists := resp.Header["Content-Type"]
				if exists == omit {
					t.Fatalf("Content-Type present=%t, omit=%t: %v", exists, omit, resp.Header)
				}
				if !omit && resp.Header.Get("Content-Type") != "text/event-stream" {
					t.Fatal(resp.Header)
				}
				if resp.Header.Get("Cache-Control") != "no-store" || resp.Header.Get("X-Accel-Buffering") != "no" {
					t.Fatal(resp.Header)
				}
			})
		}
	}
}
func TestXHTTPStreamingContentTypeMismatchRejected(t *testing.T) {
	for _, omitted := range []bool{false, true} {
		for _, values := range [][]string{nil, {""}, {"application/grpc"}, {"text/plain"}, {"application/grpc", "application/grpc"}} {
			h := newXHTTPHandler("/packet/", func(c net.Conn) { _ = c.Close() })
			h.mode, h.version, h.noGRPCHeader = "stream-one", "2", omitted
			r := httptest.NewRequest(http.MethodPost, "http://example.test/packet/", bytes.NewReader([]byte("x")))
			r.ProtoMajor = 2
			for _, value := range values {
				r.Header.Add("Content-Type", value)
			}
			xhttpPadRequest(r, 100)
			valid := omitted && len(values) == 0 || !omitted && len(values) == 1 && values[0] == "application/grpc"
			if h.validStreamContentType(r) != valid {
				t.Fatalf("omit %t values %q: validation mismatch", omitted, values)
			}
			if !valid {
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				if w.Code != http.StatusBadRequest {
					t.Fatalf("omit %t values %q: status %d", omitted, values, w.Code)
				}
			}
			h.Close()
		}
	}
}

func TestXHTTPServerHeaderLimitOnWire(t *testing.T) {
	for _, tc := range []struct {
		name       string
		configured int
		want       int
	}{
		{"default", 0, http.StatusRequestHeaderFieldsTooLarge},
		{"expanded", 16 << 10, http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newXHTTPHandler("/packet/", func(c net.Conn) { defer c.Close(); _, _ = io.Copy(io.Discard, c) })
			s := httptest.NewUnstartedServer(h)
			s.Config.MaxHeaderBytes = xhttpServerHeaderLimit(model.XHTTP{ServerMaxHeaderBytes: tc.configured})
			s.Start()
			t.Cleanup(func() { h.Close(); s.Close() })
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.URL+"/packet/"+xhttpTestSession, nil)
			if err != nil {
				t.Fatal(err)
			}
			xhttpPadRequest(req, 100)
			req.Header.Set("X-Large-Test", string(bytes.Repeat([]byte("a"), 14<<10)))
			resp, err := s.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != tc.want {
				t.Fatalf("max %d: status %d, want %d", s.Config.MaxHeaderBytes, resp.StatusCode, tc.want)
			}
		})
	}
}
