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
	"strings"
	"sync"
	"testing"
	"time"

	"veilink/internal/model"
)

func TestXHTTPCustomHeadersRoundtrip(t *testing.T) {
	for _, version := range []string{"1.1", "2"} {
		for _, mode := range []string{"packet-up", "stream-up", "stream-one"} {
			if version == "1.1" && mode != "packet-up" {
				continue
			}
			for _, method := range []string{"POST", "PUT"} {
				t.Run(version+"/"+mode+"/"+method, func(t *testing.T) {
					h := newXHTTPHandler("/custom/", func(c net.Conn) {
						defer c.Close()
						data, err := io.ReadAll(c)
						if err == nil {
							_, _ = c.Write(data)
						}
					})
					h.mode, h.version, h.uplinkMethod = mode, version, method
					var headers model.XHTTPHeaders
					if err := headers.UnmarshalJSON([]byte(`{"x-custom-route":"east","User-Agent":"Veilink-Test"}`)); err != nil {
						t.Fatal(err)
					}
					h.headers, _ = headers.Entries()
					var mu sync.Mutex
					var methods []string
					s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						mu.Lock()
						methods = append(methods, r.Method)
						mu.Unlock()
						h.ServeHTTP(w, r)
					}))
					s.EnableHTTP2 = true
					s.StartTLS()
					t.Cleanup(func() { h.Close(); s.Close() })
					u, _ := url.Parse(s.URL)
					host, _, _ := net.SplitHostPort(u.Host)
					local := model.LocalTLS{TransportSecurity: "tls", CAPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw})), XHTTP: model.XHTTP{Path: "/custom/", Mode: mode, HTTPVersion: version, TLS: true, UplinkHTTPMethod: method, Headers: headers}}
					ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
					defer cancel()
					c, err := dialXHTTP(ctx, u.Host, host, local)
					if err != nil {
						t.Fatal(err)
					}
					defer c.Close()
					_ = c.SetDeadline(time.Now().Add(6 * time.Second))
					data := bytes.Repeat([]byte("request-headers"), 100)
					if _, err := c.Write(data); err != nil {
						t.Fatal(err)
					}
					if err := c.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
						t.Fatal(err)
					}
					got, err := io.ReadAll(c)
					if err != nil || !bytes.Equal(got, data) {
						t.Fatalf("roundtrip %d bytes: %v", len(got), err)
					}
					mu.Lock()
					defer mu.Unlock()
					if mode == "stream-one" {
						if len(methods) != 1 || methods[0] != method {
							t.Fatalf("requests: %v", methods)
						}
					} else if len(methods) < 2 || methods[0] != http.MethodGet {
						t.Fatalf("requests: %v", methods)
					}
					for _, m := range methods {
						if m != http.MethodGet && m != method {
							t.Fatalf("unexpected request: %v", methods)
						}
					}
				})
			}
		}
	}
}

func TestXHTTPCustomHeadersRejectBeforeSession(t *testing.T) {
	h := newXHTTPHandler("/custom/", func(c net.Conn) { t.Error("unauthorized session created"); _ = c.Close() })
	defer h.Close()
	var headers model.XHTTPHeaders
	if err := headers.UnmarshalJSON([]byte(`{"X-Custom-Route":"east"}`)); err != nil {
		t.Fatal(err)
	}
	h.headers, _ = headers.Entries()
	for _, values := range [][]string{nil, {"west"}, {"east", "east"}, {"east, east"}} {
		r := httptest.NewRequest(http.MethodGet, "http://example.test/custom/"+xhttpTestSession, nil)
		for _, v := range values {
			r.Header.Add("X-Custom-Route", v)
		}
		xhttpPadRequest(r, 100)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("values %v accepted: %d", values, w.Code)
		}
		if len(h.sessions) != 0 {
			t.Fatal("session created")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	local := model.LocalTLS{XHTTP: model.XHTTP{Path: "/custom/", Mode: "packet-up", Headers: model.XHTTPHeaders(`{"x-custom-route":"east"}`)}}
	if _, err := dialXHTTP(ctx, "127.0.0.1:1", "127.0.0.1", local); err == nil || !strings.Contains(err.Error(), "canonical") {
		t.Fatalf("invalid direct config: %v", err)
	}
}
