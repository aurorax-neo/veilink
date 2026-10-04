package tunnel

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2/hpack"
	"veilink/internal/model"
)

func TestXHTTPPaddingConfiguration(t *testing.T) {
	base := model.LocalTLS{TransportSecurity: "tls", XHTTP: model.XHTTP{Path: "/packet/", Mode: "packet-up", TLS: true, PaddingObfsMode: true}}
	for name, change := range map[string]func(*model.XHTTP){
		"legacy-options": func(x *model.XHTTP) { x.PaddingObfsMode = false; x.PaddingMethod = "tokenish" },
		"placement":      func(x *model.XHTTP) { x.PaddingPlacement = "unknown" },
		"method":         func(x *model.XHTTP) { x.PaddingMethod = "unknown" },
		"query-key":      func(x *model.XHTTP) { x.PaddingPlacement = "query"; x.PaddingKey = "bad key" },
		"cookie-key":     func(x *model.XHTTP) { x.PaddingPlacement = "cookie"; x.PaddingKey = "session" },
		"cookie-collision": func(x *model.XHTTP) {
			x.PaddingPlacement = "cookie"
			x.PaddingKey = "x_session"
			x.SessionIDPlacement = "cookie"
		},
		"query-collision": func(x *model.XHTTP) {
			x.PaddingPlacement = "query"
			x.PaddingKey = "x_session"
			x.SessionIDPlacement = "query"
		},
		"header-reserved": func(x *model.XHTTP) { x.PaddingPlacement = "header"; x.PaddingHeader = "X-Veilink-EOF" },
		"header-cookie":   func(x *model.XHTTP) { x.PaddingPlacement = "header"; x.PaddingHeader = "Cookie" },
		"header-collision": func(x *model.XHTTP) {
			x.PaddingPlacement = "header"
			x.PaddingHeader = "X-Custom-Pad"
			x.Headers = model.XHTTPHeaders(`{"X-Custom-Pad":"fixed"}`)
		},
		"unused-key":    func(x *model.XHTTP) { x.PaddingPlacement = "header"; x.PaddingKey = "x_pad" },
		"unused-header": func(x *model.XHTTP) { x.PaddingPlacement = "query"; x.PaddingHeader = "X-Custom-Pad" },
	} {
		t.Run(name, func(t *testing.T) {
			v := base
			change(&v.XHTTP)
			if err := checkTransportSecurity(v); err == nil {
				t.Fatal("unsafe padding accepted")
			}
		})
	}
	for _, placement := range []string{"query_in_header", "query", "header", "cookie"} {
		v := base
		v.XHTTP.PaddingPlacement = placement
		if err := checkTransportSecurity(v); err != nil {
			t.Fatalf("%s: %v", placement, err)
		}
	}
}

func TestXHTTPPaddingTokenishLengthAndCharacters(t *testing.T) {
	for _, target := range []int{1, 100, 256, 1000} {
		x := model.XHTTP{PaddingObfsMode: true, PaddingMethod: "tokenish", PaddingBytes: target}
		first := ""
		for i := 0; i < 8; i++ {
			v, err := xhttpPaddingValue(x)
			if err != nil || !xhttpPaddingValidValue(v, x) {
				t.Fatalf("%d: %q %v", target, v, err)
			}
			length := int(hpack.HuffmanEncodeLength(v))
			if length < target-2 || length > target+2 {
				t.Fatalf("HPACK length %d outside %d ±2", length, target)
			}
			if target >= 100 && i > 0 && v == first {
				t.Fatal("tokenish not randomized")
			}
			first = v
		}
		if xhttpPaddingValidValue(strings.Repeat("!", target), x) {
			t.Fatal("non-base62 accepted")
		}
	}
}

func TestXHTTPPaddingRoundtrip(t *testing.T) {
	for _, mode := range []string{"packet-up", "stream-up", "stream-one"} {
		for _, placement := range []string{"query_in_header", "query", "header", "cookie"} {
			for _, method := range []string{"repeat-x", "tokenish"} {
				t.Run(mode+"/"+placement+"/"+method, func(t *testing.T) {
					secure := mode != "packet-up"
					x := model.XHTTP{Path: "/packet/", Mode: mode, TLS: secure, PaddingObfsMode: true, PaddingPlacement: placement, PaddingMethod: method, PaddingBytes: 120, PaddingMaxBytes: 180, UplinkHTTPMethod: "PUT"}
					if placement == "cookie" && mode != "stream-one" {
						x.SessionIDPlacement = "cookie"
						x.SessionIDKey = "x_sid"
						if mode == "packet-up" {
							x.SeqPlacement = "cookie"
							x.SeqKey = "x_seq"
						}
					}
					h := newXHTTPHandler(x.Path, func(c net.Conn) {
						defer c.Close()
						_ = c.SetDeadline(time.Now().Add(5 * time.Second))
						b, e := io.ReadAll(c)
						if e == nil {
							_, _ = c.Write(b)
						}
					})
					h.settings = x
					h.mode = mode
					h.uplinkMethod = http.MethodPut
					h.padding, h.paddingMax = 120, 180
					s := httptest.NewUnstartedServer(h)
					if secure {
						s.EnableHTTP2 = true
						s.StartTLS()
					} else {
						s.Start()
					}
					t.Cleanup(func() { h.Close(); s.Close() })
					ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
					defer cancel()
					c, err := xhttpTestDial(t, ctx, s, secure, x)
					if err != nil {
						t.Fatal(err)
					}
					defer c.Close()
					_ = c.SetDeadline(time.Now().Add(5 * time.Second))
					payload := bytes.Repeat([]byte("padding"), 150)
					if _, err = c.Write(payload); err != nil {
						t.Fatal(err)
					}
					if err = c.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
						t.Fatal(err)
					}
					got, err := io.ReadAll(c)
					if err != nil || !bytes.Equal(got, payload) {
						t.Fatalf("roundtrip %d: %v", len(got), err)
					}
				})
			}
		}
	}
}

func TestXHTTPPaddingRejectsAmbiguousRequestAndResponse(t *testing.T) {
	for _, placement := range []string{"query_in_header", "query", "header", "cookie"} {
		t.Run(placement, func(t *testing.T) {
			x := model.XHTTP{Path: "/packet/", Mode: "packet-up", PaddingObfsMode: true, PaddingPlacement: placement, PaddingBytes: 100}
			h := newXHTTPHandler(x.Path, func(c net.Conn) { t.Error("bad request accepted"); _ = c.Close() })
			h.settings = x
			defer h.Close()
			base := func() *http.Request {
				r := httptest.NewRequest("GET", "http://example.test/packet/"+xhttpTestSession, nil)
				if err := xhttpSetPadding(r, x); err != nil {
					t.Fatal(err)
				}
				return r
			}
			for _, change := range []func(*http.Request){
				func(r *http.Request) {
					switch placement {
					case "query_in_header", "header":
						r.Header.Add(xhttpPaddingHeader(x), r.Header.Get(xhttpPaddingHeader(x)))
					case "query":
						r.URL.RawQuery += "&x_padding=" + strings.Repeat("X", 100)
					case "cookie":
						r.AddCookie(&http.Cookie{Name: "x_padding", Value: strings.Repeat("X", 100)})
					}
				},
				func(r *http.Request) {
					switch placement {
					case "query_in_header", "header":
						r.Header.Set(xhttpPaddingHeader(x), "bad")
					case "query":
						r.URL.RawQuery += "&extra=1"
					case "cookie":
						r.AddCookie(&http.Cookie{Name: "extra", Value: "1"})
					}
				},
			} {
				r := base()
				change(r)
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				if w.Code == http.StatusOK || len(h.sessions) != 0 {
					t.Fatalf("accepted malformed padding: %d", w.Code)
				}
			}
			r := base()
			w := httptest.NewRecorder()
			if err := xhttpSetResponsePadding(w, r, x); err != nil {
				t.Fatal(err)
			}
			resp := w.Result()
			if !xhttpCheckResponsePadding(resp, x) {
				t.Fatal("valid response rejected")
			}
			if placement == "cookie" {
				resp.Header.Add("Set-Cookie", "x_padding=another")
			} else {
				key := "X-Padding"
				if placement == "header" || placement == "query_in_header" {
					key = xhttpPaddingHeader(x)
				}
				resp.Header.Add(key, "bad")
			}
			if xhttpCheckResponsePadding(resp, x) {
				t.Fatal("ambiguous response accepted")
			}
		})
	}
}

func TestXHTTPPaddingCancellation(t *testing.T) {
	x := model.XHTTP{Path: "/packet/", Mode: "packet-up", PaddingObfsMode: true, PaddingPlacement: "cookie", PaddingMethod: "tokenish"}
	h := newXHTTPHandler(x.Path, func(c net.Conn) { defer c.Close(); _, _ = io.Copy(io.Discard, c) })
	h.settings = x
	s := httptest.NewServer(h)
	defer func() { h.Close(); s.Close() }()
	ctx, cancel := context.WithCancel(context.Background())
	c, err := xhttpTestDial(t, ctx, s, false, x)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	_ = c.SetDeadline(time.Now().Add(time.Second))
	_ = c.Close()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		h.mu.Lock()
		remaining := len(h.sessions)
		h.mu.Unlock()
		if remaining == 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("cancelled padded session not released")
}
