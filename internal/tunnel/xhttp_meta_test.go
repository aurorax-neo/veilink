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

	"veilink/internal/model"
)

func TestXHTTPMetadataRoundtrip(t *testing.T) {
	for _, tc := range []struct {
		name   string
		secure bool
		x      model.XHTTP
	}{
		{"query-query", false, model.XHTTP{SessionIDPlacement: "query", SessionIDKey: "sid", SeqPlacement: "query", SeqKey: "number", SessionIDTable: "hex", SessionIDLength: 32}},
		{"header-header", false, model.XHTTP{SessionIDPlacement: "header", SessionIDKey: "X-Veilink-SID", SeqPlacement: "header", SeqKey: "X-Veilink-Number"}},
		{"path-query", false, model.XHTTP{SeqPlacement: "query"}},
		{"query-path", false, model.XHTTP{SessionIDPlacement: "query"}},
		{"cookie-cookie", false, model.XHTTP{SessionIDPlacement: "cookie", SessionIDKey: "x_sid", SeqPlacement: "cookie", SeqKey: "x_number"}},
		{"cookie-header", false, model.XHTTP{SessionIDPlacement: "cookie", SeqPlacement: "header"}},
		{"stream-up-cookie", true, model.XHTTP{Mode: "stream-up", SessionIDPlacement: "cookie"}},
		{"stream-up-header", true, model.XHTTP{Mode: "stream-up", SessionIDPlacement: "header", SessionIDTable: "base62", SessionIDLength: 24}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := tc.x
			x.Path, x.TLS = "/packet/", tc.secure
			if x.Mode == "" {
				x.Mode = "packet-up"
			}
			h := newXHTTPHandler(x.Path, func(c net.Conn) {
				defer c.Close()
				data, err := io.ReadAll(c)
				if err == nil {
					_, _ = c.Write(data)
				}
			})
			h.settings, h.mode = x, x.Mode
			if x.Mode == "stream-up" {
				h.version = "2"
			}
			var s *httptest.Server
			if tc.secure {
				s = httptest.NewUnstartedServer(h)
				s.EnableHTTP2 = true
				s.StartTLS()
			} else {
				s = httptest.NewServer(h)
			}
			t.Cleanup(func() { h.Close(); s.Close() })
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			c, err := xhttpTestDial(t, ctx, s, tc.secure, x)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(6 * time.Second))
			want := bytes.Repeat([]byte("metadata\x00"), 700)
			if _, err := c.Write(want); err != nil {
				t.Fatal(err)
			}
			if err := c.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(c)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("roundtrip: %d bytes: %v", len(got), err)
			}
		})
	}
}

func TestXHTTPMetadataRejectsAmbiguousRequests(t *testing.T) {
	x := model.XHTTP{Path: "/packet/", Mode: "packet-up", SessionIDPlacement: "query", SessionIDKey: "sid", SeqPlacement: "header", SeqKey: "X-Veilink-Number"}
	h := newXHTTPHandler(x.Path, func(c net.Conn) { t.Error("unauthorized session created"); _ = c.Close() })
	h.settings = x
	defer h.Close()
	for _, tc := range []struct {
		name, path, query string
		headers           http.Header
	}{
		{"missing", "/packet/", "", nil},
		{"duplicate", "/packet/", "sid=" + xhttpTestSession + "&sid=" + xhttpTestSession, nil},
		{"extra-query", "/packet/", "sid=" + xhttpTestSession + "&other=1", nil},
		{"extra-path", "/packet/" + xhttpTestSession, "sid=" + xhttpTestSession, nil},
		{"alternate-header", "/packet/", "sid=" + xhttpTestSession, http.Header{"X-Veilink-Session": {xhttpTestSession}}},
		{"repeated-header", "/packet/", "sid=" + xhttpTestSession, http.Header{"X-Veilink-Session": {xhttpTestSession, xhttpTestSession}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "http://example.test"+tc.path, nil)
			r.URL.RawQuery = tc.query
			for k, values := range tc.headers {
				for _, value := range values {
					r.Header.Add(k, value)
				}
			}
			xhttpPadRequest(r, 100)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("got %d", w.Code)
			}
			if len(h.sessions) != 0 {
				t.Fatal("session created")
			}
		})
	}
	r := httptest.NewRequest(http.MethodPost, "http://example.test/packet/?sid="+xhttpTestSession, strings.NewReader("payload"))
	r.Header.Add("X-Veilink-Number", "0")
	r.Header.Add("X-Veilink-Number", "0")
	xhttpPadRequest(r, 100)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("duplicate sequence accepted: %d", w.Code)
	}
}

func TestXHTTPMetadataRejectsUnsafeConfiguration(t *testing.T) {
	base := model.LocalTLS{TransportSecurity: "tls", XHTTP: model.XHTTP{Path: "/packet/", Mode: "packet-up", TLS: true}}
	for name, modify := range map[string]func(*model.XHTTP){
		"cookie-reserved": func(x *model.XHTTP) { x.SessionIDPlacement = "cookie"; x.SessionIDKey = "session" },
		"path-key":        func(x *model.XHTTP) { x.SessionIDKey = "sid" },
		"padding-key":     func(x *model.XHTTP) { x.SessionIDPlacement = "query"; x.SessionIDKey = "x_padding" },
		"reserved-header": func(x *model.XHTTP) { x.SeqPlacement = "header"; x.SeqKey = "X-Veilink-EOF" },
		"colliding-keys": func(x *model.XHTTP) {
			x.SessionIDPlacement = "query"
			x.SeqPlacement = "query"
			x.SessionIDKey = "same"
			x.SeqKey = "same"
		},
		"short-entropy":   func(x *model.XHTTP) { x.SessionIDTable = "hex"; x.SessionIDLength = 24 },
		"duplicate-table": func(x *model.XHTTP) { x.SessionIDTable = strings.Repeat("a", 32); x.SessionIDLength = 40 },
		"bad-table":       func(x *model.XHTTP) { x.SessionIDTable = "0123456789abcdef/"; x.SessionIDLength = 32 },
		"stream-seq":      func(x *model.XHTTP) { x.Mode = "stream-up"; x.SeqPlacement = "header" },
		"one-session":     func(x *model.XHTTP) { x.Mode = "stream-one"; x.SessionIDPlacement = "header" },
	} {
		t.Run(name, func(t *testing.T) {
			x := base
			modify(&x.XHTTP)
			if err := checkTransportSecurity(x); err == nil {
				t.Fatal("unsafe metadata accepted")
			}
		})
	}
}

func TestXHTTPMetadataCookieRejectsAmbiguity(t *testing.T) {
	x := model.XHTTP{Path: "/packet/", Mode: "packet-up", SessionIDPlacement: "cookie", SeqPlacement: "cookie"}
	h := newXHTTPHandler(x.Path, func(c net.Conn) { t.Error("unauthorized session created"); _ = c.Close() })
	h.settings = x
	defer h.Close()
	for _, tc := range []struct{ name, path, cookie string }{
		{"missing", "/packet/", ""},
		{"duplicate", "/packet/", "x_session=" + xhttpTestSession + "; x_session=" + xhttpTestSession},
		{"extra", "/packet/", "x_session=" + xhttpTestSession + "; session=stolen"},
		{"malformed", "/packet/", "x_session=" + xhttpTestSession + "; invalid"},
		{"mixed-path", "/packet/" + xhttpTestSession, "x_session=" + xhttpTestSession},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "http://example.test"+tc.path, nil)
			if tc.cookie != "" {
				r.Header.Set("Cookie", tc.cookie)
			}
			xhttpPadRequest(r, 100)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != http.StatusBadRequest || len(h.sessions) != 0 {
				t.Fatalf("accepted ambiguous cookie: %d", w.Code)
			}
		})
	}
}
