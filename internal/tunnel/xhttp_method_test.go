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
	"sync"
	"testing"
	"time"

	"veilink/internal/model"
)

func TestXHTTPPUTUplinkRoundtrip(t *testing.T) {
	for _, mode := range []string{"packet-up", "stream-up", "stream-one"} {
		t.Run(mode, func(t *testing.T) {
			h := newXHTTPHandler("/packet/", func(c net.Conn) {
				defer c.Close()
				b, err := io.ReadAll(c)
				if err == nil {
					_, _ = c.Write(b)
				}
			})
			h.mode, h.uplinkMethod = mode, http.MethodPut
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
			local := model.LocalTLS{TransportSecurity: "tls", CAPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw})), XHTTP: model.XHTTP{Path: "/packet/", Mode: mode, TLS: true, UplinkHTTPMethod: http.MethodPut}}
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			c, err := dialXHTTP(ctx, u.Host, host, local)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			payload := bytes.Repeat([]byte("put-up"), 6000)
			if _, err := c.Write(payload); err != nil {
				t.Fatal(err)
			}
			if err := c.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(c)
			if err != nil || !bytes.Equal(got, payload) {
				t.Fatalf("roundtrip: %d bytes: %v", len(got), err)
			}
			mu.Lock()
			observed := append([]string(nil), methods...)
			mu.Unlock()
			get, put := 0, 0
			for _, method := range observed {
				switch method {
				case http.MethodGet:
					get++
				case http.MethodPut:
					put++
				default:
					t.Fatalf("unexpected method %q", method)
				}
			}
			if get != map[string]int{"stream-one": 0, "stream-up": 1, "packet-up": 1}[mode] || put == 0 {
				t.Fatalf("mode %s methods: %v", mode, observed)
			}
		})
	}
}

func TestXHTTPPUTRejectsPOST(t *testing.T) {
	for _, mode := range []string{"packet-up", "stream-up", "stream-one"} {
		h := newXHTTPHandler("/packet/", func(c net.Conn) { _ = c.Close() })
		h.mode, h.version, h.uplinkMethod = mode, "2", http.MethodPut
		path := "/packet/" + xhttpTestSession
		if mode == "stream-one" {
			path = "/packet/"
		} else if mode == "packet-up" {
			path += "/0"
		}
		r := httptest.NewRequest(http.MethodPost, "http://example.test"+path, bytes.NewReader([]byte("x")))
		r.ProtoMajor = 2
		if mode != "packet-up" {
			r.Header.Set("Content-Type", "application/grpc")
		}
		xhttpPadRequest(r, 100)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("%s accepted POST: %d", mode, w.Code)
		}
		h.Close()
	}
}
