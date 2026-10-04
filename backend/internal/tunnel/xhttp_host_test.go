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

func TestXHTTPHostOverrideRoundtripAndRejectsMismatch(t *testing.T) {
	for _, mode := range []string{"packet-up", "stream-up", "stream-one"} {
		t.Run(mode, func(t *testing.T) {
			seen := make(chan string, 8)
			h := newXHTTPHandler("/packet/", func(c net.Conn) {
				defer c.Close()
				data, err := io.ReadAll(c)
				if err == nil {
					_, _ = c.Write(data)
				}
			})
			h.mode, h.host = mode, "edge.example.com"
			s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seen <- r.Host
				h.ServeHTTP(w, r)
			}))
			s.EnableHTTP2 = true
			s.StartTLS()
			t.Cleanup(func() { h.Close(); s.Close() })
			u, _ := url.Parse(s.URL)
			host, _, _ := net.SplitHostPort(u.Host)
			local := model.LocalTLS{TransportSecurity: "tls", CAPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw})), XHTTP: model.XHTTP{Host: "edge.example.com", Path: "/packet/", Mode: mode, TLS: true, HTTPVersion: "2"}}
			ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
			defer cancel()
			c, err := dialXHTTP(ctx, u.Host, host, local)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			payload := bytes.Repeat([]byte("host"), 1024)
			if _, err = c.Write(payload); err != nil {
				t.Fatal(err)
			}
			if err = c.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
				t.Fatal(err)
			}
			data, err := io.ReadAll(c)
			if err != nil || !bytes.Equal(data, payload) {
				t.Fatalf("roundtrip: %d bytes %v", len(data), err)
			}
			count := 2
			if mode == "stream-one" {
				count = 1
			}
			for i := 0; i < count; i++ {
				select {
				case got := <-seen:
					if got != local.XHTTP.Host {
						t.Fatalf("Host %q", got)
					}
				case <-ctx.Done():
					t.Fatal("missing uplink/downlink request")
				}
			}
			if mode == "packet-up" {
				bad, err := http.NewRequestWithContext(ctx, http.MethodGet, s.URL+"/packet/"+xhttpTestSession, nil)
				if err != nil {
					t.Fatal(err)
				}
				xhttpPadRequest(bad, 100)
				res, err := s.Client().Do(bad)
				if err != nil {
					t.Fatal(err)
				}
				res.Body.Close()
				if res.StatusCode != http.StatusNotFound {
					t.Fatalf("wrong Host status %d", res.StatusCode)
				}
				// Authority override is not a substitute for TLS name verification.
				if wrong, err := dialXHTTP(ctx, u.Host, "untrusted.invalid", local); err == nil {
					wrong.Close()
					t.Fatal("Host bypassed certificate validation")
				}
			}
		})
	}
}

func TestXHTTPHostValidation(t *testing.T) {
	base := model.LocalTLS{TransportSecurity: "plain", XHTTP: model.XHTTP{Path: "/packet/", Mode: "packet-up", TLS: true}}
	for _, host := range []string{"Example.COM", "bad:443", "[::1]", "user@host.example", "host/path", "localhost", "-bad.example", "a..example"} {
		base.XHTTP.Host = host
		if err := checkTransportSecurity(base); err == nil {
			t.Fatalf("accepted Host %q", host)
		}
	}
	base.XHTTP.Host = "edge.example.com"
	if err := checkTransportSecurity(base); err != nil {
		t.Fatal(err)
	}
}
