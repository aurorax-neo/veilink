package tunnel

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"veilink/internal/model"
)

func TestXHTTPH2CPacketAuthorizedRoundtrip(t *testing.T) {
	for _, method := range []string{"", http.MethodPut} {
		for _, obfs := range []bool{false, true} {
			t.Run(map[bool]string{false: "legacy", true: "tokenish-cookie"}[obfs], func(t *testing.T) {
				t.Run(map[bool]string{false: "POST", true: "PUT"}[method == http.MethodPut], func(t *testing.T) {
					server, client := fixtures(t, echoServer(t))
					local := model.LocalTLS{TransportSecurity: "plain", ListenHost: "127.0.0.1", ListenPort: server.Node.Port, Decryption: mustEncryption(t), XHTTP: model.XHTTP{Path: "/h2c/", Mode: "packet-up", HTTPVersion: "2", UplinkHTTPMethod: method}}
					local.XHTTP.MaxBufferedPosts, local.XHTTP.MaxConcurrentPosts = 4, 4
					local.XHTTP.MaxEachPostBytes = 1024
					if obfs {
						local.XHTTP.PaddingObfsMode = true
						local.XHTTP.PaddingPlacement = "cookie"
						local.XHTTP.PaddingKey = "x_cover"
						local.XHTTP.PaddingMethod = "tokenish"
						local.XHTTP.SessionIDPlacement = "cookie"
						local.XHTTP.SessionIDKey = "x_sid"
						local.XHTTP.SeqPlacement = "cookie"
						local.XHTTP.SeqKey = "x_seq"
					}
					server.Node.Tunnel = local
					server.Node.ConnectEndpoints = []model.ConnectEndpoint{{ID: "h2c", Name: "h2c", Host: "127.0.0.1", Port: local.ListenPort, Enabled: true}}
					public, err := DeriveClientTunnel(model.LocalTLS{}, local, server.Node)
					if err != nil {
						t.Fatal(err)
					}
					if !decryptionEnabled(public.Encryption) || public.Decryption != "" {
						t.Fatal("missing public encryption or leaked private material")
					}
					client.Nodes[0] = server.Node
					client.Nodes[0].Tunnel = public
					run(t, server, model.LocalTLS{})
					run(t, client, model.LocalTLS{})
					awaitEcho(t, server.Mappings[0].ListenPort)
					if err = exchange(server.Mappings[0].ListenPort, bytes.Repeat([]byte("h2c-encrypted\x00"), 2048), true); err != nil {
						t.Fatal(err)
					}
				})
			})
		}
	}
}

func TestXHTTPH2CUsesHTTP2AndDoesNotDowngrade(t *testing.T) {
	h := newXHTTPHandler("/h2c/", func(c net.Conn) {
		defer c.Close()
		b, err := io.ReadAll(c)
		if err == nil {
			_, _ = c.Write(b)
		}
	})
	s := httptest.NewUnstartedServer(h)
	protocols := new(http.Protocols)
	protocols.SetUnencryptedHTTP2(true)
	s.Config.Protocols = protocols
	s.Start()
	t.Cleanup(func() { h.Close(); s.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	u, _ := url.Parse(s.URL)
	host, _, _ := net.SplitHostPort(u.Host)
	local := model.LocalTLS{XHTTP: model.XHTTP{Path: "/h2c/", Mode: "packet-up", HTTPVersion: "2"}}
	c, err := dialXHTTP(ctx, u.Host, host, local)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(4 * time.Second))
	if _, err = c.Write([]byte("h2c")); err != nil {
		t.Fatal(err)
	}
	if err = c.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if got, err := io.ReadAll(c); err != nil || string(got) != "h2c" {
		t.Fatalf("roundtrip %q: %v", got, err)
	}
	// A server offering only HTTP/1.1 must fail the explicit HTTP/2 connection.
	h1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer h1.Close()
	addr, _ := url.Parse(h1.URL)
	ctx2, stop := context.WithTimeout(context.Background(), 2*time.Second)
	defer stop()
	if conn, err := dialXHTTP(ctx2, addr.Host, "127.0.0.1", local); err == nil {
		conn.Close()
		t.Fatal("h2c downgraded to HTTP/1.1")
	}
}

func TestXHTTPH2CRejectsUnsafeConfig(t *testing.T) {
	base := model.LocalTLS{TransportSecurity: "plain", XHTTP: model.XHTTP{Path: "/h2c/", Mode: "packet-up", HTTPVersion: "2"}}
	for name, change := range map[string]func(*model.LocalTLS){
		"stream-up":  func(c *model.LocalTLS) { c.XHTTP.Mode = "stream-up" },
		"stream-one": func(c *model.LocalTLS) { c.XHTTP.Mode = "stream-one" },
		"tls-origin": func(c *model.LocalTLS) { c.TransportSecurity = "tls" },
		"reality":    func(c *model.LocalTLS) { c.Reality.PublicKey = "key" },
	} {
		t.Run(name, func(t *testing.T) {
			config := base
			change(&config)
			if err := checkTransportSecurity(config); err == nil {
				t.Fatal("unsafe h2c accepted")
			}
		})
	}
	if err := checkTransportSecurity(base); err != nil {
		t.Fatal(err)
	}
	if err := CheckBootstrap("server", base); err == nil {
		t.Fatal("h2c accepted without VLESS encryption")
	}
}
