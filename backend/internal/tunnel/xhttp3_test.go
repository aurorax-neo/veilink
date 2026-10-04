package tunnel

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/pem"
	"github.com/apernet/quic-go/http3"
	"io"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"

	"veilink/internal/model"
)

func TestXHTTP3RuntimeAuthorizedRoundtrip(t *testing.T) {
	for _, mode := range []string{"packet-up", "stream-up", "stream-one", "auto"} {
		t.Run(mode, func(t *testing.T) {
			server, client := fixtures(t, echoServer(t))
			local := tlsFiles(t)
			local.ListenHost = "127.0.0.1"
			local.ListenPort = server.Node.Port
			local.XHTTP = model.XHTTP{Host: "edge.example.com", Headers: model.XHTTPHeaders(`{"User-Agent":"Veilink-Test","X-Custom-Route":"east"}`), Path: "/h3/", Mode: mode, TLS: true, HTTPVersion: "3", PaddingBytes: 100, PaddingMaxBytes: 256, NoGRPCHeader: mode == "stream-up" || mode == "stream-one", NoSSEHeader: true, UplinkHTTPMethod: "PUT"}
			if mode == "packet-up" || mode == "auto" {
				local.XHTTP.MaxEachPostBytes, local.XHTTP.PostBytesMax = 1024, 2048
				local.XHTTP.MaxBufferedPosts, local.XHTTP.MaxConcurrentPosts = 4, 4
			}
			if mode == "packet-up" {
				local.XHTTP.SessionIDPlacement, local.XHTTP.SessionIDKey = "header", "X-Veilink-SID"
				local.XHTTP.SeqPlacement, local.XHTTP.SeqKey = "query", "number"
				local.XHTTP.SessionIDTable, local.XHTTP.SessionIDLength = "hex", 32
			} else if mode == "stream-up" {
				local.XHTTP.StreamUpServerSecs, local.XHTTP.StreamUpServerMaxSecs = 1, 2
				local.XHTTP.SessionIDPlacement, local.XHTTP.SessionIDKey = "query", "sid"
			} else if mode == "auto" {
				local.XHTTP.SessionIDPlacement, local.XHTTP.SessionIDKey = "cookie", "x_sid"
				local.XHTTP.SeqPlacement, local.XHTTP.SeqKey = "cookie", "x_number"
			}
			server.Node.Tunnel = local
			server.Node.ConnectEndpoints = []model.ConnectEndpoint{{ID: "udp", Name: "UDP", Host: "127.0.0.1", Port: local.ListenPort, Enabled: true}}
			public, err := DeriveClientTunnel(model.LocalTLS{}, local, server.Node)
			if err != nil {
				t.Fatal(err)
			}
			client.Nodes[0] = server.Node
			client.Nodes[0].Tunnel = public
			run(t, server, model.LocalTLS{})
			run(t, client, model.LocalTLS{})
			awaitEcho(t, server.Mappings[0].ListenPort)
			if err := exchange(server.Mappings[0].ListenPort, bytes.Repeat([]byte("h3-stream\x00"), 1024), true); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestXHTTP3DirectRoundtrip(t *testing.T) {
	for _, mode := range []string{"packet-up", "stream-up", "stream-one"} {
		for _, obfs := range []bool{false, true} {
			t.Run(map[bool]string{false: "legacy", true: "tokenish-header"}[obfs], func(t *testing.T) {
				t.Run(mode, func(t *testing.T) {
					local := tlsFiles(t)
					cert, err := tls.X509KeyPair([]byte(local.CertPEM), []byte(local.KeyPEM))
					if err != nil {
						t.Fatal(err)
					}
					pc, err := net.ListenPacket("udp", "127.0.0.1:0")
					if err != nil {
						t.Fatal(err)
					}
					h := newXHTTPHandler("/h3/", func(c net.Conn) {
						defer c.Close()
						data, err := io.ReadAll(c)
						if err == nil {
							_, _ = c.Write(data)
						}
					})
					h.mode, h.version = mode, "3"
					srv := &http3.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						t.Logf("wire method=%s path=%s proto=%s length=%d ref=%q padding=%v", r.Method, r.URL.Path, r.Proto, r.ContentLength, r.Header.Get("Referer"), xhttpValidPadding(r, h.padding))
						h.ServeHTTP(w, r)
					}), TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"h3"}, Certificates: []tls.Certificate{cert}}}
					go func() { _ = srv.Serve(pc) }()
					t.Cleanup(func() { h.Close(); _ = srv.Close(); _ = pc.Close() })
					_, port, _ := net.SplitHostPort(pc.LocalAddr().String())
					local.XHTTP = model.XHTTP{Path: "/h3/", Mode: mode, TLS: true, HTTPVersion: "3"}
					if obfs {
						local.XHTTP.PaddingObfsMode = true
						local.XHTTP.PaddingPlacement = "query_in_header"
						local.XHTTP.PaddingKey = "x_cover"
						local.XHTTP.PaddingHeader = "X-Custom-Padding"
						local.XHTTP.PaddingMethod = "tokenish"
						h.settings = local.XHTTP
					}
					local.CAPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}))
					ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
					defer cancel()
					c, err := dialXHTTP(ctx, net.JoinHostPort("127.0.0.1", port), "127.0.0.1", local)
					if err != nil {
						t.Fatal(err)
					}
					defer c.Close()
					_ = c.SetDeadline(time.Now().Add(6 * time.Second))
					payload := bytes.Repeat([]byte("hello:"+strconv.Itoa(len(port))), 1500)
					if _, err := c.Write(payload); err != nil {
						t.Fatal(err)
					}
					if err := c.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
						t.Fatal(err)
					}
					got, err := io.ReadAll(c)
					if err != nil || !bytes.Equal(got, payload) {
						t.Fatalf("response %d bytes: %v", len(got), err)
					}
				})
			})
		}
	}
}

func TestXHTTP3RejectsUnsafeConfigurations(t *testing.T) {
	base := model.LocalTLS{TransportSecurity: "tls", XHTTP: model.XHTTP{Path: "/h3/", Mode: "packet-up", TLS: true, HTTPVersion: "3"}}
	for name, change := range map[string]func(*model.LocalTLS){
		"http":            func(c *model.LocalTLS) { c.XHTTP.TLS = false },
		"plain-origin":    func(c *model.LocalTLS) { c.TransportSecurity = "plain" },
		"reality":         func(c *model.LocalTLS) { c.Reality.PublicKey = "key" },
		"unknown-version": func(c *model.LocalTLS) { c.XHTTP.HTTPVersion = "4" },
		"stream-http11":   func(c *model.LocalTLS) { c.XHTTP.Mode, c.XHTTP.HTTPVersion = "stream-up", "1.1" },
	} {
		t.Run(name, func(t *testing.T) {
			bad := base
			change(&bad)
			if err := checkTransportSecurity(bad); err == nil {
				t.Fatal("unsafe XHTTP configuration accepted")
			}
		})
	}
	for _, mode := range []string{"packet-up", "stream-up", "stream-one"} {
		good := base
		good.XHTTP.Mode = mode
		if err := checkTransportSecurity(good); err != nil {
			t.Fatalf("HTTP/3 %s rejected: %v", mode, err)
		}
	}
}
