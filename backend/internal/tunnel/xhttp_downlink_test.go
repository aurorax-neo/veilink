package tunnel

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strconv"
	"sync/atomic"
	"testing"
	"veilink/internal/model"
)

func TestXHTTPDownloadEndpointRequiresAuthorizedGatewayEndpoint(t *testing.T) {
	gateway := model.Node{ID: "server", Role: "server", ConnectEndpoints: []model.ConnectEndpoint{{ID: "up", Host: "up.example", Port: 443, Enabled: true}}}
	if _, err := bindingGateway(gateway, model.Binding{ServerID: "server", ConnectEndpointID: "down"}); err == nil {
		t.Fatal("unknown endpoint accepted")
	}
	gateway.ConnectEndpoints = append(gateway.ConnectEndpoints, model.ConnectEndpoint{ID: "down", Host: "down.example", Port: 443, Enabled: false})
	if _, err := bindingGateway(gateway, model.Binding{ServerID: "server", ConnectEndpointID: "down"}); err == nil {
		t.Fatal("disabled endpoint accepted")
	}
}

func TestXHTTPDownloadEndpointRuntimeRoundtrip(t *testing.T) {
	for _, security := range []string{"tls", "plain", "reality"} {
		for _, mode := range []string{"packet-up", "auto", "stream-up"} {
			if security == "plain" && mode == "stream-up" {
				continue
			}
			t.Run(security+"/"+mode, func(t *testing.T) {
				s, c := fixtures(t, echoServer(t))
				local := tlsFiles(t)
				var get, post atomic.Int32
				if security == "reality" {
					priv, _, err := GenerateX25519()
					if err != nil {
						t.Fatal(err)
					}
					local = model.LocalTLS{Reality: model.Reality{PrivateKey: priv, ShortIDs: "aa", ServerNames: "gateway.test", Dest: camouflage(t, local.CertPEM, local.KeyPEM, true)}}
					local.Reality.Mldsa65Seed, local.Reality.Mldsa65Verify, err = GenerateMldsa65()
					if err != nil {
						t.Fatal(err)
					}
				}
				if security == "plain" {
					local = model.LocalTLS{TransportSecurity: "plain", Decryption: mustEncryption(t)}
				}
				local.ListenHost, local.ListenPort = "127.0.0.1", s.Node.Port
				local.XHTTP = model.XHTTP{Path: "/down/", Mode: mode, TLS: security == "tls", HTTPVersion: "2", DownloadEndpointID: "down", Xmux: model.XHTTPXmux{MaxConcurrency: 4, MaxConnections: 2}}
				// Separate TCP entrances reach one authenticated origin/session registry.
				proxy := func(counter *atomic.Int32) int {
					ln, err := net.Listen("tcp", "127.0.0.1:0")
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = ln.Close() })
					go func() {
						for {
							incoming, err := ln.Accept()
							if err != nil {
								return
							}
							counter.Add(1)
							go func() {
								defer incoming.Close()
								outgoing, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(local.ListenPort)))
								if err != nil {
									return
								}
								defer outgoing.Close()
								done := make(chan struct{})
								go func() { _, _ = io.Copy(outgoing, incoming); _ = outgoing.(*net.TCPConn).CloseWrite(); close(done) }()
								_, _ = io.Copy(incoming, outgoing)
								_ = incoming.Close()
								<-done
							}()
						}
					}()
					return ln.Addr().(*net.TCPAddr).Port
				}
				up, down := proxy(&post), proxy(&get)
				s.Node.ConnectEndpoints = []model.ConnectEndpoint{{ID: "up", Host: "127.0.0.1", Port: up, Enabled: true}, {ID: "down", Host: "127.0.0.1", Port: down, Enabled: true}}
				s.Node.Tunnel = local
				public, err := PublicPeerTunnel(local, s.Node)
				if err != nil {
					t.Fatal(err)
				}
				c.Nodes[0] = s.Node
				c.Nodes[0].Tunnel = public
				run(t, s, model.LocalTLS{})
				run(t, c, model.LocalTLS{})
				awaitEcho(t, s.Mappings[0].ListenPort)
				if err := exchange(s.Mappings[0].ListenPort, bytes.Repeat([]byte("split-download\x00"), 2048), true); err != nil {
					t.Fatal(err)
				}
				if get.Load() == 0 || post.Load() == 0 {
					t.Fatal("separate entrance not dialed")
				}
			})
		}
	}
}

func TestXHTTPStreamingDownlinkRoutesGETOnly(t *testing.T) {
	origin, _ := streamTestServer(t, "stream-up", func(c net.Conn) { defer c.Close(); _, _ = io.Copy(c, c) })
	target, _ := url.Parse(origin.URL)
	forbidden := atomic.Int32{}
	edge := func(method string) *httptest.Server {
		p := httputil.NewSingleHostReverseProxy(target)
		p.Transport = origin.Client().Transport
		p.FlushInterval = -1
		s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != method {
				forbidden.Add(1)
				http.Error(w, "wrong entrance", 403)
				return
			}
			p.ServeHTTP(w, r)
		}))
		s.EnableHTTP2 = true
		s.StartTLS()
		t.Cleanup(s.Close)
		return s
	}
	up, down := edge(http.MethodPost), edge(http.MethodGet)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c, err := dialXHTTPStream(ctx, up.Client(), down.Client(), &xhttpTransportPair{up: up.Client().Transport.(*http.Transport), down: down.Client().Transport.(*http.Transport)}, up.URL+"/packet/", down.URL+"/packet/", model.XHTTP{Mode: "stream-up", TLS: true}, false, nil, cancel)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	data := bytes.Repeat([]byte{0, 255, 23}, 1024)
	go func() { _, _ = c.Write(data); _ = c.(interface{ CloseWrite() error }).CloseWrite() }()
	got := make([]byte, len(data))
	if _, err := io.ReadFull(c, got); err != nil || !bytes.Equal(data, got) {
		t.Fatalf("split response: %v", err)
	}
	if forbidden.Load() != 0 {
		t.Fatal("request used wrong entrance")
	}
}

func TestXHTTPDownloadEndpointPreservedWithExplicitUploadBinding(t *testing.T) {
	gateway := model.Node{
		ID: "server", Role: "server",
		ConnectEndpoints: []model.ConnectEndpoint{
			{ID: "up", Host: "up.example", Port: 443, Enabled: true},
			{ID: "down", Host: "down.example", Port: 8443, Enabled: true},
		},
		Tunnel: model.LocalTLS{XHTTP: model.XHTTP{Mode: "packet-up", DownloadEndpointID: "down"}},
	}
	selected, err := bindingGateway(gateway, model.Binding{ServerID: "server", ConnectEndpointID: "up"})
	if err != nil {
		t.Fatal(err)
	}
	if len(selected.ConnectEndpoints) != 2 || selected.ConnectEndpoints[0].ID != "up" || selected.ConnectEndpoints[1].ID != "down" {
		t.Fatalf("authorized upload/downlink endpoints were not preserved: %#v", selected.ConnectEndpoints)
	}
}
func TestXHTTPDownloadEndpointRuntimeFailsClosed(t *testing.T) {
	x := model.LocalTLS{CAPEM: "", XHTTP: model.XHTTP{Path: "/x/", Mode: "packet-up", DownloadEndpointID: "down"}}
	if _, err := dialXHTTPWithDownDialer(context.Background(), "127.0.0.1:1", "127.0.0.1", x, func(context.Context) (net.Conn, error) { return nil, nil }, nil, ""); err == nil {
		t.Fatal("missing downlink dialer accepted")
	}
}
