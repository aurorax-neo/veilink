package tunnel

import (
	"bytes"
	"encoding/pem"
	"net"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strconv"
	"testing"

	"veilink/internal/model"
)

func TestXHTTPRuntimeThroughProxy(t *testing.T) {
	for _, secure := range []bool{false, true} {
		for _, dataPlacement := range []string{"body", "header", "cookie"} {
			t.Run(strconv.FormatBool(secure)+"/"+dataPlacement, func(t *testing.T) {
				server, client := fixtures(t, echoServer(t))
				local := model.LocalTLS{TransportSecurity: "plain", ListenHost: "127.0.0.1", ListenPort: server.Node.Port, Decryption: mustEncryption(t), XHTTP: model.XHTTP{Path: "/cdn/", Mode: "packet-up", TLS: secure, MaxEachPostBytes: 4096, MinPostsIntervalMs: 1, MaxPostsIntervalMs: 3}}
				local.XHTTP.MaxBufferedPosts, local.XHTTP.MaxConcurrentPosts = 4, 4
				if dataPlacement != "body" {
					local.XHTTP.UplinkDataPlacement = dataPlacement
					local.XHTTP.UplinkChunkSize = 1024
					if dataPlacement == "header" {
						local.XHTTP.UplinkDataKey = "X-Veilink-Data"
					} else {
						local.XHTTP.UplinkDataKey = "x_data"
					}
				}
				if secure {
					local.XHTTP.SessionIDPlacement, local.XHTTP.SessionIDKey = "header", "X-Veilink-SID"
					local.XHTTP.SeqPlacement, local.XHTTP.SeqKey = "query", "seq"
				} else {
					local.XHTTP.SessionIDPlacement, local.XHTTP.SessionIDKey = "query", "sid"
					local.XHTTP.SeqPlacement = "path"
				}
				local.XHTTP.SessionIDTable, local.XHTTP.SessionIDLength = "hex", 32
				origin, _ := url.Parse("http://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(local.ListenPort)))
				proxy := httputil.NewSingleHostReverseProxy(origin)
				proxy.FlushInterval = -1
				var edge *httptest.Server
				if secure {
					edge = httptest.NewTLSServer(proxy)
					local.CAPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: edge.Certificate().Raw}))
				} else {
					edge = httptest.NewServer(proxy)
				}
				t.Cleanup(edge.Close)
				edgeURL, _ := url.Parse(edge.URL)
				host, port, _ := net.SplitHostPort(edgeURL.Host)
				portNumber, _ := strconv.Atoi(port)
				server.Node.Tunnel = local
				server.Node.ConnectEndpoints = []model.ConnectEndpoint{{ID: "offline", Name: "Offline", Host: "127.0.0.1", Port: freePort(t), Enabled: true}, {ID: "cdn", Name: "CDN", Host: host, Port: portNumber, Enabled: true}}
				public, err := DeriveClientTunnel(model.LocalTLS{}, local, server.Node)
				if err != nil {
					t.Fatal(err)
				}
				client.Nodes[0] = server.Node
				client.Nodes[0].Tunnel = public
				run(t, server, model.LocalTLS{})
				run(t, client, model.LocalTLS{})
				awaitEcho(t, server.Mappings[0].ListenPort)
				if err = exchange(server.Mappings[0].ListenPort, bytes.Repeat([]byte("cdn-binary\x00\xff"), 8192), true); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestXHTTPStreamingRuntimeTLS(t *testing.T) {
	for _, mode := range []string{"stream-up", "stream-one"} {
		t.Run(mode, func(t *testing.T) {
			server, client := fixtures(t, echoServer(t))
			local := tlsFiles(t)
			local.ListenHost = "127.0.0.1"
			local.ListenPort = server.Node.Port
			local.XHTTP = model.XHTTP{Path: "/cdn/", Mode: mode, TLS: true}
			local.XHTTP.HTTPVersion = "2"
			if mode == "stream-up" {
				local.XHTTP.StreamUpServerSecs, local.XHTTP.StreamUpServerMaxSecs = 1, 2
			}
			server.Node.Tunnel = local
			server.Node.ConnectEndpoints = []model.ConnectEndpoint{{ID: "local", Name: "Local", Host: "127.0.0.1", Port: local.ListenPort, Enabled: true}}
			public, err := DeriveClientTunnel(model.LocalTLS{}, local, server.Node)
			if err != nil {
				t.Fatal(err)
			}
			client.Nodes[0] = server.Node
			client.Nodes[0].Tunnel = public
			run(t, server, model.LocalTLS{})
			run(t, client, model.LocalTLS{})
			awaitEcho(t, server.Mappings[0].ListenPort)
			if err := exchange(server.Mappings[0].ListenPort, bytes.Repeat([]byte("stream-business\x00"), 1024), true); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestXHTTPBufferedRuntimeHTTP2(t *testing.T) {
	server, client := fixtures(t, echoServer(t))
	local := tlsFiles(t)
	local.ListenHost, local.ListenPort = "127.0.0.1", server.Node.Port
	local.XHTTP = model.XHTTP{Path: "/buffer/", Mode: "packet-up", TLS: true, HTTPVersion: "2", MaxEachPostBytes: 1024, MaxBufferedPosts: 4, MaxConcurrentPosts: 4}
	server.Node.Tunnel = local
	server.Node.ConnectEndpoints = []model.ConnectEndpoint{{ID: "local", Host: "127.0.0.1", Port: local.ListenPort, Enabled: true}}
	public, err := DeriveClientTunnel(model.LocalTLS{}, local, server.Node)
	if err != nil {
		t.Fatal(err)
	}
	client.Nodes[0] = server.Node
	client.Nodes[0].Tunnel = public
	run(t, server, model.LocalTLS{})
	run(t, client, model.LocalTLS{})
	awaitEcho(t, server.Mappings[0].ListenPort)
	if err := exchange(server.Mappings[0].ListenPort, bytes.Repeat([]byte("buffer-h2\x00"), 2048), true); err != nil {
		t.Fatal(err)
	}
}
