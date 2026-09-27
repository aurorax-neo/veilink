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
		t.Run(strconv.FormatBool(secure), func(t *testing.T) {
			server, client := fixtures(t, echoServer(t))
			local := model.LocalTLS{TransportSecurity: "plain", ListenHost: "127.0.0.1", ListenPort: server.Node.Port, Decryption: mustEncryption(t), XHTTP: model.XHTTP{Path: "/cdn/", Mode: "packet-up", TLS: secure}}
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
