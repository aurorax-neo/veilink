package tunnel

import (
	"bytes"
	"strings"
	"testing"

	"veilink/internal/model"
)

func TestXHTTPAutoAuthorizedRoundtrip(t *testing.T) {
	for _, version := range []string{"1.1", "2-tls", "2-h2c"} {
		t.Run(version, func(t *testing.T) {
			server, client := fixtures(t, echoServer(t))
			local := tlsFiles(t)
			local.ListenHost, local.ListenPort = "127.0.0.1", server.Node.Port
			local.XHTTP = model.XHTTP{Path: "/auto/", Mode: "auto", TLS: true, HTTPVersion: "2"}
			if version == "1.1" {
				local.XHTTP.HTTPVersion = "1.1"
			}
			if version == "2-h2c" {
				local = model.LocalTLS{TransportSecurity: "plain", ListenHost: "127.0.0.1", ListenPort: server.Node.Port, Decryption: mustEncryption(t), XHTTP: model.XHTTP{Path: "/auto/", Mode: "auto", HTTPVersion: "2"}}
			}
			server.Node.Tunnel = local
			server.Node.ConnectEndpoints = []model.ConnectEndpoint{{ID: "auto", Name: "auto", Host: "127.0.0.1", Port: local.ListenPort, Enabled: true}}
			public, err := DeriveClientTunnel(model.LocalTLS{}, local, server.Node)
			if err != nil {
				t.Fatal(err)
			}
			if public.XHTTP.Mode != "auto" {
				t.Fatal("auto not derived")
			}
			client.Nodes[0] = server.Node
			client.Nodes[0].Tunnel = public
			run(t, server, model.LocalTLS{})
			run(t, client, model.LocalTLS{})
			awaitEcho(t, server.Mappings[0].ListenPort)
			if err := exchange(server.Mappings[0].ListenPort, bytes.Repeat([]byte("auto-business"), 1024), true); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestXHTTPAutoRealityUsesStreamOne(t *testing.T) {
	c := model.LocalTLS{XHTTP: model.XHTTP{Path: "/auto/", Mode: "auto"}, Reality: model.Reality{PublicKey: "present"}}
	if err := checkTransportSecurity(c); err != nil && !strings.Contains(err.Error(), "public") {
		t.Fatal(err)
	}
	// 对齐 Xray-core：auto + REALITY → stream-one
	if xhttpEffectiveMode(c.XHTTP, c.Reality.Enabled()) != "stream-one" {
		t.Fatal("REALITY auto did not select stream-one")
	}
}

func TestXHTTPAutoRealityWithDownloadUsesStreamUp(t *testing.T) {
	c := model.LocalTLS{
		XHTTP:   model.XHTTP{Path: "/auto/", Mode: "auto", DownloadEndpointID: "ep1"},
		Reality: model.Reality{PublicKey: "present"},
	}
	// 对齐 Xray-core：auto + REALITY + downloadSettings → stream-up
	if xhttpEffectiveMode(c.XHTTP, c.Reality.Enabled()) != "stream-up" {
		t.Fatal("REALITY auto with download did not select stream-up")
	}
}

func TestXHTTPAutoNoRealityUsesPacketUp(t *testing.T) {
	c := model.LocalTLS{XHTTP: model.XHTTP{Path: "/auto/", Mode: "auto"}}
	// 对齐 Xray-core：auto + 无 REALITY → packet-up
	if xhttpEffectiveMode(c.XHTTP, c.Reality.Enabled()) != "packet-up" {
		t.Fatal("non-REALITY auto did not select packet-up")
	}
}
