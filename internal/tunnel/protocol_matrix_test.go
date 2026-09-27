package tunnel

import (
	"bytes"
	"fmt"
	"sync"
	"testing"

	"veilink/internal/model"
)

// This is a private Veilink runtime matrix, not a third-party interoperability test.
func TestProtocolMatrixRoundTrip(t *testing.T) {
	profiles := []struct {
		transport  string
		encryption bool
		vision     bool
	}{
		{"tls", false, false}, {"reality", false, false},
		{"plain", true, false}, {"hysteria2", false, false},
		{"tls", true, false}, {"reality", true, false}, {"hysteria2", true, false},
		{"tls", false, true}, {"reality", false, true},
		{"tls", true, true}, {"reality", true, true},
		{"xhttp-https", false, false}, {"xhttp-https", true, false}, {"xhttp-http", true, false},
	}
	modes := []struct{ network, mux string }{
		{"tcp", ""}, {"tcp", model.MuxTypeSMux},
		{"tcp", model.MuxTypeYAMux}, {"tcp", model.MuxTypeH2Mux}, {"udp", ""},
	}
	count := 0
	for _, profile := range profiles {
		for _, mode := range modes {
			count++
			mux := mode.mux
			if mux == "" {
				mux = "off"
			}
			name := fmt.Sprintf("%s/encryption=%t/vision=%t/%s/%s", profile.transport, profile.encryption, profile.vision, mode.network, mux)
			t.Run(name, func(t *testing.T) {
				files := tlsFiles(t)
				local := files
				switch profile.transport {
				case "xhttp-https":
					local.XHTTP = model.XHTTP{Path: "/veilink/", Mode: "packet-up", TLS: true}
				case "xhttp-http":
					local = model.LocalTLS{TransportSecurity: "plain", XHTTP: model.XHTTP{Path: "/veilink/", Mode: "packet-up"}}
				case "plain":
					local = model.LocalTLS{TransportSecurity: "plain"}
				case "reality":
					priv, _, err := GenerateX25519()
					if err != nil {
						t.Fatal(err)
					}
					local = model.LocalTLS{Reality: model.Reality{
						Dest: camouflage(t, files.CertPEM, files.KeyPEM), PrivateKey: priv,
						ShortIDs: "0123456789abcdef", ServerNames: "gateway.test",
					}}
				case "hysteria2":
					local.TransportSecurity = ""
					local.Hysteria2.Password = "protocol-matrix-secret"
				}
				if profile.encryption {
					local.Decryption = mustEncryption(t)
				}
				if profile.vision {
					local.Flow = flowVision
				}
				var target int
				if mode.network == "udp" {
					target = udpEchoServer(t)
				} else {
					target = echoServer(t)
				}
				server, client := fixtures(t, target)
				local.ListenHost, local.ListenPort = "127.0.0.1", server.Node.Port
				if profile.transport == "hysteria2" {
					local.ListenPort = freeUDPPort(t)
				}
				server.Node.Port, server.Node.Tunnel = local.ListenPort, local
				mapping := server.Mappings[0]
				mapping.Network, mapping.Mux, mapping.MuxType = mode.network, mode.mux != "", mode.mux
				if mode.network == "udp" {
					mapping.ListenPort = freeUDPPort(t)
				}
				server.Mappings[0], client.Mappings[0] = mapping, mapping
				public, err := PublicPeerTunnel(local, server.Node)
				if err != nil {
					t.Fatal(err)
				}
				if public.KeyPEM != "" || public.CertPEM != "" || public.Decryption != "" || public.Reality.PrivateKey != "" {
					t.Fatal("private server material in public template")
				}
				// As in TestPEMSnapshotHandshakeAndTrust, supply the authorized HY2 credential separately.
				public.Hysteria2 = local.Hysteria2
				client.Nodes[0] = server.Node
				client.Nodes[0].Tunnel = public
				run(t, server, model.LocalTLS{})
				run(t, client, model.LocalTLS{})
				if mode.network == "udp" {
					awaitUDPEcho(t, mapping.ListenPort)
				} else {
					awaitEcho(t, mapping.ListenPort)
				}
				// Distinct concurrent peers exercise mux reuse / independent UDP sessions.
				var wg sync.WaitGroup
				for peer := 0; peer < 3; peer++ {
					wg.Add(1)
					go func(peer int) {
						defer wg.Done()
						payload := bytes.Repeat([]byte{0, byte(peer), 0xff, 0x17}, 256)
						var err error
						if mode.network == "udp" {
							err = exchangeUDP(mapping.ListenPort, payload)
						} else {
							err = exchange(mapping.ListenPort, bytes.Repeat(payload, 64), true)
						}
						if err != nil {
							t.Errorf("peer %d: %v", peer, err)
						}
					}(peer)
				}
				wg.Wait()
			})
		}
	}
	if count != 70 {
		t.Fatalf("matrix size changed: %d", count)
	}
}
