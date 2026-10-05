package tunnel

import (
	"bytes"
	"fmt"
	"sync"
	"testing"

	"veilink/internal/model"
)

// Exercise actual authorized reverse tunnels, not just mode selection. HTTP/1
// streaming, plaintext streaming and REALITY HTTP/3 are separately rejected.
func TestXHTTPCombinationMatrix(t *testing.T) {
	count := 0
	for _, security := range []string{"tls", "plain", "reality"} {
		for _, version := range []string{"", "1.1", "2", "3"} {
			for _, mode := range []string{"packet-up", "auto", "stream-up", "stream-one"} {
				x := model.XHTTP{Path: "/matrix/", Mode: mode, TLS: security == "tls", HTTPVersion: version}
				effective := xhttpEffectiveMode(x, security == "reality")
				if (version == "1.1" && effective != "packet-up") || (security == "plain" && (effective != "packet-up" || version == "3")) || (security == "reality" && version == "3") {
					continue
				}
				for _, encryption := range []bool{false, true} {
					if security == "plain" && !encryption {
						continue
					}
					for _, mldsa := range []bool{false, true} {
						if mldsa && security != "reality" {
							continue
						}
						for _, mux := range []string{"", model.MuxTypeSMux, model.MuxTypeYAMux, model.MuxTypeH2Mux, "udp"} {
							count++
							t.Run(fmt.Sprintf("%s/%s/%s/enc=%t/mldsa=%t/mux=%s", security, version, mode, encryption, mldsa, mux), func(t *testing.T) {
								t.Parallel()
								local := tlsFiles(t)
								if security == "plain" {
									local = model.LocalTLS{TransportSecurity: "plain"}
								}
								if security == "reality" {
									priv, _, err := GenerateX25519()
									if err != nil {
										t.Fatal(err)
									}
									local = model.LocalTLS{Reality: model.Reality{PrivateKey: priv, ShortIDs: "aa", ServerNames: "gateway.test", Dest: camouflage(t, local.CertPEM, local.KeyPEM, mldsa)}}
									if mldsa {
										local.Reality.Mldsa65Seed, local.Reality.Mldsa65Verify, err = GenerateMldsa65()
										if err != nil {
											t.Fatal(err)
										}
									}
								}
								local.XHTTP = x
								if encryption {
									local.Decryption = mustEncryption(t)
								}
								target := 0
								if mux == "udp" {
									target = udpEchoServer(t)
								} else {
									target = echoServer(t)
								}
								s, c := fixtures(t, target)
								local.ListenHost, local.ListenPort = "127.0.0.1", s.Node.Port
								if version == "3" {
									local.ListenPort = freeUDPPort(t)
									s.Node.Port = local.ListenPort
								}
								s.Node.Tunnel = local
								mapping := s.Mappings[0]
								if mux == "udp" {
									mapping.Network, mapping.ListenPort = "udp", freeUDPPort(t)
								} else {
									mapping.Mux, mapping.MuxType = mux != "", mux
								}
								s.Mappings[0], c.Mappings[0] = mapping, mapping
								public, err := PublicPeerTunnel(local, s.Node)
								if err != nil {
									t.Fatal(err)
								}
								if public.KeyPEM != "" || public.Decryption != "" || public.Reality.PrivateKey != "" || public.Reality.Mldsa65Seed != "" {
									t.Fatal("server secret in public template")
								}
								c.Nodes[0] = s.Node
								c.Nodes[0].Tunnel = public
								run(t, s, model.LocalTLS{})
								run(t, c, model.LocalTLS{})
								if mux == "udp" {
									awaitUDPEcho(t, mapping.ListenPort)
								} else {
									awaitEcho(t, mapping.ListenPort)
								}
								var wg sync.WaitGroup
								for peer := 0; peer < 2; peer++ {
									wg.Add(1)
									go func(peer int) {
										defer wg.Done()
										data := bytes.Repeat([]byte{0, byte(peer), 255, 23}, 128)
										var err error
										if mux == "udp" {
											err = exchangeUDP(mapping.ListenPort, data)
										} else {
											err = exchange(mapping.ListenPort, bytes.Repeat(data, 16), true)
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
				}
			}
		}
	}
	if count != 350 {
		t.Fatalf("unexpected matrix size: %d", count)
	}
}

func TestXHTTPInvalidCombinationMatrix(t *testing.T) {
	count := 0
	for _, security := range []string{"tls", "plain", "reality"} {
		for _, version := range []string{"1.1", "2", "3"} {
			for _, mode := range []string{"packet-up", "auto", "stream-up", "stream-one"} {
				local := model.LocalTLS{TransportSecurity: security, XHTTP: model.XHTTP{Path: "/matrix/", Mode: mode, TLS: security == "tls", HTTPVersion: version}}
				if security == "reality" {
					local.TransportSecurity = ""
					local.Reality.PublicKey = "present"
				}
				effective := xhttpEffectiveMode(local.XHTTP, security == "reality")
				invalid := (version == "1.1" && effective != "packet-up") || (security == "plain" && (effective != "packet-up" || version == "3")) || (security == "reality" && version == "3")
				if !invalid {
					continue
				}
				count++
				t.Run(security+"/"+version+"/"+mode, func(t *testing.T) {
					if err := checkTransportSecurity(local); err == nil {
						t.Fatal("unsupported combination accepted")
					}
				})
			}
		}
	}
	if count != 17 {
		t.Fatalf("unexpected rejected matrix size: %d", count)
	}
}
