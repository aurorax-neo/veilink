package store

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"veilink/internal/model"
	"veilink/internal/tunnel"
)

func TestXHTTPConfigurationSnapshotAndPersistence(t *testing.T) {
	s, db, key := testStore(t)
	server := testNode(t, s, "server", "xhttp")
	client := testNode(t, s, "client", "client")
	isolated := testNode(t, s, "client", "isolated")
	credential := testCredential(t, s, client.ID)
	isolatedCredential := testCredential(t, s, isolated.ID)
	dec, enc, _, _, err := tunnel.GenerateVLESSEnc()
	if err != nil {
		t.Fatal(err)
	}
	server.Tunnel = model.LocalTLS{TransportSecurity: "plain", ListenHost: "127.0.0.1", ListenPort: 8444, Decryption: dec, XHTTP: model.XHTTP{Host: "edge.example.com", Headers: model.XHTTPHeaders(`{"User-Agent":"Veilink-Test","X-Custom-Route":"east"}`), Path: "/cdn/", Mode: "packet-up", TLS: true, MaxEachPostBytes: 2048, PostBytesMax: 4096, MinPostsIntervalMs: 45, MaxPostsIntervalMs: 75, RequestTimeoutSeconds: 30, PaddingBytes: 256, PaddingMaxBytes: 512}}
	server.Tunnel.XHTTP.SessionIDPlacement, server.Tunnel.XHTTP.SessionIDKey = "header", "X-Veilink-SID"
	server.Tunnel.XHTTP.SeqPlacement, server.Tunnel.XHTTP.SeqKey = "query", "number"
	server.Tunnel.XHTTP.SessionIDTable, server.Tunnel.XHTTP.SessionIDLength = "hex", 32
	server.Tunnel.XHTTP.PaddingObfsMode = true
	server.Tunnel.XHTTP.PaddingPlacement = "query_in_header"
	server.Tunnel.XHTTP.PaddingKey = "x_cover"
	server.Tunnel.XHTTP.PaddingHeader = "X-Custom-Padding"
	server.Tunnel.XHTTP.PaddingMethod = "tokenish"
	server.Tunnel.XHTTP.MaxBufferedPosts, server.Tunnel.XHTTP.MaxConcurrentPosts = 8, 4
	server.Tunnel.XHTTP.UplinkDataPlacement, server.Tunnel.XHTTP.UplinkDataKey, server.Tunnel.XHTTP.UplinkChunkSize = "header", "X-Veilink-Data", 1024
	server.Tunnel.XHTTP.Xmux = model.XHTTPXmux{MaxConcurrency: 2, MaxConnections: 2, CMaxReuseTimes: 10, HMaxRequestTimes: 20, HMaxReusableSecs: 60, KeepAlivePeriod: 30}
	server.Address, server.Port = "cdn.example.com", 443
	server.ConnectEndpoints = []model.ConnectEndpoint{{ID: "cdn", Name: "CDN", Host: "cdn.example.com", Port: 443, Enabled: true}, {ID: "backup", Name: "Backup", Host: "backup.example.com", Port: 443, Enabled: true}}
	server.ClientTunnel = nil
	server, err = s.SaveNode(server)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.SaveMapping(testMapping(server.ID, client.ID, 8080)); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(db, key)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	snap, err := s.Snapshot(client.ID, credential)
	if err != nil || len(snap.Nodes) != 1 || len(snap.Mappings) != 1 {
		t.Fatal("snapshot", err)
	}
	peer := snap.Nodes[0]
	if peer.Tunnel.XHTTP != server.Tunnel.XHTTP || peer.Tunnel.Encryption != enc || peer.Tunnel.Decryption != "" || peer.Tunnel.KeyPEM != "" || peer.Tunnel.CertPEM != "" || peer.Tunnel.ListenPort != 0 || peer.Tunnel.ListenHost != "" {
		t.Fatal("invalid derived public template")
	}
	if len(peer.ConnectEndpoints) != 2 || peer.ConnectEndpoints[0].Host != "cdn.example.com" || peer.ConnectEndpoints[1].Host != "backup.example.com" {
		t.Fatal("candidate order lost")
	}
	raw, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	var decoded model.Snapshot
	if err = json.Unmarshal(raw, &decoded); err != nil || decoded.Nodes[0].Tunnel != peer.Tunnel {
		t.Fatal("JSON snapshot roundtrip", err)
	}
	other, err := s.Snapshot(isolated.ID, isolatedCredential)
	if err != nil || len(other.Nodes) != 0 {
		t.Fatal("unauthorized template", err)
	}
	server.ClientTunnel.XHTTP.Path = "/override/"
	if _, err = s.SaveNode(server); !errors.Is(err, ErrInvalid) {
		t.Fatal("editable client template accepted", err)
	}
}

func TestXHTTPInvalidConfigurationDoesNotAdvanceRevision(t *testing.T) {
	s, _, _ := testStore(t)
	server := testNode(t, s, "server", "xhttp")
	base := testTLS(t)
	base.XHTTP = model.XHTTP{Path: "/cdn/", Mode: "packet-up", TLS: true}
	cases := map[string]func(*model.LocalTLS){
		"stream-policy-packet": func(v *model.LocalTLS) { v.XHTTP.StreamUpServerSecs = 1 },
		"stream-policy-range": func(v *model.LocalTLS) {
			v.XHTTP.Mode = "stream-up"
			v.XHTTP.StreamUpServerSecs = 2
			v.XHTTP.StreamUpServerMaxSecs = 1
		},
		"buffer-too-large":          func(v *model.LocalTLS) { v.XHTTP.MaxBufferedPosts = 33 },
		"concurrency-window":        func(v *model.LocalTLS) { v.XHTTP.MaxBufferedPosts = 1; v.XHTTP.MaxConcurrentPosts = 3 },
		"metadata-cookie-reserved":  func(v *model.LocalTLS) { v.XHTTP.SessionIDPlacement = "cookie"; v.XHTTP.SessionIDKey = "session" },
		"metadata-low-entropy":      func(v *model.LocalTLS) { v.XHTTP.SessionIDTable = "hex"; v.XHTTP.SessionIDLength = 24 },
		"metadata-reserved-header":  func(v *model.LocalTLS) { v.XHTTP.SeqPlacement = "header"; v.XHTTP.SeqKey = "X-Veilink-EOF" },
		"padding-legacy-options":    func(v *model.LocalTLS) { v.XHTTP.PaddingMethod = "tokenish" },
		"padding-invalid-placement": func(v *model.LocalTLS) { v.XHTTP.PaddingObfsMode = true; v.XHTTP.PaddingPlacement = "unknown" },
		"padding-cookie-unsafe": func(v *model.LocalTLS) {
			v.XHTTP.PaddingObfsMode = true
			v.XHTTP.PaddingPlacement = "cookie"
			v.XHTTP.PaddingKey = "session"
		},
		"padding-meta-collision": func(v *model.LocalTLS) {
			v.XHTTP.PaddingObfsMode = true
			v.XHTTP.PaddingPlacement = "cookie"
			v.XHTTP.PaddingKey = "x_session"
			v.XHTTP.SessionIDPlacement = "cookie"
		},
		"padding-reserved-header": func(v *model.LocalTLS) {
			v.XHTTP.PaddingObfsMode = true
			v.XHTTP.PaddingPlacement = "header"
			v.XHTTP.PaddingHeader = "X-Veilink-EOF"
		},
		"invalid-header-direct":           func(v *model.LocalTLS) { v.XHTTP.Headers = model.XHTTPHeaders(`{"x-custom-key":"ok"}`) },
		"invalid-header-reserved":         func(v *model.LocalTLS) { v.XHTTP.Headers = model.XHTTPHeaders(`{"Cookie":"bad"}`) },
		"invalid-host-port":               func(v *model.LocalTLS) { v.XHTTP.Host = "edge.example.com:443" },
		"invalid-host-uppercase":          func(v *model.LocalTLS) { v.XHTTP.Host = "Edge.example.com" },
		"unknown-mode":                    func(v *model.LocalTLS) { v.XHTTP.Mode = "unexpected" },
		"missing-mode":                    func(v *model.LocalTLS) { v.XHTTP.Mode = "" },
		"get-uplink":                      func(v *model.LocalTLS) { v.XHTTP.UplinkHTTPMethod = "GET" },
		"lowercase-uplink":                func(v *model.LocalTLS) { v.XHTTP.UplinkHTTPMethod = "put" },
		"delete-uplink":                   func(v *model.LocalTLS) { v.XHTTP.UplinkHTTPMethod = "DELETE" },
		"relative-path":                   func(v *model.LocalTLS) { v.XHTTP.Path = "cdn/" },
		"missing-slash":                   func(v *model.LocalTLS) { v.XHTTP.Path = "/cdn" },
		"query":                           func(v *model.LocalTLS) { v.XHTTP.Path = "/cdn/?a=1" },
		"escape":                          func(v *model.LocalTLS) { v.XHTTP.Path = "/a%2fb/" },
		"dot":                             func(v *model.LocalTLS) { v.XHTTP.Path = "/a/../b/" },
		"double-slash":                    func(v *model.LocalTLS) { v.XHTTP.Path = "//" },
		"long-path":                       func(v *model.LocalTLS) { v.XHTTP.Path = "/" + strings.Repeat("a", 256) + "/" },
		"vision":                          func(v *model.LocalTLS) { v.Flow = "xtls-rprx-vision" },
		"reality":                         func(v *model.LocalTLS) { v.Reality.PublicKey = "key" },
		"hy2":                             func(v *model.LocalTLS) { v.Hysteria2.Password = "secret" },
		"http-without-encryption":         func(v *model.LocalTLS) { v.XHTTP.TLS = false },
		"plain-origin-without-encryption": func(v *model.LocalTLS) { v.TransportSecurity = "plain"; v.CertPEM = ""; v.KeyPEM = "" },
		"post-too-small":                  func(v *model.LocalTLS) { v.XHTTP.MaxEachPostBytes = 1023 },
		"post-too-large":                  func(v *model.LocalTLS) { v.XHTTP.MaxEachPostBytes = 32769 },
		"post-max-without-min":            func(v *model.LocalTLS) { v.XHTTP.PostBytesMax = 2048 },
		"post-max-below-min":              func(v *model.LocalTLS) { v.XHTTP.MaxEachPostBytes = 2048; v.XHTTP.PostBytesMax = 2047 },
		"post-max-too-large":              func(v *model.LocalTLS) { v.XHTTP.MaxEachPostBytes = 2048; v.XHTTP.PostBytesMax = 32769 },
		"post-max-stream":                 func(v *model.LocalTLS) { v.XHTTP.Mode = "stream-up"; v.XHTTP.PostBytesMax = 4096 },
		"interval-negative":               func(v *model.LocalTLS) { v.XHTTP.MinPostsIntervalMs = -1 },
		"interval-too-large":              func(v *model.LocalTLS) { v.XHTTP.MinPostsIntervalMs = 1001 },
		"interval-stream":                 func(v *model.LocalTLS) { v.XHTTP.Mode = "stream-up"; v.XHTTP.MinPostsIntervalMs = 30 },
		"interval-max-without-min":        func(v *model.LocalTLS) { v.XHTTP.MaxPostsIntervalMs = 30 },
		"interval-max-below-min":          func(v *model.LocalTLS) { v.XHTTP.MinPostsIntervalMs = 40; v.XHTTP.MaxPostsIntervalMs = 39 },
		"interval-max-too-large":          func(v *model.LocalTLS) { v.XHTTP.MinPostsIntervalMs = 40; v.XHTTP.MaxPostsIntervalMs = 1001 },
		"interval-max-stream": func(v *model.LocalTLS) {
			v.XHTTP.Mode = "stream-up"
			v.XHTTP.MinPostsIntervalMs = 0
			v.XHTTP.MaxPostsIntervalMs = 30
		},
		"timeout-too-short":       func(v *model.LocalTLS) { v.XHTTP.RequestTimeoutSeconds = 4 },
		"timeout-too-long":        func(v *model.LocalTLS) { v.XHTTP.RequestTimeoutSeconds = 61 },
		"padding-negative":        func(v *model.LocalTLS) { v.XHTTP.PaddingBytes = -1 },
		"padding-too-large":       func(v *model.LocalTLS) { v.XHTTP.PaddingBytes = 1001 },
		"padding-max-below-min":   func(v *model.LocalTLS) { v.XHTTP.PaddingBytes = 256; v.XHTTP.PaddingMaxBytes = 255 },
		"padding-max-over-limit":  func(v *model.LocalTLS) { v.XHTTP.PaddingMaxBytes = 1001 },
		"padding-max-negative":    func(v *model.LocalTLS) { v.XHTTP.PaddingMaxBytes = -1 },
		"grpc-header-packet-only": func(v *model.LocalTLS) { v.XHTTP.NoGRPCHeader = true },
		"header-limit-negative":   func(v *model.LocalTLS) { v.XHTTP.ServerMaxHeaderBytes = -1 },
		"header-limit-below-min":  func(v *model.LocalTLS) { v.XHTTP.ServerMaxHeaderBytes = 8191 },
		"header-limit-above-max":  func(v *model.LocalTLS) { v.XHTTP.ServerMaxHeaderBytes = 32769 },
		"h2c-stream":              func(v *model.LocalTLS) { v.XHTTP.HTTPVersion = "2"; v.XHTTP.TLS = false; v.XHTTP.Mode = "stream-up" },
		"h2c-tls-origin":          func(v *model.LocalTLS) { v.XHTTP.HTTPVersion = "2"; v.XHTTP.TLS = false },
		"stream-up-without-https": func(v *model.LocalTLS) { v.XHTTP.Mode = "stream-up"; v.XHTTP.TLS = false },
		"stream-one-plain-origin": func(v *model.LocalTLS) {
			v.XHTTP.Mode = "stream-one"
			v.TransportSecurity = "plain"
			v.CertPEM = ""
			v.KeyPEM = ""
		},
		"stream-up-reality":      func(v *model.LocalTLS) { v.XHTTP.Mode = "stream-up"; v.Reality.PublicKey = "key" },
		"stream-one-packet-size": func(v *model.LocalTLS) { v.XHTTP.Mode = "stream-one"; v.XHTTP.MaxEachPostBytes = 2048 },
	}
	before, err := s.load()
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			local := base
			mutate(&local)
			server.Tunnel = local
			server.ClientTunnel = nil
			if _, err := s.SaveNode(server); !errors.Is(err, ErrInvalid) {
				t.Fatal("invalid configuration accepted", err)
			}
			after, err := s.load()
			if err != nil || after.Revision != before.Revision {
				t.Fatal("rejected configuration changed revision", err)
			}
		})
	}
}

func TestXHTTPStreamingModesPersistAndDerive(t *testing.T) {
	for _, mode := range []string{"stream-up", "stream-one"} {
		t.Run(mode, func(t *testing.T) {
			s, db, key := testStore(t)
			server := testNode(t, s, "server", "server")
			client := testNode(t, s, "client", "client")
			credential := testCredential(t, s, client.ID)
			server.Tunnel = testTLS(t)
			server.Tunnel.XHTTP = model.XHTTP{Path: "/cdn/", Mode: mode, TLS: true, PaddingBytes: 256, NoGRPCHeader: true, NoSSEHeader: true, ServerMaxHeaderBytes: 16384, UplinkHTTPMethod: "PUT"}
			if mode == "stream-up" {
				server.Tunnel.XHTTP.StreamUpServerSecs, server.Tunnel.XHTTP.StreamUpServerMaxSecs = 1, 3
				server.Tunnel.XHTTP.SessionIDPlacement, server.Tunnel.XHTTP.SessionIDKey = "cookie", "x_sid"
			}
			server.ClientTunnel = nil
			var err error
			server, err = s.SaveNode(server)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = s.SaveMapping(testMapping(server.ID, client.ID, 8080)); err != nil {
				t.Fatal(err)
			}
			if err = s.Close(); err != nil {
				t.Fatal(err)
			}
			s, err = Open(db, key)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			snap, err := s.Snapshot(client.ID, credential)
			if err != nil || len(snap.Nodes) != 1 || snap.Nodes[0].Tunnel.XHTTP != server.Tunnel.XHTTP {
				t.Fatalf("mode not derived: %+v %v", snap.Nodes, err)
			}
		})
	}
}

func TestXHTTPRealityMLDSAConfigurationPersistsAndDerives(t *testing.T) {
	for _, mode := range []string{"packet-up", "auto", "stream-up", "stream-one"} {
		for _, downlink := range []bool{false, true} {
			if mode == "stream-one" && downlink {
				continue
			}
			name := mode
			if downlink {
				name += "/downlink"
			}
			t.Run(name, func(t *testing.T) {
				s, db, key := testStore(t)
				server := testNode(t, s, "server", "server")
				client := testNode(t, s, "client", "client")
				credential := testCredential(t, s, client.ID)
				private, public, err := tunnel.GenerateX25519()
				if err != nil {
					t.Fatal(err)
				}
				seed, verify, err := tunnel.GenerateMldsa65()
				if err != nil {
					t.Fatal(err)
				}
				server.Tunnel = model.LocalTLS{ListenHost: "127.0.0.1", ListenPort: 8444, Reality: model.Reality{PrivateKey: private, Dest: "cover.example:443", ShortIDs: "aa", ServerNames: "cover.example", Mldsa65Seed: seed, Mldsa65Verify: verify}, XHTTP: model.XHTTP{Path: "/cdn/", Mode: mode, HTTPVersion: "2"}}
				server.ConnectEndpoints = []model.ConnectEndpoint{{ID: "up", Name: "Upload", Host: "127.0.0.1", Port: 8444, Enabled: true}, {ID: "down", Name: "Download", Host: "127.0.0.1", Port: 9444, Enabled: true}}
				if downlink {
					server.Tunnel.XHTTP.DownloadEndpointID = "down"
				}
				server.ClientTunnel = nil
				server, err = s.SaveNode(server)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = s.SaveMapping(testMapping(server.ID, client.ID, 8080)); err != nil {
					t.Fatal(err)
				}
				if err = s.Close(); err != nil {
					t.Fatal(err)
				}
				s, err = Open(db, key)
				if err != nil {
					t.Fatal(err)
				}
				defer s.Close()
				snap, err := s.Snapshot(client.ID, credential)
				if err != nil || len(snap.Nodes) != 1 {
					t.Fatal("snapshot", err)
				}
				peer := snap.Nodes[0].Tunnel
				if peer.XHTTP != server.Tunnel.XHTTP || peer.Reality.PublicKey != public || peer.Reality.Mldsa65Verify != verify || peer.Reality.Mldsa65Seed != "" || peer.Reality.PrivateKey != "" || peer.KeyPEM != "" || peer.Decryption != "" {
					t.Fatal("invalid public REALITY template")
				}
			})
		}
	}
}

func TestXHTTP3PersistenceAndDerivation(t *testing.T) {
	for _, mode := range []string{"packet-up", "stream-up", "stream-one", "auto"} {
		t.Run(mode, func(t *testing.T) {
			s, db, key := testStore(t)
			server := testNode(t, s, "server", "h3")
			client := testNode(t, s, "client", "client")
			credential := testCredential(t, s, client.ID)
			server.Tunnel = testTLS(t)
			server.Tunnel.XHTTP = model.XHTTP{Path: "/h3/", Mode: mode, TLS: true, HTTPVersion: "3", PaddingBytes: 120, PaddingMaxBytes: 450, NoGRPCHeader: mode == "stream-up" || mode == "stream-one", NoSSEHeader: true}
			server.ClientTunnel = nil
			var err error
			server, err = s.SaveNode(server)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = s.SaveMapping(testMapping(server.ID, client.ID, 8080)); err != nil {
				t.Fatal(err)
			}
			if err = s.Close(); err != nil {
				t.Fatal(err)
			}
			s, err = Open(db, key)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			snap, err := s.Snapshot(client.ID, credential)
			if err != nil || len(snap.Nodes) != 1 || snap.Nodes[0].Tunnel.XHTTP != server.Tunnel.XHTTP {
				t.Fatalf("HTTP/3 template not derived: %+v %v", snap.Nodes, err)
			}
			if snap.Nodes[0].Tunnel.KeyPEM != "" || snap.Nodes[0].Tunnel.CertPEM != "" {
				t.Fatal("server identity leaked")
			}
		})
	}
}

func TestXHTTPH2CPersistenceAndDerivation(t *testing.T) {
	s, db, key := testStore(t)
	server := testNode(t, s, "server", "h2c")
	client := testNode(t, s, "client", "client")
	credential := testCredential(t, s, client.ID)
	dec, enc, _, _, err := tunnel.GenerateVLESSEnc()
	if err != nil {
		t.Fatal(err)
	}
	server.Tunnel = model.LocalTLS{TransportSecurity: "plain", ListenHost: "127.0.0.1", ListenPort: 8444, Decryption: dec, XHTTP: model.XHTTP{Path: "/h2c/", Mode: "packet-up", HTTPVersion: "2", UplinkHTTPMethod: "PUT"}}
	server.ClientTunnel = nil
	server, err = s.SaveNode(server)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.SaveMapping(testMapping(server.ID, client.ID, 8080)); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(db, key)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	snap, err := s.Snapshot(client.ID, credential)
	if err != nil || len(snap.Nodes) != 1 {
		t.Fatalf("snapshot: %v %v", err, snap.Nodes)
	}
	peer := snap.Nodes[0].Tunnel
	if peer.XHTTP != server.Tunnel.XHTTP || peer.Encryption != enc || peer.Decryption != "" || peer.CertPEM != "" || peer.KeyPEM != "" {
		t.Fatal("unsafe or incomplete h2c template")
	}
}

func TestXHTTPDownloadEndpointSelectionPersistsAndRejectsUnauthorized(t *testing.T) {
	s, db, key := testStore(t)
	server := testNode(t, s, "server", "download")
	client := testNode(t, s, "client", "download-client")
	credential := testCredential(t, s, client.ID)
	dec, enc, _, _, err := tunnel.GenerateVLESSEnc()
	if err != nil {
		t.Fatal(err)
	}
	server.Address, server.Port = "up.example.com", 443
	server.ConnectEndpoints = []model.ConnectEndpoint{{ID: "up", Name: "上行", Host: "up.example.com", Port: 443, Enabled: true}, {ID: "down", Name: "下行", Host: "down.example.com", Port: 443, Enabled: true}, {ID: "off", Name: "禁用", Host: "off.example.com", Port: 443, Enabled: false}}
	server.Tunnel = model.LocalTLS{TransportSecurity: "plain", ListenPort: 8444, Decryption: dec, XHTTP: model.XHTTP{Path: "/cdn/", Mode: "packet-up", TLS: true, DownloadEndpointID: "down"}}
	server.ClientTunnel = nil
	server, err = s.SaveNode(server)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.SaveMapping(testMapping(server.ID, client.ID, 8080)); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(db, key)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	snap, err := s.Snapshot(client.ID, credential)
	if err != nil || len(snap.Nodes) != 1 {
		t.Fatalf("snapshot: %v", err)
	}
	if snap.Nodes[0].Tunnel.XHTTP.DownloadEndpointID != "down" || snap.Nodes[0].Tunnel.Encryption != enc {
		t.Fatalf("download endpoint not derived: %+v", snap.Nodes[0].Tunnel.XHTTP)
	}
	server.Tunnel.XHTTP.DownloadEndpointID = "missing"
	if _, err = s.SaveNode(server); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown download endpoint accepted: %v", err)
	}
	server.Tunnel.XHTTP.DownloadEndpointID = "off"
	if _, err = s.SaveNode(server); !errors.Is(err, ErrInvalid) {
		t.Fatalf("disabled download endpoint accepted: %v", err)
	}
	server.Tunnel.XHTTP.Mode = "stream-up"
	server.Tunnel.XHTTP.DownloadEndpointID = "down"
	if _, err = s.SaveNode(server); !errors.Is(err, ErrInvalid) {
		t.Fatalf("stream download endpoint accepted: %v", err)
	}
}
