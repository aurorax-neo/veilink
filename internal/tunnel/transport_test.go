package tunnel

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"veilink/internal/model"
)

// A subprocess isolates x509's process-global fallback roots. This exercises the
// real nil-RootCAs/system-root path without installing a CA in the host trust store.
func TestTLSMetadataEncryptionSystemRoots(t *testing.T) {
	if os.Getenv("VEILINK_TEST_SYSTEM_ROOTS") != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestTLSMetadataEncryptionSystemRoots$", "-test.timeout=30s")
		cmd.Env = append(os.Environ(), "VEILINK_TEST_SYSTEM_ROOTS=1", "GODEBUG=x509usefallbackroots=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("system-roots child: %v\n%s", err, out)
		}
		return
	}
	files := tlsFiles(t)
	pem := []byte(files.CertPEM)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		t.Fatal("test CA failed")
	}
	x509.SetFallbackRoots(roots)
	dec, _, _, _, err := GenerateVLESSEnc()
	if err != nil {
		t.Fatal(err)
	}
	for _, flow := range []string{"", flowVision} {
		t.Run("flow="+flow, func(t *testing.T) {
			server, client := fixtures(t, echoServer(t))
			serverLocal := files
			serverLocal.ListenPort = server.Node.Tunnel.ListenPort
			serverLocal.Decryption, serverLocal.Flow = dec, flow
			serverLocal.CAPEM = "" // Exercise system roots rather than distributed trust.
			public, err := PublicPeerTunnel(serverLocal, server.Node)
			if err != nil {
				t.Fatal(err)
			}
			if public.TransportSecurity != "tls" || public.CAPEM != "" || public.CertPEM != "" || public.KeyPEM != "" {
				t.Fatal("public TLS metadata or credential leak")
			}
			client.Nodes[0].Tunnel = public
			effective, err := gatewayClientConfig(model.LocalTLS{}, client.Nodes[0])
			if err != nil || effective.TransportSecurity != "tls" || effective.CAPEM != "" {
				t.Fatal("effective config", err)
			}
			run(t, server, serverLocal)
			run(t, client, model.LocalTLS{})
			awaitEcho(t, server.Mappings[0].ListenPort)
		})
	}
}

func TestPlainMetadataEncryptionNoCA(t *testing.T) {
	dec, _, _, _, err := GenerateVLESSEnc()
	if err != nil {
		t.Fatal(err)
	}
	for _, explicit := range []string{"plain"} {
		t.Run("server="+explicit, func(t *testing.T) {
			server, client := fixtures(t, echoServer(t))
			local := model.LocalTLS{TransportSecurity: explicit, Decryption: dec, ListenPort: server.Node.Tunnel.ListenPort}
			public, err := PublicPeerTunnel(local, server.Node)
			if err != nil || public.TransportSecurity != "plain" {
				t.Fatal("plain derivation", err)
			}
			client.Nodes[0].Tunnel = public
			run(t, server, local)
			run(t, client, model.LocalTLS{})
			awaitEcho(t, server.Mappings[0].ListenPort)
		})
	}
}

func TestClientEndpointFailover(t *testing.T) {
	server, client := fixtures(t, echoServer(t))
	local := model.LocalTLS{TransportSecurity: "plain", Decryption: mustEncryption(t), ListenPort: server.Node.Tunnel.ListenPort}
	peer, err := PublicPeerTunnel(local, server.Node)
	if err != nil {
		t.Fatal(err)
	}
	server.Node.Tunnel = local
	client.Nodes[0].Tunnel = peer
	client.Nodes[0].ConnectEndpoints = []model.ConnectEndpoint{
		{ID: "failed", Name: "failed", Host: "127.0.0.1", Port: freePort(t), ServerName: "gateway.test", Priority: 0, Enabled: true},
		{ID: "working", Name: "working", Host: "127.0.0.1", Port: local.ListenPort, ServerName: "gateway.test", Priority: 1, Enabled: true},
	}
	run(t, server, model.LocalTLS{})
	run(t, client, model.LocalTLS{})
	awaitEcho(t, server.Mappings[0].ListenPort)
}

func TestConnectEndpointStrictJSON(t *testing.T) {
	for _, kind := range []string{"direct", "nat", "cdn"} {
		decoder := json.NewDecoder(strings.NewReader(`{"connect_endpoints":[{"kind":"` + kind + `"}]}`))
		decoder.DisallowUnknownFields()
		var node model.Node
		if err := decoder.Decode(&node); err == nil || !strings.Contains(err.Error(), `unknown field "kind"`) {
			t.Fatalf("legacy kind %q accepted: %v", kind, err)
		}
	}
	var node model.Node
	decoder := json.NewDecoder(strings.NewReader(`{"connect_endpoints":[{"id":"public","name":"Public","host":"public.example.com","port":443,"server_name":"tls.example.com","enabled":true}]}`))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&node); err != nil {
		t.Fatal(err)
	}
	node.Tunnel.ListenHost, node.Tunnel.ListenPort = "127.0.0.1", 8443
	endpoints := enabledEndpoints(node)
	if len(endpoints) != 1 || endpoints[0].Host != "public.example.com" || endpoints[0].Port != 443 || endpoints[0].ServerName != "tls.example.com" {
		t.Fatalf("dial address or independent SNI changed: %+v", endpoints)
	}
}

func mustEncryption(t *testing.T) string {
	t.Helper()
	dec, _, _, _, err := GenerateVLESSEnc()
	if err != nil {
		t.Fatal(err)
	}
	return dec
}

func TestTransportSecurityValidationAndOverrides(t *testing.T) {
	dec, enc, _, _, err := GenerateVLESSEnc()
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"TLS", "none", "bogus", " tls "} {
		for _, role := range []string{"server", "client"} {
			if err := CheckBootstrap(role, model.LocalTLS{TransportSecurity: value}); err == nil || !strings.Contains(err.Error(), "transport_security") {
				t.Fatalf("accepted %q for %s: %v", value, role, err)
			}
		}
		if _, err := DeriveClientTunnel(model.LocalTLS{TransportSecurity: value}, model.LocalTLS{}, model.Node{}); err == nil {
			t.Fatal("bad override accepted")
		}
		if _, err := PublicPeerTunnel(model.LocalTLS{TransportSecurity: value}, model.Node{}); err == nil {
			t.Fatal("bad public enum accepted")
		}
	}
	for _, security := range []string{"tls", "plain"} {
		_, err := newClientGateway(model.LocalTLS{TransportSecurity: security}, model.Node{Tunnel: model.LocalTLS{TransportSecurity: "tls", Encryption: enc}})
		if err == nil {
			t.Fatal("client transport override accepted")
		}
		local := model.LocalTLS{TransportSecurity: security, Encryption: enc, Flow: flowVision}
		if err := CheckBootstrap("client", local); (err == nil) != (security == "tls") {
			t.Fatalf("Vision %s: %v", security, err)
		}
	}
	for _, local := range []model.LocalTLS{
		{TransportSecurity: "plain", Encryption: "none"},
		{TransportSecurity: "plain", Encryption: enc, Reality: model.Reality{PublicKey: "public"}},
		{TransportSecurity: "plain", Encryption: enc, Hysteria2: model.Hysteria2{Password: "secret"}},
	} {
		if err := CheckBootstrap("client", local); err == nil {
			t.Fatal("invalid plain config accepted")
		}
	}
	server, _ := fixtures(t, 8080)
	missing := model.LocalTLS{TransportSecurity: "tls", Decryption: dec}
	if _, err := PublicPeerTunnel(missing, server.Node); err != nil {
		t.Fatal("structural helper requires certificate PEM", err)
	}
	if err := CheckBootstrap("server", missing); err == nil {
		t.Fatal("TLS bootstrap accepted absent certificate")
	}
	if _, err := Build(server, missing); err == nil {
		t.Fatal("TLS runtime validation accepted absent certificate")
	}
	files := tlsFiles(t)
	files.TransportSecurity = "plain"
	files.Decryption = dec
	if err := CheckBootstrap("server", files); err == nil {
		t.Fatal("plain server accepted TLS PEM")
	}
	files.TransportSecurity = ""
	for _, local := range []model.LocalTLS{files, {Decryption: dec}, {Encryption: enc}, {}} {
		if _, err := PublicPeerTunnel(local, server.Node); err == nil {
			t.Fatal("missing server transport_security accepted")
		}
		if err := CheckBootstrap("server", local); err == nil {
			t.Fatal("server inferred transport_security")
		}
	}
	if _, err := newClientGateway(model.LocalTLS{TransportSecurity: "tls"}, model.Node{}); err == nil {
		t.Fatal("missing gateway metadata accepted")
	}
	if err := CheckBootstrap("client", model.LocalTLS{}); err != nil {
		t.Fatal("empty client inheritance rejected", err)
	}
}

func TestPEMSnapshotHandshakeAndTrust(t *testing.T) {
	for _, hy := range []bool{false, true} {
		name := "tls"
		if hy {
			name = "hysteria2"
		}
		t.Run(name, func(t *testing.T) {
			server, client := fixtures(t, echoServer(t))
			listenPort := server.Node.Tunnel.ListenPort
			server.Node.Tunnel = tlsFiles(t)
			server.Node.Tunnel.ListenPort = listenPort
			if hy {
				server.Node.Tunnel.TransportSecurity = ""
				server.Node.Tunnel.Hysteria2.Password = "pem-secret"
				server.Node.Tunnel.ListenPort = freeUDPPort(t)
				server.Node.Port = server.Node.Tunnel.ListenPort
			}
			run(t, server, model.LocalTLS{})
			gateway := server.Node
			peer, err := PublicPeerTunnel(server.Node.Tunnel, server.Node)
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := json.Marshal(peer)
			if err != nil || strings.Contains(string(encoded), "PRIVATE KEY") || peer.CertPEM != "" || peer.KeyPEM != "" || peer.CAPEM != server.Node.Tunnel.CAPEM {
				t.Fatal("public peer leaked credentials or lost explicit trust", err)
			}
			// Authorized clients receive the HY2 credential separately.
			peer.Hysteria2 = server.Node.Tunnel.Hysteria2
			gateway.Tunnel = peer
			client.Nodes[0] = gateway
			run(t, client, model.LocalTLS{})
			awaitEcho(t, server.Mappings[0].ListenPort)
			for _, ca := range []string{"", tlsFiles(t).CAPEM} {
				gateway.Tunnel.CAPEM = ca
				config, err := newClientGateway(model.LocalTLS{}, gateway)
				if err != nil {
					t.Fatal(err)
				}
				svc := &service{ctx: context.Background()}
				conn, err := svc.dialGateway(gateway, config)
				if err == nil {
					_ = conn.Close()
					t.Fatal("self-signed certificate accepted without explicit matching CA PEM")
				}
			}
		})
	}
}

func TestRejectInvalidPEM(t *testing.T) {
	valid := tlsFiles(t)
	other := tlsFiles(t)
	server, client := fixtures(t, 8080)
	for name, mutate := range map[string]func(*model.LocalTLS){
		"certificate": func(c *model.LocalTLS) { c.CertPEM = "not PEM" },
		"key":         func(c *model.LocalTLS) { c.KeyPEM = "not PEM" },
		"mismatch":    func(c *model.LocalTLS) { c.KeyPEM = other.KeyPEM },
		"missing-key": func(c *model.LocalTLS) { c.KeyPEM = "" },
		"CA":          func(c *model.LocalTLS) { c.CAPEM = "not PEM" },
		"private-CA":  func(c *model.LocalTLS) { c.CAPEM = valid.KeyPEM },
	} {
		t.Run(name, func(t *testing.T) {
			bad := valid
			mutate(&bad)
			for _, snapshot := range []model.Snapshot{server, client} {
				if err := CheckBootstrap(snapshot.Node.Role, bad); err == nil {
					t.Fatal("invalid PEM accepted by settings validation")
				}
				if _, err := Build(snapshot, bad); err == nil {
					t.Fatal("invalid PEM accepted by runtime validation")
				}
			}
			bad.Hysteria2.Password = "secret"
			if _, err := Build(server, bad); err == nil {
				t.Fatal("Hysteria2 accepted invalid PEM")
			}
		})
	}
}

func TestRuntimeUnconfiguredServerLifecycle(t *testing.T) {
	configured, client := fixtures(t, echoServer(t))
	configured.Node.Tunnel = tlsFiles(t)
	configured.Node.Tunnel.ListenPort = configured.Node.Port
	idle := clone(configured)
	idle.Node.Tunnel = model.LocalTLS{}
	idle.Bindings, idle.Mappings = nil, nil
	r := run(t, idle, model.LocalTLS{})
	assertIdle := func() {
		t.Helper()
		if r.instance == nil || len(r.instance.listeners) != 0 || len(r.instance.packets) != 0 || r.instance.inbound != nil || r.instance.reality != nil || r.instance.quic != nil {
			t.Fatal("idle server allocated listeners or crypto")
		}
		for _, port := range []int{configured.Node.Port, configured.Mappings[0].ListenPort} {
			ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
			if err != nil {
				t.Fatal("idle port still bound", err)
			}
			ln.Close()
		}
	}
	assertIdle()
	configured.Revision++
	if err := r.Apply(configured); err != nil {
		t.Fatal(err)
	}
	public, err := PublicPeerTunnel(configured.Node.Tunnel, configured.Node)
	if err != nil {
		t.Fatal(err)
	}
	client.Nodes[0].Tunnel = public
	run(t, client, model.LocalTLS{})
	awaitEcho(t, configured.Mappings[0].ListenPort)
	idle.Revision = configured.Revision + 1
	if err := r.Apply(idle); err != nil || r.Revision() != idle.Revision {
		t.Fatal("configured server did not return to idle", err)
	}
	assertIdle()
}

func TestUnconfiguredServerRemainsFailClosed(t *testing.T) {
	server, _ := fixtures(t, 8080)
	server.Node.Tunnel = model.LocalTLS{}
	idle := clone(server)
	idle.Bindings, idle.Mappings = nil, nil
	r := run(t, idle, model.LocalTLS{})
	for name, mutate := range map[string]func(*model.Snapshot){
		"invalid-id":            func(s *model.Snapshot) { s.Node.ID = "bad/id" },
		"invalid-role":          func(s *model.Snapshot) { s.Node.Role = "unknown" },
		"revoked":               func(s *model.Snapshot) { s.Node.Revoked = true },
		"negative-revision":     func(s *model.Snapshot) { s.Revision = -1 },
		"invalid-listen-ip":     func(s *model.Snapshot) { s.Node.Tunnel.ListenHost = "11111" },
		"idle-tls-without-cert": func(s *model.Snapshot) { s.Node.Tunnel.TransportSecurity = "tls" },
		"binding":               func(s *model.Snapshot) { s.Bindings = server.Bindings },
		"mapping":               func(s *model.Snapshot) { s.Mappings = server.Mappings },
		"active-empty":          func(s *model.Snapshot) { s.Bindings, s.Mappings = server.Bindings, server.Mappings },
		"active-tls-without-cert": func(s *model.Snapshot) {
			s.Bindings, s.Mappings = server.Bindings, server.Mappings
			s.Node.Tunnel.TransportSecurity = "tls"
		},
	} {
		t.Run(name, func(t *testing.T) {
			bad := clone(idle)
			bad.Revision++
			mutate(&bad)
			if _, err := Build(bad, bad.Node.Tunnel); err == nil {
				t.Fatal("invalid snapshot passed validation")
			}
			if err := r.Apply(bad); err == nil {
				t.Fatal("invalid snapshot applied")
			}
			if r.Revision() != idle.Revision || len(r.instance.listeners) != 0 {
				t.Fatal("invalid snapshot changed idle runtime")
			}
		})
	}
}

func TestClientLocalOverridesRejected(t *testing.T) {
	dec, enc, _, otherEnc, err := GenerateVLESSEnc()
	if err != nil {
		t.Fatal(err)
	}
	server := tlsFiles(t)
	server.Decryption, server.Flow = dec, flowVision
	_, snapshot := fixtures(t, 8080)
	public, err := DeriveClientTunnel(model.LocalTLS{}, server, snapshot.Nodes[0])
	if err != nil || public.Encryption != enc {
		t.Fatal("authoritative derivation failed", err)
	}
	snapshot.Nodes[0].Tunnel = public
	if got, err := gatewayClientConfig(model.LocalTLS{}, snapshot.Nodes[0]); err != nil || got != public {
		t.Fatal("gateway template was changed", err)
	}
	for name, override := range map[string]model.LocalTLS{
		"encryption-none":      {Encryption: "none"},
		"encryption-different": {Encryption: otherEnc},
		"encryption-same":      {Encryption: enc},
		"flow-none":            {Flow: "none"},
		"flow-different":       {Flow: flowVision + "-udp443"},
		"CA":                   {CAPEM: tlsFiles(t).CAPEM},
		"transport":            {TransportSecurity: "plain"},
		"password":             {Hysteria2: model.Hysteria2{Password: "local-password"}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DeriveClientTunnel(override, server, snapshot.Nodes[0]); err == nil {
				t.Fatal("derivation accepted client override")
			}
			if _, err := gatewayClientConfig(override, snapshot.Nodes[0]); err == nil {
				t.Fatal("gateway accepted client override")
			}
			if _, err := Build(snapshot, override); err == nil {
				t.Fatal("Build accepted client override")
			}
			r := New(override)
			defer r.Close()
			if err := r.Apply(snapshot); err == nil {
				t.Fatal("runtime accepted local override")
			}
			bad := clone(snapshot)
			bad.Node.Tunnel = override
			r = New(model.LocalTLS{})
			defer r.Close()
			if err := r.Apply(bad); err == nil {
				t.Fatal("runtime accepted client snapshot Tunnel")
			}
			bad.Node.Tunnel = model.LocalTLS{}
			bad.Node.ClientTunnel = &override
			if err := r.Apply(bad); err == nil {
				t.Fatal("runtime accepted client-owned template")
			}
		})
	}
}

func TestGatewayConsumesExactPublicTemplate(t *testing.T) {
	_, pub, err := GenerateX25519()
	if err != nil {
		t.Fatal(err)
	}
	for _, template := range []model.LocalTLS{
		{TransportSecurity: "tls", CAPEM: tlsFiles(t).CAPEM, Flow: flowVision, Encryption: "none"},
		{CAPEM: tlsFiles(t).CAPEM, Hysteria2: model.Hysteria2{Password: "authoritative-password"}},
		{Reality: model.Reality{PublicKey: pub, ShortID: "bb", ServerNames: "selected-cover.test,other-cover.test", Fingerprint: "firefox"}},
	} {
		gateway := model.Node{ServerName: "metadata.test", Tunnel: template}
		got, err := gatewayClientConfig(model.LocalTLS{}, gateway)
		if err != nil || got != template {
			t.Fatal("authoritative public template was rederived or changed", err)
		}
	}
}
