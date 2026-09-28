package tunnel

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"veilink/internal/model"
)

func TestProtocolSelection(t *testing.T) {
	for _, protocol := range []string{"vless", "hysteria2"} {
		local := tlsFiles(t)
		local.Protocol = protocol
		if protocol == "hysteria2" {
			local.Hysteria2.Password = "secret"
		}
		public, err := DeriveClientTunnel(model.LocalTLS{}, local, model.Node{})
		if err != nil || public.Protocol != protocol {
			t.Fatalf("derive: %+v %v", public, err)
		}
		for _, mutate := range []func(*model.LocalTLS){
			func(c *model.LocalTLS) { c.Protocol = "unknown" },
			func(c *model.LocalTLS) {
				if protocol == "vless" {
					c.Hysteria2.Password = "secret"
				} else {
					c.Decryption = "none"
				}
			},
		} {
			bad := local
			mutate(&bad)
			if CheckBootstrap("server", bad) == nil {
				t.Fatal("accepted invalid protocol")
			}
		}
		server, client := fixtures(t, 8080)
		client.Nodes[0].Tunnel = public
		doc, err := Build(client, model.LocalTLS{})
		if err != nil {
			t.Fatal(err)
		}
		var p policy
		if json.Unmarshal(doc, &p) != nil || p.Outbounds[1].Protocol != protocol {
			t.Fatalf("policy: %s", doc)
		}
		_ = server
	}
}

func TestFlowRequiresSupportedCombination(t *testing.T) {
	files := tlsFiles(t)
	vision := func() model.LocalTLS {
		return model.LocalTLS{Protocol: "vless", TransportSecurity: "tls", CertPEM: files.CertPEM, KeyPEM: files.KeyPEM, Flow: flowVision}
	}
	validTLS := vision()
	if err := CheckBootstrap("server", validTLS); err != nil {
		t.Fatal("TLS Vision rejected", err)
	}
	validReality := model.LocalTLS{Protocol: "vless", Flow: flowVision, Reality: model.Reality{PrivateKey: "4A39kZk0Nvd5uD3fXJbF2WvJqCq23xQ3_gL7_J0mE1s", Dest: "example.com:443", ShortIDs: "aa", ServerNames: "example.com"}}
	if err := CheckBootstrap("server", validReality); err != nil {
		t.Fatal("REALITY Vision rejected", err)
	}
	for name, bad := range map[string]model.LocalTLS{
		"plain":     {Protocol: "vless", TransportSecurity: "plain", Decryption: "valid-encryption", Flow: flowVision},
		"xhttp":     {Protocol: "vless", TransportSecurity: "tls", CertPEM: files.CertPEM, KeyPEM: files.KeyPEM, XHTTP: model.XHTTP{Path: "/veilink/", Mode: "packet-up", TLS: true}, Flow: flowVision},
		"hysteria2": {Protocol: "hysteria2", CertPEM: files.CertPEM, KeyPEM: files.KeyPEM, Hysteria2: model.Hysteria2{Password: "password"}, Flow: flowVision},
	} {
		t.Run(name, func(t *testing.T) {
			if err := CheckBootstrap("server", bad); err == nil {
				t.Fatal("unsupported Flow combination accepted")
			}
		})
	}
}

func TestHysteriaNativeSessionAuthorization(t *testing.T) {
	server, _ := fixtures(t, echoServer(t))
	local := tlsFiles(t)
	local.Protocol = "hysteria2"
	local.Hysteria2.Password = strings.Repeat("p", 128)
	local.ListenPort = freeUDPPort(t)
	second := model.Binding{ID: "two", ServerID: server.Node.ID, ClientID: "client-two", UUID: "e2587f5e-b746-4e68-a131-184984fa56a1", Domain: "two.reverse.test"}
	server.Bindings = append(server.Bindings, second)
	server.Node.Tunnel = local
	run(t, server, model.LocalTLS{})
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(local.ListenPort))
	binding := server.Bindings[0]
	credential := binding.UUID
	wrongBindingCredential := second.UUID
	target := net.JoinHostPort(binding.Domain, "0")
	for _, tc := range []struct {
		name, auth, target string
		good               bool
	}{
		{"authorized", credential, target, true},
		{"shared-password-only", local.Hysteria2.Password, target, false},
		{"foreign-identity", "00000000-0000-0000-0000-000000000000", target, false},
		{"wrong-password", "wrong", target, false},
		{"cross-binding-identity", wrongBindingCredential, target, false},
		{"cross-binding-target", credential, net.JoinHostPort(second.Domain, "0"), false},
		{"foreign-domain", credential, "other.test:0", false},
		{"forward-proxy", credential, "example.com:443", false},
		{"invalid-port", credential, binding.Domain + ":65536", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			c, err := dialHysteriaSession(ctx, addr, "127.0.0.1", local, tc.auth, tc.target)
			if err != nil {
				if tc.good {
					t.Fatal(err)
				}
				if ctx.Err() != nil {
					t.Fatal("rejection relied on timeout")
				}
				return
			}
			defer c.Close()
			if !tc.good {
				t.Fatal("unauthorized session accepted")
			}
			// First payload is Veilink framing, without VLESS request/response or Encryption.
			c.SetDeadline(time.Now().Add(time.Second))
			if err := writeAll(c, []byte{framePing, 0, 0, 0, 0, 0, 0}); err != nil {
				t.Fatal(err)
			}
			kind, _, _, err := readFrame(c)
			if err != nil || kind != framePong {
				t.Fatalf("native session: %d %v", kind, err)
			}
		})
	}
}

func TestHysteriaQPACKAndRequestBounds(t *testing.T) {
	value := strings.Repeat("p", 165)
	encoded := encodeFields([][2]string{{"hysteria-auth", value}})
	if decodeQPACK(encoded)["hysteria-auth"] != value {
		t.Fatal("long credential lost")
	}
	if decodeQPACK(append(encoded, 0xff)) != nil {
		t.Fatal("partial malformed headers accepted")
	}
	if decodeQPACK(encodeFields([][2]string{{"hysteria-auth", "one"}, {"hysteria-auth", "two"}})) != nil {
		t.Fatal("duplicate credentials accepted")
	}
	var b bytes.Buffer
	writeTCPRequest(&b, "binding.test:0")
	if kind, err := readVarint(&b); err != nil || kind != hysteriaTCP {
		t.Fatal(kind, err)
	}
	if addr, err := readTCPRequest(&b); err != nil || addr != "binding.test:0" {
		t.Fatal(addr, err)
	}
	b.Reset()
	writeTCPRequest(&b, strings.Repeat("a", 513))
	readVarint(&b)
	if _, err := readTCPRequest(&b); err == nil {
		t.Fatal("oversized target accepted")
	}
}
