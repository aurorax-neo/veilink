package tunnel

import (
	"context"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"veilink/internal/model"
)

func TestHysteriaRejectsCredentialsAndCancellation(t *testing.T) {
	server, _ := fixtures(t, echoServer(t))
	local := tlsFiles(t)
	local.Hysteria2.Password = "correct-password"
	local.Protocol = "hysteria2"
	local.ListenPort = freeUDPPort(t)
	server.Node.Tunnel = local
	run(t, server, model.LocalTLS{})
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(local.ListenPort))
	binding := server.Bindings[0]
	for _, name := range []string{"password", "server-name", "cancelled"} {
		t.Run(name, func(t *testing.T) {
			client := local
			sni := "gateway.test"
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			switch name {
			case "password":
				client.Hysteria2.Password = "wrong-password"
			case "server-name":
				sni = "wrong.test"
			case "cancelled":
				cancel()
			}
			credential := binding.UUID
			if name == "password" {
				credential = "wrong-password"
			}
			conn, err := dialHysteriaSession(ctx, addr, sni, client, credential, net.JoinHostPort(binding.Domain, "0"))
			if conn != nil {
				conn.Close()
			}
			if err == nil {
				t.Fatal("invalid Hysteria2 connection accepted")
			}
			if name != "cancelled" && ctx.Err() != nil {
				t.Fatalf("rejection relied on timeout: %v", err)
			}
		})
	}
}

func TestHysteriaFieldAndCombinationValidation(t *testing.T) {
	base := tlsFiles(t)
	base.TransportSecurity = ""
	base.Hysteria2.Password = strings.Repeat("p", 128)
	if err := CheckBootstrap("server", base); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, message string
		mutate        func(*model.LocalTLS)
	}{
		{"password-length", "128", func(c *model.LocalTLS) { c.Hysteria2.Password += "p" }},
		{"missing-certificate", "cert_pem", func(c *model.LocalTLS) { c.CertPEM, c.KeyPEM = "", "" }},
		{"plain", "plain", func(c *model.LocalTLS) { c.TransportSecurity = "plain" }},
		{"reality", "cannot both", func(c *model.LocalTLS) { c.Reality.PrivateKey = "invalid" }},
		{"vision", "Vision", func(c *model.LocalTLS) { c.Flow = flowVision }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			local := base
			tc.mutate(&local)
			if err := CheckBootstrap("server", local); err == nil || !strings.Contains(err.Error(), tc.message) {
				t.Fatalf("expected %s rejection, got %v", tc.message, err)
			}
		})
	}
}
