package model

import (
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
)

func TestDeriveClientTunnelPublicKeys(t *testing.T) {
	x, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pq, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding.EncodeToString
	for _, mode := range []string{"native", "xorpub", "random"} {
		for _, pair := range [][2][]byte{{x.Bytes(), x.PublicKey().Bytes()}, {pq.Bytes(), pq.EncapsulationKey().Bytes()}} {
			dec := "mlkem768x25519plus." + mode + ".600s." + enc(pair[0])
			server := LocalTLS{Decryption: dec, CertPEM: "server-cert", KeyPEM: "server-key", CAPEM: "server-ca", Flow: "xtls-rprx-vision", Hysteria2: Hysteria2{Password: "secret"}, Reality: Reality{PrivateKey: enc(x.Bytes()), Dest: "example.com:443", ShortIDs: "ab,cd"}}
			got := DeriveClientTunnel(server, Node{Address: "example.com"})
			want := "mlkem768x25519plus." + mode + ".0rtt." + enc(pair[1])
			if got.Encryption != want {
				t.Fatalf("incorrect public encryption for %s", mode)
			}
			if got.CAPEM != server.CAPEM || got.CertPEM != "" || got.KeyPEM != "" || got.Decryption != "" || got.Reality.PrivateKey != "" || got.Reality.Dest != "" {
				t.Fatal("server-only fields leaked")
			}
			if got.Flow != server.Flow || got.Hysteria2 != server.Hysteria2 {
				t.Fatal("authoritative server settings lost")
			}
			peer := PublicPeerTunnel(server, Node{})
			if peer.Hysteria2.Password != "" || peer.CertPEM != "" || peer.KeyPEM != "" || peer.CAPEM != server.CAPEM || strings.Contains(peer.Encryption, enc(pair[0])) {
				t.Fatal("private credentials leaked")
			}
		}
	}
}

func TestDeriveInvalidKeyNeverCopied(t *testing.T) {
	for _, raw := range []string{"secret-private", "mlkem768x25519plus.native.600s.bad", "mlkem768x25519plus.random.600s." + base64.RawURLEncoding.EncodeToString(make([]byte, 31))} {
		got := DeriveClientTunnel(LocalTLS{Decryption: raw}, Node{})
		if got.Encryption != "" {
			t.Fatal("invalid private material propagated")
		}
	}
	if got := DeriveClientTunnel(LocalTLS{Decryption: "none"}, Node{}); got.Encryption != "none" {
		t.Fatal("none lost")
	}
}

func TestTransportSecurityDerivation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		server LocalTLS
		want   string
	}{
		{"certificate", LocalTLS{TransportSecurity: "tls", CertPEM: "server-cert", KeyPEM: "server-key", Decryption: "private"}, "tls"},
		{"raw", LocalTLS{TransportSecurity: "plain", Decryption: "private"}, "plain"},
		{"public-tls", LocalTLS{TransportSecurity: "tls", Encryption: "public"}, "tls"},
		{"public-plain", LocalTLS{TransportSecurity: "plain", Encryption: "public"}, "plain"},
		{"unspecified", LocalTLS{CertPEM: "server-cert", KeyPEM: "server-key", Decryption: "private"}, ""},
		{"reality", LocalTLS{Decryption: "private", Reality: Reality{PublicKey: "public"}}, ""},
		{"hysteria", LocalTLS{CertPEM: "server-cert", KeyPEM: "server-key", Hysteria2: Hysteria2{Password: "secret"}}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := PublicPeerTunnel(tc.server, Node{})
			if got.TransportSecurity != tc.want || got.CertPEM != "" || got.KeyPEM != "" || got.CAPEM != "" {
				t.Fatalf("unexpected public transport: %+v", got)
			}
			if got := DeriveClientTunnel(tc.server, Node{}); got.TransportSecurity != tc.want {
				t.Fatal("authoritative transport lost")
			}
		})
	}
}

func TestCertificateTrustIsExplicit(t *testing.T) {
	server := LocalTLS{TransportSecurity: "tls", CertPEM: "self-signed-cert", KeyPEM: "private-key"}
	for _, got := range []LocalTLS{DeriveClientTunnel(server, Node{}), PublicPeerTunnel(server, Node{})} {
		if got.CAPEM != "" || got.CertPEM != "" || got.KeyPEM != "" {
			t.Fatal("leaf certificate implicitly trusted or private credentials leaked")
		}
	}
	server.CAPEM = "explicit-ca"
	if got := PublicPeerTunnel(server, Node{}); got.CAPEM != server.CAPEM {
		t.Fatal("explicit trust not retained")
	}
	client := LocalTLS{CertPEM: "client-cert", KeyPEM: "client-key", CAPEM: "client-ca"}
	if got := server.Merge(client); got.CertPEM != client.CertPEM || got.KeyPEM != client.KeyPEM || got.CAPEM != client.CAPEM {
		t.Fatal("PEM overrides lost")
	}
}
