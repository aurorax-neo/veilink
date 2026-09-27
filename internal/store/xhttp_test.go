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
	server.Tunnel = model.LocalTLS{TransportSecurity: "plain", ListenHost: "127.0.0.1", ListenPort: 8444, Decryption: dec, XHTTP: model.XHTTP{Path: "/cdn/", Mode: "packet-up", TLS: true}}
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
		"mode":                            func(v *model.LocalTLS) { v.XHTTP.Mode = "stream-up" },
		"auto":                            func(v *model.LocalTLS) { v.XHTTP.Mode = "auto" },
		"missing-mode":                    func(v *model.LocalTLS) { v.XHTTP.Mode = "" },
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
