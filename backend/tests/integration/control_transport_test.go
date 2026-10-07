//go:build integration

package integration

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"veilink/internal/httpapi/backend"
	"veilink/internal/model"
	"veilink/internal/store"
)

// Exercise the actual CLI and authenticated control streams for both node roles.
// All database, credentials, listeners and processes are confined to this test.
func TestNodeControlTransportMatrix(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("process signal harness is POSIX")
	}
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "../.."))
	dir := t.TempDir()
	bin := filepath.Join(dir, "veilink")
	command(t, root, nil, "go", "build", "-o", bin, "./cmd/veilink")
	certs := filepath.Join(dir, "certs")
	command(t, filepath.Dir(root), []string{"GO111MODULE=off"}, "go", "run", "./tools/devcert", "-out", certs)
	ca, err := os.ReadFile(filepath.Join(certs, "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		t.Fatal("invalid test CA")
	}
	for _, scheme := range []string{"http", "https"} {
		t.Run(scheme, func(t *testing.T) {
			controlPort, tunnelPort, publicPort := freePort(t), freePort(t), freePort(t)
			state := t.TempDir()
			flags := []string{"-database", filepath.Join(state, "master.db"), "-deployment-key", filepath.Join(state, "master.key"), "-listen-addr", fmt.Sprintf("127.0.0.1:%d", controlPort), "-scheme=" + scheme, "-embedded-server-enabled=false"}
			if scheme == "https" {
				flags = append(flags, "-cert-file", filepath.Join(certs, "cert.pem"), "-key-file", filepath.Join(certs, "key.pem"))
			}
			masterDB := filepath.Join(state, "master.db")
			masterKey := filepath.Join(state, "master.key")
			st, err := store.Open(masterDB, masterKey)
			if err != nil {
				t.Fatal(err)
			}
			ks := backend.NewKeyStore(st.DB())
			if err := ks.Migrate(); err != nil {
				t.Fatal(err)
			}
			adminKey, err := ks.Create("admin", backend.RoleAdmin)
			if err != nil {
				t.Fatal(err)
			}
			st.Close()
			var masterEnv []string
			launchWithEnv(t, masterEnv, bin, "master", flags...)
			transport := &http.Transport{}
			if scheme == "https" {
				transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, ServerName: "localhost"}
			}
			a := &api{c: &http.Client{Transport: transport}, base: fmt.Sprintf("%s://127.0.0.1:%d", scheme, controlPort), token: adminKey}
			eventually(t, "master ready", func() error { return a.call("GET", "/nodes", nil, nil) })
			var material struct {
				CertPEM string `json:"cert_pem"`
				KeyPEM  string `json:"key_pem"`
				CAPEM   string `json:"ca_pem"`
			}
			a.must(t, "POST", "/nodes/generate", map[string]any{"role": "server", "kind": "certificate", "host": "127.0.0.1", "ttl_days": 1}, &material)
			var server, client model.Node
			a.must(t, "POST", "/nodes", model.Node{Name: "gateway", Role: "server", Address: "127.0.0.1", Port: tunnelPort, Tunnel: model.LocalTLS{TransportSecurity: "tls", CertPEM: material.CertPEM, KeyPEM: material.KeyPEM, CAPEM: material.CAPEM, ListenHost: "127.0.0.1", ListenPort: tunnelPort}}, &server)
			a.must(t, "POST", "/nodes", model.Node{Name: "inside", Role: "client"}, &client)
			join := func(id string) string {
				var out struct {
					Token string `json:"token"`
				}
				a.must(t, "POST", "/nodes/"+id+"/enroll", map[string]int{"ttl_seconds": 3600}, &out)
				if out.Token == "" {
					t.Fatal("empty enrollment token")
				}
				return out.Token
			}
			nodeArgs := func(id, role string) []string {
				args := []string{"-master-addr", fmt.Sprintf("127.0.0.1:%d", controlPort), "-node-id", id, "-state-dir", filepath.Join(state, role)}
				if scheme == "https" {
					args = append(args, "-control-ca", filepath.Join(certs, "ca.pem"), "-control-server-name", "localhost")
				}
				return append(args, "-enroll-token", join(id))
			}
			launch(t, bin, "server", nodeArgs(server.ID, "server")...)
			launch(t, bin, "client", nodeArgs(client.ID, "client")...)
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "control-transport-ok") }))
			defer target.Close()
			var mapping model.Mapping
			a.must(t, "POST", "/mappings", model.Mapping{Name: "probe", ServerID: server.ID, ClientID: client.ID, Pool: 1, ListenHost: "127.0.0.1", ListenPort: publicPort, TargetHost: "127.0.0.1", TargetPort: target.Listener.Addr().(*net.TCPAddr).Port, Enabled: true}, &mapping)
			a.applied(t, server.ID, client.ID)
			var nodes []managementNode
			a.must(t, "GET", "/nodes", nil, &nodes)
			for _, id := range []string{server.ID, client.ID} {
				seen := false
				for _, n := range nodes {
					if n.ID == id && n.LastSeen > 0 && n.Error == "" && n.DesiredRevision > 0 && n.AppliedRevision == n.DesiredRevision {
						seen = true
					}
				}
				if !seen {
					t.Fatalf("%s %s never reported a successful apply", scheme, id)
				}
			}
			eventually(t, scheme+" server/client traffic", func() error {
				return checkBody(fmt.Sprintf("http://127.0.0.1:%d/", publicPort), "control-transport-ok")
			})
		})
	}
}
