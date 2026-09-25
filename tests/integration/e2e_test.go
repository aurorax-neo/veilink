//go:build integration

// Package integration exercises the built CLI, not a mocked transport.
package integration

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"veilink/internal/model"
)

type process struct {
	cmd  *exec.Cmd
	done chan error
	once sync.Once
}

func launch(t *testing.T, bin, role string, flags ...string) *process {
	t.Helper()
	log, err := os.CreateTemp(t.TempDir(), role+"-*.log")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, append([]string{role}, flags...)...)
	cmd.Stdout = log
	cmd.Stderr = log
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	p := &process{cmd: cmd, done: make(chan error, 1)}
	go func() { p.done <- cmd.Wait(); _ = log.Close() }()
	t.Cleanup(func() {
		p.stop()
		if t.Failed() {
			b, _ := os.ReadFile(log.Name())
			if len(b) > 12000 {
				b = b[len(b)-12000:]
			}
			t.Logf("%s process log:\n%s", role, b)
		}
	})
	return p
}
func (p *process) stop() {
	p.once.Do(func() {
		_ = p.cmd.Process.Signal(os.Interrupt)
		select {
		case <-p.done:
		case <-time.After(8 * time.Second):
			_ = p.cmd.Process.Kill()
			<-p.done
		}
	})
}
func freePort(t *testing.T) int {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}
func nodeFlags(port int, ca, id, state string) []string {
	return []string{"-master-addr", fmt.Sprintf("127.0.0.1:%d", port), "-control-ca", ca, "-control-server-name", "localhost", "-node-id", id, "-state-dir", state}
}
func command(t *testing.T, root string, env []string, args ...string) {
	t.Helper()
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), env...)
	if b, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("%s failed: %v\n%s", args[0], e, b)
	}
}
func eventually(t *testing.T, label string, fn func() error) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	var err error
	for time.Now().Before(deadline) {
		if err = fn(); err == nil {
			return
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatalf("%s: %v", label, err)
}

type api struct {
	c          *http.Client
	base, csrf string
}

func (a *api) call(method, path string, body, out any) error {
	var b bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&b).Encode(body); err != nil {
			return err
		}
	}
	req, err := http.NewRequest(method, a.base+"/api"+path, &b)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", a.csrf)
	resp, err := a.c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("%s %s: %d %s", method, path, resp.StatusCode, raw)
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}
func (a *api) must(t *testing.T, method, path string, body, out any) {
	t.Helper()
	if e := a.call(method, path, body, out); e != nil {
		t.Fatal(e)
	}
}
func (a *api) login(t *testing.T) {
	t.Helper()
	var r struct {
		CSRF string `json:"csrf"`
	}
	eventually(t, "master ready/login", func() error {
		return a.call("POST", "/login", map[string]string{"username": "admin", "password": "integration-secret-not-production-8429"}, &r)
	})
	a.csrf = r.CSRF
	if a.csrf == "" {
		t.Fatal("missing CSRF token")
	}
}
func (a *api) applied(t *testing.T, ids ...string) {
	t.Helper()
	eventually(t, "desired revisions applied", func() error {
		var ns []model.Node
		if e := a.call("GET", "/nodes", nil, &ns); e != nil {
			return e
		}
		for _, id := range ids {
			found := false
			for _, n := range ns {
				if n.ID == id {
					found = true
					if n.Error != "" || n.DesiredRevision == 0 || n.DesiredRevision != n.AppliedRevision {
						return fmt.Errorf("node %s: desired=%d applied=%d error=%s", id, n.DesiredRevision, n.AppliedRevision, n.Error)
					}
				}
			}
			if !found {
				return fmt.Errorf("node absent: %s", id)
			}
		}
		return nil
	})
}
func checkBody(url, expected string) error {
	c := http.Client{Timeout: 3 * time.Second}
	r, e := c.Get(url)
	if e != nil {
		return e
	}
	defer r.Body.Close()
	b, e := io.ReadAll(io.LimitReader(r.Body, 2<<20))
	if e != nil {
		return e
	}
	if string(b) != expected {
		return fmt.Errorf("unexpected body (%d bytes)", len(b))
	}
	return nil
}

func TestCLIEndToEnd(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("process signal harness is POSIX; data-plane tests remain portable")
	}
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "../.."))
	dir := t.TempDir()
	bin := filepath.Join(dir, "veilink")
	command(t, root, nil, "go", "build", "-o", bin, "./cmd/veilink")
	certs := filepath.Join(dir, "certs")
	command(t, root, nil, "go", "run", "./tools/devcert", "-out", certs)
	controlPort, tunnelPort, publicPort := freePort(t), freePort(t), freePort(t)
	masterFlags := []string{"-database", filepath.Join(dir, "master.db"), "-deployment-key", filepath.Join(dir, "master.key"), "-listen-addr", fmt.Sprintf("127.0.0.1:%d", controlPort), "-scheme=https", "-cert-file", filepath.Join(certs, "cert.pem"), "-key-file", filepath.Join(certs, "key.pem")}
	master := launch(t, bin, "master", masterFlags...)
	jar, _ := cookiejar.New(nil)
	pool := x509.NewCertPool()
	ca, err := os.ReadFile(filepath.Join(certs, "ca.pem"))
	if err != nil || !pool.AppendCertsFromPEM(ca) {
		t.Fatal(err)
	}
	a := &api{c: &http.Client{Jar: jar, Timeout: 4 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, ServerName: "localhost"}}}, base: fmt.Sprintf("https://127.0.0.1:%d", controlPort)}
	eventually(t, "setup ready", func() error { return a.call("GET", "/setup", nil, nil) })
	a.must(t, "POST", "/register", map[string]string{"username": "admin", "password": "integration-secret-not-production-8429"}, nil)
	a.login(t)
	// Authenticated mutations must still require CSRF.
	csrf := a.csrf
	a.csrf = ""
	if e := a.call("POST", "/nodes", model.Node{Name: "csrf-probe", Role: "client"}, nil); e == nil {
		t.Fatal("CSRF-less mutation allowed")
	}
	a.csrf = csrf
	var server, client model.Node
	var generated struct {
		CertPEM string `json:"cert_pem"`
		KeyPEM  string `json:"key_pem"`
		CAPEM   string `json:"ca_pem"`
	}
	a.must(t, "POST", "/nodes/generate", map[string]any{"role": "server", "kind": "certificate", "server_name": "localhost", "ttl_days": 1}, &generated)
	a.must(t, "POST", "/nodes", model.Node{Name: "gateway", Role: "server", Address: "127.0.0.1", Port: tunnelPort, ServerName: "localhost", Tunnel: model.LocalTLS{TransportSecurity: "tls", CertPEM: generated.CertPEM, KeyPEM: generated.KeyPEM, CAPEM: generated.CAPEM, ListenHost: "127.0.0.1", ListenPort: tunnelPort}}, &server)
	if server.ClientTunnel == nil || server.ClientTunnel.CAPEM != generated.CAPEM || server.ClientTunnel.KeyPEM != "" {
		t.Fatal("server paired client settings not persisted safely")
	}
	a.must(t, "POST", "/nodes", model.Node{Name: "inside", Role: "client"}, &client)
	for _, override := range []model.Node{
		{ID: client.ID, Name: client.Name, Role: "client", Tunnel: model.LocalTLS{CAPEM: generated.CAPEM}},
		{ID: client.ID, Name: client.Name, Role: "client", ClientTunnel: &model.LocalTLS{TransportSecurity: "tls"}},
	} {
		if e := a.call("PUT", "/nodes/"+client.ID, override, nil); e == nil {
			t.Fatal("client-side tunnel override accepted")
		}
	}
	enroll := func(id string) string {
		var v struct {
			Token string `json:"token"`
		}
		a.must(t, "POST", "/nodes/"+id+"/enroll", map[string]int{"ttl_seconds": 3600}, &v)
		if v.Token == "" {
			t.Fatal("no enroll token")
		}
		return v.Token
	}
	serverToken, clientToken := enroll(server.ID), enroll(client.ID)
	serverFlags := nodeFlags(controlPort, filepath.Join(certs, "ca.pem"), server.ID, filepath.Join(dir, "server"))
	clientFlags := nodeFlags(controlPort, filepath.Join(certs, "ca.pem"), client.ID, filepath.Join(dir, "client"))
	launch(t, bin, "server", append(serverFlags, "-enroll-token", serverToken)...)
	cli := launch(t, bin, "client", append(clientFlags, "-enroll-token", clientToken)...)
	if e := a.call("GET", "/bindings", nil, nil); e == nil {
		t.Fatal("binding management endpoint still exists")
	}
	// HTTP is a TCP application; a large body also checks sustained bidirectional transfer.
	body := strings.Repeat("veilink-real-vless-tls\n", 16384)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, body) }))
	defer target.Close()
	targetPort := target.Listener.Addr().(*net.TCPAddr).Port
	mapping := model.Mapping{Name: "web", ServerID: server.ID, ClientID: client.ID, Pool: 2, ListenHost: "127.0.0.1", ListenPort: publicPort, TargetHost: "127.0.0.1", TargetPort: targetPort, Enabled: true}
	a.must(t, "POST", "/mappings", mapping, &mapping)
	a.applied(t, server.ID, client.ID)
	url := fmt.Sprintf("http://127.0.0.1:%d/", publicPort)
	eventually(t, "HTTP over reverse VLESS TLS", func() error { return checkBody(url, body) })
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); errs <- checkBody(url, body) }()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	// Rotating only the server updates the persisted client template and both runtimes.
	a.must(t, "POST", "/nodes/generate", map[string]any{"role": "server", "kind": "certificate", "server_name": "localhost", "ttl_days": 1}, &generated)
	server.Tunnel.CertPEM, server.Tunnel.KeyPEM, server.Tunnel.CAPEM = generated.CertPEM, generated.KeyPEM, generated.CAPEM
	server.ClientTunnel = nil // derive the matching client template atomically
	a.must(t, "PUT", "/nodes/"+server.ID, server, &server)
	if server.ClientTunnel == nil || server.ClientTunnel.CAPEM != generated.CAPEM {
		t.Fatal("rotation retained stale client trust")
	}
	a.applied(t, server.ID, client.ID)
	eventually(t, "server-only certificate rotation reaches clients", func() error { return checkBody(url, body) })

	// Exercise real HTTPS over the dedicated Vision application path. Raw handoff
	// counters are asserted in tunnel tests; this checks the complete CLI/API path.
	secureTarget := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, body)
	}))
	secureTarget.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
	secureTarget.StartTLS()
	defer secureTarget.Close()
	server.Tunnel.Flow = "xtls-rprx-vision"
	server.ClientTunnel = nil
	a.must(t, "PUT", "/nodes/"+server.ID, server, &server)
	mapping.TargetPort = secureTarget.Listener.Addr().(*net.TCPAddr).Port
	a.must(t, "PUT", "/mappings/"+mapping.ID, mapping, &mapping)
	a.applied(t, server.ID, client.ID)
	httpsClient := secureTarget.Client()
	httpsClient.Timeout = 5 * time.Second
	defer httpsClient.CloseIdleConnections()
	eventually(t, "TLS 1.3 HTTPS over Vision", func() error {
		r, err := httpsClient.Get(fmt.Sprintf("https://127.0.0.1:%d/", publicPort))
		if err != nil {
			return err
		}
		defer r.Body.Close()
		got, err := io.ReadAll(io.LimitReader(r.Body, 2<<20))
		if err != nil {
			return err
		}
		if r.TLS == nil || r.TLS.Version != tls.VersionTLS13 || string(got) != body {
			return fmt.Errorf("unexpected Vision HTTPS response")
		}
		return nil
	})
	httpsClient.CloseIdleConnections()
	mapping.TargetPort = targetPort
	a.must(t, "PUT", "/mappings/"+mapping.ID, mapping, &mapping)
	a.applied(t, server.ID, client.ID)
	eventually(t, "plain HTTP uses encrypted Vision fallback", func() error { return checkBody(url, body) })

	// Central outage must not stop existing traffic; cached state permits offline client restart.
	master.stop()
	if e := checkBody(url, body); e != nil {
		t.Fatalf("master outage interrupted data plane: %v", e)
	}
	cli.stop()
	cli = launch(t, bin, "client", clientFlags...)
	eventually(t, "client restores last-good config without master", func() error { return checkBody(url, body) })
	master = launch(t, bin, "master", masterFlags...)
	a.login(t)
	a.applied(t, server.ID, client.ID)
	var persistedNodes []model.Node
	a.must(t, "GET", "/nodes", nil, &persistedNodes)
	foundServer, foundClient := false, false
	for _, n := range persistedNodes {
		switch n.ID {
		case server.ID:
			foundServer = true
			if n.ClientTunnel == nil || *n.ClientTunnel != *server.ClientTunnel || n.Tunnel != server.Tunnel {
				t.Fatal("server pair changed across master restart")
			}
		case client.ID:
			foundClient = true
			if n.Tunnel != (model.LocalTLS{}) || n.ClientTunnel != nil {
				t.Fatal("rejected client override persisted")
			}
		}
	}
	if !foundServer || !foundClient {
		t.Fatal("server/client metadata missing after master restart")
	}
	// Persistent database survives master restart and disable/enable is applied, not just stored.
	mapping.Enabled = false
	a.must(t, "PUT", "/mappings/"+mapping.ID, mapping, &mapping)
	a.applied(t, server.ID, client.ID)
	eventually(t, "disabled public listener closed", func() error {
		c, e := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", publicPort), time.Second)
		if e != nil {
			return nil
		}
		c.Close()
		return fmt.Errorf("disabled listener still open")
	})
	target2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "changed-target") }))
	defer target2.Close()
	mapping.Enabled = true
	mapping.TargetPort = target2.Listener.Addr().(*net.TCPAddr).Port
	a.must(t, "PUT", "/mappings/"+mapping.ID, mapping, &mapping)
	a.applied(t, server.ID, client.ID)
	eventually(t, "mapping target update", func() error { return checkBody(url, "changed-target") })
	conflict := mapping
	conflict.ID = ""
	conflict.Name = "conflict"
	if e := a.call("POST", "/mappings", conflict, nil); e == nil {
		t.Fatal("conflicting public port accepted")
	}
	// Revocation updates gateway authorization and the node cannot keep exposing service.
	a.must(t, "POST", "/nodes/"+client.ID+"/revoke", map[string]any{}, nil)
	a.applied(t, server.ID)
	eventually(t, "revoked client cannot serve traffic", func() error {
		if checkBody(url, "changed-target") != nil {
			return nil
		}
		return fmt.Errorf("revoked tunnel still forwards")
	})
	a.must(t, "DELETE", "/mappings/"+mapping.ID, nil, nil)
	a.must(t, "DELETE", "/nodes/"+client.ID, nil, nil)
	a.must(t, "DELETE", "/nodes/"+server.ID, nil, nil)
	var audit []map[string]any
	a.must(t, "GET", "/audit", nil, &audit)
	if len(audit) == 0 {
		t.Fatal("missing audit trail")
	}
}
