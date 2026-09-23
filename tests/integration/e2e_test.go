//go:build integration

// Package integration exercises the built CLI, not a mocked transport.
package integration

import (
	"bytes"
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

func launch(t *testing.T, bin, role, cfg string, env ...string) *process {
	t.Helper()
	log, err := os.CreateTemp(t.TempDir(), role+"-*.log")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, role, "-config", cfg)
	cmd.Env = append(os.Environ(), env...)
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
func write(t *testing.T, path, content string) {
	t.Helper()
	if e := os.WriteFile(path, []byte(content), 0600); e != nil {
		t.Fatal(e)
	}
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
	httpPort, controlPort, tunnelPort, publicPort := freePort(t), freePort(t), freePort(t), freePort(t)
	masterCfg := filepath.Join(dir, "master.yaml")
	write(t, masterCfg, fmt.Sprintf("database: %q\ndeployment_key: %q\nhttp_addr: 127.0.0.1:%d\ninsecure_loopback_http: true\ncontrol_addr: 127.0.0.1:%d\ncontrol_cert: %q\ncontrol_key: %q\n", filepath.Join(dir, "master.db"), filepath.Join(dir, "master.key"), httpPort, controlPort, filepath.Join(certs, "cert.pem"), filepath.Join(certs, "key.pem")))
	command(t, root, []string{"VEILINK_ADMIN_PASSWORD=integration-secret-not-production-8429"}, bin, "init-admin", "-config", masterCfg, "-username", "admin")
	master := launch(t, bin, "master", masterCfg)
	jar, _ := cookiejar.New(nil)
	a := &api{c: &http.Client{Jar: jar, Timeout: 4 * time.Second}, base: fmt.Sprintf("http://127.0.0.1:%d", httpPort)}
	a.login(t)
	// Authenticated mutations must still require CSRF.
	csrf := a.csrf
	a.csrf = ""
	if e := a.call("POST", "/nodes", model.Node{Name: "csrf-probe", Role: "client"}, nil); e == nil {
		t.Fatal("CSRF-less mutation allowed")
	}
	a.csrf = csrf
	var server, client model.Node
	a.must(t, "POST", "/nodes", model.Node{Name: "gateway", Role: "server", Address: "127.0.0.1", Port: tunnelPort, ServerName: "localhost"}, &server)
	a.must(t, "POST", "/nodes", model.Node{Name: "inside", Role: "client"}, &client)
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
	serverCfg, clientCfg := filepath.Join(dir, "server.yaml"), filepath.Join(dir, "client.yaml")
	common := fmt.Sprintf("master_addr: 127.0.0.1:%d\ncontrol_ca: %q\ncontrol_server_name: localhost\n", controlPort, filepath.Join(certs, "ca.pem"))
	write(t, serverCfg, common+fmt.Sprintf("node_id: %q\nstate_dir: %q\ntls:\n  cert_file: %q\n  key_file: %q\n  listen_host: 127.0.0.1\n", server.ID, filepath.Join(dir, "server"), filepath.Join(certs, "cert.pem"), filepath.Join(certs, "key.pem")))
	write(t, clientCfg, common+fmt.Sprintf("node_id: %q\nstate_dir: %q\ntls:\n  ca_file: %q\n", client.ID, filepath.Join(dir, "client"), filepath.Join(certs, "ca.pem")))
	launch(t, bin, "server", serverCfg, "VEILINK_ENROLL_TOKEN="+serverToken)
	cli := launch(t, bin, "client", clientCfg, "VEILINK_ENROLL_TOKEN="+clientToken)
	var binding model.Binding
	a.must(t, "POST", "/bindings", model.Binding{ServerID: server.ID, ClientID: client.ID}, &binding)
	if binding.UUID != "" {
		t.Fatal("management binding API leaked VLESS credential")
	}
	var rawBindings []map[string]any
	a.must(t, "GET", "/bindings", nil, &rawBindings)
	for _, b := range rawBindings {
		if v, ok := b["uuid"]; ok && v != "" {
			t.Fatal("management list leaked UUID")
		}
	}
	// HTTP is a TCP application; a large body also checks sustained bidirectional transfer.
	body := strings.Repeat("veilink-real-vless-tls\n", 16384)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, body) }))
	defer target.Close()
	targetPort := target.Listener.Addr().(*net.TCPAddr).Port
	mapping := model.Mapping{Name: "web", BindingID: binding.ID, ListenHost: "127.0.0.1", ListenPort: publicPort, TargetHost: "127.0.0.1", TargetPort: targetPort, Enabled: true}
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
	// Central outage must not stop existing traffic; cached state permits offline client restart.
	master.stop()
	if e := checkBody(url, body); e != nil {
		t.Fatalf("master outage interrupted data plane: %v", e)
	}
	cli.stop()
	cli = launch(t, bin, "client", clientCfg)
	eventually(t, "client restores last-good config without master", func() error { return checkBody(url, body) })
	master = launch(t, bin, "master", masterCfg)
	a.login(t)
	a.applied(t, server.ID, client.ID)
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
	a.must(t, "DELETE", "/bindings/"+binding.ID, nil, nil)
	a.must(t, "DELETE", "/nodes/"+client.ID, nil, nil)
	a.must(t, "DELETE", "/nodes/"+server.ID, nil, nil)
	var audit []map[string]any
	a.must(t, "GET", "/audit", nil, &audit)
	if len(audit) == 0 {
		t.Fatal("missing audit trail")
	}
}
