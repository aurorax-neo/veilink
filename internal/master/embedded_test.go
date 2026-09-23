package master

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"veilink/internal/config"
	"veilink/internal/model"
	"veilink/internal/store"
)
func TestEmbeddedServerLifecycleAndAutoAdmin(t *testing.T) {
	dir := t.TempDir()
	cert, key := writeCert(t, dir)

	// Pick two free ports
	lnMaster, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	masterAddr := lnMaster.Addr().String()
	_ = lnMaster.Close()

	lnServer, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serverPort := lnServer.Addr().(*net.TCPAddr).Port
	_ = lnServer.Close()

	dbPath := filepath.Join(dir, "veilink.db")
	keyPath := filepath.Join(dir, "veilink.key")
	cfgPath := filepath.Join(dir, "master.yaml")

	body := fmt.Sprintf(`
database: %s
deployment_key: %s
bind_addr: %s
state_dir: %s
control_cert: %s
control_key: %s
embedded_server:
  enabled: true
  name: "integrated-gateway"
  port: %d
  address: "127.0.0.1"
  server_name: "localhost"
`, quote(dbPath), quote(keyPath), quote(masterAddr), quote(filepath.Join(dir, "state")), quote(cert), quote(key), serverPort)

	if err := os.WriteFile(cfgPath, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("VEILINK_INIT_ADMIN_PASSWORD", "SuperSecureAdminPassword123!")
	t.Setenv("VEILINK_INIT_ADMIN_USERNAME", "admin-root")

	c, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errc := make(chan error, 1)
	go func() {
		errc <- Run(ctx, c)
	}()

	// 1. Wait for Master HTTP server to become responsive
	httpClient := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		resp, err := httpClient.Get("https://" + masterAddr + "/api/v1/auth/login")
		if err == nil {
			resp.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("master did not start in time: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}

	// 2. Verify auto-admin initialization in database
	s, err := store.Open(dbPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	hasAdmin, err := s.HasAdmin()
	if err != nil {
		t.Fatal(err)
	}
	if !hasAdmin {
		t.Fatalf("expected admin to be auto-initialized")
	}
	if !s.Login("admin-root", "SuperSecureAdminPassword123!") {
		t.Fatalf("admin login verification failed")
	}

	// 3. Verify embedded server node auto-registration and heartbeat in database
	nodeDeadline := time.Now().Add(5 * time.Second)
	var embeddedNodeFound bool
	for time.Now().Before(nodeDeadline) {
		node, found, err := s.FindNodeByName("integrated-gateway")
		if err == nil && found {
			if node.Role == "server" && node.Port == serverPort && node.LastSeen > 0 {
				embeddedNodeFound = true
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !embeddedNodeFound {
		t.Fatalf("embedded server node was not registered or last_seen not updated")
	}

	// 4. Create client and binding so the server has active bindings to listen for
	embeddedNode, _, err := s.FindNodeByName("integrated-gateway")
	if err != nil {
		t.Fatal(err)
	}
	clientNode, err := s.SaveNode(model.Node{
		Name: "test-client",
		Role: "client",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.SaveBinding(model.Binding{
		ServerID: embeddedNode.ID,
		ClientID: clientNode.ID,
	})
	if err != nil {
		t.Fatal(err)
	}

	// 5. Verify embedded server starts listening on its allocated port (heartbeat cycle is 10s)
	portDeadline := time.Now().Add(15 * time.Second)
	var serverPortOpen bool
	serverAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(serverPort))
	for time.Now().Before(portDeadline) {
		conn, err := net.DialTimeout("tcp", serverAddr, 200*time.Millisecond)
		if err == nil {
			conn.Close()
			serverPortOpen = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !serverPortOpen {
		t.Fatalf("embedded server is not listening on port %d", serverPort)
	}

	// 5. Test graceful shutdown
	cancel()
	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("expected clean shutdown, got error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("master and embedded server did not stop in time")
	}
}

func TestEmbeddedServerDisabled(t *testing.T) {
	dir := t.TempDir()
	cert, key := writeCert(t, dir)

	lnMaster, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	masterAddr := lnMaster.Addr().String()
	_ = lnMaster.Close()

	dbPath := filepath.Join(dir, "veilink.db")
	keyPath := filepath.Join(dir, "veilink.key")
	cfgPath := filepath.Join(dir, "master.yaml")

	body := fmt.Sprintf(`
database: %s
deployment_key: %s
bind_addr: %s
state_dir: %s
control_cert: %s
control_key: %s
embedded_server:
  enabled: false
`, quote(dbPath), quote(keyPath), quote(masterAddr), quote(filepath.Join(dir, "state")), quote(cert), quote(key))

	if err := os.WriteFile(cfgPath, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}

	c, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errc := make(chan error, 1)
	go func() {
		errc <- Run(ctx, c)
	}()

	httpClient := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		resp, err := httpClient.Get("https://" + masterAddr + "/api/v1/auth/login")
		if err == nil {
			resp.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("master did not start in time: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}

	s, err := store.Open(dbPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	nodes, err := s.Nodes()
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 0 {
		t.Fatalf("expected 0 nodes when embedded_server is disabled, got %d", len(nodes))
	}

	cancel()
	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("clean shutdown error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("master shutdown timeout")
	}
}
