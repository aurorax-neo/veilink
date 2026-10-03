package master

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"veilink/internal/config"
	"veilink/internal/httpapi/backend"
	"veilink/internal/model"
	"veilink/internal/store"
)

func TestEmbeddedServerLifecycleAndRegistration(t *testing.T) {
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

	c, err := config.ParseFlags("master", []string{"-database", dbPath, "-deployment-key", keyPath, "-listen-addr", masterAddr, "-state-dir", filepath.Join(dir, "state"), "-scheme=https", "-cert-file", cert, "-key-file", key, "-embedded-server-enabled", "-embedded-server-name=integrated-gateway", "-embedded-server-port", strconv.Itoa(serverPort), "-embedded-server-address=127.0.0.1"})
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
		resp, err := httpClient.Get("https://" + masterAddr + "/healthz")
		if err == nil {
			resp.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("master did not start in time: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}

	// 2. API Key auth: first boot auto-generates an admin key, no username/password exists.
	s, err := store.Open(dbPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	ks := backend.NewKeyStore(s.DB())
	if err := ks.Migrate(); err != nil {
		t.Fatal(err)
	}
	keys, err := ks.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) == 0 {
		t.Fatal("expected auto-generated admin API key on first boot")
	}
	foundAdmin := false
	for _, k := range keys {
		if k.Name == "default-admin" && k.Role == "admin" {
			foundAdmin = true
			break
		}
	}
	if !foundAdmin {
		t.Fatalf("expected default-admin key, got %+v", keys)
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

	// 4. Configure tunnel PEM in the database, as Web does, then add a mapping.
	embeddedNode, _, err := s.FindNodeByName("integrated-gateway")
	if err != nil {
		t.Fatal(err)
	}
	if embeddedNode.Tunnel != (model.LocalTLS{ListenPort: serverPort}) {
		t.Fatal("embedded initialization must contain only the explicit tunnel listen port")
	}
	serverAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(serverPort))
	if conn, err := net.DialTimeout("tcp", serverAddr, 200*time.Millisecond); err == nil {
		conn.Close()
		t.Fatal("unconfigured embedded tunnel is listening")
	}
	tunnelCert, tunnelKey := writeCert(t, t.TempDir())
	certPEM, err := os.ReadFile(tunnelCert)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := os.ReadFile(tunnelKey)
	if err != nil {
		t.Fatal(err)
	}
	embeddedNode.Tunnel = model.LocalTLS{ListenPort: serverPort, TransportSecurity: "tls", CertPEM: string(certPEM), KeyPEM: string(keyPEM)}
	if _, err := s.SaveNode(embeddedNode); err != nil {
		t.Fatal(err)
	}
	clientNode, err := s.SaveNode(model.Node{
		Name: "test-client",
		Role: "client",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.SaveMapping(model.Mapping{
		Name: "test-route", ServerID: embeddedNode.ID, ClientID: clientNode.ID,
		Pool: 1, ListenHost: "127.0.0.1", ListenPort: 10080,
		TargetHost: "127.0.0.1", TargetPort: 80, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	// 5. Verify embedded server starts listening on its allocated port (heartbeat cycle is 10s)
	portDeadline := time.Now().Add(15 * time.Second)
	var serverPortOpen bool
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

	c, err := config.ParseFlags("master", []string{"-database", dbPath, "-deployment-key", keyPath, "-listen-addr", masterAddr, "-state-dir", filepath.Join(dir, "state"), "-scheme=https", "-cert-file", cert, "-key-file", key, "-embedded-server-enabled=false"})
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
		resp, err := httpClient.Get("https://" + masterAddr + "/healthz")
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
