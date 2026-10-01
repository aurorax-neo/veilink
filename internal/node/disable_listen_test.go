package node

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	pb "veilink/api/control/v1"
	"veilink/internal/config"
	"veilink/internal/control"
	"veilink/internal/model"
	"veilink/internal/store"
	"veilink/internal/tunnel"
)

func TestDisableClosesListenersThroughControl(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "db"), filepath.Join(dir, "key"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	tunnelPort, publicPort := freeNodePort(t), freeNodePort(t)
	cert, key := nodeCert(t)
	local := model.LocalTLS{TransportSecurity: "tls", CertPEM: cert, KeyPEM: key, CAPEM: cert, ListenHost: "127.0.0.1", ListenPort: tunnelPort}
	server, err := st.SaveNode(model.Node{Name: "gateway", Role: "server", Address: "127.0.0.1", Port: tunnelPort, Tunnel: local})
	if err != nil {
		t.Fatal(err)
	}
	clientNode, err := st.SaveNode(model.Node{Name: "client", Role: "client"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = st.SaveMapping(model.Mapping{Name: "web", ServerID: server.ID, ClientID: clientNode.ID, Pool: 1, ListenHost: "127.0.0.1", ListenPort: publicPort, TargetHost: "127.0.0.1", TargetPort: 80, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	serverCred := enrollNode(t, st, server.ID)
	clientCred := enrollNode(t, st, clientNode.ID)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gs := grpc.NewServer()
	pb.RegisterControlServer(gs, &control.Service{Store: st})
	go gs.Serve(listener)
	t.Cleanup(gs.Stop)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serverRuntime := startNodeCycle(t, ctx, listener.Addr().String(), server.ID, "server", serverCred)
	clientRuntime := startNodeCycle(t, ctx, listener.Addr().String(), clientNode.ID, "client", clientCred)
	waitTCP(t, tunnelPort, true)
	waitTCP(t, publicPort, true)

	if err = st.SetNodeDisabled(server.ID, true); err != nil {
		t.Fatal(err)
	}
	waitTCP(t, tunnelPort, false)
	waitTCP(t, publicPort, false)
	if serverRuntime.Revision() < 0 || clientRuntime.Revision() < 0 {
		t.Fatalf("disable did not apply server=%d client=%d", serverRuntime.Revision(), clientRuntime.Revision())
	}

	if err = st.SetNodeDisabled(server.ID, false); err != nil {
		t.Fatal(err)
	}
	waitTCP(t, tunnelPort, true)
	waitTCP(t, publicPort, true)
	if err = st.SetNodeDisabled(clientNode.ID, true); err != nil {
		t.Fatal(err)
	}
	waitTCP(t, tunnelPort, false)
	waitTCP(t, publicPort, false)
}

func startNodeCycle(t *testing.T, ctx context.Context, master, id, role, credential string) *tunnel.Runtime {
	t.Helper()
	conn, err := grpc.NewClient(master, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	runtime := tunnel.New(model.LocalTLS{})
	t.Cleanup(func() { _ = runtime.Close() })
	state := newSyncState(ctx, runtime)
	disk := diskState{NodeID: id, Master: master, Credential: credential}
	path := filepath.Join(t.TempDir(), "state.json")
	errc := make(chan error, 1)
	go func() {
		errc <- cycle(ctx, pb.NewControlClient(conn), config.Config{NodeID: id}, role, &disk, state, path, nil, cycleTiming{30 * time.Second, 20 * time.Millisecond, 2 * time.Second})
	}()
	t.Cleanup(func() {
		select {
		case err := <-errc:
			if err != nil && ctx.Err() == nil {
				t.Errorf("%s cycle: %v", role, err)
			}
		default:
		}
	})
	return runtime
}

func enrollNode(t *testing.T, st *store.Store, id string) string {
	t.Helper()
	token, err := st.EnrollToken(id, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := st.Enroll(id, token)
	if err != nil {
		t.Fatal(err)
	}
	return credential
}

func nodeCert(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "gateway.test"}, DNSNames: []string{"gateway.test"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}))
}

func freeNodePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

func waitTCP(t *testing.T, port int, open bool) {
	t.Helper()
	deadline := time.Now().Add(4 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 100*time.Millisecond)
		up := err == nil
		if up {
			_ = conn.Close()
		}
		if up == open {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("port %d open=%v, want %v", port, up, open)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
