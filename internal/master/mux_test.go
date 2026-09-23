package master

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"

	pb "veilink/api/control/v1"
	"veilink/internal/config"
)

func TestWebAndGRPCShareOnePort(t *testing.T) {
	dir := t.TempDir()
	cert, key := writeCert(t, dir)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	cfg := filepath.Join(dir, "master.yaml")
	body := "database: " + quote(filepath.Join(dir, "veilink.db")) + "\n" +
		"deployment_key: " + quote(filepath.Join(dir, "veilink.key")) + "\n" +
		"bind_addr: " + quote(addr) + "\n" +
		"control_cert: " + quote(cert) + "\n" +
		"control_key: " + quote(key) + "\n"
	if err = os.WriteFile(cfg, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := config.Load(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errc := make(chan error, 1)
	go func() { errc <- Run(ctx, c) }()
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	var page *http.Response
	deadline := time.Now().Add(5 * time.Second)
	for {
		page, err = client.Get("https://" + addr + "/")
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	pageBody, err := io.ReadAll(page.Body)
	page.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if page.StatusCode != http.StatusOK {
		t.Fatalf("http status %d", page.StatusCode)
	}
	if !strings.Contains(string(pageBody), "Veilink management API") {
		t.Fatalf("embedded console must not be served, body %q", pageBody)
	}
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{InsecureSkipVerify: true})))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, err = pb.NewControlClient(conn).Enroll(context.Background(), &structpb.Struct{})
	if status.Code(err) == codes.OK || status.Code(err) == codes.Unavailable {
		t.Fatal(err)
	}
	cancel()
	select {
	case err = <-errc:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("master did not stop")
	}
}

func quote(s string) string { return "\"" + s + "\"" }

func writeCert(t *testing.T, dir string) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err = os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	raw, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw}), 0600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}
