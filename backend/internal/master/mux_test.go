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
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("<html>builtin-web</html>"), 0600); err != nil {
		t.Fatal(err)
	}
	cert, key := writeCert(t, dir)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	c, err := config.ParseFlags("master", []string{"-database", filepath.Join(dir, "veilink.db"), "-deployment-key", filepath.Join(dir, "veilink.key"), "-html-dir", dir, "-listen-addr", addr, "-scheme=https", "-cert-file", cert, "-key-file", key, "-embedded-server-enabled=false"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errc := make(chan error, 1)
	go func() { errc <- Run(ctx, c) }()
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
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
	if page.ProtoMajor != 2 {
		t.Fatalf("HTTPS listener did not negotiate HTTP/2: %s", page.Proto)
	}
	if page.StatusCode != http.StatusOK {
		t.Fatalf("http status %d", page.StatusCode)
	}
	if !strings.Contains(string(pageBody), "builtin-web") {
		t.Fatalf("expected bundled web body, got %q", pageBody)
	}
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{InsecureSkipVerify: true})))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	call, cancelCall := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancelCall()
	_, err = pb.NewControlClient(conn).Enroll(call, &structpb.Struct{})
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
