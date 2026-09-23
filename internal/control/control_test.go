package control

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"math/big"
	"net"
	"path/filepath"
	"testing"
	"time"
	pb "veilink/api/control/v1"
	"veilink/internal/model"
	"veilink/internal/store"
)

func TestTLSProtocolAndLiveRevocation(t *testing.T) {
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, e := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	cert, e := x509.ParseCertificate(der)
	if e != nil {
		t.Fatal(e)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	d := t.TempDir()
	s, e := store.Open(filepath.Join(d, "db"), filepath.Join(d, "key"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	n, e := s.SaveNode(model.Node{Name: "client", Role: "client"})
	if e != nil {
		t.Fatal(e)
	}
	token, e := s.EnrollToken(n.ID, time.Hour)
	if e != nil {
		t.Fatal(e)
	}
	listener := bufconn.Listen(1 << 20)
	g := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})))
	pb.RegisterControlServer(g, &Service{Store: s})
	go g.Serve(listener)
	defer g.Stop()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, e := grpc.NewClient("passthrough:///localhost", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }), grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, ServerName: "localhost"})))
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	c := pb.NewControlClient(conn)
	req, _ := Envelope(map[string]any{"node_id": n.ID, "token": token})
	enrolled, e := c.Enroll(ctx, req)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = c.Enroll(ctx, req); status.Code(e) != codes.Unauthenticated {
		t.Fatal("token reuse", e)
	}
	req, _ = Envelope(map[string]any{"node_id": n.ID, "credential": String(enrolled, "credential"), "applied_revision": 0})
	if _, e = c.Pull(ctx, req); e != nil {
		t.Fatal(e)
	}
	stream, e := c.Events(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if e = stream.Send(req); e != nil {
		t.Fatal(e)
	}
	if _, e = stream.Recv(); e != nil {
		t.Fatal(e)
	}
	if e = s.RemoveNode(n.ID, false); e != nil {
		t.Fatal(e)
	}
	if e = stream.Send(req); e != nil {
		t.Fatal(e)
	}
	if _, e = stream.Recv(); status.Code(e) != codes.Unauthenticated {
		t.Fatal("revoked live stream", e)
	}
	if _, e = c.Pull(ctx, req); status.Code(e) != codes.Unauthenticated {
		t.Fatal("revoked pull", e)
	}
}
