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
	req, _ = Envelope(map[string]any{"node_id": n.ID, "credential": String(enrolled, "credential")})
	if _, e = c.Pull(ctx, req); e != nil {
		t.Fatal(e)
	}
	beat, _ := Envelope(map[string]any{"node_id": n.ID, "credential": String(enrolled, "credential"), "applied_revision": 0, "software_version": "v1.2.3", "software_commit": "abc123"})
	stream, e := c.Events(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if e = stream.Send(beat); e != nil {
		t.Fatal(e)
	}
	if _, e = stream.Recv(); e != nil {
		t.Fatal(e)
	}
	nodes, err := s.ReportedNodes()
	if err != nil || len(nodes) != 1 || nodes[0].SoftwareVersion != "v1.2.3" || nodes[0].SoftwareCommit != "abc123" {
		t.Fatalf("heartbeat identity: %+v %v", nodes, err)
	}
	for _, bad := range []any{123, nil, "bad\nvalue"} {
		invalid, err := c.Events(ctx)
		if err != nil {
			t.Fatal(err)
		}
		message, _ := Envelope(map[string]any{"node_id": n.ID, "credential": String(enrolled, "credential"), "software_version": bad})
		if err := invalid.Send(message); err != nil {
			t.Fatal(err)
		}
		if _, err := invalid.Recv(); status.Code(err) != codes.InvalidArgument {
			t.Fatalf("invalid version accepted: %v", err)
		}
	}
	nodes, err = s.ReportedNodes()
	if err != nil || nodes[0].SoftwareVersion != "v1.2.3" {
		t.Fatalf("invalid report replaced identity: %+v %v", nodes, err)
	}
	if e = s.RemoveNode(n.ID, false); e != nil {
		t.Fatal(e)
	}
	if e = stream.Send(beat); e != nil {
		t.Fatal(e)
	}
	if _, e = stream.Recv(); status.Code(e) != codes.Unauthenticated {
		t.Fatal("revoked live stream", e)
	}
	if _, e = c.Pull(ctx, req); status.Code(e) != codes.Unauthenticated {
		t.Fatal("revoked pull", e)
	}
}

func TestPullRejectsUploadsAndReturnsDatabaseSnapshot(t *testing.T) {
	d := t.TempDir()
	s, err := store.Open(filepath.Join(d, "db"), filepath.Join(d, "key"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	n, err := s.SaveNode(model.Node{Name: "database-only", Role: "client"})
	if err != nil {
		t.Fatal(err)
	}
	token, err := s.EnrollToken(n.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := s.Enroll(n.ID, token)
	if err != nil {
		t.Fatal(err)
	}
	service := &Service{Store: s}
	before, err := s.Snapshot(n.ID, credential)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"bootstrap", "role", "tls"} {
		req, _ := Envelope(map[string]any{"node_id": n.ID, "credential": credential, field: map[string]any{}})
		if _, err := service.Pull(context.Background(), req); status.Code(err) != codes.InvalidArgument {
			t.Fatalf("accepted removed field %s: %v", field, err)
		}
	}
	after, err := s.Snapshot(n.ID, credential)
	if err != nil {
		t.Fatal(err)
	}
	if after.Revision != before.Revision || after.Node.Tunnel != before.Node.Tunnel {
		t.Fatal("Pull changed database configuration")
	}
	req, _ := Envelope(map[string]any{"node_id": n.ID, "credential": credential})
	out, err := service.Pull(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if String(out.Fields["node"].GetStructValue(), "id") != n.ID {
		t.Fatal("wrong database snapshot")
	}
	req, _ = Envelope(map[string]any{"node_id": n.ID, "credential": "wrong"})
	if _, err := service.Pull(context.Background(), req); status.Code(err) != codes.Unauthenticated {
		t.Fatal("bad credential accepted", err)
	}
}
