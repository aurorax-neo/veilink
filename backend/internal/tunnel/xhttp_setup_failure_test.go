package tunnel

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apernet/quic-go/http3"
	"veilink/internal/model"
)

type xhttpFailingTransport struct{ closed atomic.Bool }

func (f *xhttpFailingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: http.StatusForbidden, ProtoMajor: 3, Body: io.NopCloser(strings.NewReader("denied"))}, nil
}
func (f *xhttpFailingTransport) CloseIdleConnections() {}
func (f *xhttpFailingTransport) Close() error          { f.closed.Store(true); return nil }

func TestXHTTPStreamUpRejectedGETClosesTransport(t *testing.T) {
	tr := new(xhttpFailingTransport)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, err := dialXHTTPStream(ctx, &http.Client{Transport: tr}, &http.Client{Transport: tr}, tr, "https://example.test/packet/", "https://example.test/packet/", model.XHTTP{Path: "/packet/", Mode: "stream-up", TLS: true}, false, nil, cancel)
	if c != nil || err == nil || !tr.closed.Load() {
		t.Fatalf("conn=%v err=%v transport closed=%t", c, err, tr.closed.Load())
	}
}

func TestXHTTP3PacketUpGETHeaderTimeout(t *testing.T) {
	local := tlsFiles(t)
	cert, err := tls.X509KeyPair([]byte(local.CertPEM), []byte(local.KeyPEM))
	if err != nil {
		t.Fatal(err)
	}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	arrived := make(chan struct{}, 1)
	srv := &http3.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		arrived <- struct{}{}
		<-r.Context().Done() // The peer accepts GET but never returns response headers.
	}), TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"h3"}, Certificates: []tls.Certificate{cert}}}
	go func() { _ = srv.Serve(pc) }()
	t.Cleanup(func() { _ = srv.Close(); _ = pc.Close() })
	local.CAPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}))
	local.XHTTP = model.XHTTP{Path: "/packet/", Mode: "packet-up", TLS: true, HTTPVersion: "3", RequestTimeoutSeconds: 5}
	ctx, cancel := context.WithTimeout(context.Background(), 9*time.Second)
	defer cancel()
	started := time.Now()
	c, err := dialXHTTP(ctx, pc.LocalAddr().String(), "127.0.0.1", local)
	if c != nil {
		_ = c.Close()
		t.Fatal("unanswered GET established connection")
	}
	if err == nil || time.Since(started) > 8*time.Second {
		t.Fatalf("GET did not time out promptly: %v after %v", err, time.Since(started))
	}
	select {
	case <-arrived:
	default:
		t.Fatal("GET never reached HTTP/3 peer")
	}
}
