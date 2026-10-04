package tunnel

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/apernet/quic-go"
	"strconv"

	"github.com/apernet/quic-go/http3"
	"veilink/internal/model"
)

// xhttpCloser lets H1/H2 and H3 share the same bounded request lifecycle.
type xhttpCloser interface {
	http.RoundTripper
	CloseIdleConnections()
}

type xhttpTransportPair struct {
	up, down xhttpCloser
	once     sync.Once
}

func (p *xhttpTransportPair) RoundTrip(r *http.Request) (*http.Response, error) {
	return p.up.RoundTrip(r)
}
func (p *xhttpTransportPair) CloseIdleConnections() {}
func (p *xhttpTransportPair) Close() error {
	p.once.Do(func() {
		if p.up != nil {
			closeXHTTPTransport(p.up)
		}
		if p.down != nil && p.down != p.up {
			closeXHTTPTransport(p.down)
		}
	})
	return nil
}

func closeXHTTPTransport(tr xhttpCloser) {
	if closer, ok := tr.(interface{ Close() error }); ok {
		_ = closer.Close() // H3 owns a UDP socket, not just idle connections.
	} else {
		tr.CloseIdleConnections()
	}
}

func xhttpTLSNextProto(version string) map[string]func(string, *tls.Conn) http.RoundTripper {
	if version == "1.1" {
		// Prevent an explicit HTTP/1.1 choice from negotiating h2.
		return map[string]func(string, *tls.Conn) http.RoundTripper{}
	}
	return nil
}

func newXHTTP3ClientTransport(pool *x509.CertPool, serverName string, keepAlive time.Duration) xhttpCloser {
	config := &quic.Config{}
	if keepAlive > 0 {
		config.KeepAlivePeriod = keepAlive
	}
	return &http3.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, ServerName: serverName, NextProtos: []string{"h3"}},
		QUICConfig:      config, MaxResponseHeaderBytes: 8 << 10, DisableCompression: true,
	}
}

func xhttpExpectedStreamMajor(x model.XHTTP) int {
	if x.HTTPVersion == "3" {
		return 3
	}
	return 2
}

func (h *xhttpHandler) streamHTTPMajor() int {
	if h.version == "3" {
		return 3
	}
	return 2
}

func (s *service) listenXHTTP3() error {
	cert, err := tls.X509KeyPair([]byte(s.local.CertPEM), []byte(s.local.KeyPEM))
	if err != nil {
		return err
	}
	addr := net.JoinHostPort(listenHost(s.local.ListenHost), strconv.Itoa(s.local.ListenPort))
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	s.packets = append(s.packets, pc)
	h := newXHTTPHandler(s.local.XHTTP.Path, func(c net.Conn) {
		if !s.track(c) {
			_ = c.Close()
			return
		}
		s.authenticate(c)
	})
	h.mode = xhttpEffectiveMode(s.local.XHTTP, s.local.Reality.Enabled())
	h.settings = s.local.XHTTP
	h.host = s.local.XHTTP.Host
	h.headers, _ = s.local.XHTTP.Headers.Entries()
	h.version = "3"
	h.uplinkMethod = xhttpUplinkMethod(s.local.XHTTP)
	h.noGRPCHeader, h.noSSEHeader = s.local.XHTTP.NoGRPCHeader, s.local.XHTTP.NoSSEHeader
	h.timeout = xhttpRequestTimeout(s.local.XHTTP)
	h.padding, h.paddingMax = xhttpPaddingMinimum(s.local.XHTTP), xhttpPaddingMaximum(s.local.XHTTP)
	h.maxPost = xhttpPostMaximum(s.local.XHTTP)
	server := &http3.Server{
		Handler: h, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, NextProtos: []string{"h3"}},
		MaxHeaderBytes: xhttpServerHeaderLimit(s.local.XHTTP),
	}
	s.xhttpClose = func() { h.Close(); _ = server.Close() }
	go func() { _ = server.Serve(pc) }()
	return nil
}

func xhttpHTTP2Config(seconds int) *http.HTTP2Config {
	if seconds <= 0 {
		return nil
	}
	d := time.Duration(seconds) * time.Second
	return &http.HTTP2Config{SendPingTimeout: d, PingTimeout: 15 * time.Second}
}
