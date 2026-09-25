package tunnel

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/apernet/quic-go"
)

// TestQUICPerformanceControl removes authentication, mux, XUDP and TCP forwarding.
// The inner-TLS variant preserves the application's second encryption layer.
// Both endpoints use the production BBR standard controller.
func TestQUICPerformanceControl(t *testing.T) {
	perfEnabled(t)
	for _, variant := range []string{"raw", "inner-TLS", "inner-TLS-large-window"} {
		for round := 1; round <= perfEnvInt(t, "VEILINK_PERF_ROUNDS", 3); round++ {
			t.Run(fmt.Sprintf("%s/%d", variant, round), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
				defer cancel()
				files := tlsFiles(t)
				cert, err := tls.X509KeyPair([]byte(files.CertPEM), []byte(files.KeyPEM))
				if err != nil {
					t.Fatal(err)
				}
				ca, err := roots(files.CAPEM)
				if err != nil {
					t.Fatal(err)
				}
				cfg := hysteriaQUIC.Clone()
				if variant == "inner-TLS-large-window" {
					cfg.InitialStreamReceiveWindow = 4 << 20
					cfg.MaxStreamReceiveWindow = 16 << 20
					cfg.InitialConnectionReceiveWindow = 8 << 20
					cfg.MaxConnectionReceiveWindow = 32 << 20
				}
				serverTLS := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13, NextProtos: []string{"perf"}}
				clientTLS := &tls.Config{RootCAs: ca, ServerName: "gateway.test", MinVersion: tls.VersionTLS13, NextProtos: []string{"perf"}}
				ln, err := quic.ListenAddr("127.0.0.1:0", serverTLS, cfg)
				if err != nil {
					t.Fatal(err)
				}
				defer ln.Close()
				done := make(chan error, 1)
				go func() {
					c, err := ln.Accept(ctx)
					if err != nil {
						done <- err
						return
					}
					defer c.CloseWithError(0, "")
					enableHysteriaBBR(c)
					s, err := c.AcceptStream(ctx)
					if err != nil {
						done <- err
						return
					}
					var echo net.Conn = &quicConn{Stream: s, local: c.LocalAddr(), remote: c.RemoteAddr()}
					if variant != "raw" {
						echo = tls.Server(echo, serverTLS)
					}
					_, err = io.Copy(echo, echo)
					done <- err
				}()
				c, err := quic.DialAddr(ctx, ln.Addr().String(), clientTLS, cfg)
				if err != nil {
					t.Fatal(err)
				}
				defer c.CloseWithError(0, "")
				enableHysteriaBBR(c)
				defer func() {
					cancel()
					_ = c.CloseWithError(0, "")
					select {
					case <-done:
					case <-time.After(5 * time.Second):
						t.Error("echo did not stop")
					}
				}()
				s, err := c.OpenStreamSync(ctx)
				if err != nil {
					t.Fatal(err)
				}
				var app net.Conn = &quicConn{Stream: s, local: c.LocalAddr(), remote: c.RemoteAddr()}
				if variant != "raw" {
					inner := tls.Client(app, clientTLS)
					if err := inner.HandshakeContext(ctx); err != nil {
						t.Fatal(err)
					}
					app = inner
				}
				blocks := perfEnvInt(t, "VEILINK_PERF_BLOCKS", 1024)
				elapsed, latencies := perfTCP(t, app, blocks)
				t.Logf("CONTROL variant=%s round=%d MiBps=%.3f p50_us=%.3f p95_us=%.3f", variant, round, float64(blocks)/16/elapsed.Seconds(), float64(latencies[99])/1e3, float64(latencies[189])/1e3)
			})
		}
	}
}
