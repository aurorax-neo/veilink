package tunnel

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/apernet/quic-go"
)

// Raw QUIC only: each stream has a concurrent writer and reader. Warmup and
// handshakes finish before the shared start barrier. Report aggregate goodput.
func TestQUICStreamsPerformance(t *testing.T) {
	perfEnabled(t)
	for _, count := range []int{1, 4} {
		for round := 1; round <= perfEnvInt(t, "VEILINK_PERF_ROUNDS", 3); round++ {
			t.Run(fmt.Sprintf("streams%d/%d", count, round), func(t *testing.T) {
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
				ln, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"perf"}}, hysteriaQUIC)
				if err != nil {
					t.Fatal(err)
				}
				defer ln.Close()
				serverDone := make(chan struct{})
				go func() {
					defer close(serverDone)
					c, err := ln.Accept(ctx)
					if err != nil {
						return
					}
					defer c.CloseWithError(0, "")
					enableHysteriaBBR(c)
					for i := 0; i < count; i++ {
						s, err := c.AcceptStream(ctx)
						if err != nil {
							return
						}
						go func() { _, _ = io.Copy(s, s) }()
					}
					<-ctx.Done()
				}()
				c, err := quic.DialAddr(ctx, ln.Addr().String(), &tls.Config{RootCAs: ca, ServerName: "gateway.test", NextProtos: []string{"perf"}}, hysteriaQUIC)
				if err != nil {
					t.Fatal(err)
				}
				enableHysteriaBBR(c)
				defer func() { cancel(); c.CloseWithError(0, ""); <-serverDone }()
				payload := perfPayloadBlock()
				var streams []*quic.Stream
				for i := 0; i < count; i++ {
					s, err := c.OpenStreamSync(ctx)
					if err != nil {
						t.Fatal(err)
					}
					// Make the stream visible, then warm up it before the common timer.
					for j := 0; j < 16; j++ {
						if err := writeAll(s, payload); err != nil {
							t.Fatal(err)
						}
						got := make([]byte, len(payload))
						if _, err := io.ReadFull(s, got); err != nil {
							t.Fatal(err)
						}
						if !bytes.Equal(got, payload) {
							t.Fatal("warmup corruption")
						}
					}
					streams = append(streams, s)
				}
				blocks := perfEnvInt(t, "VEILINK_PERF_BLOCKS", 8192) / count
				result := make(chan error, 2*count)
				start := time.Now()
				for _, s := range streams {
					go func() {
						for j := 0; j < blocks; j++ {
							if err := writeAll(s, payload); err != nil {
								result <- err
								return
							}
						}
						result <- nil
					}()
					go func() {
						got := make([]byte, len(payload))
						for j := 0; j < blocks; j++ {
							if _, err := io.ReadFull(s, got); err != nil {
								result <- err
								return
							}
							if !bytes.Equal(got, payload) {
								result <- fmt.Errorf("corruption")
								return
							}
						}
						result <- nil
					}()
				}
				for i := 0; i < 2*count; i++ {
					if err := <-result; err != nil {
						t.Fatal(err)
					}
				}
				t.Logf("STREAMS count=%d round=%d MiBps=%.3f", count, round, float64(blocks*count)/16/time.Since(start).Seconds())
			})
		}
	}
}
