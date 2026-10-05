package tunnel

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"veilink/internal/model"
)

func TestSingRecordPayloadDoesNotWaitForHeaderACK(t *testing.T) {
	for _, concurrent := range []int{1, 2} {
		t.Run(fmt.Sprintf("posts%d", concurrent), func(t *testing.T) {
			x := model.XHTTP{Path: "/record-latency/", Mode: "packet-up"}
			if concurrent > 1 {
				x.MaxBufferedPosts, x.MaxConcurrentPosts = concurrent, concurrent
			}
			received := make(chan error, 1)
			h := newXHTTPHandler(x.Path, func(c net.Conn) {
				defer c.Close()
				r := &singRecordConn{Conn: c}
				var payload [1]byte
				_, err := io.ReadFull(r, payload[:])
				if err == nil && payload[0] != 'x' {
					err = fmt.Errorf("unexpected payload %q", payload)
				}
				received <- err
			})
			h.settings = x
			release := make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				h.ServeHTTP(w, r)
				if r.Method == http.MethodPost {
					select {
					case <-release:
					case <-r.Context().Done():
					}
				}
			}))
			t.Cleanup(func() { h.Close(); server.Close() })
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			c, err := dialXHTTP(ctx, strings.TrimPrefix(server.URL, "http://"), "", model.LocalTLS{XHTTP: x})
			if err != nil {
				close(release)
				t.Fatal(err)
			}
			defer c.Close()
			done := make(chan error, 1)
			go func() { _, err := (&singRecordConn{Conn: c}).Write([]byte("x")); done <- err }()
			select {
			case err := <-received:
				close(release)
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				close(release)
				t.Fatal("payload waited for a separate header-only POST acknowledgement")
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestTunnelSmallWritesForwardWithoutMoreData(t *testing.T) {
	cases := []perfCase{
		{name: "TLS", transport: "TLS"},
		{name: "TLS-Vision", transport: "TLS", vision: true},
		{name: "REALITY", transport: "REALITY"},
		{name: "REALITY-Vision", transport: "REALITY", vision: true},
		{name: "TLS-Encryption", transport: "TLS", mode: "native", key: "mlkem", ticket: "0rtt"},
		{name: "HY2", transport: "HY2"},
	}
	for _, version := range []string{"1.1", "2", "3"} {
		for _, mode := range []string{"packet-up", "stream-up", "stream-one"} {
			if version == "1.1" && mode != "packet-up" {
				continue
			}
			cases = append(cases, perfCase{name: "XHTTP-h" + version + "-" + mode, transport: "TLS", xhttp: model.XHTTP{Path: "/small-writes/", TLS: true, HTTPVersion: version, Mode: mode}})
		}
	}
	files := tlsFiles(t)
	cover := camouflage(t, files.CertPEM, files.KeyPEM)
	for _, tc := range cases {
		for _, kind := range []string{"", model.MuxTypeSMux, model.MuxTypeYAMux, model.MuxTypeH2Mux} {
			name := kind
			if name == "" {
				name = "off"
			}
			t.Run(tc.name+"/"+name, func(t *testing.T) {
				// A server-first byte verifies downlink independently of uploads.
				ln, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { ln.Close() })
				go func() {
					for {
						c, err := ln.Accept()
						if err != nil {
							return
						}
						go func() {
							defer c.Close()
							_ = c.SetDeadline(time.Now().Add(10 * time.Second))
							if _, err := c.Write([]byte("s")); err == nil {
								_, _ = io.Copy(c, c)
							}
						}()
					}
				}()
				port, _ := perfSetupWithFiles(t, tc, ln.Addr().(*net.TCPAddr).Port, 1, "tcp", kind, files, cover)
				c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
				if err != nil {
					t.Fatal(err)
				}
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				var greeting [1]byte
				if _, err := io.ReadFull(c, greeting[:]); err != nil || greeting[0] != 's' {
					t.Fatalf("server-first byte: %q %v", greeting, err)
				}
				var latencies []time.Duration
				for round := 0; round < 10; round++ {
					for _, size := range []int{1, 64, 1024} {
						payload := bytes.Repeat([]byte{byte(round + 1)}, size)
						got := make([]byte, size)
						_ = c.SetDeadline(time.Now().Add(time.Second))
						start := time.Now()
						if err := writeAll(c, payload); err != nil {
							t.Fatal(err)
						}
						// Do not send a second write or FIN to release the first.
						if _, err := io.ReadFull(c, got); err != nil || !bytes.Equal(got, payload) {
							t.Fatalf("size %d forwarded only after more data/FIN, or corrupted: %v", size, err)
						}
						latencies = append(latencies, time.Since(start))
					}
					if round == 0 {
						time.Sleep(20 * time.Millisecond)
					}
				}
				sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
				t.Logf("small-write RTT p50=%v p95=%v max=%v", latencies[14], latencies[28], latencies[29])
			})
		}
	}
}

func TestTunnelSlowReaderDoesNotBlockOtherPoolLanes(t *testing.T) {
	files := tlsFiles(t)
	cover := camouflage(t, files.CertPEM, files.KeyPEM)
	cases := []perfCase{
		{name: "TLS", transport: "TLS"},
		{name: "TLS-Vision", transport: "TLS", vision: true},
		{name: "REALITY", transport: "REALITY"},
		{name: "REALITY-Vision", transport: "REALITY", vision: true},
		{name: "TLS-Encryption", transport: "TLS", mode: "native", key: "mlkem", ticket: "0rtt"},
		{name: "HY2", transport: "HY2"},
	}
	for _, tc := range cases {
		for _, kind := range []string{"", model.MuxTypeSMux, model.MuxTypeYAMux, model.MuxTypeH2Mux} {
			name := kind
			if name == "" {
				name = "off"
			}
			t.Run(tc.name+"/"+name, func(t *testing.T) {
				ln, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { ln.Close() })
				flooding := make(chan struct{})
				go func() {
					for {
						c, err := ln.Accept()
						if err != nil {
							return
						}
						go func() {
							defer c.Close()
							_ = c.SetDeadline(time.Now().Add(10 * time.Second))
							var command [1]byte
							if _, err := io.ReadFull(c, command[:]); err != nil {
								return
							}
							if command[0] == 'b' {
								close(flooding)
								block := make([]byte, 32<<10)
								for i := 0; i < 1024; i++ {
									if err := writeAll(c, block); err != nil {
										return
									}
								}
								return
							}
							_, _ = c.Write(command[:])
							_, _ = io.Copy(c, c)
						}()
					}
				}()
				port, _ := perfSetupWithFiles(t, tc, ln.Addr().(*net.TCPAddr).Port, 4, "tcp", kind, files, cover)
				address := fmt.Sprintf("127.0.0.1:%d", port)
				blocked, err := net.DialTimeout("tcp", address, time.Second)
				if err != nil {
					t.Fatal(err)
				}
				defer blocked.Close()
				_ = blocked.(*net.TCPConn).SetReadBuffer(1024)
				if err := writeAll(blocked, []byte("b")); err != nil {
					t.Fatal(err)
				}
				select {
				case <-flooding:
				case <-time.After(3 * time.Second):
					t.Fatal("bulk transfer did not start")
				}
				// Fill the slow reader's socket and shared mux receive buffers.
				time.Sleep(300 * time.Millisecond)
				probe, err := net.DialTimeout("tcp", address, time.Second)
				if err != nil {
					t.Fatal(err)
				}
				defer probe.Close()
				_ = probe.SetDeadline(time.Now().Add(time.Second))
				start := time.Now()
				if err := writeAll(probe, []byte("p")); err != nil {
					t.Fatal(err)
				}
				var got [1]byte
				if _, err := io.ReadFull(probe, got[:]); err != nil || got[0] != 'p' {
					t.Fatalf("slow reader blocked another flow despite Pool=4: %v", err)
				}
				t.Logf("small flow alongside stalled download: %v", time.Since(start))
			})
		}
	}
}

func TestTunnelSingleDatagramsForwardWithoutMoreData(t *testing.T) {
	files := tlsFiles(t)
	cover := camouflage(t, files.CertPEM, files.KeyPEM)
	cases := []perfCase{
		{name: "TLS", transport: "TLS"},
		{name: "REALITY", transport: "REALITY"},
		{name: "TLS-Encryption", transport: "TLS", mode: "native", key: "mlkem", ticket: "0rtt"},
		{name: "HY2", transport: "HY2"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			port, _ := perfSetupWithFiles(t, tc, udpEchoServer(t), 4, "udp", "", files, cover)
			c, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", port))
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			for round := 0; round < 10; round++ {
				for _, size := range []int{1, 64, 1024} {
					payload := bytes.Repeat([]byte{byte(round + 1)}, size)
					got := make([]byte, size+1)
					_ = c.SetDeadline(time.Now().Add(time.Second))
					if _, err := c.Write(payload); err != nil {
						t.Fatal(err)
					}
					if n, err := c.Read(got); err != nil || !bytes.Equal(got[:n], payload) {
						t.Fatalf("single datagram size %d stalled or corrupted: %v", size, err)
					}
				}
			}
		})
	}
}
