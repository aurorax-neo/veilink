package tunnel

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"veilink/internal/model"
)

// All 65 finite legal supported transport/flow/encryption choices. Padding lengths,
// ticket lifetimes and arbitrary keys are not separate throughput dimensions.
// 0rtt/1rtt is the configured policy; the measurement excludes handshakes and
// does not claim that a fresh connection resumed a ticket.
type perfCase struct {
	name, transport, mode, key, ticket string
	vision                             bool
	mldsa                              bool
	xhttp                              model.XHTTP
}

func performanceCases() []perfCase {
	var out []perfCase
	for _, transport := range []string{"TLS", "plain", "REALITY", "HY2"} {
		for _, vision := range []bool{false, true} {
			if vision && (transport == "plain" || transport == "HY2") {
				continue
			}
			base := transport
			if vision {
				base += "-Vision"
			}
			if transport != "plain" {
				out = append(out, perfCase{name: base, transport: transport, vision: vision})
			}
			if transport == "HY2" {
				continue
			}
			for _, mode := range []string{"native", "xorpub", "random"} {
				for _, key := range []string{"x25519", "mlkem"} {
					for _, ticket := range []string{"0rtt", "1rtt"} {
						out = append(out, perfCase{name: base + "-" + mode + "-" + key + "-" + ticket, transport: transport, vision: vision, mode: mode, key: key, ticket: ticket})
					}
				}
			}
		}
	}
	return out
}
func perfEnvInt(t *testing.T, key string, fallback int) int {
	t.Helper()
	if os.Getenv(key) == "" {
		return fallback
	}
	n, err := strconv.Atoi(os.Getenv(key))
	if err != nil || n < 1 {
		t.Fatalf("invalid %s", key)
	}
	return n
}
func perfEnabled(t *testing.T) {
	t.Helper()
	if os.Getenv("VEILINK_PERF") != "1" {
		t.Skip("set VEILINK_PERF=1; see tests/perf/README.md")
	}
}
func perfSelected(name string) bool { f := os.Getenv("VEILINK_PERF_CASE"); return f == "" || name == f }
func perfSetup(t *testing.T, tc perfCase, target, pool int, network string) (int, *Runtime) {
	t.Helper()
	files := tlsFiles(t)
	cover := ""
	if tc.transport == "REALITY" {
		cover = camouflage(t, files.CertPEM, files.KeyPEM, tc.mldsa)
	}
	return perfSetupWithFiles(t, tc, target, pool, network, "", files, cover)
}

func perfSetupWithFiles(t *testing.T, tc perfCase, target, pool int, network, mux string, files model.LocalTLS, cover string) (int, *Runtime) {
	t.Helper()
	server, client := fixtures(t, target)
	local := files
	if tc.transport == "plain" {
		local = model.LocalTLS{TransportSecurity: "plain"}
	}
	if tc.transport == "REALITY" {
		priv, _, err := GenerateX25519()
		if err != nil {
			t.Fatal(err)
		}
		local = model.LocalTLS{Reality: model.Reality{PrivateKey: priv, Dest: cover, ShortIDs: "0123456789abcdef", ServerNames: "gateway.test"}}
		if tc.mldsa {
			local.Reality.Mldsa65Seed, local.Reality.Mldsa65Verify, err = GenerateMldsa65()
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	if tc.transport == "HY2" {
		local.Hysteria2.Password = "local-perf-only"
		server.Node.Tunnel.ListenPort = freeUDPPort(t)
		server.Node.Port = server.Node.Tunnel.ListenPort
		client.Nodes[0] = server.Node
	}
	if tc.mode != "" {
		dec, _, pq, _, err := GenerateVLESSEnc()
		if err != nil {
			t.Fatal(err)
		}
		if tc.key == "mlkem" {
			dec = pq
		}
		local.Decryption = strings.Replace(dec, ".native.", "."+tc.mode+".", 1)
	}
	if tc.vision {
		local.Flow = flowVision
	}
	local.XHTTP = tc.xhttp
	if tc.xhttp.HTTPVersion == "3" {
		server.Node.Tunnel.ListenPort = freeUDPPort(t)
		server.Node.Port = server.Node.Tunnel.ListenPort
	}
	local.ListenPort = server.Node.Tunnel.ListenPort
	public, err := PublicPeerTunnel(local, server.Node)
	if err != nil {
		t.Fatal(err)
	}
	public.Hysteria2 = local.Hysteria2
	if tc.ticket == "1rtt" {
		public.Encryption = strings.Replace(public.Encryption, ".0rtt.", ".1rtt.", 1)
	}
	client.Nodes[0] = server.Node
	client.Nodes[0].Tunnel = public
	server.Mappings[0].Network = network
	server.Mappings[0].Pool = pool
	server.Mappings[0].Mux, server.Mappings[0].MuxType = mux != "", mux
	if network == "udp" {
		server.Mappings[0].ListenPort = freeUDPPort(t)
	}
	client.Mappings[0] = server.Mappings[0]
	sr := run(t, server, local)
	run(t, client, model.LocalTLS{})
	until := time.Now().Add(10 * time.Second)
	binding := testBindingService(sr.instance, "one")
	for {
		binding.mu.Lock()
		ready := len(binding.sessions["one"]) >= pool
		binding.mu.Unlock()
		if ready {
			break
		}
		if time.Now().After(until) {
			t.Fatal("authenticated session not ready")
		}
		time.Sleep(time.Millisecond * 10)
	}
	if mux != "" {
		p := binding.singPools[singKey("one", mux)]
		for {
			p.mu.Lock()
			ready := p.count >= pool
			p.mu.Unlock()
			if ready {
				break
			}
			if time.Now().After(until) {
				t.Fatal("authenticated mux pool not ready")
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	if tc.vision && network == "tcp" && mux == "" {
		awaitApplication(t, sr.instance, "one")
	}
	return server.Mappings[0].ListenPort, sr
}

const perfBlockSize = 64 << 10

func perfPayloadBlock() []byte {
	pattern := []byte("veilink-perf-data")
	return bytes.Repeat(pattern, (perfBlockSize+len(pattern)-1)/len(pattern))[:perfBlockSize]
}

func TestPerformancePayloadSize(t *testing.T) {
	if got := len(perfPayloadBlock()); got != 65536 {
		t.Fatalf("performance block has %d bytes, want 65536", got)
	}
}

func perfTCP(t *testing.T, app net.Conn, blocks int) (time.Duration, []time.Duration) {
	t.Helper()
	if err := app.SetDeadline(time.Now().Add(90 * time.Second)); err != nil {
		t.Fatal(err)
	}
	block := perfPayloadBlock()
	transfer := func(n int) time.Duration {
		t.Helper()
		result := make(chan error, 1)
		start := time.Now()
		go func() {
			for i := 0; i < n; i++ {
				if err := writeAll(app, block); err != nil {
					result <- err
					return
				}
			}
			result <- nil
		}()
		got := make([]byte, len(block))
		for i := 0; i < n; i++ {
			if _, err := io.ReadFull(app, got); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, block) {
				t.Fatal("payload corruption")
			}
		}
		if err := <-result; err != nil {
			t.Fatal(err)
		}
		return time.Since(start)
	}
	transfer(16)
	elapsed := transfer(blocks)
	small := block[:64]
	got := make([]byte, 64)
	latencies := make([]time.Duration, 200)
	for i := range latencies {
		start := time.Now()
		if err := writeAll(app, small); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(app, got); err != nil {
			t.Fatal(err)
		}
		latencies[i] = time.Since(start)
		if !bytes.Equal(got, small) {
			t.Fatal("RTT corruption")
		}
	}
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	return elapsed, latencies
}

// Fixed batches of 16 datagrams bound offered load below the association queue
// capacity (32). This measures windowed echo goodput, not maximum line rate.
// Every datagram carries a sequence and its whole payload is validated. No
// retransmission: loss/duplicates/corruption fail the run, never count as bytes.
func perfUDP(t *testing.T, app net.Conn) (time.Duration, []time.Duration) {
	t.Helper()
	payload := bytes.Repeat([]byte{0x5a}, 1200)
	got := make([]byte, 1500)
	batch := func(base, count int) {
		t.Helper()
		if err := app.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < count; i++ {
			binary.BigEndian.PutUint64(payload, uint64(base+i))
			if _, err := app.Write(payload); err != nil {
				t.Fatal(err)
			}
		}
		seen := make(map[uint64]bool, count)
		for i := 0; i < count; i++ {
			n, err := app.Read(got)
			if err != nil {
				t.Fatalf("UDP loss/timeout: received=%d/%d: %v", i, count, err)
			}
			if n != len(payload) {
				t.Fatal("UDP size mismatch")
			}
			id := binary.BigEndian.Uint64(got)
			if id < uint64(base) || id >= uint64(base+count) || seen[id] {
				t.Fatal("UDP sequence mismatch")
			}
			seen[id] = true
			if !bytes.Equal(got[8:n], payload[8:]) {
				t.Fatal("UDP corruption")
			}
		}
	}
	for i := 0; i < 256; i += 16 {
		batch(i, 16)
	}
	start := time.Now()
	datagrams := perfEnvInt(t, "VEILINK_PERF_DATAGRAMS", 16384)
	for i := 0; i < datagrams; i += 16 {
		batch(i, min(16, datagrams-i))
	}
	elapsed := time.Since(start)
	latencies := make([]time.Duration, 200)
	payload = payload[:64]
	for i := range latencies {
		start := time.Now()
		batch(i, 1)
		latencies[i] = time.Since(start)
	}
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	return elapsed, latencies
}

// VEILINK_PERF=1 go test ./internal/tunnel -run '^TestLocalPerformance$'
// -count=1 -v -timeout=30m. Non-race numbers only; all cases carry identical
// inner TLS1.3 application TCP traffic, and separate 1200-byte XUDP datagrams.
func TestLocalPerformance(t *testing.T) {
	perfEnabled(t)
	t.Logf("environment go=%s os=%s arch=%s cpus=%d gomaxprocs=%d", runtime.Version(), runtime.GOOS, runtime.GOARCH, runtime.NumCPU(), runtime.GOMAXPROCS(0))
	rounds := perfEnvInt(t, "VEILINK_PERF_ROUNDS", 3)
	blocks := perfEnvInt(t, "VEILINK_PERF_BLOCKS", 1024)
	pool := perfEnvInt(t, "VEILINK_PERF_POOL", 1)
	for round := 1; round <= rounds; round++ {
		for _, tc := range performanceCases() {
			if !perfSelected(tc.name) {
				continue
			}
			for _, network := range []string{"tcp", "udp"} {
				if f := os.Getenv("VEILINK_PERF_NETWORK"); f != "" && f != network {
					continue
				}
				t.Run(fmt.Sprintf("round%d/%s/%s", round, tc.name, network), func(t *testing.T) {
					files := tlsFiles(t)
					target := 0
					if network == "tcp" {
						target = tlsApplicationTargetTimeout(t, files, tls.VersionTLS13, 90*time.Second)
					} else {
						target = udpEchoServer(t)
					}
					port, sr := perfSetup(t, tc, target, pool, network)
					app, err := net.DialTimeout(network, fmt.Sprintf("127.0.0.1:%d", port), time.Second)
					if err != nil {
						t.Fatal(err)
					}
					defer app.Close()
					var elapsed time.Duration
					var latencies []time.Duration
					size := perfEnvInt(t, "VEILINK_PERF_DATAGRAMS", 16384) * 1200
					if network == "tcp" {
						roots, err := roots(files.CAPEM)
						if err != nil {
							t.Fatal(err)
						}
						c := tls.Client(app, &tls.Config{RootCAs: roots, ServerName: "gateway.test", MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13})
						if err := c.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
							t.Fatal(err)
						}
						if err := c.Handshake(); err != nil {
							t.Fatal(err)
						}
						elapsed, latencies = perfTCP(t, c, blocks)
						size = blocks * perfBlockSize
					} else {
						elapsed, latencies = perfUDP(t, app)
					}
					r, w, rr, rw := applicationCounters(sr.instance)
					if network == "tcp" && tc.vision && tc.mode == "" {
						if r != 1 || w != 1 || rr == 0 || rw == 0 {
							t.Fatalf("direct copy missing: %d/%d %d/%d", r, w, rr, rw)
						}
					} else if r != 0 || w != 0 || rr != 0 || rw != 0 {
						t.Fatal("unexpected raw handoff")
					}
					t.Logf("PERF protocol=%s network=%s pool=%d round=%d bytes=%d seconds=%.6f MiBps=%.3f p50_us=%.3f p95_us=%.3f switches=%d/%d", tc.name, network, pool, round, size, elapsed.Seconds(), float64(size)/(1<<20)/elapsed.Seconds(), float64(latencies[99])/1e3, float64(latencies[189])/1e3, r, w)
				})
			}
		}
	}
}
