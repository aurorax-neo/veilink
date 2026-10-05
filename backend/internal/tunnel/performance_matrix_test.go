package tunnel

import (
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"runtime"
	"testing"
	"time"

	"veilink/internal/model"
)

// Enumerate finite protocol choices; arbitrary keys, padding and rate limits
// remain parameters rather than separate protocols. No parallel measurements.
func extendedPerformanceCases() []perfCase {
	var out []perfCase
	for _, tc := range performanceCases() {
		out = append(out, tc)
		if tc.transport == "REALITY" {
			tc.mldsa = true
			tc.name += "-MLDSA"
			out = append(out, tc)
		}
	}
	for _, security := range []string{"TLS", "plain", "REALITY"} {
		for _, version := range []string{"", "1.1", "2", "3"} {
			for _, mode := range []string{"packet-up", "auto", "stream-up", "stream-one"} {
				x := model.XHTTP{Path: "/perf/", Mode: mode, TLS: security == "TLS", HTTPVersion: version}
				effective := xhttpEffectiveMode(x, security == "REALITY")
				if (version == "1.1" && effective != "packet-up") || (security == "plain" && (effective != "packet-up" || version == "3")) || (security == "REALITY" && version == "3") {
					continue
				}
				for _, base := range performanceCases() {
					if base.transport != security || base.vision {
						continue
					}
					v := version
					if v == "" {
						v = "default"
					}
					base.name = "XHTTP-" + base.name + "-h" + v + "-" + mode
					base.xhttp = x
					out = append(out, base)
					if security == "REALITY" {
						base.mldsa = true
						base.name += "-MLDSA"
						out = append(out, base)
					}
				}
			}
		}
	}
	return out
}

func TestPerformanceMatrixCoverage(t *testing.T) {
	seen := make(map[string]bool)
	counts := make(map[string]int)
	for _, tc := range extendedPerformanceCases() {
		if seen[tc.name] {
			t.Fatalf("duplicate performance case: %s", tc.name)
		}
		seen[tc.name] = true
		key := tc.transport
		if tc.xhttp.Enabled() {
			key = "XHTTP-" + key
		}
		counts[key]++
		if tc.transport == "plain" && tc.mode == "" || tc.mldsa && tc.transport != "REALITY" || tc.xhttp.Enabled() && tc.vision {
			t.Fatalf("invalid case: %+v", tc)
		}
	}
	for key, want := range map[string]int{"TLS": 26, "plain": 12, "REALITY": 52, "HY2": 1, "XHTTP-TLS": 182, "XHTTP-plain": 72, "XHTTP-REALITY": 234} {
		if counts[key] != want {
			t.Errorf("%s: got %d, want %d", key, counts[key], want)
		}
	}
	if len(seen) != 579 {
		t.Fatalf("matrix size: %d", len(seen))
	}
}

// Shared real listeners reuse upstream REALITY detection naturally. Each case
// still creates independent keys, authenticated runtimes and mapping sessions.
func TestAllProtocolPerformance(t *testing.T) {
	runPerformanceMatrix(t, extendedPerformanceCases())
}

func parameterPerformanceCases() []perfCase {
	out := []perfCase{{name: "TLS", transport: "TLS"}, {name: "TLS-Vision", transport: "TLS", vision: true}, {name: "REALITY", transport: "REALITY"}, {name: "REALITY-Vision-MLDSA", transport: "REALITY", vision: true, mldsa: true}, {name: "plain-native-mlkem-1rtt", transport: "plain", mode: "native", key: "mlkem", ticket: "1rtt"}, {name: "HY2", transport: "HY2"}}
	for _, version := range []string{"1.1", "2", "3"} {
		for _, option := range []string{"baseline", "buffered", "xmux", "header", "cookie", "metadata", "PUT", "pacing"} {
			x := model.XHTTP{Path: "/parameters/", TLS: true, Mode: "packet-up", HTTPVersion: version}
			switch option {
			case "buffered":
				x.MaxBufferedPosts, x.MaxConcurrentPosts = 4, 4
			case "xmux":
				x.Xmux = model.XHTTPXmux{MaxConcurrency: 4, MaxConnections: 2, KeepAlivePeriod: 1}
			case "header", "cookie":
				x.UplinkDataPlacement = option
				x.MaxEachPostBytes = 16384
				x.MaxBufferedPosts, x.MaxConcurrentPosts = 4, 4
			case "metadata":
				x.SessionIDPlacement, x.SeqPlacement = "header", "cookie"
				x.PaddingObfsMode = true
				x.PaddingPlacement, x.PaddingMethod = "header", "tokenish"
			case "PUT":
				x.UplinkHTTPMethod = "PUT"
			case "pacing":
				x.MinPostsIntervalMs, x.MaxPostsIntervalMs = 1, 2
			}
			out = append(out, perfCase{name: "XHTTP-TLS-h" + version + "-" + option, transport: "TLS", xhttp: x})
		}
		if version != "1.1" {
			for _, mode := range []string{"stream-up", "stream-one"} {
				out = append(out, perfCase{name: "XHTTP-TLS-h" + version + "-" + mode + "-xmux", transport: "TLS", xhttp: model.XHTTP{Path: "/parameters/", TLS: true, Mode: mode, HTTPVersion: version, NoSSEHeader: true, NoGRPCHeader: true, Xmux: model.XHTTPXmux{MaxConcurrency: 4, MaxConnections: 2, KeepAlivePeriod: 1}}})
			}
		}
	}
	return out
}

func TestParameterPerformanceCoverage(t *testing.T) {
	seen := make(map[string]bool)
	for _, tc := range parameterPerformanceCases() {
		if seen[tc.name] {
			t.Fatal("duplicate parameter case")
		}
		seen[tc.name] = true
		local := model.LocalTLS{TransportSecurity: "tls", XHTTP: tc.xhttp}
		if err := checkTransportSecurity(local); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
	}
	if len(seen) != 34 {
		t.Fatalf("parameter matrix size: %d", len(seen))
	}
}

func TestParameterPerformance(t *testing.T) {
	runPerformanceMatrix(t, parameterPerformanceCases())
}

func runPerformanceMatrix(t *testing.T, cases []perfCase) {
	t.Helper()
	perfEnabled(t)
	rounds := perfEnvInt(t, "VEILINK_PERF_ROUNDS", 1)
	blocks := perfEnvInt(t, "VEILINK_PERF_BLOCKS", 1024)
	pool := perfEnvInt(t, "VEILINK_PERF_POOL", 1)
	datagrams := perfEnvInt(t, "VEILINK_PERF_DATAGRAMS", 16384)
	files := tlsFiles(t)
	covers := map[bool]string{
		false: camouflage(t, files.CertPEM, files.KeyPEM),
		true:  camouflage(t, files.CertPEM, files.KeyPEM, true),
	}
	targets := map[string]int{"tcp": tlsApplicationTargetTimeout(t, files, tls.VersionTLS13, 90*time.Second), "udp": udpEchoServer(t)}
	ca, err := roots(files.CAPEM)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("PERF_MATRIX cases=%d paths=5 rounds=%d pool=%d blocks=%d datagrams=%d go=%s os=%s arch=%s gomaxprocs=%d", len(cases), rounds, pool, blocks, datagrams, runtime.Version(), runtime.GOOS, runtime.GOARCH, runtime.GOMAXPROCS(0))
	for round := 1; round <= rounds; round++ {
		for _, tc := range cases {
			if !perfSelected(tc.name) {
				continue
			}
			for _, mux := range []string{"off", model.MuxTypeSMux, model.MuxTypeYAMux, model.MuxTypeH2Mux, "udp"} {
				if f := os.Getenv("VEILINK_PERF_MUX"); f != "" && mux != f {
					continue
				}
				// Opt-in shard filters keep full runs serial but restartable.
				if f := os.Getenv("VEILINK_PERF_GROUP"); f != "" {
					group := tc.transport
					if tc.xhttp.Enabled() {
						group = "XHTTP-" + group
					}
					if group != f {
						continue
					}
				}
				network, kind := "tcp", mux
				if mux == "udp" {
					network, kind = "udp", ""
				} else if mux == "off" {
					kind = ""
				}
				if f := os.Getenv("VEILINK_PERF_NETWORK"); f != "" && network != f {
					continue
				}
				t.Run(fmt.Sprintf("round%d/%s/%s", round, tc.name, mux), func(t *testing.T) {
					size := datagrams * 1200
					if network == "tcp" {
						size = blocks * perfBlockSize
					}
					t.Logf("PERF_EXPECT protocol=%s network=%s mux=%s pool=%d round=%d bytes=%d", tc.name, network, mux, pool, round, size)
					port, sr := perfSetupWithFiles(t, tc, targets[network], pool, network, kind, files, covers[tc.mldsa])
					app, err := net.DialTimeout(network, fmt.Sprintf("127.0.0.1:%d", port), time.Second)
					if err != nil {
						t.Fatal(err)
					}
					defer app.Close()
					var elapsed time.Duration
					var latencies []time.Duration
					if network == "tcp" {
						c := tls.Client(app, &tls.Config{RootCAs: ca, ServerName: "gateway.test", MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13})
						if err := c.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
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
					if network == "tcp" && kind == "" && tc.vision && tc.mode == "" {
						if r != 1 || w != 1 || rr == 0 || rw == 0 {
							t.Fatalf("direct copy missing: %d/%d %d/%d", r, w, rr, rw)
						}
					} else if r != 0 || w != 0 || rr != 0 || rw != 0 {
						t.Fatal("unexpected raw handoff")
					}
					t.Logf("PERF protocol=%s network=%s mux=%s pool=%d round=%d bytes=%d seconds=%.6f MiBps=%.3f p50_us=%.3f p95_us=%.3f switches=%d/%d", tc.name, network, mux, pool, round, size, elapsed.Seconds(), float64(size)/(1<<20)/elapsed.Seconds(), float64(latencies[99])/1e3, float64(latencies[189])/1e3, r, w)
				})
			}
		}
	}
}
