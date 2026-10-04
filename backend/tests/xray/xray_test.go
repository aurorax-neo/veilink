package xray_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"veilink/internal/model"
	"veilink/internal/tunnel"
)

// findXrayBinary locates the Xray binary or returns empty string if unavailable.
func findXrayBinary() string {
	if bin := os.Getenv("XRAY_BIN"); bin != "" {
		if fi, err := os.Stat(bin); err == nil && !fi.IsDir() {
			return bin
		}
	}
	if scratch := os.Getenv("PI_SCRATCH_DIR"); scratch != "" {
		candidate := filepath.Join(scratch, "xray-build", "xray")
		if fi, err := os.Stat(candidate); err == nil && !fi.IsDir() {
			return candidate
		}
	}
	// Fallback to hardcoded scratch path if environment variable not passed
	defaultScratch := "/Users/wunk/.pi-desktop/scratch/e654bad2-22af-4e02-940a-1dfcaa4fdf60/xray-build/xray"
	if fi, err := os.Stat(defaultScratch); err == nil && !fi.IsDir() {
		return defaultScratch
	}
	if bin, err := exec.LookPath("xray"); err == nil {
		return bin
	}
	return ""
}

// generateSelfSignedCert generates a self-signed ECDSA or RSA cert for localhost.
func generateSelfSignedCert(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate private key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Veilink Xray Test"},
			CommonName:   "127.0.0.1",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.IPv6loopback},
		DNSNames:              []string{"localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER := x509.MarshalPKCS1PrivateKey(priv)
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

func getFreePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("get free port: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// startEchoServer runs a TCP echo server on 127.0.0.1 and returns its port and a stop func.
func startEchoServer(t *testing.T) (int, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
					return
				}
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()

	stop := func() {
		cancel()
		_ = ln.Close()
	}
	return port, stop
}

type xrayInbound struct {
	Port           int             `json:"port"`
	Listen         string          `json:"listen"`
	Protocol       string          `json:"protocol"`
	Settings       json.RawMessage `json:"settings"`
	StreamSettings json.RawMessage `json:"streamSettings"`
}

type dokodemoSettings struct {
	Address string `json:"address"`
	Port    int    `json:"port"`
	Network string `json:"network"`
}

type xrayConfig struct {
	Log       map[string]string `json:"log"`
	Inbounds  []xrayInbound     `json:"inbounds"`
	Outbounds []any             `json:"outbounds"`
}

// startXrayServer creates an Xray process running dokodemo-door with XHTTP inbound
// pointing to targetPort (echo server).
func startXrayServer(t *testing.T, xrayBin string, certFile, keyFile string, mode string, targetPort int) (int, func(), func() string) {
	t.Helper()
	xrayPort := getFreePort(t)

	dokoJSON, _ := json.Marshal(dokodemoSettings{
		Address: "127.0.0.1",
		Port:    targetPort,
		Network: "tcp",
	})

	type tlsCert struct {
		CertificateFile string `json:"certificateFile"`
		KeyFile         string `json:"keyFile"`
	}
	type tlsConfig struct {
		Certificates []tlsCert `json:"certificates"`
		Alpn         []string  `json:"alpn"`
	}
	type xhttpConf struct {
		Path string `json:"path"`
		Mode string `json:"mode"`
	}
	type streamConf struct {
		Network       string     `json:"network"`
		Security      string     `json:"security"`
		TLSSettings   tlsConfig  `json:"tlsSettings"`
		XHTTPSettings xhttpConf  `json:"xhttpSettings"`
	}

	streamJSON, _ := json.Marshal(streamConf{
		Network:  "xhttp",
		Security: "tls",
		TLSSettings: tlsConfig{
			Certificates: []tlsCert{{
				CertificateFile: certFile,
				KeyFile:         keyFile,
			}},
			Alpn: []string{"h2"},
		},
		XHTTPSettings: xhttpConf{
			Path: "/xhttp-test/",
			Mode: mode,
		},
	})

	cfg := xrayConfig{
		Log: map[string]string{
			"loglevel": "debug",
		},
		Inbounds: []xrayInbound{
			{
				Port:           xrayPort,
				Listen:         "127.0.0.1",
				Protocol:       "dokodemo-door",
				Settings:       dokoJSON,
				StreamSettings: streamJSON,
			},
		},
		Outbounds: []any{
			map[string]string{
				"protocol": "freedom",
			},
		},
	}

	cfgBytes, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatalf("marshal xray config: %v", err)
	}

	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.json")
	if err := os.WriteFile(cfgPath, cfgBytes, 0600); err != nil {
		t.Fatalf("write xray config: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, xrayBin, "run", "-c", cfgPath)
	var outBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &outBuf

	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatalf("start xray: %v", err)
	}

	// Wait for Xray to be listening
	addr := fmt.Sprintf("127.0.0.1:%d", xrayPort)
	ready := false
	for i := 0; i < 50; i++ {
		time.Sleep(50 * time.Millisecond)
		c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = c.Close()
			ready = true
			break
		}
	}
	if !ready {
		cancel()
		_ = cmd.Wait()
		t.Fatalf("xray failed to start listening on %s; output:\n%s", addr, outBuf.String())
	}

	cleanup := func() {
		cancel()
		_ = cmd.Wait()
	}
	getLogs := func() string {
		return outBuf.String()
	}
	return xrayPort, cleanup, getLogs
}

func TestXrayXHTTPInteroperability(t *testing.T) {
	xrayBin := findXrayBinary()
	if xrayBin == "" {
		t.Skip("xray binary not found in XRAY_BIN, scratch directory, or PATH; skipping blackbox interoperability test")
	}
	t.Logf("Using Xray binary: %s", xrayBin)

	certPEM, keyPEM := generateSelfSignedCert(t)
	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "server.crt")
	keyFile := filepath.Join(tmpDir, "server.key")
	if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	echoPort, stopEcho := startEchoServer(t)
	defer stopEcho()

	modes := []struct {
		name       string
		serverMode string
		clientMode string
	}{
		{
			name:       "stream-one",
			serverMode: "auto",
			clientMode: "stream-one",
		},
		{
			name:       "stream-up",
			serverMode: "auto",
			clientMode: "stream-up",
		},
		{
			name:       "packet-up",
			serverMode: "auto",
			clientMode: "packet-up",
		},
	}

	for _, tc := range modes {
		t.Run(tc.name, func(t *testing.T) {
			xrayPort, stopXray, getLogs := startXrayServer(t, xrayBin, certFile, keyFile, tc.serverMode, echoPort)
			defer func() {
				stopXray()
				if t.Failed() {
					t.Logf("Xray logs for %s:\n%s", tc.name, getLogs())
				}
			}()
			local := model.LocalTLS{
				CAPEM: string(certPEM),
				XHTTP: model.XHTTP{
					Path:                  "/xhttp-test/",
					TLS:                   true,
					HTTPVersion:           "2",
					RequestTimeoutSeconds: 5,
					MaxEachPostBytes:      16384,
					PaddingBytes:          100,
					PaddingMaxBytes:       1000,
				},
			}

			addr := fmt.Sprintf("127.0.0.1:%d", xrayPort)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			conn, err := tunnel.DialXHTTP(ctx, addr, "localhost", local)
			if err != nil {
				t.Fatalf("DialXHTTP mode=%s failed: %v", tc.clientMode, err)
			}
			defer conn.Close()

			testPayload := []byte("Hello, Xray XHTTP interoperability test for mode " + tc.clientMode + "!")
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

			// Write test payload
			if _, err := conn.Write(testPayload); err != nil {
				t.Fatalf("write to xray conn failed: %v", err)
			}

			// Read echo response
			buf := make([]byte, len(testPayload))
			if _, err := io.ReadFull(conn, buf); err != nil {
				t.Fatalf("read from xray conn failed: %v", err)
			}

			if !bytes.Equal(buf, testPayload) {
				t.Fatalf("echo mismatch: got %q, want %q", string(buf), string(testPayload))
			}

			// Verify connection close and cleanup
			if err := conn.Close(); err != nil {
				t.Errorf("conn.Close() failed: %v", err)
			}
			// Reading after close should return error or EOF
			var extra [16]byte
			_, err = conn.Read(extra[:])
			if err == nil {
				t.Errorf("expected error reading from closed connection, got nil")
			}
		})
	}
}

func TestXrayXHTTPLargePayload(t *testing.T) {
	xrayBin := findXrayBinary()
	if xrayBin == "" {
		t.Skip("xray binary not found; skipping")
	}

	certPEM, keyPEM := generateSelfSignedCert(t)
	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "server.crt")
	keyFile := filepath.Join(tmpDir, "server.key")
	if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	echoPort, stopEcho := startEchoServer(t)
	defer stopEcho()

	xrayPort, stopXray, getLogs := startXrayServer(t, xrayBin, certFile, keyFile, "auto", echoPort)
	defer func() {
		stopXray()
		if t.Failed() {
			t.Logf("Xray logs:\n%s", getLogs())
		}
	}()

	local := model.LocalTLS{
		CAPEM: string(certPEM),
		XHTTP: model.XHTTP{
			Path:                  "/xhttp-test/",
			TLS:                   true,
			HTTPVersion:           "2",
			RequestTimeoutSeconds: 10,
			MaxEachPostBytes:      16384,
			PaddingBytes:          100,
			PaddingMaxBytes:       1000,
		},
	}

	addr := fmt.Sprintf("127.0.0.1:%d", xrayPort)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := tunnel.DialXHTTP(ctx, addr, "localhost", local)
	if err != nil {
		t.Fatalf("DialXHTTP failed: %v", err)
	}
	defer conn.Close()

	// 64 KB of patterned test data spanning multiple XHTTP chunks
	payloadSize := 64 * 1024
	testData := make([]byte, payloadSize)
	for i := range testData {
		testData[i] = byte(i % 251)
	}

	errCh := make(chan error, 2)
	receivedData := make([]byte, payloadSize)

	// Read in background
	go func() {
		_, err := io.ReadFull(conn, receivedData)
		errCh <- err
	}()

	// Write concurrently
	go func() {
		_, err := conn.Write(testData)
		errCh <- err
	}()

	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			t.Fatalf("large payload transfer error (%d): %v", i, err)
		}
	}

	if !bytes.Equal(receivedData, testData) {
		t.Fatalf("large payload data mismatch")
	}
}

func TestXrayXHTTPMultiRound(t *testing.T) {
	xrayBin := findXrayBinary()
	if xrayBin == "" {
		t.Skip("xray binary not found; skipping")
	}

	certPEM, keyPEM := generateSelfSignedCert(t)
	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "server.crt")
	keyFile := filepath.Join(tmpDir, "server.key")
	if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	echoPort, stopEcho := startEchoServer(t)
	defer stopEcho()

	xrayPort, stopXray, getLogs := startXrayServer(t, xrayBin, certFile, keyFile, "auto", echoPort)
	defer func() {
		stopXray()
		if t.Failed() {
			t.Logf("Xray logs:\n%s", getLogs())
		}
	}()

	local := model.LocalTLS{
		CAPEM: string(certPEM),
		XHTTP: model.XHTTP{
			Path:                  "/xhttp-test/",
			TLS:                   true,
			HTTPVersion:           "2",
			RequestTimeoutSeconds: 10,
			MaxEachPostBytes:      16384,
			PaddingBytes:          100,
			PaddingMaxBytes:       1000,
		},
	}

	addr := fmt.Sprintf("127.0.0.1:%d", xrayPort)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := tunnel.DialXHTTP(ctx, addr, "localhost", local)
	if err != nil {
		t.Fatalf("DialXHTTP failed: %v", err)
	}
	defer conn.Close()

	// 10 ping-pong rounds
	for round := 1; round <= 10; round++ {
		msg := fmt.Sprintf("ping-round-%02d-%s", round, bytes.Repeat([]byte("data-"), 20))
		if _, err := conn.Write([]byte(msg)); err != nil {
			t.Fatalf("round %d write error: %v", round, err)
		}
		buf := make([]byte, len(msg))
		if _, err := io.ReadFull(conn, buf); err != nil {
			t.Fatalf("round %d read error: %v", round, err)
		}
		if string(buf) != msg {
			t.Fatalf("round %d content mismatch: got %q, want %q", round, string(buf), msg)
		}
	}
}
