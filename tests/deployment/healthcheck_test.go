package deployment

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"veilink/internal/config"
)

func TestMasterHealthcheckPersistedListenerAfterRestart(t *testing.T) {
	if _, err := exec.LookPath("sqlite3"); err != nil {
		t.Skip("sqlite3 CLI required by Master image")
	}
	root := projectRoot(t)
	body, err := os.ReadFile(filepath.Join(root, "docker-healthcheck.sh"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, storedListen, storedScheme string
		flags                            []string
		wantURL                          string
		insecure                         bool
	}{
		{"restart HTTP", "127.0.0.1:19543", "http", nil, "http://127.0.0.1:19543/healthz", false},
		{"restart HTTPS wildcard", "0.0.0.0:19443", "https", nil, "https://127.0.0.1:19443/healthz", true},
		{"restart IPv6 wildcard", "[::]:19443", "https", nil, "https://[::1]:19443/healthz", true},
		{"restart IPv6 loopback", "[::1]:19443", "http", nil, "http://[::1]:19443/healthz", false},
		{"explicit listener and scheme", "127.0.0.1:19543", "http", []string{"-listen-addr", "[::1]:24443", "-scheme=https"}, "https://[::1]:24443/healthz", true},
		{"explicit listener persisted scheme", "127.0.0.1:19543", "https", []string{"-listen-addr=127.0.0.1:24443"}, "https://127.0.0.1:24443/healthz", true},
		{"explicit scheme persisted listener", "127.0.0.1:19543", "https", []string{"-scheme", "http"}, "http://127.0.0.1:19543/healthz", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			db := filepath.Join(dir, "master.db")
			cert, key := healthcheckCert(t, dir)
			tlsFlags := []string{"-cert-file", cert, "-key-file", key}
			bootstrap := []string{"-database", db, "-deployment-key", filepath.Join(dir, "key")}
			initial, err := config.ParseFlags("master", append(append(append([]string{}, bootstrap...), tlsFlags...), append([]string{"-embedded-server-enabled=false"}, "-listen-addr", tc.storedListen, "-scheme", tc.storedScheme)...))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := config.PersistMaster(initial); err != nil {
				t.Fatal(err)
			}
			// A restart with only bootstrap flags keeps the nondefault listener.
			restart, err := config.ParseFlags("master", append(append(append([]string{}, bootstrap...), tlsFlags...), tc.flags...))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := config.PersistMaster(restart); err != nil {
				t.Fatal(err)
			}
			args := append([]string{"/usr/local/bin/veilink", "master"}, bootstrap...)
			args = append(args, tc.flags...)
			runHealthcheck(t, body, dir, args, tc.wantURL, tc.insecure, true)
		})
	}
}

func TestMasterHealthcheckFallbackAndFailure(t *testing.T) {
	if _, err := exec.LookPath("sqlite3"); err != nil {
		t.Skip("sqlite3 CLI required by Master image")
	}
	body, err := os.ReadFile(filepath.Join(projectRoot(t), "docker-healthcheck.sh"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	args := []string{"veilink", "master", "-database", filepath.Join(dir, "missing.db")}
	runHealthcheck(t, body, dir, args, "http://127.0.0.1:8443/healthz", false, true)
	// A reachable but wrong endpoint must never make a probe healthy.
	runHealthcheck(t, body, dir, args, "http://127.0.0.1:9999/healthz", false, false)
	if err := os.WriteFile(filepath.Join(dir, "missing.db"), []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	runHealthcheck(t, body, dir, args, "http://127.0.0.1:8443/healthz", false, false)
}

// Substitute only the procfs path in a private copy; production always reads PID 1.
func runHealthcheck(t *testing.T, source []byte, dir string, args []string, wantURL string, insecure, wantSuccess bool) {
	t.Helper()
	work := t.TempDir()
	cmdline := filepath.Join(work, "cmdline")
	if err := os.WriteFile(cmdline, []byte(strings.Join(args, "\x00")+"\x00"), 0600); err != nil {
		t.Fatal(err)
	}
	script := strings.ReplaceAll(string(source), "/proc/1/cmdline", cmdline)
	if err := os.WriteFile(filepath.Join(work, "healthcheck.sh"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	curl := "#!/bin/sh\nfor arg do\n  [ \"$arg\" = \"$WANT_URL\" ] && found=1\n  [ \"$arg\" = --insecure ] && tls=1\ndone\n[ \"${found:-}\" = 1 ] && [ \"${tls:-}\" = \"$WANT_INSECURE\" ]\n"
	if err := os.WriteFile(filepath.Join(work, "curl"), []byte(curl), 0700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", filepath.Join(work, "healthcheck.sh"))
	cmd.Dir = dir
	wantTLS := ""
	if insecure {
		wantTLS = "1"
	}
	cmd.Env = append(os.Environ(), "PATH="+work+":"+os.Getenv("PATH"), "WANT_URL="+wantURL, "WANT_INSECURE="+wantTLS)
	output, err := cmd.CombinedOutput()
	if (err == nil) != wantSuccess {
		t.Fatalf("healthcheck success=%t, want %t: %v (%s)", err == nil, wantSuccess, err, output)
	}
}

func healthcheckCert(t *testing.T, dir string) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	raw, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw}), 0600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}
