package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMasterControlTrustFlagsPersist(t *testing.T) {
	dir := t.TempDir()
	bootstrap := []string{"-database", filepath.Join(dir, "master.db"), "-deployment-key", filepath.Join(dir, "master.key")}
	first, err := ParseFlags("master", append(append([]string{}, bootstrap...), "-control-server-name", "panel.example.com", "-control-ca", "/config/master-ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PersistMaster(first); err != nil {
		t.Fatal(err)
	}
	restart, err := ParseFlags("master", bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	got, err := PersistMaster(restart)
	if err != nil || got.ControlServerName != "panel.example.com" || got.ControlCA != "/config/master-ca.pem" {
		t.Fatalf("omitted trust flags lost persisted values: %+v %v", got, err)
	}
	clear, err := ParseFlags("master", append(append([]string{}, bootstrap...), "-control-server-name=", "-control-ca="))
	if err != nil {
		t.Fatal(err)
	}
	got, err = PersistMaster(clear)
	if err != nil || got.ControlServerName != "" || got.ControlCA != "" {
		t.Fatalf("explicit empty trust flags did not override stored values: %+v %v", got, err)
	}
}

func TestMasterEmbeddedControlCAInvalidUpdatePreservesSettings(t *testing.T) {
	dir := t.TempDir()
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	cert := filepath.Join(dir, "cert.pem")
	key := filepath.Join(dir, "key.pem")
	pair := server.TLS.Certificates[0]
	keyDER, err := x509.MarshalPKCS8PrivateKey(pair.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pair.Certificate[0]}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatal(err)
	}
	base := []string{"-database", filepath.Join(dir, "db"), "-deployment-key", filepath.Join(dir, "deployment.key")}
	parse := func(flags ...string) Config {
		t.Helper()
		c, err := ParseFlags("master", append(append([]string{}, base...), flags...))
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	good := parse("-scheme=https", "-cert-file="+cert, "-key-file="+key, "-embedded-server-enabled", "-control-ca="+cert, "-control-server-name=example.com")
	if _, err := PersistMaster(good); err != nil {
		t.Fatal(err)
	}
	badPEM := filepath.Join(dir, "invalid.pem")
	if err := os.WriteFile(badPEM, []byte("not a certificate"), 0600); err != nil {
		t.Fatal(err)
	}
	unrelated := filepath.Join(dir, "unrelated.pem")
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(12345), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	otherDER, err := x509.CreateCertificate(rand.Reader, template, template, &otherKey.PublicKey, otherKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(unrelated, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: otherDER}), 0600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(dir, "missing.pem"), badPEM, unrelated} {
		if _, err := PersistMaster(parse("-control-ca=" + path)); err == nil || !(strings.Contains(err.Error(), "embedded control CA") || strings.Contains(err.Error(), "embedded control TLS trust")) {
			t.Fatalf("accepted invalid embedded CA %q: %v", path, err)
		}
		got, err := PersistMaster(parse())
		if err != nil || got.ControlCA != cert || got.ControlServerName != "example.com" || !got.EmbeddedServer.Enabled {
			t.Fatalf("bad CA replaced saved settings: %+v %v", got, err)
		}
	}
}
