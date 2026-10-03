package httpapi

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/mlkem"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"veilink/internal/httpapi/backend"
	"veilink/internal/model"
	"veilink/internal/store"
	"veilink/internal/tunnel"
)

func TestGenerationAPI(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Open(filepath.Join(dir, "db"), filepath.Join(dir, "key"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	h := New(s, false, nil)
	apiKey, err := h.(*API).keyStore.Create("test", backend.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	call := func(method, body, key string) *httptest.ResponseRecorder {
		w := testCall(h, key, method, "/api/v1/nodes/generate", body)
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("generation response may be cached")
		}
		return w
	}
	generate := func(body string) map[string]string {
		t.Helper()
		w := call("POST", body, apiKey)
		if w.Code != http.StatusOK {
			t.Fatalf("generation failed: %d", w.Code)
		}
		var out map[string]string
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	// Compare every store file, including any journal, before/after generation.
	snapshot := func() map[string]string {
		t.Helper()
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]string{}
		for _, entry := range entries {
			data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
			if err != nil {
				t.Fatal(err)
			}
			out[entry.Name()] = string(data)
		}
		return out
	}
	t.Run("authentication", func(t *testing.T) {
		body := `{"role":"server","kind":"reality"}`
		for _, tc := range []struct {
			key  string
			want int
		}{
			{"", 401}, {"vlk_invalid_key", 401}, {"Bearer " + apiKey, 401},
		} {
			if got := call("POST", body, tc.key).Code; got != tc.want {
				t.Fatalf("got %d, want %d", got, tc.want)
			}
		}
		// 吊销后的 key 应被拒绝
		revoked, err := h.(*API).keyStore.Create("revoked", backend.RoleAdmin)
		if err != nil {
			t.Fatal(err)
		}
		keys, err := h.(*API).keyStore.List()
		if err != nil {
			t.Fatal(err)
		}
		for _, k := range keys {
			if k.Name == "revoked" {
				if err := h.(*API).keyStore.Revoke(k.ID); err != nil {
					t.Fatal(err)
				}
			}
		}
		if got := call("POST", body, revoked).Code; got != 401 {
			t.Fatalf("revoked key accepted: %d", got)
		}
		for _, method := range []string{"GET", "PUT", "DELETE"} {
			if got := call(method, body, apiKey).Code; got != 404 {
				t.Fatalf("unexpected %s status %d", method, got)
			}
		}
	})
	// authentication 子测试会操作 key 表，基准快照在其后采集
	before := snapshot()
	t.Run("invalid inputs", func(t *testing.T) {
		for _, body := range []string{
			`{}`, `null`, `{"kind":"reality"}`, `{"kind":"reality","role":"client"}`,
			`{"role":"server","kind":"unknown"}`, `{"role":"server","kind":"vless","mode":"bad"}`,
			`{"role":"server","kind":"vless","authentication":"bad"}`,
			`{"role":"server","kind":"short_id","mode":"native"}`,
			`{"role":"server","kind":"short_id","ttl_days":30}`,
			`{"role":"server","kind":"certificate"}`,
			`{"role":"server","kind":"certificate","server_name":"example.com","host":"example.com"}`,
			`{"role":"server","kind":"certificate","host":"example.com","ttl_days":0}`,
			`{"role":"server","kind":"certificate","host":"example.com","ttl_days":-1}`,
			`{"role":"server","kind":"certificate","host":"example.com","ttl_days":366}`,
			`{"role":"server","kind":"certificate","host":"example.com","ttl_days":1.5}`,
			`{"role":"server","kind":"short_id","unknown":true}`,
			`{"role":"server","kind":"short_id"} {}`, `{"role":"server",`,
			`{"role":"server","kind":"short_id"}` + strings.Repeat(" ", 4096),
		} {
			if got := call("POST", body, apiKey).Code; got != 400 {
				t.Fatalf("invalid input accepted: %d", got)
			}
		}
		for _, name := range []string{"", "*.example.com", "https://example.com", "example.com:443", "host/path", "a..b", "-host", "host-", "host\n", " host", "host.", "host_name", "[::1]", "fe80::1%eth0", strings.Repeat("a", 64) + ".com", strings.Repeat("a.", 127) + "a"} {
			body := fmt.Sprintf(`{"role":"server","kind":"certificate","host":%q}`, name)
			if got := call("POST", body, apiKey).Code; got != 400 {
				t.Fatalf("unsafe name accepted: %q (%d)", name, got)
			}
		}
	})
	t.Run("reality and passwords", func(t *testing.T) {
		out := generate(`{"role":"server","kind":"reality"}`)
		private, err := base64.RawURLEncoding.DecodeString(out["private_key"])
		if err != nil {
			t.Fatal(err)
		}
		key, err := ecdh.X25519().NewPrivateKey(private)
		if err != nil {
			t.Fatal(err)
		}
		if len(out) != 3 || base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()) != out["public_key"] {
			t.Fatal("REALITY key pair mismatch")
		}
		other := generate(`{"role":"server","kind":"reality"}`)
		if out["private_key"] == other["private_key"] || out["short_id"] == other["short_id"] {
			t.Fatal("REALITY material reused")
		}
		short := generate(`{"role":"server","kind":"short_id"}`)
		for _, id := range []string{out["short_id"], short["short_id"]} {
			decoded, err := hex.DecodeString(id)
			if err != nil || len(decoded) != 8 {
				t.Fatal("invalid short ID")
			}
		}
		password := generate(`{"role":"server","kind":"hysteria2"}`)
		raw, err := base64.RawURLEncoding.DecodeString(password["password"])
		if err != nil || len(raw) != 32 || len(password) != 1 {
			t.Fatal("invalid password")
		}
		if password["password"] == generate(`{"role":"server","kind":"hysteria2"}`)["password"] {
			t.Fatal("password reused")
		}
	})
	t.Run("vless pairs", func(t *testing.T) {
		for _, mode := range []string{"", "native", "xorpub", "random"} {
			for _, authentication := range []string{"", "x25519", "mlkem768"} {
				out := generate(fmt.Sprintf(`{"role":"server","kind":"vless","mode":%q,"authentication":%q}`, mode, authentication))
				wantMode := mode
				if wantMode == "" {
					wantMode = "native"
				}
				dec, enc := strings.Split(out["decryption"], "."), strings.Split(out["encryption"], ".")
				if len(out) != 2 || len(dec) != 4 || len(enc) != 4 || dec[1] != wantMode || enc[1] != wantMode || dec[2] != "600s" || enc[2] != "0rtt" {
					t.Fatal("invalid VLESS grammar")
				}
				private, err := base64.RawURLEncoding.DecodeString(dec[3])
				if err != nil {
					t.Fatal(err)
				}
				var public []byte
				if authentication == "mlkem768" {
					key, err := mlkem.NewDecapsulationKey768(private)
					if err != nil {
						t.Fatal(err)
					}
					public = key.EncapsulationKey().Bytes()
				} else {
					key, err := ecdh.X25519().NewPrivateKey(private)
					if err != nil {
						t.Fatal(err)
					}
					public = key.PublicKey().Bytes()
				}
				if base64.RawURLEncoding.EncodeToString(public) != enc[3] {
					t.Fatal("VLESS key pair mismatch")
				}
				derived, err := tunnel.DeriveClientTunnel(model.LocalTLS{}, model.LocalTLS{TransportSecurity: "plain", Decryption: out["decryption"]}, model.Node{})
				if err != nil || derived.Encryption != out["encryption"] {
					t.Fatalf("VLESS parser/derivation mismatch: %v", err)
				}
			}
		}
	})
	t.Run("local certificates", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			days int
		}{{"example.com", 0}, {"localhost", 1}, {"127.0.0.1", 365}, {"::1", 30}} {
			extra := ""
			days := tc.days
			if days == 0 {
				days = 30
			} else {
				extra = fmt.Sprintf(`,"ttl_days":%d`, days)
			}
			out := generate(fmt.Sprintf(`{"role":"server","kind":"certificate","host":%q%s}`, tc.name, extra))
			pair, err := tls.X509KeyPair([]byte(out["cert_pem"]), []byte(out["key_pem"]))
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := pair.PrivateKey.(*ecdsa.PrivateKey); !ok {
				t.Fatal("not ECDSA")
			}
			leaf, err := x509.ParseCertificate(pair.Certificate[0])
			if err != nil {
				t.Fatal(err)
			}
			block, rest := pem.Decode([]byte(out["ca_pem"]))
			if len(out) != 4 || block == nil || len(rest) != 0 {
				t.Fatal("invalid CA response")
			}
			ca, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			if !ca.IsCA || leaf.IsCA || bytes.Equal(ca.RawSubjectPublicKeyInfo, leaf.RawSubjectPublicKeyInfo) || ca.CheckSignatureFrom(ca) != nil {
				t.Fatal("invalid local CA")
			}
			roots := x509.NewCertPool()
			roots.AddCert(ca)
			if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: tc.name}); err != nil {
				t.Fatal(err)
			}
			if _, err := leaf.Verify(x509.VerifyOptions{Roots: x509.NewCertPool(), DNSName: tc.name}); err == nil {
				t.Fatal("certificate trusted without local CA")
			}
			if net.ParseIP(tc.name) != nil {
				if len(leaf.IPAddresses) != 1 || len(leaf.DNSNames) != 0 {
					t.Fatal("missing IP SAN")
				}
			} else if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != tc.name {
				t.Fatal("missing DNS SAN")
			}
			expires, err := time.Parse(time.RFC3339, out["expires_at"])
			if err != nil || !expires.Equal(leaf.NotAfter) || !expires.Equal(ca.NotAfter) || time.Until(expires) > time.Duration(days)*24*time.Hour || time.Until(expires) < time.Duration(days)*24*time.Hour-time.Minute {
				t.Fatal("incorrect expiry")
			}
		}
	})
	after := snapshot()
	if len(before) != len(after) {
		t.Fatal("generation changed store files")
	}
	for name, data := range before {
		if after[name] != data {
			t.Fatalf("generation mutated store file %s", name)
		}
	}
	nodes, err := s.Nodes()
	if err != nil || len(nodes) != 0 {
		t.Fatal("generation persisted a node", err)
	}
}
