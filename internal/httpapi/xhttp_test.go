package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"veilink/internal/model"
	"veilink/internal/store"
	"veilink/internal/tunnel"
)

func TestXHTTPJSONAPI(t *testing.T) {
	d := t.TempDir()
	s, err := store.Open(filepath.Join(d, "db"), filepath.Join(d, "key"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = s.InitAdmin("admin", "long test password"); err != nil {
		t.Fatal(err)
	}
	h := New(s, true, nil, nil)
	var cookie *http.Cookie
	csrf := ""
	call := func(body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/api/nodes", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-CSRF-Token", csrf)
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if w := call(`{"role":"server","name":"xhttp"}`); w.Code != 401 {
		t.Fatal(w.Code)
	}
	r := httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"username":"admin","password":"long test password"}`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	cookie = w.Result().Cookies()[0]
	var login map[string]string
	if err = json.Unmarshal(w.Body.Bytes(), &login); err != nil {
		t.Fatal(err)
	}
	dec, _, _, _, err := tunnel.GenerateVLESSEnc()
	if err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf(`{"name":"xhttp","role":"server","address":"cdn.example.com","port":443,"tunnel":{"transport_security":"plain","listen_port":8444,"decryption":%q,"xhttp":{"path":"/cdn/","mode":"packet-up","tls":true}}}`, dec)
	if w = call(body); w.Code != 403 {
		t.Fatal("CSRF bypass", w.Code)
	}
	csrf = login["csrf"]
	for name, bad := range map[string]string{
		"unknown-option":          strings.Replace(body, `"tls":true`, `"tls":true,"host":"override.example"`, 1),
		"unsupported-mode":        strings.Replace(body, "packet-up", "stream-one", 1),
		"wrong-type":              strings.Replace(body, `"tls":true`, `"tls":"true"`, 1),
		"private-client-template": strings.TrimSuffix(body, "}") + `,"client_tunnel":{}}`,
	} {
		t.Run(name, func(t *testing.T) {
			if got := call(bad); got.Code != 400 {
				t.Fatal(got.Code, got.Body.String())
			}
		})
	}
	w = call(body)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var n model.Node
	if err = json.Unmarshal(w.Body.Bytes(), &n); err != nil {
		t.Fatal(err)
	}
	if n.Tunnel.XHTTP.Path != "/cdn/" || n.ClientTunnel == nil || n.ClientTunnel.XHTTP != n.Tunnel.XHTTP || n.ClientTunnel.Decryption != "" || n.ClientTunnel.Encryption == "" {
		t.Fatal("API derivation mismatch")
	}
}
