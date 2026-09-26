package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"veilink/internal/store"
	"veilink/internal/tunnel"
)

func TestSessionCSRFAndLimits(t *testing.T) {
	d := t.TempDir()
	s, e := store.Open(filepath.Join(d, "db"), filepath.Join(d, "key"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if e = s.InitAdmin("admin", "long test password"); e != nil {
		t.Fatal(e)
	}
	h := New(s, false, nil, nil)
	call := func(method, path, body, csrf string, cookie *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-CSRF-Token", csrf)
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if w := call("GET", "/api/nodes", "", "", nil); w.Code != 401 {
		t.Fatal(w.Code)
	}
	w := call("POST", "/api/login", `{"username":"admin","password":"long test password"}`, "", nil)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	cookie := w.Result().Cookies()[0]
	if !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatal("unsafe cookie")
	}
	var out map[string]string
	json.Unmarshal(w.Body.Bytes(), &out)
	csrf := out["csrf"]
	if w = call("POST", "/api/nodes", `{"name":"private","role":"client"}`, "", cookie); w.Code != 403 {
		t.Fatal("CSRF accepted", w.Code)
	}
	if w = call("POST", "/api/nodes", `{"name":"private","role":"client"}`, csrf, cookie); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w = call("GET", "/api/nodes", "", "", cookie); w.Code != 200 || !strings.Contains(w.Body.String(), "private") {
		t.Fatal(w.Code)
	}
	if w = call("POST", "/api/nodes", strings.Repeat("x", 600000), csrf, cookie); w.Code != 400 {
		t.Fatal("oversize accepted")
	}
	for _, legacy := range []string{`"cert_file":"/old/cert"`, `"key_file":"/old/key"`, `"ca_file":"/old/ca"`, `"pool":8`} {
		body := `{"name":"legacy","role":"client","tunnel":{` + legacy + `}}`
		if w = call("POST", "/api/nodes", body, csrf, cookie); w.Code != http.StatusBadRequest {
			t.Fatalf("legacy tunnel key accepted: %s (%d)", legacy, w.Code)
		}
	}
	for _, invalid := range []string{`"cert_pem":"/old/cert","key_pem":"/old/key"`, `"ca_pem":"invalid"`, `"key_pem":"private"`} {
		body := `{"name":"invalid","role":"client","tunnel":{` + invalid + `}}`
		if w = call("POST", "/api/nodes", body, csrf, cookie); w.Code != http.StatusBadRequest {
			t.Fatalf("invalid PEM accepted: %s (%d)", invalid, w.Code)
		}
	}
	for _, legacy := range []string{
		`"server_name":"example.com"`,
		`"connect_endpoints":[{"server_name":"example.com"}]`,
		`"connect_endpoints":[{"priority":0}]`,
	} {
		body := `{"name":"legacy","role":"client",` + legacy + `}`
		if got := call("POST", "/api/nodes", body, csrf, cookie); got.Code != http.StatusBadRequest {
			t.Fatalf("obsolete node JSON accepted: %s (%d)", legacy, got.Code)
		}
	}
	dec, _, _, _, err := tunnel.GenerateVLESSEnc()
	if err != nil {
		t.Fatal(err)
	}
	w = call("POST", "/api/nodes", fmt.Sprintf(`{"name":"gateway","role":"server","address":"localhost","port":443,"tunnel":{"listen_port":8444,"transport_security":"plain","decryption":%q}}`, dec), csrf, cookie)
	if w.Code != http.StatusOK {
		t.Fatal(w.Code, w.Body.String())
	}
	var server struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &server); err != nil {
		t.Fatal(err)
	}
	nodes, err := s.Nodes()
	if err != nil {
		t.Fatal(err)
	}
	var clientID string
	for _, n := range nodes {
		if n.Name == "private" {
			clientID = n.ID
		}
	}
	base := fmt.Sprintf(`"name":"direct","server_id":%q,"client_id":%q,"listen_host":"0.0.0.0","listen_port":8080,"target_host":"localhost","target_port":80,"enabled":true`, server.ID, clientID)
	for _, extra := range []string{``, `,"pool":0`, `,"pool":33`, `,"pool":1,"binding_id":"legacy"`} {
		if w = call("POST", "/api/mappings", `{`+base+extra+`}`, csrf, cookie); w.Code != http.StatusBadRequest {
			t.Fatalf("invalid mapping accepted: %s (%d)", extra, w.Code)
		}
	}
	if w = call("POST", "/api/mappings", `{`+base+`,"pool":32}`, csrf, cookie); w.Code != http.StatusOK {
		t.Fatal(w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "binding_id") {
		t.Fatal("internal binding exposed")
	}
	var saved struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &saved); err != nil {
		t.Fatal(err)
	}
	if update := call("PUT", "/api/mappings/"+saved.ID, w.Body.String(), csrf, cookie); update.Code != 200 {
		t.Fatal("mapping round trip failed", update.Body.String())
	}
	rows, err := s.Mappings()
	if err != nil || len(rows) != 1 || rows[0].ServerID != server.ID || rows[0].ClientID != clientID || rows[0].Pool != 32 {
		t.Fatal("direct mapping not persisted", err)
	}
	if w = call("POST", "/api/logout", "", csrf, cookie); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if w = call("GET", "/api/nodes", "", "", cookie); w.Code != 401 {
		t.Fatal("logout retained session")
	}
}
