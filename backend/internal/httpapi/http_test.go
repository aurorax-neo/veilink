package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"veilink/internal/httpapi/backend"
	"veilink/internal/store"
	"veilink/internal/tunnel"
)

func TestAPIKeyAuthAndLimits(t *testing.T) {
	d := t.TempDir()
	s, e := store.Open(filepath.Join(d, "db"), filepath.Join(d, "key"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	h := New(s, false, nil, WebPersistConfig{})
	apiKey, e := h.(*API).keyStore.Create("test", backend.RoleAdmin)
	if e != nil {
		t.Fatal(e)
	}
	call := func(method, path, body, key string) *httptest.ResponseRecorder {
		return testCall(h, key, method, path, body)
	}
	// 未认证
	if w := call("GET", "/api/v1/nodes", "", ""); w.Code != 401 {
		t.Fatal(w.Code)
	}
	if w := call("GET", "/api/v1/nodes", "", "vlk_invalid"); w.Code != 401 {
		t.Fatal("invalid key accepted", w.Code)
	}
	// 正常请求
	if w := call("POST", "/api/v1/nodes", `{"name":"private","role":"client"}`, apiKey); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := call("GET", "/api/v1/nodes", "", apiKey); w.Code != 200 || !strings.Contains(w.Body.String(), "private") {
		t.Fatal(w.Code)
	}
	// 超大请求体
	if w := call("POST", "/api/v1/nodes", strings.Repeat("x", 600000), apiKey); w.Code != 400 {
		t.Fatal("oversize accepted")
	}
	var w *httptest.ResponseRecorder
	for _, legacy := range []string{`"cert_file":"/old/cert"`, `"key_file":"/old/key"`, `"ca_file":"/old/ca"`, `"pool":8`} {
		body := `{"name":"legacy","role":"client","tunnel":{` + legacy + `}}`
		if w = call("POST", "/api/v1/nodes", body, apiKey); w.Code != 400 {
			t.Fatalf("legacy tunnel key accepted: %s (%d)", legacy, w.Code)
		}
	}
	for _, invalid := range []string{`"cert_pem":"/old/cert","key_pem":"/old/key"`, `"ca_pem":"invalid"`, `"key_pem":"private"`} {
		body := `{"name":"invalid","role":"client","tunnel":{` + invalid + `}}`
		if w = call("POST", "/api/v1/nodes", body, apiKey); w.Code != http.StatusBadRequest {
			t.Fatalf("invalid PEM accepted: %s (%d)", invalid, w.Code)
		}
	}
	for _, legacy := range []string{
		`"server_name":"example.com"`,
		`"connect_endpoints":[{"server_name":"example.com"}]`,
		`"connect_endpoints":[{"priority":0}]`,
	} {
		body := `{"name":"legacy","role":"client",` + legacy + `}`
		if got := call("POST", "/api/v1/nodes", body, apiKey); got.Code != http.StatusBadRequest {
			t.Fatalf("obsolete node JSON accepted: %s (%d)", legacy, got.Code)
		}
	}
	dec, _, _, _, err := tunnel.GenerateVLESSEnc()
	if err != nil {
		t.Fatal(err)
	}
	w = call("POST", "/api/v1/nodes", fmt.Sprintf(`{"name":"gateway","role":"server","address":"localhost","port":443,"tunnel":{"listen_port":8444,"transport_security":"plain","decryption":%q}}`, dec), apiKey)
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
		if w = call("POST", "/api/v1/mappings", `{`+base+extra+`}`, apiKey); w.Code != http.StatusBadRequest {
			t.Fatalf("invalid mapping accepted: %s (%d)", extra, w.Code)
		}
	}
	if w = call("POST", "/api/v1/mappings", `{`+base+`,"pool":32}`, apiKey); w.Code != http.StatusOK {
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
	if update := call("PUT", "/api/v1/mappings/"+saved.ID, w.Body.String(), apiKey); update.Code != 200 {
		t.Fatal("mapping round trip failed", update.Body.String())
	}
	rows, err := s.Mappings()
	if err != nil || len(rows) != 1 || rows[0].ServerID != server.ID || rows[0].ClientID != clientID || rows[0].Pool != 32 {
		t.Fatal("direct mapping not persisted", err)
	}
	// 吊销 key 后应被拒绝
	keys, err := h.(*API).keyStore.List()
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range keys {
		if k.Name == "test" {
			if err := h.(*API).keyStore.Revoke(k.ID); err != nil {
				t.Fatal(err)
			}
		}
	}
	if w = call("GET", "/api/v1/nodes", "", apiKey); w.Code != 401 {
		t.Fatal("revoked key retained access")
	}
}
