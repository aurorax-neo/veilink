package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"veilink/internal/model"
	"veilink/internal/store"
	"veilink/internal/tunnel"
)

func TestMappingStatusRouteRequiresSessionAndOnlyGET(t *testing.T) {
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
	request := func(method, path string, cookie *http.Cookie) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, path, nil)
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if w := request("GET", "/api/mappings/status", nil); w.Code != 401 {
		t.Fatal(w.Code)
	}
	login := httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"username":"admin","password":"long test password"}`))
	login.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, login)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	cookie := w.Result().Cookies()[0]
	if got := request("GET", "/api/mappings/status", cookie); got.Code != 200 || got.Header().Get("Cache-Control") != "no-store" || !json.Valid(got.Body.Bytes()) || strings.TrimSpace(got.Body.String()) != "{}" {
		t.Fatal(got.Code, got.Body.String())
	}
	dec, _, _, _, err := tunnel.GenerateVLESSEnc()
	if err != nil {
		t.Fatal(err)
	}
	server, err := s.SaveNode(model.Node{Name: "gateway", Role: "server", Address: "localhost", Port: 443, Tunnel: model.LocalTLS{TransportSecurity: "plain", Decryption: dec, ListenPort: 8444}})
	if err != nil {
		t.Fatal(err)
	}
	client, err := s.SaveNode(model.Node{Name: "client", Role: "client"})
	if err != nil {
		t.Fatal(err)
	}
	m, err := s.SaveMapping(model.Mapping{Name: "route", ServerID: server.ID, ClientID: client.ID, ListenHost: "0.0.0.0", ListenPort: 18080, TargetHost: "localhost", TargetPort: 80, Pool: 1, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	got := request("GET", "/api/mappings/status", cookie)
	var statuses map[string]store.MappingStatus
	if got.Code != 200 || json.Unmarshal(got.Body.Bytes(), &statuses) != nil || len(statuses) != 1 || statuses[m.ID].Server.Reason != "unknown" || statuses[m.ID].Client.Reason != "unknown" {
		t.Fatal(got.Code, got.Body.String())
	}
	if strings.Contains(got.Body.String(), dec) || strings.Contains(got.Body.String(), m.BindingID) {
		t.Fatal("status disclosed private policy")
	}
	for _, path := range []string{"/api/mappings/status/other", "/api/mappings/status?x=1"} {
		got := request("POST", path, cookie)
		if got.Code != 403 {
			t.Fatal("missing CSRF", got.Code)
		}
	}
	if got := request("GET", "/api/mappings/status/other", cookie); got.Code != 404 {
		t.Fatal(got.Code)
	}
	if got := request("GET", "/api/mappings/status/", cookie); got.Code != 404 {
		t.Fatal(got.Code)
	}
	if got := request("GET", "/api/mappings/status?unexpected=1", cookie); got.Code != 404 {
		t.Fatal(got.Code)
	}
	if got := request("POST", "/api/mappings/status", cookie); got.Code != 403 {
		t.Fatal(got.Code)
	}
	var session map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &session); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("PUT", "/api/mappings/status", strings.NewReader(`{}`))
	r.AddCookie(cookie)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", session["csrf"])
	denied := httptest.NewRecorder()
	h.ServeHTTP(denied, r)
	if denied.Code != 404 {
		t.Fatal(denied.Code)
	}
}
