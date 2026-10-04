package httpapi

import (
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"veilink/internal/httpapi/backend"
	"veilink/internal/model"
	"veilink/internal/store"
	"veilink/internal/tunnel"
)

func TestMappingStatusRouteRequiresKeyAndOnlyGET(t *testing.T) {
	d := t.TempDir()
	s, err := store.Open(filepath.Join(d, "db"), filepath.Join(d, "key"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	h := New(s, true, nil, WebPersistConfig{})
	apiKey, err := h.(*API).keyStore.Create("test", backend.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	request := func(method, path, key string) *httptest.ResponseRecorder {
		t.Helper()
		return testCall(h, key, method, path, "")
	}
	if w := request("GET", "/api/v1/mappings/status", ""); w.Code != 401 {
		t.Fatal(w.Code)
	}
	if got := request("GET", "/api/v1/mappings/status", apiKey); got.Code != 200 || got.Header().Get("Cache-Control") != "no-store" || !json.Valid(got.Body.Bytes()) || strings.TrimSpace(got.Body.String()) != "{}" {
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
	got := request("GET", "/api/v1/mappings/status", apiKey)
	var statuses map[string]store.MappingStatus
	if got.Code != 200 || json.Unmarshal(got.Body.Bytes(), &statuses) != nil || len(statuses) != 1 || statuses[m.ID].Server.Reason != "unknown" || statuses[m.ID].Client.Reason != "unknown" {
		t.Fatal(got.Code, got.Body.String())
	}
	if strings.Contains(got.Body.String(), dec) || strings.Contains(got.Body.String(), m.BindingID) {
		t.Fatal("status disclosed private policy")
	}
	for _, path := range []string{"/api/v1/mappings/status/other", "/api/v1/mappings/status?x=1"} {
		got := request("POST", path, apiKey)
		if got.Code != 404 {
			t.Fatal("unexpected status", got.Code)
		}
	}
	if got := request("GET", "/api/v1/mappings/status/other", apiKey); got.Code != 404 {
		t.Fatal(got.Code)
	}
	if got := request("GET", "/api/v1/mappings/status/", apiKey); got.Code != 404 {
		t.Fatal(got.Code)
	}
	if got := request("GET", "/api/v1/mappings/status?unexpected=1", apiKey); got.Code != 404 {
		t.Fatal(got.Code)
	}
	if got := request("POST", "/api/v1/mappings/status", apiKey); got.Code != 404 {
		t.Fatal(got.Code)
	}
	// PUT 同样不被允许
	if denied := request("PUT", "/api/v1/mappings/status", apiKey); denied.Code != 404 {
		t.Fatal(denied.Code)
	}
}
