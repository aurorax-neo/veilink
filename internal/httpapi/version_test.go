package httpapi

import (
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"veilink/internal/httpapi/backend"
	"veilink/internal/model"
	"veilink/internal/store"
)

func TestVersionAndReportedNodeAPI(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Open(filepath.Join(dir, "db"), filepath.Join(dir, "key"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.InitAdmin("admin", "long test password"); err != nil {
		t.Fatal(err)
	}
	h := New(s, true, nil, WebPersistConfig{})
	apiKey, err := h.(*API).keyStore.Create("test", backend.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	call := func(method, path, body string) *httptest.ResponseRecorder {
		return testCall(h, apiKey, method, path, body)
	}
	// /api/version 是公开路径，无需认证
	w := testCall(h, "", "GET", "/api/version", "")
	var info map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &info); err != nil || w.Code != 200 {
		t.Fatalf("version: %d %s %v", w.Code, w.Body, err)
	}
	if info["api_version"] != "v1" {
		t.Fatalf("api_version mismatch: %v", info)
	}
	for _, k := range []string{"api_version", "backend_version", "web_version", "web_mode"} {
		if _, ok := info[k]; !ok {
			t.Fatalf("version missing field %s: %v", k, info)
		}
	}
	n, err := s.SaveNode(model.Node{Name: "client", Role: "client"})
	if err != nil {
		t.Fatal(err)
	}
	w = call("GET", "/api/v1/nodes", "")
	if w.Code != 200 || strings.Contains(w.Body.String(), "software_") {
		t.Fatalf("unreported: %d %s", w.Code, w.Body)
	}
	for _, method := range []string{"POST", "PUT"} {
		path := "/api/v1/nodes"
		if method == "PUT" {
			path += "/" + n.ID
		}
		for _, field := range []string{"software_version", "software_commit", "SOFTWARE_VERSION", "SOFTWARE_COMMIT"} {
			for _, value := range []string{`null`, `"forged"`} {
				w = call(method, path, `{"name":"client","role":"client","`+field+`":`+value+`}`)
				if w.Code != 400 {
					t.Fatalf("accepted %s %s: %d %s", method, field, w.Code, w.Body)
				}
			}
		}
	}
	token, err := s.EnrollToken(n.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := s.Enroll(n.ID, token)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.HeartbeatSoftware(n.ID, credential, 0, false, store.SoftwareReport{SoftwareVersion: "v9.8.7", SoftwareCommit: "abc123"}); err != nil {
		t.Fatal(err)
	}
	w = call("GET", "/api/v1/nodes", "")
	var nodes []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &nodes); err != nil || w.Code != 200 || len(nodes) != 1 {
		t.Fatalf("nodes: %d %s %v", w.Code, w.Body, err)
	}
	if nodes[0]["software_version"] != "v9.8.7" || nodes[0]["software_commit"] != "abc123" {
		t.Fatal(nodes)
	}
}
