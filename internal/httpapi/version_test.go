package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"veilink/internal/auth"
	"veilink/internal/buildinfo"
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
	h := New(s, true, nil, nil).(*API)
	v, err := s.AdminVersion()
	if err != nil {
		t.Fatal(err)
	}
	h.sessions[auth.Hash("session")] = session{csrf: "csrf", version: v, expires: time.Now().Add(time.Hour)}
	call := func(method, path, body string, authenticated bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-CSRF-Token", "csrf")
		if authenticated {
			r.AddCookie(&http.Cookie{Name: "veilink_session", Value: "session"})
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if w := call("GET", "/api/version", "", false); w.Code != 401 {
		t.Fatal(w.Code)
	}
	w := call("GET", "/api/version", "", true)
	var info map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &info); err != nil || w.Code != 200 || info["version"] != buildinfo.Version || info["commit"] != buildinfo.Commit || len(info) != 2 {
		t.Fatalf("version: %d %s %v", w.Code, w.Body, err)
	}
	n, err := s.SaveNode(model.Node{Name: "client", Role: "client"})
	if err != nil {
		t.Fatal(err)
	}
	w = call("GET", "/api/nodes", "", true)
	if w.Code != 200 || strings.Contains(w.Body.String(), "software_") {
		t.Fatalf("unreported: %d %s", w.Code, w.Body)
	}
	for _, method := range []string{"POST", "PUT"} {
		path := "/api/nodes"
		if method == "PUT" {
			path += "/" + n.ID
		}
		for _, field := range []string{"software_version", "software_commit", "SOFTWARE_VERSION", "SOFTWARE_COMMIT"} {
			for _, value := range []string{`null`, `"forged"`} {
				w = call(method, path, `{"name":"client","role":"client","`+field+`":`+value+`}`, true)
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
	w = call("GET", "/api/nodes", "", true)
	var nodes []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &nodes); err != nil || w.Code != 200 || len(nodes) != 1 {
		t.Fatalf("nodes: %d %s %v", w.Code, w.Body, err)
	}
	if nodes[0]["software_version"] != "v9.8.7" || nodes[0]["software_commit"] != "abc123" {
		t.Fatal(nodes)
	}
}
