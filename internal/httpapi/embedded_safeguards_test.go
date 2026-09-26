package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"veilink/internal/auth"
	"veilink/internal/model"
	"veilink/internal/store"
)

func TestEmbeddedAPISafeguards(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Open(filepath.Join(dir, "db"), filepath.Join(dir, "key"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	n, err := s.EnsureEmbeddedNode(model.Node{Name: "embedded", Role: "server", Address: "localhost", Port: 8444})
	if err != nil {
		t.Fatal(err)
	}
	ordinary, err := s.SaveNode(model.Node{Name: "ordinary", Role: "client"})
	if err != nil {
		t.Fatal(err)
	}
	h := New(s, true, nil, nil).(*API)
	if err := s.InitAdmin("admin", "long test password"); err != nil {
		t.Fatal(err)
	}
	version, err := s.AdminVersion()
	if err != nil {
		t.Fatal(err)
	}
	h.sessions[auth.Hash("session")] = session{csrf: "csrf", version: version, expires: time.Now().Add(time.Hour)}
	call := func(method, path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-CSRF-Token", "csrf")
		r.AddCookie(&http.Cookie{Name: "veilink_session", Value: "session"})
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	token, err := s.EnrollToken(n.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := s.Enroll(n.ID, token)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ method, path, body string }{
		{"POST", "/api/nodes/" + n.ID + "/join", `{"master_url":"http://localhost:8443"}`},
		{"POST", "/api/nodes/" + n.ID + "/enroll", `{}`},
		{"DELETE", "/api/nodes/" + n.ID + "/enroll", ""},
		{"POST", "/api/nodes/" + n.ID + "/revoke", ""},
		{"DELETE", "/api/nodes/" + n.ID, ""},
		{"POST", "/api/nodes", `{"name":"spoof","role":"client","embedded":true}`},
		{"PUT", "/api/nodes/" + ordinary.ID, `{"name":"ordinary","role":"client","embedded":true}`},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			pending, err := s.EnrollToken(n.ID, time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			before, err := s.Snapshot(n.ID, credential)
			if err != nil {
				t.Fatal(err)
			}
			if w := call(tc.method, tc.path, tc.body); w.Code != 400 {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
			after, err := s.Snapshot(n.ID, credential)
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatal("forbidden operation changed node/credential", err)
			}
			credential, err = s.Enroll(n.ID, pending)
			if err != nil {
				t.Fatal("forbidden operation changed pending token", err)
			}
		})
	}
	// Master can still issue and revoke its own pending enrollment.
	pending, err := s.EnrollToken(n.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeEnrollToken(n.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Enroll(n.ID, pending); err == nil {
		t.Fatal("internal revoke failed")
	}
	if _, err := s.Snapshot(n.ID, credential); err != nil {
		t.Fatal(err)
	}
	for _, flag := range []bool{true, false} {
		n.Embedded = flag
		body, err := json.Marshal(n)
		if err != nil {
			t.Fatal(err)
		}
		w := call("PUT", "/api/nodes/"+n.ID, string(body))
		var saved model.Node
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &saved) != nil || !saved.Embedded {
			t.Fatal("embedded roundtrip/omission failed", w.Body.String())
		}
	}
	for _, suffix := range []string{"/join", "/enroll"} {
		body := `{"master_url":"https://localhost:8443"}`
		if suffix == "/enroll" {
			body = `{}`
		}
		w := call("POST", "/api/nodes/"+ordinary.ID+suffix, body)
		if w.Code != 200 {
			t.Fatal("ordinary enrollment blocked", w.Body.String())
		}
	}
	for _, tc := range []struct{ method, suffix string }{{"DELETE", "/enroll"}, {"POST", "/revoke"}, {"DELETE", ""}} {
		if w := call(tc.method, "/api/nodes/"+ordinary.ID+tc.suffix, ""); w.Code != 200 {
			t.Fatal("ordinary operation blocked", w.Body.String())
		}
	}
}
