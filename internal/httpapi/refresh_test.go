package httpapi

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"veilink/internal/auth"
	"veilink/internal/model"
	"veilink/internal/store"
)

func TestNodeRefreshAuthenticationAndStatus(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Open(filepath.Join(dir, "db"), filepath.Join(dir, "key"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = s.InitAdmin("admin", "long test password"); err != nil {
		t.Fatal(err)
	}
	h := New(s, true, nil, nil).(*API)
	version, err := s.AdminVersion()
	if err != nil {
		t.Fatal(err)
	}
	h.sessions[auth.Hash("session")] = session{csrf: "csrf", version: version, expires: time.Now().Add(time.Hour)}
	n, err := s.SaveNode(model.Node{Name: "client", Role: "client"})
	if err != nil {
		t.Fatal(err)
	}
	call := func(body, csrf, origin string, authenticated bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/api/nodes/"+n.ID+"/refresh", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-CSRF-Token", csrf)
		r.Header.Set("Origin", origin)
		if authenticated {
			r.AddCookie(&http.Cookie{Name: "veilink_session", Value: "session"})
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	for _, tc := range []struct {
		body, csrf, origin string
		auth               bool
		code               int
	}{
		{"{}", "csrf", "", false, 401}, {"{}", "", "", true, 403}, {"{}", "csrf", "http://evil.test", true, 403}, {`{"force":true}`, "csrf", "", true, 400}, {"{} {}", "csrf", "", true, 400}, {"{}", "csrf", "", true, 200},
	} {
		if w := call(tc.body, tc.csrf, tc.origin, tc.auth); w.Code != tc.code {
			t.Fatalf("got %d want %d", w.Code, tc.code)
		}
	}
	if w := call("{}", "csrf", "", true); !strings.Contains(w.Body.String(), `"connected":false`) {
		t.Fatal(w.Body)
	}
	updates, stop := s.Subscribe(n.ID)
	defer stop()
	if w := call("{}", "csrf", "", true); w.Code != 200 || !strings.Contains(w.Body.String(), `"connected":true`) {
		t.Fatal(w.Code, w.Body)
	}
	select {
	case <-updates:
	default:
		t.Fatal("no notification")
	}
	got, _, _ := s.FindNodeByName(n.Name)
	if got.LastSeen != 0 || got.AppliedRevision != 0 {
		t.Fatal("refresh fabricated status")
	}
	if err = s.RemoveNode(n.ID, false); err != nil {
		t.Fatal(err)
	}
	if w := call("{}", "csrf", "", true); w.Code != 400 {
		t.Fatal(w.Code)
	}
}
