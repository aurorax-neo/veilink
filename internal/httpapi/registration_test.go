package httpapi

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"veilink/internal/store"
)

func TestRegistrationAndExternalReset(t *testing.T) {
	dir := t.TempDir()
	db, key := filepath.Join(dir, "db"), filepath.Join(dir, "key")
	s, err := store.Open(db, key)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	h := New(s, true, nil, nil)
	call := func(method, path, body, origin string, cookie *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", origin)
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	credentials := `{"username":"admin","password":"long test password"}`
	if w := call("GET", "/api/setup", "", "", nil); w.Code != 200 || !strings.Contains(w.Body.String(), `true`) {
		t.Fatal(w)
	}
	if w := call("POST", "/api/login", credentials, "", nil); w.Code != 401 {
		t.Fatal(w)
	}
	if w := call("GET", "/api/nodes", "", "", nil); w.Code != 401 {
		t.Fatal(w)
	}
	if w := call("POST", "/api/register", credentials, "https://evil.example", nil); w.Code != 403 {
		t.Fatal(w)
	}
	if w := call("POST", "/api/register", `{"username":"admin","password":"short"}`, "", nil); w.Code != 400 {
		t.Fatal(w)
	}
	if w := call("POST", "/api/register", credentials, "", nil); w.Code != 201 || strings.Contains(w.Body.String(), "password") {
		t.Fatal(w)
	}
	if w := call("POST", "/api/register", credentials, "", nil); w.Code != 409 {
		t.Fatal(w)
	}
	if w := call("GET", "/api/setup", "", "", nil); w.Code != 200 || !strings.Contains(w.Body.String(), `false`) {
		t.Fatal(w)
	}
	w := call("POST", "/api/login", credentials, "", nil)
	if w.Code != 200 {
		t.Fatal(w)
	}
	cookie := w.Result().Cookies()[0]
	if w := call("GET", "/api/session", "", "", cookie); w.Code != 200 {
		t.Fatal(w)
	}
	other, err := store.OpenExisting(db, key)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	// Do not touch the API between renames: its original session must remain
	// present so this detects version revival, not incidental session eviction.
	for _, name := range []string{"renamed", "admin"} {
		if err = other.ResetAdminUsername(name); err != nil {
			t.Fatal(err)
		}
	}
	if w := call("GET", "/api/session", "", "", cookie); w.Code != 401 {
		t.Fatal("A->B->A revived the original cookie", w)
	}
	w = call("POST", "/api/login", credentials, "", nil)
	if w.Code != 200 {
		t.Fatal("original credentials no longer work after rename round trip", w)
	}
	cookie = w.Result().Cookies()[0]
	if err = other.ResetAdminUsername("renamed"); err != nil {
		t.Fatal(err)
	}
	if w := call("GET", "/api/session", "", "", cookie); w.Code != 401 {
		t.Fatal("old session survived", w)
	}
	w = call("POST", "/api/login", `{"username":"renamed","password":"long test password"}`, "", nil)
	if w.Code != 200 {
		t.Fatal("renamed login failed", w)
	}
	cookie = w.Result().Cookies()[0]
	if w := call("GET", "/api/session", "", "", cookie); w.Code != 200 {
		t.Fatal(w)
	}
	if err = other.ResetAdminPassword("replacement password"); err != nil {
		t.Fatal(err)
	}
	if w := call("GET", "/api/session", "", "", cookie); w.Code != 401 {
		t.Fatal("old session survived password reset", w)
	}
	if w := call("POST", "/api/login", `{"username":"renamed","password":"replacement password"}`, "", nil); w.Code != 200 {
		t.Fatal("password reset login failed", w)
	}
	s.Close()
	if w := call("GET", "/api/setup", "", "", nil); w.Code != 503 || strings.Contains(w.Body.String(), "registration_required") {
		t.Fatal("not fail closed", w)
	}
}
