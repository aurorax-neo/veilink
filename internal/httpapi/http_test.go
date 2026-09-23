package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"veilink/internal/store"
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
	h := New(s, false, nil)
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
	if w = call("POST", "/api/nodes", strings.Repeat("x", 70000), csrf, cookie); w.Code != 400 {
		t.Fatal("oversize accepted")
	}
	if w = call("POST", "/api/logout", "", csrf, cookie); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if w = call("GET", "/api/nodes", "", "", cookie); w.Code != 401 {
		t.Fatal("logout retained session")
	}
}
