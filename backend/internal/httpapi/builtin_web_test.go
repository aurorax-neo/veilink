package httpapi

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"veilink/internal/httpapi/backend"
	"veilink/internal/store"
)

func TestBuiltinWebAndRemovedUpdateAPI(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Open(filepath.Join(dir, "db"), filepath.Join(dir, "key"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("<html>bundled</html>"), 0600); err != nil {
		t.Fatal(err)
	}
	h := New(s, true, nil, WebPersistConfig{HTMLDir: dir})
	key, err := h.(*API).keyStore.Create("test", backend.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	for path, code := range map[string]int{"/": 200, "/settings": 200, "/assets/gone.js": 404, "/missing.css": 404} {
		w := testCall(h, "", "GET", path, "")
		if w.Code != code || w.Header().Get("Cache-Control") != "no-cache" {
			t.Fatalf("%s: %d %s", path, w.Code, w.Header())
		}
	}
	for _, path := range []string{"/api/v1/web/update", "/api/v1/web/probe", "/api/v1/web/config"} {
		w := testCall(h, key, "POST", path, `{}`)
		if w.Code != 404 {
			t.Fatalf("removed endpoint %s: %d", path, w.Code)
		}
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Origin", "https://example.invalid")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("cross-origin frontend enabled")
	}
	missing := New(s, true, nil, WebPersistConfig{HTMLDir: filepath.Join(dir, "missing")})
	if w := testCall(missing, "", "GET", "/", ""); w.Code != 503 {
		t.Fatalf("missing web: %d", w.Code)
	}
}
