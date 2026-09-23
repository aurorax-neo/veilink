package console

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMissingConsole(t *testing.T) {
	h := Handler("")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Veilink management API") || !strings.Contains(w.Body.String(), "console html not found") {
		t.Fatalf("%d %q", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/assets/app.js", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("missing asset %d", w.Code)
	}
}

func TestServesHTML(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "assets"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("<!doctype html><title>Veilink</title>"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "assets", "app.js"), []byte("/* X-CSRF-Token */"), 0o644); err != nil {
		t.Fatal(err)
	}
	h := Handler(dir)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Veilink") {
		t.Fatalf("index %d %q", w.Code, w.Body.String())
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("html must not be cached")
	}
	if !strings.Contains(w.Header().Get("Content-Security-Policy"), "script-src 'self'") {
		t.Fatal("missing script policy")
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/assets/app.js", nil))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "X-CSRF-Token") {
		t.Fatalf("asset %d %q", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/assets/", nil))
	if w.Code != http.StatusNotFound {
		t.Fatal("directory listing must be disabled")
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("post %d", w.Code)
	}
}

func TestLocateExplicit(t *testing.T) {
	dir := t.TempDir()
	if Locate(dir) != dir {
		t.Fatal("explicit path was not kept")
	}
	if Locate("") == dir {
		t.Fatal("empty locate must not invent this temp dir")
	}
}
