package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEmbeddedConsole(t *testing.T) {
	h := Handler()
	for _, tc := range []struct{ path, contentType, contains string }{
		{"/", "text/html", "Veilink"},
		{"/static/style.css", "text/css", "prefers-reduced-motion"},
		{"/static/app.js", "javascript", "X-CSRF-Token"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, tc.path, nil))
			if w.Code != http.StatusOK {
				t.Fatalf("status %d", w.Code)
			}
			if !strings.Contains(w.Header().Get("Content-Type"), tc.contentType) {
				t.Fatalf("content type %s", w.Header().Get("Content-Type"))
			}
			if !strings.Contains(w.Body.String(), tc.contains) {
				t.Fatalf("missing %q", tc.contains)
			}
			if tc.path == "/" {
				if w.Header().Get("Cache-Control") != "no-store" {
					t.Fatal("HTML must not be cached")
				}
				if !strings.Contains(w.Header().Get("Content-Security-Policy"), "script-src 'self'") {
					t.Fatal("missing script policy")
				}
			}
		})
	}
}

func TestRoutesAndMethods(t *testing.T) {
	h := Handler()
	for _, tc := range []struct {
		method, path string
		code         int
	}{
		{"GET", "/unknown", 404}, {"POST", "/", 405}, {"GET", "/static/missing.js", 404}, {"HEAD", "/", 200},
	} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(tc.method, tc.path, nil))
		if w.Code != tc.code {
			t.Errorf("%s %s: got %d want %d", tc.method, tc.path, w.Code, tc.code)
		}
		if tc.method == "HEAD" && w.Body.Len() != 0 {
			t.Error("HEAD returned a body")
		}
	}
}
