// Package console serves the built management HTML next to the veilink binary.
package console

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// Locate finds the directory that contains index.html.
// An explicit path wins. Otherwise it checks ./html, then html beside the
// executable, then html next to the executable's parent (bin/veilink + ../html).
func Locate(explicit string) string {
	if explicit != "" {
		return explicit
	}
	candidates := []string{"html"}
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		candidates = append(candidates, filepath.Join(dir, "html"), filepath.Join(dir, "..", "html"))
	}
	for _, dir := range candidates {
		info, err := os.Stat(filepath.Join(dir, "index.html"))
		if err == nil && !info.IsDir() {
			return dir
		}
	}
	return ""
}

// Handler serves dir over HTTP. A missing directory still answers GET / so the
// API port stays usable, and tells the operator the console files are absent.
func Handler(dir string) http.Handler {
	if dir == "" {
		return missing()
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return missing()
	}
	files := http.FileServerFS(root.FS())
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.URL.Path != "/" && strings.HasSuffix(r.URL.Path, "/") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
		if r.URL.Path == "/" || strings.HasSuffix(r.URL.Path, ".html") {
			w.Header().Set("Cache-Control", "no-store")
		} else if strings.HasPrefix(r.URL.Path, "/assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		}
		files.ServeHTTP(w, r)
	})
}

func missing() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		if r.Method == http.MethodHead {
			return
		}
		_, _ = w.Write([]byte("Veilink management API\nconsole html not found\n"))
	})
}
