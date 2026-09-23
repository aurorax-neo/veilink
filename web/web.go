// Package web serves the embedded, dependency-free management console.
package web

import (
	"embed"
	"html/template"
	"io/fs"
	"net/http"
)

//go:embed templates/*.html static/*
var assets embed.FS

// Handler serves the console at / and embedded assets under /static/.
func Handler() http.Handler {
	page := template.Must(template.ParseFS(assets, "templates/index.html"))
	static, err := fs.Sub(assets, "static")
	if err != nil {
		panic(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(static))))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
		if r.Method == http.MethodHead {
			return
		}
		_ = page.ExecuteTemplate(w, "index.html", nil)
	})
	return mux
}
