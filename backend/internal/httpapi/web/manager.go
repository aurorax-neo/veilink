package web

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"veilink/internal/buildinfo"
	"veilink/internal/webui"
)

type WebConfig struct {
	PrebundledDir string
	EmbeddedFS    fs.FS
}

// WebManager serves embedded or explicit directory resources. It never downloads or writes data.
type WebManager struct {
	dir      string
	embedded fs.FS
	root     string
	fsys     fs.FS
}

func NewWebManager(cfg WebConfig) *WebManager {
	embedded := cfg.EmbeddedFS
	if embedded == nil {
		embedded = webui.FS()
	}
	return &WebManager{dir: cfg.PrebundledDir, embedded: embedded}
}

func (m *WebManager) Ensure() (string, error) {
	if m.dir != "" {
		info, err := os.Stat(filepath.Join(m.dir, "index.html"))
		if err != nil {
			return "", fmt.Errorf("bundled web unavailable: %w", err)
		}
		if !info.Mode().IsRegular() || info.Size() == 0 {
			return "", fmt.Errorf("bundled web index.html must be a nonempty regular file")
		}
		m.root = m.dir
		m.fsys = os.DirFS(m.dir)
		return m.root, nil
	}
	if m.embedded == nil {
		return "", fmt.Errorf("embedded web unavailable")
	}
	info, err := fs.Stat(m.embedded, "index.html")
	if err != nil {
		return "", fmt.Errorf("embedded web unavailable: %w", err)
	}
	if info.IsDir() || info.Size() == 0 {
		return "", fmt.Errorf("embedded web index.html must be a nonempty regular file")
	}
	m.root = "embedded"
	m.fsys = m.embedded
	return m.root, nil
}

type WebStatus struct {
	Mode       string `json:"mode"`
	ActiveVer  string `json:"active_version"`
	Serving    bool   `json:"serving"`
	Prebundled bool   `json:"prebundled"`
}

func (m *WebManager) Status() WebStatus {
	return WebStatus{Mode: "builtin", ActiveVer: m.Version(), Serving: m.fsys != nil, Prebundled: true}
}
func (m *WebManager) Root() string    { return m.root }
func (m *WebManager) FS() fs.FS       { return m.fsys }
func (m *WebManager) Version() string { return buildinfo.Version }
