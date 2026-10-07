package web

import (
	"fmt"
	"os"
	"path/filepath"

	"veilink/internal/buildinfo"
)

const BundledDir = "/opt/veilink-web"

type WebConfig struct{ PrebundledDir string }

// WebManager serves immutable image resources. It never downloads or writes data.
type WebManager struct{ dir, root string }

func NewWebManager(cfg WebConfig) *WebManager {
	dir := cfg.PrebundledDir
	if dir == "" {
		dir = BundledDir
	}
	return &WebManager{dir: dir}
}

func (m *WebManager) Ensure() (string, error) {
	info, err := os.Stat(filepath.Join(m.dir, "index.html"))
	if err != nil {
		return "", fmt.Errorf("bundled web unavailable: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() == 0 {
		return "", fmt.Errorf("bundled web index.html must be a nonempty regular file")
	}
	m.root = m.dir
	return m.root, nil
}

type WebStatus struct {
	Mode       string `json:"mode"`
	ActiveVer  string `json:"active_version"`
	Serving    bool   `json:"serving"`
	Prebundled bool   `json:"prebundled"`
}

func (m *WebManager) Status() WebStatus {
	return WebStatus{Mode: "builtin", ActiveVer: m.Version(), Serving: m.root != "", Prebundled: true}
}
func (m *WebManager) Root() string    { return m.root }
func (m *WebManager) Version() string { return buildinfo.Version }
