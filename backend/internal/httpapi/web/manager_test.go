package web

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBuiltinWebOnly(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("WEB_MODE", "pull")
	t.Setenv("WEB_FRONTEND_URL", "https://example.invalid")
	m := NewWebManager(WebConfig{PrebundledDir: dir})
	if _, err := m.Ensure(); err == nil {
		t.Fatal("missing bundled index accepted")
	}
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("<html>builtin</html>"), 0600); err != nil {
		t.Fatal(err)
	}
	root, err := m.Ensure()
	if err != nil || root != dir {
		t.Fatalf("root: %q %v", root, err)
	}
	status := m.Status()
	if status.Mode != "builtin" || !status.Serving || !status.Prebundled {
		t.Fatal(status)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("wrote runtime assets: %v %v", entries, err)
	}
	def := NewWebManager(WebConfig{})
	defRoot, err := def.Ensure()
	if err != nil || defRoot != "embedded" || def.FS() == nil {
		t.Fatalf("default embedded web failed: root=%q err=%v", defRoot, err)
	}
	if !def.Status().Serving {
		t.Fatal("expected default embedded web manager to be serving")
	}
}
