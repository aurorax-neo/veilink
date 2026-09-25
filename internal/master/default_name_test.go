package master

import (
	"path/filepath"
	"testing"
	"veilink/internal/config"
	"veilink/internal/store"
)

func TestEmbeddedDefaultNamePreservesIdentity(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Open(filepath.Join(dir, "db"), filepath.Join(dir, "key"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	c := config.Defaults()
	n, err := embeddedNode(c, s)
	if err != nil {
		t.Fatal(err)
	}
	if n.Name != "default" || !n.Embedded {
		t.Fatalf("unexpected default: %+v", n)
	}
	n.Name = "custom gateway"
	n, err = s.SaveNode(n)
	if err != nil {
		t.Fatal(err)
	}
	again, err := embeddedNode(c, s)
	if err != nil {
		t.Fatal(err)
	}
	if again.ID != n.ID || again.Name != n.Name || !again.Embedded {
		t.Fatal("existing identity/name changed")
	}
}
