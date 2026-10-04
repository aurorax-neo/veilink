package httpapi

import (
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"veilink/internal/httpapi/backend"
	"veilink/internal/model"
	"veilink/internal/store"
)

func TestNodeRefreshAuthenticationAndStatus(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Open(filepath.Join(dir, "db"), filepath.Join(dir, "key"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = s.InitAdmin("admin", "long test password"); err != nil {
		t.Fatal(err)
	}
	h := New(s, true, nil, WebPersistConfig{})
	apiKey, err := h.(*API).keyStore.Create("test", backend.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	n, err := s.SaveNode(model.Node{Name: "client", Role: "client"})
	if err != nil {
		t.Fatal(err)
	}
	call := func(body, key string) *httptest.ResponseRecorder {
		return testCall(h, key, "POST", "/api/v1/nodes/"+n.ID+"/refresh", body)
	}
	for _, tc := range []struct {
		body, key string
		code      int
	}{
		{"{}", "", 401}, {"{}", "vlk_invalid", 401},
		{`{"force":true}`, apiKey, 400}, {"{} {}", apiKey, 400}, {"{}", apiKey, 200},
	} {
		if w := call(tc.body, tc.key); w.Code != tc.code {
			t.Fatalf("got %d want %d", w.Code, tc.code)
		}
	}
	if w := call("{}", apiKey); !strings.Contains(w.Body.String(), `"connected":false`) {
		t.Fatal(w.Body)
	}
	updates, stop := s.Subscribe(n.ID)
	defer stop()
	if w := call("{}", apiKey); w.Code != 200 || !strings.Contains(w.Body.String(), `"connected":true`) {
		t.Fatal(w.Code, w.Body)
	}
	select {
	case <-updates:
	default:
		t.Fatal("no notification")
	}
	got, _, _ := s.FindNodeByName(n.Name)
	if got.LastSeen != 0 || got.AppliedRevision != 0 {
		t.Fatal("refresh fabricated status")
	}
	if err = s.RemoveNode(n.ID, false); err != nil {
		t.Fatal(err)
	}
	if w := call("{}", apiKey); w.Code != 400 {
		t.Fatal(w.Code)
	}
}
