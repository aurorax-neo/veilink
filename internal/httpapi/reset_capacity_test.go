package httpapi

import (
	"fmt"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"veilink/internal/store"
)

func TestResetAdminClearsFullRevokedSessionCapacity(t *testing.T) {
	d := t.TempDir()
	s, err := store.Open(filepath.Join(d, "db"), filepath.Join(d, "key"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.InitAdmin("admin", "old test password"); err != nil {
		t.Fatal(err)
	}
	old, err := s.AdminVersion()
	if err != nil {
		t.Fatal(err)
	}
	a := New(s, false, nil, nil).(*API)
	for i := 0; i < 100; i++ {
		a.sessions[fmt.Sprint(i)] = session{csrf: "old", version: old, expires: time.Now().Add(time.Hour)}
	}
	if err := s.ResetAdminPassword("new test password"); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"username":"admin","password":"new test password"}`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("new login rejected: %d %s", w.Code, w.Body.String())
	}
	if len(a.sessions) != 1 {
		t.Fatalf("revoked sessions retained: %d", len(a.sessions))
	}
}
