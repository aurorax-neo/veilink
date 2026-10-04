package store

import (
	"path/filepath"
	"sync"
	"testing"
)

func TestAtomicRegistrationAcrossStores(t *testing.T) {
	dir := t.TempDir()
	db, key := filepath.Join(dir, "db"), filepath.Join(dir, "key")
	a, err := Open(db, key)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := Open(db, key)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if a.Login("admin", "long test password") {
		t.Fatal("empty DB login")
	}
	if err = a.ResetAdminPassword("long test password"); err == nil {
		t.Fatal("reset bootstrapped admin")
	}
	if err = a.ResetAdminUsername("renamed"); err == nil {
		t.Fatal("rename bootstrapped admin")
	}
	var wg sync.WaitGroup
	results := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s := a
			if i%2 == 1 {
				s = b
			}
			results <- s.InitAdmin("admin", "long test password")
		}(i)
	}
	wg.Wait()
	close(results)
	wins := 0
	for err := range results {
		if err == nil {
			wins++
		} else if err != ErrRegistrationClosed {
			t.Fatal(err)
		}
	}
	if wins != 1 {
		t.Fatalf("winners=%d", wins)
	}
	if err = a.InitAdmin("other", "long test password"); err != ErrRegistrationClosed {
		t.Fatal(err)
	}
}

func TestSeparateAdminResets(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "db"), filepath.Join(dir, "key"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = s.InitAdmin("admin", "long test password"); err != nil {
		t.Fatal(err)
	}
	credentials := func() (string, string, string) {
		t.Helper()
		var user, hash string
		if err := s.db.QueryRow("SELECT username,password FROM admin").Scan(&user, &hash); err != nil {
			t.Fatal(err)
		}
		version, err := s.AdminVersion()
		if err != nil {
			t.Fatal(err)
		}
		return user, hash, version
	}
	_, oldHash, oldVersion := credentials()
	if err = s.ResetAdminUsername("renamed"); err != nil {
		t.Fatal(err)
	}
	user, hash, version := credentials()
	if user != "renamed" || hash != oldHash || version == oldVersion {
		t.Fatal("rename did not preserve hash and revoke version")
	}
	if loginVersion, ok := s.LoginVersion(user, "long test password"); !ok || loginVersion != version {
		t.Fatal("login version mismatch after rename")
	}
	if err = s.ResetAdminUsername(user); err == nil {
		t.Fatal("no-op rename accepted")
	}
	if err = s.ResetAdminPassword("replacement password"); err != nil {
		t.Fatal(err)
	}
	newUser, newHash, newVersion := credentials()
	if newUser != user || newHash == hash || newVersion == version {
		t.Fatal("password reset did not preserve username and revoke version")
	}
	if loginVersion, ok := s.LoginVersion(user, "replacement password"); !ok || loginVersion != newVersion {
		t.Fatal("login version mismatch after password reset")
	}
	if s.Login(user, "long test password") {
		t.Fatal("old password accepted")
	}
	if err = s.ResetAdminPassword("replacement password"); err != nil {
		t.Fatal(err)
	}
	_, _, repeatedVersion := credentials()
	if repeatedVersion == newVersion {
		t.Fatal("same-password reset did not revoke sessions")
	}
	for _, password := range []string{"", "12345678901", string(make([]byte, 73))} {
		if s.ResetAdminPassword(password) == nil {
			t.Fatal("invalid password accepted")
		}
	}
	if adminVersion("ab", "c", "") == adminVersion("a", "bc", "") || adminVersion("a", "bc", "d") == adminVersion("a", "b", "cd") {
		t.Fatal("ambiguous credential encoding")
	}
}

func TestAdminRenameMarkerPersistsAndRollsBack(t *testing.T) {
	dir := t.TempDir()
	db, key := filepath.Join(dir, "db"), filepath.Join(dir, "key")
	s, err := Open(db, key)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = s.InitAdmin("admin", "long test password"); err != nil {
		t.Fatal(err)
	}
	other, err := OpenExisting(db, key)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	read := func() (string, string, string) {
		t.Helper()
		var user, hash, marker string
		if err := s.db.QueryRow(adminCredentials).Scan(&user, &hash, &marker); err != nil {
			t.Fatal(err)
		}
		return user, hash, marker
	}
	_, originalHash, marker := read()
	if marker != "" {
		t.Fatal("unexpected initial marker")
	}
	seen := map[string]bool{}
	initial, err := s.AdminVersion()
	if err != nil {
		t.Fatal(err)
	}
	seen[initial] = true
	for _, name := range []string{"renamed", "admin", "renamed", "admin"} {
		if err = other.ResetAdminUsername(name); err != nil {
			t.Fatal(err)
		}
		user, hash, nextMarker := read()
		if user != name || hash != originalHash || nextMarker == "" || nextMarker == marker {
			t.Fatal("rename changed hash or failed to rotate marker")
		}
		marker = nextMarker
		version, err := s.AdminVersion()
		if err != nil {
			t.Fatal(err)
		}
		if seen[version] {
			t.Fatal("rename revived an old credential version")
		}
		seen[version] = true
		if loginVersion, ok := s.LoginVersion(name, "long test password"); !ok || loginVersion != version {
			t.Fatal("login version mismatch")
		}
	}
	// Force marker insertion failure after UPDATE and verify the entire transaction rolls back.
	if _, err = s.db.Exec("CREATE TRIGGER reject_admin_rename BEFORE INSERT ON audit WHEN NEW.action='admin.rename' BEGIN SELECT RAISE(ABORT, 'injected failure'); END"); err != nil {
		t.Fatal(err)
	}
	if err = other.ResetAdminUsername("failed"); err == nil {
		t.Fatal("expected audit insertion failure")
	}
	user, hash, afterMarker := read()
	if user != "admin" || hash != originalHash || afterMarker != marker {
		t.Fatal("failed transaction changed credentials or marker")
	}
	if err = other.ResetAdminUsername("admin"); err == nil {
		t.Fatal("no-op rename accepted")
	}
	var count int
	if err = s.db.QueryRow("SELECT count(*) FROM audit WHERE action='admin.rename'").Scan(&count); err != nil || count != 4 {
		t.Fatal("failed rename wrote a marker", count, err)
	}
}
