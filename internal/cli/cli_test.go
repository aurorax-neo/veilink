package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"veilink/internal/store"
)

func TestRemovedConfigFlagAndRoleFlags(t *testing.T) {
	for _, args := range [][]string{{"master", "-config", "old.yaml"}, {"server", "-config=old.yaml"}, {"client", "-config", "old.yaml"}, {"init-admin", "-config", "old.yaml"}, {"init-admin", "-scheme", "https"}, {"master", "-username", "admin"}, {"version", "-config", "old.yaml"}, {"x25519", "-config=old.yaml"}, {"vlessenc", "-config", "old.yaml"}} {
		if err := Run(context.Background(), args, &bytes.Buffer{}); err == nil {
			t.Errorf("accepted %v", args)
		}
	}
}

func TestMissingRoleBeforeFlagsExplainsDockerCommand(t *testing.T) {
	for _, args := range [][]string{
		{"-database", "/data/veilink.db", "-scheme", "http"},
		{"-listen-addr", "127.0.0.1:2545"},
	} {
		err := Run(context.Background(), args, &bytes.Buffer{})
		if err == nil || !strings.Contains(err.Error(), "missing role") || !strings.Contains(err.Error(), "veilink master -database") {
			t.Fatalf("missing role not explained for %v: %v", args, err)
		}
	}
}

func TestResetAdminCommands(t *testing.T) {
	dir := t.TempDir()
	db, key := filepath.Join(dir, "db"), filepath.Join(dir, "key")
	run := func(command string, flags []string, password string) error {
		args := append([]string{command, "-database", db, "-deployment-key", key}, flags...)
		return RunWithInput(context.Background(), args, strings.NewReader(password), &bytes.Buffer{})
	}
	for _, command := range []string{"reset-admin-username", "reset-admin-password"} {
		flags := []string{"-username", "renamed"}
		if command == "reset-admin-password" {
			flags = []string{"-password-stdin"}
		}
		if run(command, flags, "new password long") == nil {
			t.Fatal("created missing database")
		}
	}
	for _, p := range []string{db, key} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatal("created file", p)
		}
	}
	s, err := store.Open(db, key)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if run("reset-admin-username", []string{"-username", "renamed"}, "") == nil || run("reset-admin-password", []string{"-password-stdin"}, "new password long") == nil {
		t.Fatal("reset created first admin")
	}
	if err = s.InitAdmin("admin", "old password long"); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		command string
		flags   []string
	}{
		{"reset-admin", []string{"-username", "renamed", "-password-stdin"}},
		{"reset-admin-username", nil},
		{"reset-admin-username", []string{"-username", ""}},
		{"reset-admin-username", []string{"-username", " "}},
		{"reset-admin-username", []string{"-username", strings.Repeat("x", 129)}},
		{"reset-admin-username", []string{"-username", "renamed", "-password-stdin"}},
		{"reset-admin-username", []string{"-username", "renamed", "trailing"}},
		{"reset-admin-username", []string{"-unknown"}},
		{"reset-admin-password", nil},
		{"reset-admin-password", []string{"-password-stdin=false"}},
		{"reset-admin-password", []string{"-password-stdin", "-username", "renamed"}},
		{"reset-admin-password", []string{"-password-stdin", "trailing"}},
		{"reset-admin-password", []string{"-password-stdin", "-unknown"}},
	} {
		if run(tc.command, tc.flags, "new password long") == nil {
			t.Fatalf("accepted %v", tc)
		}
	}
	if err = run("reset-admin-username", []string{"-username", "renamed"}, ""); err != nil {
		t.Fatal(err)
	}
	if !s.Login("renamed", "old password long") || s.Login("admin", "old password long") {
		t.Fatal("rename changed password or retained old name")
	}
	if run("reset-admin-username", []string{"-username", "renamed"}, "") == nil {
		t.Fatal("accepted no-op rename")
	}
	for _, password := range []string{"", strings.Repeat("x", 11), strings.Repeat("x", 73), strings.Repeat("x", 74), strings.Repeat("x", 75), strings.Repeat("密", 25)} {
		if run("reset-admin-password", []string{"-password-stdin"}, password) == nil {
			t.Fatal("accepted invalid password length", len(password))
		}
	}
	for _, password := range []string{strings.Repeat("x", 12), strings.Repeat("x", 72), strings.Repeat("密", 24)} {
		for _, suffix := range []string{"", "\n", "\r\n"} {
			if err = run("reset-admin-password", []string{"-password-stdin"}, password+suffix); err != nil {
				t.Fatal(err)
			}
			if !s.Login("renamed", password) {
				t.Fatal("password reset changed username or password bytes")
			}
		}
	}
}
