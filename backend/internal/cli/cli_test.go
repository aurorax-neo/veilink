package cli

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"veilink/internal/store"
)

func TestKeysCommands(t *testing.T) {
	dir := t.TempDir()
	db, key := filepath.Join(dir, "db"), filepath.Join(dir, "key")
	run := func(args ...string) (string, error) {
		full := append([]string{"keys", "-database", db, "-deployment-key", key}, args...)
		var out bytes.Buffer
		err := RunWithInput(context.Background(), full, strings.NewReader(""), &out)
		return out.String(), err
	}

	// keys 命令在数据库不存在时应报错（不自动创建）
	if _, err := run("list"); err == nil {
		t.Fatal("keys list should fail on missing database")
	}

	// 创建数据库
	s, err := store.Open(db, key)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()

	// list 应为空
	out, err := run("list")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "no API keys") {
		t.Fatalf("expected empty list, got: %s", out)
	}

	// create
	out, err = run("create", "test-key")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "vlk_") {
		t.Fatalf("expected key in output, got: %s", out)
	}

	// list 应显示
	out, err = run("list")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "test-key") {
		t.Fatalf("expected test-key in list, got: %s", out)
	}

	// revoke 需要 ID
	if _, err := run("revoke"); err == nil {
		t.Fatal("revoke without id should fail")
	}
	if _, err := run("revoke", "invalid"); err == nil {
		t.Fatal("revoke with invalid id should fail")
	}

	// 未知子命令
	if _, err := run("unknown"); err == nil {
		t.Fatal("unknown subcommand should fail")
	}
}
