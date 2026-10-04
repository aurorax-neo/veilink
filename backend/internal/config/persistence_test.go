package config

import (
	"database/sql"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestMasterPersistenceRedeployAndOverrides(t *testing.T) {
	dir := t.TempDir()
	database := filepath.Join(dir, "master.db")
	bootstrap := []string{"-database", database, "-deployment-key", filepath.Join(dir, "master.key")}
	load := func(flags ...string) Config {
		t.Helper()
		c, err := ParseFlags("master", append(append([]string{}, bootstrap...), flags...))
		if err != nil {
			t.Fatal(err)
		}
		c, err = PersistMaster(c)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	first := load("-listen-addr=0.0.0.0:9443", "-state-dir=durable-state", "-scheme=http", "-cert-file=/local/cert.pem", "-key-file=/local/key.pem", "-embedded-server-enabled", "-embedded-server-address=gateway.example.com", "-embedded-server-port=9444")
	second := load()
	if second.ListenAddr != first.ListenAddr || second.StateDir != first.StateDir || second.EmbeddedServer != first.EmbeddedServer || second.CertFile != first.CertFile || second.Scheme != "http" {
		t.Fatal("redeploy defaults replaced persisted settings")
	}
	if second.EnrollToken != "" {
		t.Fatal("enrollment token persisted")
	}
	// Explicit false and nested leaves override without resetting omitted siblings.
	third := load("-embedded-server-enabled=false", "-embedded-server-address=updated.example.com", "-cert-file=")
	if third.EmbeddedServer.Enabled || third.EmbeddedServer.Port != 9444 || third.EmbeddedServer.Address != "updated.example.com" {
		t.Fatal("nested override lost settings")
	}
	t.Setenv("VEILINK_LISTEN_ADDR", "0.0.0.0:10443")
	t.Setenv("VEILINK_EMBEDDED_SERVER_ENABLED", "true")
	last := load()
	if last.ListenAddr != "0.0.0.0:9443" || last.EmbeddedServer.Enabled || last.CertFile != "" {
		t.Fatal("environment override or explicit empty ignored")
	}
	updated := load("-listen-addr=0.0.0.0:10443", "-embedded-server-enabled=true")
	if updated.ListenAddr != "0.0.0.0:10443" || !updated.EmbeddedServer.Enabled {
		t.Fatal("explicit CLI override ignored")
	}
	db, err := sql.Open("sqlite", database)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var raw string
	if err := db.QueryRow("SELECT data FROM master_config WHERE id=1").Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"Database", "DeploymentKey", "EnrollToken", "HTMLDir", "html_dir"} {
		if _, ok := doc[field]; ok {
			t.Errorf("bootstrap/transient field %s persisted", field)
		}
	}
	if strings.Contains(raw, "BEGIN CERTIFICATE") {
		t.Fatal("transient secret or certificate bytes persisted")
	}
}

func TestMasterPersistenceRejectsInvalidUpdate(t *testing.T) {
	dir := t.TempDir()
	c := Defaults()
	c.Database, c.DeploymentKey = filepath.Join(dir, "db"), filepath.Join(dir, "key")
	if _, err := PersistMaster(c); err != nil {
		t.Fatal(err)
	}
	c.ListenAddr = "invalid"
	c.explicit["listen_addr"] = true
	if _, err := PersistMaster(c); err == nil {
		t.Fatal("invalid config accepted")
	}
	delete(c.explicit, "listen_addr")
	c, err := PersistMaster(c)
	if err != nil || c.ListenAddr != "127.0.0.1:2545" {
		t.Fatal("invalid update replaced saved config")
	}
}

func TestMasterPersistenceRejectsRemovedFields(t *testing.T) {
	for _, document := range []string{`{"BindAddr":"localhost:8443"}`, `{"TLSMode":"http"}`, `{"ControlCert":"cert"}`, `{"ControlKey":"key"}`, `{"TLS":{}}`, `{"Pool":2}`, `{"EmbeddedServer":{"TLS":{}}}`, `{} {}`} {
		t.Run(document, func(t *testing.T) {
			c := Defaults()
			dir := t.TempDir()
			c.Database, c.DeploymentKey = filepath.Join(dir, "db"), filepath.Join(dir, "key")
			if _, err := PersistMaster(c); err != nil {
				t.Fatal(err)
			}
			db, err := sql.Open("sqlite", c.Database)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			if _, err := db.Exec("UPDATE master_config SET data=? WHERE id=1", document); err != nil {
				t.Fatal(err)
			}
			if _, err := PersistMaster(c); err == nil {
				t.Fatal("removed persisted schema accepted")
			}
			var after string
			if err := db.QueryRow("SELECT data FROM master_config WHERE id=1").Scan(&after); err != nil {
				t.Fatal(err)
			}
			if after != document {
				t.Fatal("invalid persisted schema migrated")
			}
		})
	}
}

func TestMasterExplicitEmptySchemeDoesNotCommit(t *testing.T) {
	dir := t.TempDir()
	base := []string{"-database", filepath.Join(dir, "db"), "-deployment-key", filepath.Join(dir, "key")}
	for _, seed := range []bool{false, true} {
		if seed {
			c, err := ParseFlags("master", base)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = PersistMaster(c); err != nil {
				t.Fatal(err)
			}
		}
		c, err := ParseFlags("master", append(append([]string{}, base...), "-scheme="))
		if err != nil {
			t.Fatal(err)
		}
		if _, err = PersistMaster(c); err == nil {
			t.Fatal("explicit empty scheme accepted")
		}
	}
}

func TestUpdateWebConfig(t *testing.T) {
	dir := t.TempDir()
	database := filepath.Join(dir, "master.db")
	bootstrap := []string{"-database", database, "-deployment-key", filepath.Join(dir, "master.key")}
	c, err := ParseFlags("master", bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	c, err = PersistMaster(c)
	if err != nil {
		t.Fatal(err)
	}
	// 初始为空
	if len(c.WebMirrors) != 0 || c.WebVersion != "" || c.FrontendURL != "" {
		t.Fatalf("initial web config = (%v, %q, %q), want empty", c.WebMirrors, c.WebVersion, c.FrontendURL)
	}
	// 更新镜像列表
	if err := UpdateWebConfig(database, []string{"https://ghfast.top", "https://ghproxy.com"}, "", false, nil); err != nil {
		t.Fatal(err)
	}
	c2, err := ParseFlags("master", bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	c2, _, err = ResolveMaster(c2)
	if err != nil {
		t.Fatal(err)
	}
	if len(c2.WebMirrors) != 2 || c2.WebMirrors[0] != "https://ghfast.top" {
		t.Errorf("WebMirrors = %v, want 2", c2.WebMirrors)
	}
	// CLI 显式标志优先于 DB
	c3, err := ParseFlags("master", append(bootstrap, "-web-mirror=https://example.com", "-web-mirror=https://example2.com"))
	if err != nil {
		t.Fatal(err)
	}
	c3, _, err = ResolveMaster(c3)
	if err != nil {
		t.Fatal(err)
	}
	if len(c3.WebMirrors) != 2 || c3.WebMirrors[0] != "https://example.com" {
		t.Errorf("explicit flag should win, got %v", c3.WebMirrors)
	}
	// 设置前端地址
	frontendURL := "https://ui.example.com"
	if err := UpdateWebConfig(database, nil, "", false, &frontendURL); err != nil {
		t.Fatal(err)
	}
	c4, err := ParseFlags("master", bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	c4, _, err = ResolveMaster(c4)
	if err != nil {
		t.Fatal(err)
	}
	if c4.FrontendURL != "https://ui.example.com" {
		t.Errorf("FrontendURL = %q", c4.FrontendURL)
	}
	// 镜像列表保持不变（nil 不覆盖）
	if len(c4.WebMirrors) != 2 {
		t.Errorf("mirrors should persist, got %v", c4.WebMirrors)
	}
	// 清空镜像和前端地址
	empty := ""
	if err := UpdateWebConfig(database, []string{}, "web-v1.0.0", true, &empty); err != nil {
		t.Fatal(err)
	}
	c5, err := ParseFlags("master", bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	c5, _, err = ResolveMaster(c5)
	if err != nil {
		t.Fatal(err)
	}
	if len(c5.WebMirrors) != 0 || c5.WebVersion != "web-v1.0.0" || c5.FrontendURL != "" {
		t.Errorf("after clear = (%v, %q, %q)", c5.WebMirrors, c5.WebVersion, c5.FrontendURL)
	}
}

func TestMasterPersistenceStaleHTMLDir(t *testing.T) {
	dir := t.TempDir()
	database := filepath.Join(dir, "master.db")
	dbKey := filepath.Join(dir, "master.key")
	bootstrap := []string{"-database", database, "-deployment-key", dbKey}

	// 初始化一个含有历史残留 HTMLDir 的 master_config 记录
	c, err := ParseFlags("master", bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PersistMaster(c); err != nil {
		t.Fatal(err)
	}

	db, err := sql.Open("sqlite", database)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// 模拟旧版本将不存在的 /usr/local/html 写入了 master_config
	legacyJSON := `{"ListenAddr":"127.0.0.1:2545","Scheme":"http","HTMLDir":"/usr/local/html"}`
	if _, err := db.Exec("UPDATE master_config SET data=? WHERE id=1", []byte(legacyJSON)); err != nil {
		t.Fatal(err)
	}

	// 1. 无 -html-dir 启动，必须成功且自动清空失效的 HTMLDir，平滑迁移
	c1, err := ParseFlags("master", bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	eff1, commit1, err := ResolveMaster(c1)
	if err != nil {
		t.Fatalf("expected successful startup with stale html_dir, got: %v", err)
	}
	if eff1.HTMLDir != "" {
		t.Fatalf("expected HTMLDir to be reset to empty, got: %q", eff1.HTMLDir)
	}
	if err := commit1(); err != nil {
		t.Fatal(err)
	}

	// 验证 commit 之后数据库中不再包含 HTMLDir 或 html_dir
	var raw string
	if err := db.QueryRow("SELECT data FROM master_config WHERE id=1").Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatal(err)
	}
	if _, ok := doc["HTMLDir"]; ok {
		t.Error("HTMLDir persisted after stale cleanup")
	}
	if _, ok := doc["html_dir"]; ok {
		t.Error("html_dir persisted after stale cleanup")
	}

	// 2. 显式指定不存在的 -html-dir，必须报错校验失败
	c2, err := ParseFlags("master", append(bootstrap, "-html-dir=/nonexistent/html/custom"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ResolveMaster(c2); err == nil || !strings.Contains(err.Error(), "html_dir must contain index.html") {
		t.Fatalf("expected html_dir validation error, got: %v", err)
	}
}
