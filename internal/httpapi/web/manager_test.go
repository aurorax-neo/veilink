package web

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBuildDownloadURL(t *testing.T) {
	repo := "aurorax-neo/veilink"
	cases := []struct {
		version string
		mirror  string
		want    string
	}{
		{"latest", "", "https://github.com/aurorax-neo/veilink/releases/latest/download/veilink-web.tar.gz"},
		{"web-v1.2.0", "", "https://github.com/aurorax-neo/veilink/releases/download/web-v1.2.0/veilink-web-web-v1.2.0.tar.gz"},
		{"latest", "https://ghfast.top", "https://ghfast.top/aurorax-neo/veilink/releases/latest/download/veilink-web.tar.gz"},
		{"latest", "https://ghfast.top/", "https://ghfast.top/aurorax-neo/veilink/releases/latest/download/veilink-web.tar.gz"},
		{"latest", "https://ghproxy.com/https://github.com", "https://ghproxy.com/https://github.com/aurorax-neo/veilink/releases/latest/download/veilink-web.tar.gz"},
	}
	for _, c := range cases {
		got := buildDownloadURL(repo, c.version, c.mirror)
		if got != c.want {
			t.Errorf("buildDownloadURL(%q, %q) = %q, want %q", c.version, c.mirror, got, c.want)
		}
	}
}

func TestDownloadCandidatesFallback(t *testing.T) {
	// 未配置镜像：直连优先，其次内置镜像
	m := NewWebManager(WebConfig{Repo: "aurorax-neo/veilink"})
	urls := m.downloadCandidates("latest")
	if len(urls) < 2 {
		t.Fatalf("expected at least 2 candidates, got %d", len(urls))
	}
	if urls[0] != "https://github.com/aurorax-neo/veilink/releases/latest/download/veilink-web.tar.gz" {
		t.Errorf("first candidate should be direct github, got %q", urls[0])
	}
	found := false
	for _, u := range urls[1:] {
		if u == "https://ghfast.top/aurorax-neo/veilink/releases/latest/download/veilink-web.tar.gz" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected ghfast.top in fallback candidates: %v", urls)
	}

	// 配置了 ghfast.top：不再重复，且直连作为第二候选
	m2 := NewWebManager(WebConfig{Repo: "aurorax-neo/veilink", GithubMirror: "https://ghfast.top"})
	urls2 := m2.downloadCandidates("latest")
	if urls2[0] != "https://ghfast.top/aurorax-neo/veilink/releases/latest/download/veilink-web.tar.gz" {
		t.Errorf("first candidate should be configured mirror, got %q", urls2[0])
	}
	if urls2[1] != "https://github.com/aurorax-neo/veilink/releases/latest/download/veilink-web.tar.gz" {
		t.Errorf("second candidate should be direct github, got %q", urls2[1])
	}
	count := 0
	for _, u := range urls2 {
		if u == urls2[0] {
			count++
		}
	}
	if count != 1 {
		t.Errorf("duplicate candidate urls: %v", urls2)
	}
}

func TestMirrorPersistence(t *testing.T) {
	dir := t.TempDir()
	m := NewWebManager(WebConfig{CacheDir: dir, Repo: "aurorax-neo/veilink"})
	if err := m.SetMirror("https://ghfast.top"); err != nil {
		t.Fatalf("SetMirror: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "web-config.json")); err != nil {
		t.Fatalf("config file not written: %v", err)
	}
	// 重新加载：持久化的镜像应覆盖环境变量（空）
	cfg := LoadConfigFromEnv()
	// LoadConfigFromEnv 用默认 CacheDir，这里直接测 loadSavedConfig
	saved, err := loadSavedConfig(dir)
	if err != nil {
		t.Fatalf("loadSavedConfig: %v", err)
	}
	if saved.GithubMirror != "https://ghfast.top" {
		t.Errorf("saved mirror = %q, want ghfast.top", saved.GithubMirror)
	}
	_ = cfg

	// 清空镜像也能持久化
	if err := m.SetMirror(""); err != nil {
		t.Fatalf("SetMirror empty: %v", err)
	}
	saved2, err := loadSavedConfig(dir)
	if err != nil {
		t.Fatalf("loadSavedConfig after clear: %v", err)
	}
	if saved2.GithubMirror != "" {
		t.Errorf("saved mirror after clear = %q, want empty", saved2.GithubMirror)
	}
}
