package web

import (
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

func TestMirrorApplyAndSet(t *testing.T) {
	m := NewWebManager(WebConfig{Repo: "aurorax-neo/veilink"})
	// ApplyPersisted: DB 有值才覆盖
	m.ApplyPersisted("https://ghfast.top", "web-v1.0.0")
	if m.cfg.GithubMirror != "https://ghfast.top" {
		t.Errorf("mirror = %q, want ghfast.top", m.cfg.GithubMirror)
	}
	if m.cfg.Version != "web-v1.0.0" {
		t.Errorf("version = %q", m.cfg.Version)
	}
	// 空值不覆盖已有
	m.ApplyPersisted("", "")
	if m.cfg.GithubMirror != "https://ghfast.top" {
		t.Errorf("empty ApplyPersisted should not overwrite, got %q", m.cfg.GithubMirror)
	}

	// SetMirror 触发 persist 回调
	var gotMirror, gotVersion string
	m.SetPersist(func(mirror, version string) error {
		gotMirror, gotVersion = mirror, version
		return nil
	})
	if err := m.SetMirror("https://ghproxy.com/https://github.com"); err != nil {
		t.Fatalf("SetMirror: %v", err)
	}
	if gotMirror != "https://ghproxy.com/https://github.com" || gotVersion != "web-v1.0.0" {
		t.Errorf("persist got (%q, %q)", gotMirror, gotVersion)
	}
	// 清空也触发
	if err := m.SetMirror(""); err != nil {
		t.Fatalf("SetMirror empty: %v", err)
	}
	if gotMirror != "" {
		t.Errorf("persist after clear = %q, want empty", gotMirror)
	}
}
