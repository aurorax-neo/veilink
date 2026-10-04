package web

import (
	"io"
	"net/http"
	"net/http/httptest"
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
		{"web-v1.2.0", "", "https://github.com/aurorax-neo/veilink/releases/download/web-v1.2.0/veilink-web-1.2.0.tar.gz"},
		{"0.4.0", "", "https://github.com/aurorax-neo/veilink/releases/download/web-v0.4.0/veilink-web-0.4.0.tar.gz"},
		{"v0.4.0", "", "https://github.com/aurorax-neo/veilink/releases/download/web-v0.4.0/veilink-web-0.4.0.tar.gz"},
		{"latest", "https://ghfast.top", "https://ghfast.top/aurorax-neo/veilink/releases/latest/download/veilink-web.tar.gz"},
		{"latest", "https://ghfast.top/", "https://ghfast.top/aurorax-neo/veilink/releases/latest/download/veilink-web.tar.gz"},
		{"latest", "https://ghproxy.com/https://github.com", "https://ghproxy.com/https://github.com/aurorax-neo/veilink/releases/latest/download/veilink-web.tar.gz"},
		{"0.4.0", "https://ghfast.top", "https://ghfast.top/aurorax-neo/veilink/releases/download/web-v0.4.0/veilink-web-0.4.0.tar.gz"},
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

	// 配置的镜像两种格式均先尝试，然后直连，不重复地址。
	m2 := NewWebManager(WebConfig{Repo: "aurorax-neo/veilink", GithubMirrors: []string{"https://ghfast.top"}})
	urls2 := m2.downloadCandidates("latest")
	if urls2[0] != "https://ghfast.top/aurorax-neo/veilink/releases/latest/download/veilink-web.tar.gz" {
		t.Errorf("first candidate should be configured mirror, got %q", urls2[0])
	}
	if urls2[2] != "https://github.com/aurorax-neo/veilink/releases/latest/download/veilink-web.tar.gz" {
		t.Errorf("third candidate should be direct github, got %q", urls2[2])
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
	m.ApplyPersisted([]string{"https://ghfast.top"}, "web-v1.0.0", "https://ui.example.com", "")
	if len(m.cfg.GithubMirrors) != 1 || m.cfg.GithubMirrors[0] != "https://ghfast.top" {
		t.Errorf("mirrors = %v, want [ghfast.top]", m.cfg.GithubMirrors)
	}
	if m.cfg.Version != "web-v1.0.0" {
		t.Errorf("version = %q", m.cfg.Version)
	}
	if m.cfg.FrontendURL != "https://ui.example.com" {
		t.Errorf("frontend_url = %q", m.cfg.FrontendURL)
	}
	// 空值不覆盖已有
	m.ApplyPersisted(nil, "", "", "")
	if len(m.cfg.GithubMirrors) != 1 || m.cfg.FrontendURL != "https://ui.example.com" {
		t.Errorf("empty ApplyPersisted should not overwrite, got %v / %q", m.cfg.GithubMirrors, m.cfg.FrontendURL)
	}
	if got := m.FrontendRedirect(); got != "https://ui.example.com" {
		t.Errorf("FrontendRedirect = %q", got)
	}

	// SetMirrors 触发 persist 回调，去重+清理
	var gotMirrors []string
	var gotVersion string
	var gotURL *string
	m.SetPersist(func(mirrors []string, version string, frontendURL *string) error {
		gotMirrors, gotVersion, gotURL = mirrors, version, frontendURL
		return nil
	})
	if err := m.SetMirrors([]string{
		"https://ghfast.top",
		" https://ghfast.top/ ", // 重复（归一化后相同）
		"",
		"https://ghproxy.com/https://github.com",
	}); err != nil {
		t.Fatalf("SetMirrors: %v", err)
	}
	if len(gotMirrors) != 2 || gotMirrors[0] != "https://ghfast.top" {
		t.Errorf("persist mirrors = %v, want 2 deduped", gotMirrors)
	}
	if gotVersion != "web-v1.0.0" {
		t.Errorf("persist version = %q", gotVersion)
	}
	if gotURL != nil {
		t.Errorf("SetMirrors should pass nil frontendURL, got %v", gotURL)
	}

	// SetFrontendURL
	if err := m.SetFrontendURL("https://cdn.example.com/veilink/"); err != nil {
		t.Fatalf("SetFrontendURL: %v", err)
	}
	if gotURL == nil || *gotURL != "https://cdn.example.com/veilink/" {
		t.Errorf("persist frontendURL = %v", gotURL)
	}
	if m.FrontendRedirect() != "https://cdn.example.com/veilink/" {
		t.Errorf("FrontendRedirect after set = %q", m.FrontendRedirect())
	}
	// 清空
	if err := m.SetMirrors(nil); err != nil {
		t.Fatalf("SetMirrors empty: %v", err)
	}
	if len(gotMirrors) != 0 {
		t.Errorf("persist after clear = %v, want empty", gotMirrors)
	}
}

func TestDownloadCandidatesNormalization(t *testing.T) {
	m := NewWebManager(WebConfig{Repo: "aurorax-neo/veilink"})
	inputs := []string{"0.4.0", "v0.4.0", "web-v0.4.0"}
	for _, in := range inputs {
		urls := m.downloadCandidates(in)
		if len(urls) == 0 {
			t.Fatalf("expected candidate urls for %s", in)
		}
		// 首选直连地址必须规范解析到 web-v0.4.0 并且文件为 veilink-web-0.4.0.tar.gz
		wantFirst := "https://github.com/aurorax-neo/veilink/releases/download/web-v0.4.0/veilink-web-0.4.0.tar.gz"
		if urls[0] != wantFirst {
			t.Errorf("input %s: urls[0] = %q, want %q", in, urls[0], wantFirst)
		}
		// 候选列表必须包含冗余 tag 命名前缀以及通用 veilink-web.tar.gz
		var hasWebTagVer, hasGeneric bool
		wantWebTagVer := "https://github.com/aurorax-neo/veilink/releases/download/web-v0.4.0/veilink-web-web-v0.4.0.tar.gz"
		wantGeneric := "https://github.com/aurorax-neo/veilink/releases/download/web-v0.4.0/veilink-web.tar.gz"
		for _, u := range urls {
			if u == wantWebTagVer {
				hasWebTagVer = true
			}
			if u == wantGeneric {
				hasGeneric = true
			}
		}
		if !hasWebTagVer {
			t.Errorf("input %s: missing candidate %s", in, wantWebTagVer)
		}
		if !hasGeneric {
			t.Errorf("input %s: missing candidate %s", in, wantGeneric)
		}
	}
}

func TestProbeOnlySavedMirrors(t *testing.T) {
	// 未配置镜像：Probe 结果必须为空
	m := NewWebManager(WebConfig{Repo: "aurorax-neo/veilink"})
	res := m.Probe("latest")
	if len(res) != 0 {
		t.Fatalf("expected 0 probe results for empty mirrors, got %d", len(res))
	}
}

func TestVersionFallbackToBuildinfo(t *testing.T) {
	m := NewWebManager(WebConfig{Repo: "aurorax-neo/veilink"})
	// 初始状态 Version() 应该回退到 buildinfo.Version
	if v := m.Version(); v == "" {
		t.Fatalf("expected non-empty version, got %q", v)
	}
}

func TestFetchLatestWebTagFromAtom(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/releases.atom", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/atom+xml")
		w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <entry>
    <title>v0.4.2</title>
    <link rel="alternate" type="text/html" href="https://github.com/aurorax-neo/veilink/releases/tag/v0.4.2"/>
  </entry>
  <entry>
    <title>web-v0.4.2</title>
    <link rel="alternate" type="text/html" href="https://github.com/aurorax-neo/veilink/releases/tag/web-v0.4.2"/>
  </entry>
</feed>`))
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/releases.atom", nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if len(body) == 0 {
		t.Fatal("empty feed")
	}
	if got := fetchWebTag(ts.URL+"/releases.atom", ts.Client()); got != "web-v0.4.2" {
		t.Fatalf("expected web-v0.4.2, got %q", got)
	}
}
