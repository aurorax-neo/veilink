package web

import (
	"archive/tar"
	"compress/gzip"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// 内置加速镜像：直连失败时自动尝试
var builtinMirrors = []string{
	"https://ghfast.top",
	"https://ghproxy.com/https://github.com",
	"https://mirror.ghproxy.com",
}

// LoadConfigFromEnv 从环境变量加载配置
// DB 持久化的 WebMirrors/WebVersion 由调用方在 NewWebManager 后通过 ApplyPersisted 覆盖
func LoadConfigFromEnv() WebConfig {
	var mirrors []string
	if v := os.Getenv("WEB_GITHUB_MIRROR"); v != "" {
		for _, part := range strings.Split(v, ",") {
			if trimmed := strings.TrimSpace(part); trimmed != "" {
				mirrors = append(mirrors, trimmed)
			}
		}
	}
	return WebConfig{
		Mode:          WebMode(getenv("WEB_MODE", "pull")),
		Version:       os.Getenv("WEB_VERSION"),
		CacheDir:      getenv("WEB_CACHE_DIR", "/data/web"),
		GithubMirrors: mirrors,
		FrontendURL:   strings.TrimSpace(os.Getenv("FRONTEND_URL")),
		Repo:          getenv("WEB_REPO", "aurorax-neo/veilink"),
		EnableCORS:    getenv("WEB_CORS", "true") == "true",
	}
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// WebMode 前端托管模式
type WebMode string

const (
	WebModeOff  WebMode = "off"  // 纯 API，不托管前端（CPA 式）
	WebModePull WebMode = "pull" // 从 GitHub Release 拉取前端（默认）
)

type WebConfig struct {
	Mode WebMode `env:"WEB_MODE" default:"pull"`

	// pull 模式：前端版本（如 web-v1.2.0，空 = latest）
	Version string `env:"WEB_VERSION" default:""`

	// pull 模式：缓存目录
	CacheDir string `env:"WEB_CACHE_DIR" default:"/data/web"`

	// CPA 式自定义前端地址：设置后 / 重定向到该地址（前后端分离部署）
	// 示例：https://veilink.example.com
	FrontendURL string `env:"FRONTEND_URL" default:""`

	// pull 模式：GitHub 加速地址列表（按顺序尝试）
	// 为空 = 直连 github.com
	// 示例：https://ghfast.top
	//       https://ghproxy.com/https://github.com
	GithubMirrors []string `env:"WEB_GITHUB_MIRROR" default:""`

	// 仓库
	Repo string `env:"WEB_REPO" default:"aurorax-neo/veilink"`

	// CORS 开关（分离部署时前端跨域调用 API）
	EnableCORS bool `env:"WEB_CORS" default:"true"`
}

// WebManager 管理前端静态资源的拉取与 serving
type WebManager struct {
	cfg    WebConfig
	mu     sync.RWMutex
	root   string
	ver    string
	client *http.Client
	// persist 将配置变更写回 DB（由 httpapi 注入）
	persist func(mirrors []string, version string, frontendURL *string) error
}

func NewWebManager(cfg WebConfig) *WebManager {
	return &WebManager{
		cfg:    cfg,
		client: &http.Client{Timeout: 15 * time.Second},
	}
}

// SetPersist 设置配置持久化回调（master 将 DB 写回函数注入进来）
func (m *WebManager) SetPersist(fn func(mirrors []string, version string, frontendURL *string) error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.persist = fn
}

// ApplyPersisted 用 DB 中持久化的值覆盖环境变量（master 启动时调用）
func (m *WebManager) ApplyPersisted(mirrors []string, version string, frontendURL string, mode string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	// DB 有值才覆盖：环境变量优先于空 DB 值
	if len(mirrors) > 0 {
		m.cfg.GithubMirrors = mirrors
	}
	if version != "" {
		m.cfg.Version = version
	}
	if frontendURL != "" {
		m.cfg.FrontendURL = frontendURL
	}
	if mode == string(WebModePull) || mode == string(WebModeOff) {
		m.cfg.Mode = WebMode(mode)
	}
}

// Ensure 保证前端可用，返回实际 serving 的目录（空 = 纯 API 模式）
func (m *WebManager) Ensure() (string, error) {
	if m.cfg.Mode == WebModeOff {
		return "", nil
	}

	// 1. 如果用户持久化配置了特定前端版本，优先走 pull 缓存目录
	if m.cfg.Version != "" {
		switch m.cfg.Mode {
		case WebModePull:
			return m.ensurePulled()
		default:
			return "", fmt.Errorf("unknown web mode: %s", m.cfg.Mode)
		}
	}

	// 2. 统一镜像预置：在未指定自定义版本时，默认使用本地预置版本，无需下载
	prebundled := os.Getenv("WEB_PREBUNDLED_DIR")
	if prebundled == "" {
		if fi, err := os.Stat("/opt/veilink-web/index.html"); err == nil && !fi.IsDir() {
			prebundled = "/opt/veilink-web"
		} else {
			dir, _ := os.Getwd()
			for i := 0; i < 5; i++ {
				cand := filepath.Join(dir, "frontend", "dist")
				if fi, err := os.Stat(filepath.Join(cand, "index.html")); err == nil && !fi.IsDir() {
					prebundled = cand
					break
				}
				parent := filepath.Dir(dir)
				if parent == dir {
					break
				}
				dir = parent
			}
		}
	}
	if prebundled != "" {
		if _, err := os.Stat(filepath.Join(prebundled, "index.html")); err == nil {
			m.mu.Lock()
			m.root = prebundled
			m.ver = "prebundled"
			m.mu.Unlock()
			return m.ver, nil
		}
	}
	switch m.cfg.Mode {
	case WebModeOff:
		return "", nil
	case WebModePull:
		return m.ensurePulled()
	default:
		return "", fmt.Errorf("unknown web mode: %s", m.cfg.Mode)
	}
}

func (m *WebManager) ensurePulled() (string, error) {
	wantVer := m.cfg.Version
	if wantVer == "" {
		wantVer = "latest"
	}
	m.mu.RLock()
	if m.root != "" && m.ver == wantVer {
		defer m.mu.RUnlock()
		return m.root, nil
	}
	m.mu.RUnlock()

	dir := filepath.Join(m.cfg.CacheDir, sanitizeVersion(wantVer))
	if _, err := os.Stat(filepath.Join(dir, ".ok")); os.IsNotExist(err) {
		if err := m.pull(wantVer, dir); err != nil {
			return "", err
		}
	}
	m.mu.Lock()
	m.root = dir
	m.ver = wantVer
	m.mu.Unlock()
	return dir, nil
}

// downloadURL 拼接下载地址（首选镜像）
func (m *WebManager) downloadURL(version string) string {
	mirrors := m.cfg.GithubMirrors
	var first string
	if len(mirrors) > 0 {
		first = mirrors[0]
	}
	return buildDownloadURL(m.cfg.Repo, version, first)
}

// normalizeWebTagAndFile 解析前端版本对应的 release tag 和纯版本号
func normalizeWebTagAndFile(version string) (tag string, fileVer string) {
	v := strings.TrimSpace(version)
	if v == "" || v == "latest" {
		return "latest", ""
	}
	clean := strings.TrimPrefix(strings.TrimPrefix(v, "web-"), "v")
	return "web-v" + clean, clean
}

// candidatePaths 返回该版本可能对应的 release 下载相对路径列表（按优先级排序）
func candidatePaths(repo, version string) []string {
	v := strings.TrimSpace(version)
	if v == "" || v == "latest" {
		return []string{
			fmt.Sprintf("%s/releases/latest/download/veilink-web.tar.gz", repo),
		}
	}
	tag, cleanVer := normalizeWebTagAndFile(v)

	var paths []string
	seen := map[string]bool{}
	add := func(p string) {
		if !seen[p] {
			seen[p] = true
			paths = append(paths, p)
		}
	}

	// 1. 标准资产名: veilink-web-${cleanVer}.tar.gz
	add(fmt.Sprintf("%s/releases/download/%s/veilink-web-%s.tar.gz", repo, tag, cleanVer))
	// 2. 冗余 tag 命名前缀资产名: veilink-web-${tag}.tar.gz (如 veilink-web-web-v0.4.0.tar.gz)
	add(fmt.Sprintf("%s/releases/download/%s/veilink-web-%s.tar.gz", repo, tag, tag))
	// 3. 通用资产名称: veilink-web.tar.gz
	add(fmt.Sprintf("%s/releases/download/%s/veilink-web.tar.gz", repo, tag))

	// 4. 容错尝试原始输入作为 tag（如果用户输入了非标准 tag）
	if v != tag {
		add(fmt.Sprintf("%s/releases/download/%s/veilink-web-%s.tar.gz", repo, v, cleanVer))
		add(fmt.Sprintf("%s/releases/download/%s/veilink-web-%s.tar.gz", repo, v, v))
		add(fmt.Sprintf("%s/releases/download/%s/veilink-web.tar.gz", repo, v))
	}

	return paths
}

// downloadCandidates 返回按优先级排序的下载地址：
// 1. 配置的镜像列表（按顺序）；2. 直连；3. 内置公共镜像
func (m *WebManager) downloadCandidates(version string) []string {
	paths := candidatePaths(m.cfg.Repo, version)
	var urls []string
	seen := map[string]bool{}
	add := func(u string) {
		if !seen[u] {
			seen[u] = true
			urls = append(urls, u)
		}
	}

	configured := map[string]bool{}
	for _, mirror := range m.cfg.GithubMirrors {
		configured[normalizeMirror(mirror)] = true
	}

	for _, p := range paths {
		for _, mirror := range m.cfg.GithubMirrors {
			add(assembleURL(p, mirror))
		}
		add(assembleURL(p, ""))
		for _, b := range builtinMirrors {
			if configured[normalizeMirror(b)] {
				continue
			}
			add(assembleURL(p, b))
		}
	}
	return urls
}

func normalizeMirror(m string) string {
	return strings.ToLower(strings.TrimRight(strings.TrimSpace(m), "/"))
}

// buildDownloadURL 拼接下载首选地址，支持加速镜像
func buildDownloadURL(repo, version, mirror string) string {
	paths := candidatePaths(repo, version)
	var path string
	if len(paths) > 0 {
		path = paths[0]
	} else {
		path = fmt.Sprintf("%s/releases/latest/download/veilink-web.tar.gz", repo)
	}
	return assembleURL(path, mirror)
}

func assembleURL(path, mirror string) string {
	mirror = strings.TrimRight(strings.TrimSpace(mirror), "/")
	if mirror == "" {
		return "https://github.com/" + path
	}
	// 加速地址格式兼容两种写法：
	// 1. https://gh-proxy.com/https://github.com  → 拼接完整 URL
	// 2. https://mirror.ghproxy.com/ / https://ghfast.top → 替换域名
	if strings.Contains(mirror, "://github.com") || strings.HasSuffix(mirror, "github.com") {
		return mirror + "/" + path
	}
	return mirror + "/" + path
}
func (m *WebManager) pull(version, dir string) error {
	var lastErr error
	for _, url := range m.downloadCandidates(version) {
		if err := m.pullFrom(url, version, dir); err != nil {
			slog.Warn("前端下载失败，尝试下一个地址", "url", redactURL(url), "err", err)
			if os.IsPermission(err) || strings.Contains(err.Error(), "read-only file system") {
				return fmt.Errorf("local cache dir error: %w", err)
			}
			lastErr = err
			continue
		}
		if url != m.downloadURL(version) {
			slog.Info("前端经备用地址下载成功", "url", redactURL(url))
		}
		return nil
	}
	return fmt.Errorf("download web %s: all candidates failed: %w", version, lastErr)
}

func redactURL(u string) string {
	// 日志脱敏：只保留 host，隐藏完整路径
	if i := strings.Index(u, "://"); i >= 0 {
		rest := u[i+3:]
		if j := strings.Index(rest, "/"); j >= 0 {
			return u[:i+3] + rest[:j] + "/…"
		}
		return u
	}
	return u
}

func (m *WebManager) pullFrom(url, version, dir string) error {
	resp, err := m.client.Get(url)
	if err != nil {
		return fmt.Errorf("download web %s: %w", version, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download web %s: status %d (url: %s)", version, resp.StatusCode, url)
	}

	tmpDir := dir + ".tmp"
	os.RemoveAll(tmpDir)
	if err := os.MkdirAll(tmpDir, 0o755); err != nil {
		return err
	}
	if err := extractTarGz(resp.Body, tmpDir); err != nil {
		os.RemoveAll(tmpDir)
		return fmt.Errorf("extract web %s: %w", version, err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, ".ok"), []byte(version), 0o644); err != nil {
		os.RemoveAll(tmpDir)
		return err
	}
	os.RemoveAll(dir)
	if err := os.Rename(tmpDir, dir); err != nil {
		return err
	}
	return nil
}

// Update 热更新前端（供 API 调用）
func (m *WebManager) Update(version string) error {
	if version != "" {
		m.mu.Lock()
		m.cfg.Version = version
		persist := m.persist
		m.mu.Unlock()
		if persist != nil {
			if err := persist(m.cfg.GithubMirrors, version, nil); err != nil {
				slog.Warn("保存前端配置失败", "err", err)
			}
		}
	}
	m.mu.Lock()
	m.ver = ""
	m.mu.Unlock()
	_, err := m.ensurePulled()
	return err
}

// WebStatus 前端状态（供设置页展示）
type WebStatus struct {
	Mode         string   `json:"mode"`
	WantVersion  string   `json:"want_version"`
	ActiveVer    string   `json:"active_version"`
	Mirrors      []string `json:"mirrors"`
	FrontendURL  string   `json:"frontend_url"`
	Repo         string   `json:"repo"`
	Root         string   `json:"-"`
	Serving      bool     `json:"serving"`
	Prebundled   bool     `json:"prebundled"`
}

// Status 返回当前前端配置与状态
func (m *WebManager) Status() WebStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return WebStatus{
		Mode:        string(m.cfg.Mode),
		WantVersion: m.cfg.Version,
		ActiveVer:   m.ver,
		Mirrors:     append([]string{}, m.cfg.GithubMirrors...),
		FrontendURL: m.cfg.FrontendURL,
		Repo:        m.cfg.Repo,
		Root:        m.root,
		Serving:     m.root != "",
		Prebundled:  m.ver == "prebundled",
	}
}

// FrontendRedirect 返回 CPA 重定向地址（未配置返回空）
func (m *WebManager) FrontendRedirect() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cfg.FrontendURL
}

// SetFrontendURL 更新自定义前端地址并持久化（空 = 取消）
func (m *WebManager) SetFrontendURL(url string) error {
	url = strings.TrimSpace(url)
	m.mu.Lock()
	m.cfg.FrontendURL = url
	persist := m.persist
	mirrors := append([]string{}, m.cfg.GithubMirrors...)
	version := m.cfg.Version
	m.mu.Unlock()
	if persist != nil {
		return persist(mirrors, version, &url)
	}
	return nil
}

// SetMirrors 更新加速镜像列表并持久化到 DB（空列表 = 直连）
func (m *WebManager) SetMirrors(mirrors []string) error {
	cleaned := make([]string, 0, len(mirrors))
	seen := map[string]bool{}
	for _, mirror := range mirrors {
		mirror = strings.TrimSpace(mirror)
		if mirror == "" || seen[normalizeMirror(mirror)] {
			continue
		}
		seen[normalizeMirror(mirror)] = true
		cleaned = append(cleaned, mirror)
	}
	m.mu.Lock()
	m.cfg.GithubMirrors = cleaned
	persist := m.persist
	version := m.cfg.Version
	m.mu.Unlock()
	if persist != nil {
		return persist(cleaned, version, nil)
	}
	return nil
}

// ProbeResult 连通性探测结果
type ProbeResult struct {
	URL     string `json:"url"`
	OK      bool   `json:"ok"`
	Status  int    `json:"status,omitempty"`
	Elapsed int64  `json:"elapsed_ms"`
	Error   string `json:"error,omitempty"`
}

// Probe 探测各候选下载地址的连通性（HEAD 请求，不下载）
func (m *WebManager) Probe(version string) []ProbeResult {
	if version == "" {
		version = m.cfg.Version
		if version == "" {
			version = "latest"
		}
	}
	results := make([]ProbeResult, 0)
	client := &http.Client{Timeout: 15 * time.Second}
	for _, url := range m.downloadCandidates(version) {
		start := time.Now()
		r := ProbeResult{URL: redactURL(url)}
		req, err := http.NewRequest(http.MethodHead, url, nil)
		if err != nil {
			r.Error = err.Error()
			results = append(results, r)
			continue
		}
		resp, err := client.Do(req)
		r.Elapsed = time.Since(start).Milliseconds()
		if err != nil {
			r.Error = err.Error()
		} else {
			resp.Body.Close()
			r.Status = resp.StatusCode
			r.OK = resp.StatusCode == http.StatusOK
			if !r.OK {
				r.Error = fmt.Sprintf("status %d", resp.StatusCode)
			}
		}
		results = append(results, r)
	}
	return results
}

func (m *WebManager) Root() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.root
}

func (m *WebManager) Version() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.ver
}

func sanitizeVersion(v string) string {
	return strings.ReplaceAll(strings.ReplaceAll(v, "/", "_"), "..", "_")
}

func extractTarGz(r io.Reader, dest string) error {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		target := filepath.Join(dest, hdr.Name)
		if !strings.HasPrefix(target, filepath.Clean(dest)+string(os.PathSeparator)) {
			return fmt.Errorf("illegal path: %s", hdr.Name)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(hdr.Mode))
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return err
			}
			f.Close()
		}
	}
	return nil
}

// generateKey 生成 API Key
func generateKey() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "vlk_" + hex.EncodeToString(b), nil
}
