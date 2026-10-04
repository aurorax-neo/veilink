package web

import (
	"archive/tar"
	"compress/gzip"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
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
func LoadConfigFromEnv() WebConfig {
	cfg := WebConfig{
		Mode:         WebMode(getenv("WEB_MODE", "pull")),
		Version:      os.Getenv("WEB_VERSION"),
		CacheDir:     getenv("WEB_CACHE_DIR", "/data/web"),
		GithubMirror: os.Getenv("WEB_GITHUB_MIRROR"),
		Repo:         getenv("WEB_REPO", "aurorax-neo/veilink"),
		EnableCORS:   getenv("WEB_CORS", "true") == "true",
	}
	// 本地持久化配置覆盖环境变量（设置页保存的优先）
	if saved, err := loadSavedConfig(cfg.CacheDir); err == nil && saved != nil {
		if saved.GithubMirror != "" || saved.mirrorTouched {
			cfg.GithubMirror = saved.GithubMirror
		}
		if saved.Version != "" {
			cfg.Version = saved.Version
		}
	}
	return cfg
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

	// pull 模式：GitHub 加速地址
	// 为空 = 直连 github.com
	// 示例：https://gh-proxy.com/https://github.com
	//       https://mirror.ghproxy.com/
	GithubMirror string `env:"WEB_GITHUB_MIRROR" default:""`

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
}

func NewWebManager(cfg WebConfig) *WebManager {
	return &WebManager{
		cfg:    cfg,
		client: &http.Client{Timeout: 5 * time.Minute},
	}
}

// Ensure 保证前端可用，返回实际 serving 的目录（空 = 纯 API 模式）
func (m *WebManager) Ensure() (string, error) {
	// 统一镜像预置：优先使用本地预置版本，无需下载
	if prebundled := os.Getenv("WEB_PREBUNDLED_DIR"); prebundled != "" {
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

// downloadURL 拼接下载地址，支持加速镜像
func (m *WebManager) downloadURL(version string) string {
	return buildDownloadURL(m.cfg.Repo, version, m.cfg.GithubMirror)
}

// downloadCandidates 返回按优先级排序的下载地址：
// 1. 配置的镜像（或直连）；2. 直连（如果配置了镜像）；3. 内置公共镜像
func (m *WebManager) downloadCandidates(version string) []string {
	var urls []string
	seen := map[string]bool{}
	add := func(u string) {
		if !seen[u] {
			seen[u] = true
			urls = append(urls, u)
		}
	}
	mirror := strings.TrimSpace(m.cfg.GithubMirror)
	add(buildDownloadURL(m.cfg.Repo, version, mirror))
	if mirror != "" {
		add(buildDownloadURL(m.cfg.Repo, version, ""))
	}
	for _, b := range builtinMirrors {
		// 跳过与已配置镜像等价的内置项
		if normalizeMirror(b) == normalizeMirror(mirror) {
			continue
		}
		add(buildDownloadURL(m.cfg.Repo, version, b))
	}
	return urls
}

func normalizeMirror(m string) string {
	return strings.ToLower(strings.TrimRight(strings.TrimSpace(m), "/"))
}

// buildDownloadURL 拼接下载地址，支持加速镜像
func buildDownloadURL(repo, version, mirror string) string {
	var path string
	if version == "latest" {
		path = fmt.Sprintf("%s/releases/latest/download/veilink-web.tar.gz", repo)
	} else {
		path = fmt.Sprintf("%s/releases/download/%s/veilink-web-%s.tar.gz",
			repo, version, version)
	}
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
	// 纯域名镜像：替换 github.com
	return mirror + "/" + path
}

func (m *WebManager) pull(version, dir string) error {
	var lastErr error
	for _, url := range m.downloadCandidates(version) {
		if err := m.pullFrom(url, version, dir); err != nil {
			slog.Warn("前端下载失败，尝试下一个地址", "url", redactURL(url), "err", err)
			lastErr = err
			continue
		}
		if url != buildDownloadURL(m.cfg.Repo, version, m.cfg.GithubMirror) {
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
		m.cfg.Version = version
		if err := m.saveConfig(); err != nil {
			slog.Warn("保存前端配置失败", "err", err)
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
	Mode         string `json:"mode"`
	WantVersion  string `json:"want_version"`
	ActiveVer    string `json:"active_version"`
	Mirror       string `json:"mirror"`
	Repo         string `json:"repo"`
	Root         string `json:"-"`
	Serving      bool   `json:"serving"`
	Prebundled   bool   `json:"prebundled"`
}

// Status 返回当前前端配置与状态
func (m *WebManager) Status() WebStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return WebStatus{
		Mode:        string(m.cfg.Mode),
		WantVersion: m.cfg.Version,
		ActiveVer:   m.ver,
		Mirror:      m.cfg.GithubMirror,
		Repo:        m.cfg.Repo,
		Root:        m.root,
		Serving:     m.root != "",
		Prebundled:  m.ver == "prebundled",
	}
}

// SetMirror 更新加速镜像并持久化（空字符串 = 直连）
func (m *WebManager) SetMirror(mirror string) error {
	mirror = strings.TrimSpace(mirror)
	m.mu.Lock()
	m.cfg.GithubMirror = mirror
	m.mu.Unlock()
	return m.saveConfig()
}

// savedWebConfig 持久化到本地的配置（设置页保存）
type savedWebConfig struct {
	GithubMirror  string `json:"github_mirror"`
	Version       string `json:"version,omitempty"`
	mirrorTouched bool   // 内存标记：用户是否显式设置过镜像（含清空）
}

func webConfigPath(cacheDir string) string {
	return filepath.Join(cacheDir, "web-config.json")
}

func loadSavedConfig(cacheDir string) (*savedWebConfig, error) {
	data, err := os.ReadFile(webConfigPath(cacheDir))
	if err != nil {
		return nil, err
	}
	var sc savedWebConfig
	if err := json.Unmarshal(data, &sc); err != nil {
		return nil, err
	}
	sc.mirrorTouched = true
	return &sc, nil
}

func (m *WebManager) saveConfig() error {
	m.mu.RLock()
	sc := savedWebConfig{
		GithubMirror:  m.cfg.GithubMirror,
		Version:       m.cfg.Version,
		mirrorTouched: true,
	}
	dir := m.cfg.CacheDir
	m.mu.RUnlock()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(sc, "", "  ")
	if err != nil {
		return err
	}
	tmp := webConfigPath(dir) + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, webConfigPath(dir))
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
