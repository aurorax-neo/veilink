package web

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"veilink/internal/buildinfo"
)

// 内置加速镜像：直连失败时自动尝试
var builtinMirrors = []string{
	"https://ghfast.top",
	"https://ghproxy.com/https://github.com",
	"https://mirror.ghproxy.com",
}

// fetchLatestWebTagFromAtom 从 GitHub release atom feed 提取最新的 web-v* tag
func fetchLatestWebTagFromAtom(repo string, client *http.Client) string {
	return fetchWebTag("https://github.com/"+repo+"/releases.atom", client)
}

func fetchWebTag(feedURL string, client *http.Client) string {
	c := &http.Client{Timeout: 4 * time.Second}
	if client != nil {
		*c = *client
		c.Timeout = 4 * time.Second
	}
	req, err := http.NewRequest(http.MethodGet, feedURL, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "Veilink-WebManager/1.0")
	resp, err := c.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	var feed struct {
		Entries []struct {
			Links []struct {
				Href string `xml:"href,attr"`
			} `xml:"link"`
		} `xml:"entry"`
	}
	if err := xml.NewDecoder(io.LimitReader(resp.Body, 1024*1024)).Decode(&feed); err != nil {
		return ""
	}
	for _, entry := range feed.Entries {
		for _, link := range entry.Links {
			_, tag, found := strings.Cut(link.Href, "/releases/tag/")
			if found && strings.HasPrefix(tag, "web-v") && validVersion(tag) {
				return tag
			}
		}
	}
	return ""
}

// resolveLatestWebTag 解析最新前端发布 tag
func resolveLatestWebTag(repo string, client *http.Client) string {
	return fetchLatestWebTagFromAtom(repo, client)
}

func (m *WebManager) resolveLatestTag() string {
	m.mu.RLock()
	repo := m.cfg.Repo
	mirrors := append([]string(nil), m.cfg.GithubMirrors...)
	m.mu.RUnlock()
	for _, mirror := range mirrors {
		for _, url := range mirrorURLs(repo+"/releases.atom", mirror) {
			if tag := fetchWebTag(url, m.client); tag != "" {
				return tag
			}
		}
	}
	return resolveLatestWebTag(repo, m.client)
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

	// 本地静态资源目录（优先于环境变量 WEB_PREBUNDLED_DIR）
	PrebundledDir string `json:"-"`
}

// WebManager 管理前端静态资源的拉取与 serving
type WebManager struct {
	cfg        WebConfig
	mu         sync.RWMutex
	opMu       sync.Mutex
	root       string
	ver        string
	prebundled bool
	client     *http.Client
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
	m.opMu.Lock()
	defer m.opMu.Unlock()
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
	m.opMu.Lock()
	defer m.opMu.Unlock()
	if m.cfg.Mode == WebModeOff {
		return "", nil
	}
	var active activeWeb
	if data, err := os.ReadFile(filepath.Join(m.cfg.CacheDir, "active.json")); err == nil && json.Unmarshal(data, &active) == nil && active.Want == m.cfg.Version && active.Repo == m.cfg.Repo && active.Dir != "" && filepath.Base(active.Dir) == active.Dir && active.Dir != "." && active.Dir != ".." && validVersion(active.Version) {
		root := filepath.Join(m.cfg.CacheDir, active.Dir)
		if info, err := os.Stat(filepath.Join(root, "index.html")); err == nil && info.Mode().IsRegular() && info.Size() > 0 {
			m.mu.Lock()
			m.root, m.ver, m.prebundled = root, active.Version, false
			m.mu.Unlock()
			return root, nil
		}
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
	prebundled := m.cfg.PrebundledDir
	if prebundled == "" {
		prebundled = os.Getenv("WEB_PREBUNDLED_DIR")
	}
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
			m.prebundled = true
			ver := buildinfo.Version
			if ver == "" || ver == "dev" {
				ver = "prebundled"
			}
			m.ver = ver
			m.mu.Unlock()
			return prebundled, nil
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
		wantVer = m.resolveLatestTag()
		if wantVer == "" {
			return "", errors.New("cannot resolve latest web release")
		}
	}
	if !validVersion(wantVer) {
		return "", errors.New("invalid web version")
	}
	m.mu.RLock()
	if m.root != "" && m.ver == wantVer {
		defer m.mu.RUnlock()
		return m.root, nil
	}
	m.mu.RUnlock()

	dir := filepath.Join(m.cfg.CacheDir, sanitizeVersion(wantVer))
	if _, err := os.Stat(filepath.Join(dir, ".ok")); err != nil {
		if err := m.pull(wantVer, dir); err != nil {
			return "", err
		}
	}
	m.mu.Lock()
	m.root = dir
	m.ver = wantVer
	m.prebundled = false
	m.mu.Unlock()
	return dir, nil
}

// downloadURL 拼接下载地址（首选镜像）
func (m *WebManager) downloadURL(version string) string {
	m.mu.RLock()
	defer m.mu.RUnlock()
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
	if cleanVer != "" {
		add(fmt.Sprintf("%s/releases/download/%s/veilink-web-%s.tar.gz", repo, tag, cleanVer))
	}
	// 2. 通用资产名称: veilink-web.tar.gz
	add(fmt.Sprintf("%s/releases/download/%s/veilink-web.tar.gz", repo, tag))
	// 3. 冗余 tag 命名前缀资产名: veilink-web-${tag}.tar.gz (如 veilink-web-web-v0.4.0.tar.gz)
	add(fmt.Sprintf("%s/releases/download/%s/veilink-web-%s.tar.gz", repo, tag, tag))

	// 4. 容错尝试原始输入作为 tag（如果用户输入了非标准 tag）
	if v != tag {
		if cleanVer != "" {
			add(fmt.Sprintf("%s/releases/download/%s/veilink-web-%s.tar.gz", repo, v, cleanVer))
		}
		add(fmt.Sprintf("%s/releases/download/%s/veilink-web.tar.gz", repo, v))
	}

	return paths
}

// downloadCandidates 返回按优先级排序的下载地址：
// 1. 配置的镜像列表（按顺序）；2. 直连；3. 内置公共镜像
func (m *WebManager) downloadCandidates(version string) []string {
	m.mu.RLock()
	repo := m.cfg.Repo
	mirrors := append([]string(nil), m.cfg.GithubMirrors...)
	m.mu.RUnlock()
	paths := candidatePaths(repo, version)
	var urls []string
	seen := map[string]bool{}
	add := func(u string) {
		if !seen[u] {
			seen[u] = true
			urls = append(urls, u)
		}
	}

	configured := map[string]bool{}
	for _, mirror := range mirrors {
		configured[normalizeMirror(mirror)] = true
	}

	for _, mirror := range mirrors {
		for _, p := range paths {
			for _, url := range mirrorURLs(p, mirror) {
				add(url)
			}
		}
	}
	for _, p := range paths {
		add(assembleURL(p, ""))
	}
	for _, p := range paths {
		for _, b := range builtinMirrors {
			if configured[normalizeMirror(b)] {
				continue
			}
			add(assembleURL(p, b))
		}
	}
	return urls
}

func mirrorURLs(path, mirror string) []string {
	first := assembleURL(path, mirror)
	if mirror != "" && !strings.Contains(mirror, "github.com") {
		return []string{first, strings.TrimRight(mirror, "/") + "/https://github.com/" + path}
	}
	return []string{first}
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
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	targetVer := strings.TrimSpace(version)
	if targetVer == "" || targetVer == "latest" {
		if resolved := m.resolveLatestTag(); resolved != "" {
			targetVer = resolved
		} else {
			targetVer = "latest"
		}
	}
	var lastErr error
	candidates := m.downloadCandidates(targetVer)
	for _, url := range candidates {
		if ctx.Err() != nil {
			return fmt.Errorf("download web %s timed out after 25s: %w", version, ctx.Err())
		}
		if err := m.pullFrom(ctx, url, version, dir); err != nil {
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

func (m *WebManager) pullFrom(ctx context.Context, url, version, dir string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("download web %s: %w", version, err)
	}
	req.Header.Set("User-Agent", "Veilink-WebManager/1.0")

	candCtx, candCancel := context.WithTimeout(ctx, 8*time.Second)
	defer candCancel()
	req = req.WithContext(candCtx)

	resp, err := m.client.Do(req)
	if err != nil {
		return fmt.Errorf("download web %s: %w", version, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download web %s: status %d (url: %s)", version, resp.StatusCode, url)
	}
	if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
		return err
	}
	tmpDir, err := os.MkdirTemp(filepath.Dir(dir), ".web-extract-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)
	if err := extractTarGz(resp.Body, tmpDir); err != nil {
		os.RemoveAll(tmpDir)
		return fmt.Errorf("extract web %s: %w", version, err)
	}
	if info, err := os.Stat(filepath.Join(tmpDir, "index.html")); err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
		return errors.New("web archive has no index.html")
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
	m.opMu.Lock()
	defer m.opMu.Unlock()
	version = strings.TrimSpace(version)
	if version == "latest" {
		version = ""
	}
	if version != "" && !validVersion(version) {
		return errors.New("invalid web version")
	}
	target := version
	if target == "" {
		target = m.resolveLatestTag()
		if target == "" {
			return errors.New("cannot resolve latest web release")
		}
	} else {
		target, _ = normalizeWebTagAndFile(target)
	}
	m.mu.RLock()
	cache := m.cfg.CacheDir
	persist := m.persist
	mirrors := append([]string(nil), m.cfg.GithubMirrors...)
	previous := m.cfg.Version
	repo := m.cfg.Repo
	m.mu.RUnlock()
	if err := os.MkdirAll(cache, 0o755); err != nil {
		return err
	}
	dir, err := os.MkdirTemp(cache, sanitizeVersion(target)+"-")
	if err != nil {
		return err
	}
	if err := m.pull(target, dir); err != nil {
		os.RemoveAll(dir)
		return err
	}
	if persist != nil {
		if err := persist(mirrors, version, nil); err != nil {
			os.RemoveAll(dir)
			return fmt.Errorf("persist web configuration: %w", err)
		}
	}
	if err := saveActiveWeb(cache, activeWeb{Want: version, Version: target, Repo: repo, Dir: filepath.Base(dir)}); err != nil {
		if persist != nil {
			if rollbackErr := persist(mirrors, previous, nil); rollbackErr != nil {
				slog.Error("restore web configuration failed", "err", rollbackErr)
			}
		}
		os.RemoveAll(dir)
		return fmt.Errorf("persist active web: %w", err)
	}
	m.mu.Lock()
	m.cfg.Version = version
	m.root, m.ver, m.prebundled = dir, target, false
	m.mu.Unlock()
	return nil
}

type activeWeb struct {
	Want    string `json:"want"`
	Version string `json:"version"`
	Repo    string `json:"repo"`
	Dir     string `json:"dir"`
}

func saveActiveWeb(cache string, active activeWeb) error {
	f, err := os.CreateTemp(cache, ".active-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err := json.NewEncoder(f).Encode(active); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), filepath.Join(cache, "active.json"))
}

func validVersion(version string) bool {
	if len(version) == 0 || len(version) > 100 {
		return false
	}
	for _, c := range version {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return !strings.Contains(version, "..")
}

// WebStatus 前端状态（供设置页展示）
type WebStatus struct {
	Mode        string   `json:"mode"`
	WantVersion string   `json:"want_version"`
	ActiveVer   string   `json:"active_version"`
	Mirrors     []string `json:"mirrors"`
	FrontendURL string   `json:"frontend_url"`
	Repo        string   `json:"repo"`
	Root        string   `json:"-"`
	Serving     bool     `json:"serving"`
	Prebundled  bool     `json:"prebundled"`
}

// Status 返回当前前端配置与状态
func (m *WebManager) Status() WebStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()
	activeVer := m.ver
	isPrebundled := m.prebundled
	if activeVer == "" || activeVer == "prebundled" {
		if buildinfo.Version != "" && buildinfo.Version != "dev" {
			activeVer = buildinfo.Version
		}
	}
	return WebStatus{
		Mode:        string(m.cfg.Mode),
		WantVersion: m.cfg.Version,
		ActiveVer:   activeVer,
		Mirrors:     append([]string{}, m.cfg.GithubMirrors...),
		FrontendURL: m.cfg.FrontendURL,
		Repo:        m.cfg.Repo,
		Root:        m.root,
		Serving:     m.root != "",
		Prebundled:  isPrebundled,
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
	m.opMu.Lock()
	defer m.opMu.Unlock()
	url = strings.TrimSpace(url)
	m.mu.RLock()
	persist := m.persist
	mirrors := append([]string{}, m.cfg.GithubMirrors...)
	version := m.cfg.Version
	m.mu.RUnlock()
	if persist != nil {
		if err := persist(mirrors, version, &url); err != nil {
			return err
		}
	}
	m.mu.Lock()
	m.cfg.FrontendURL = url
	m.mu.Unlock()
	return nil
}

// SetMirrors 更新加速镜像列表并持久化到 DB（空列表 = 直连）
func (m *WebManager) SetMirrors(mirrors []string) error {
	m.opMu.Lock()
	defer m.opMu.Unlock()
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
	m.mu.RLock()
	persist := m.persist
	version := m.cfg.Version
	m.mu.RUnlock()
	if persist != nil {
		if err := persist(cleaned, version, nil); err != nil {
			return err
		}
	}
	m.mu.Lock()
	m.cfg.GithubMirrors = cleaned
	m.mu.Unlock()
	return nil
}

// ProbeResult 连通性探测结果
type ProbeResult struct {
	Mirror  string `json:"mirror"`
	URL     string `json:"url"`
	OK      bool   `json:"ok"`
	Status  int    `json:"status,omitempty"`
	Elapsed int64  `json:"elapsed_ms"`
	Error   string `json:"error,omitempty"`
}

// Probe 探测已保存的各加速地址的连通性（HEAD 请求，不下载）
func (m *WebManager) Probe(version string) []ProbeResult {
	m.mu.RLock()
	if version == "" {
		version = m.cfg.Version
		if version == "" {
			version = "latest"
		}
	}
	mirrors := append([]string(nil), m.cfg.GithubMirrors...)
	repo := m.cfg.Repo
	m.mu.RUnlock()

	// 需求：只测试保存过的地址
	if len(mirrors) == 0 {
		return make([]ProbeResult, 0)
	}

	targetVer := strings.TrimSpace(version)
	if targetVer == "" {
		m.mu.RLock()
		targetVer = m.cfg.Version
		m.mu.RUnlock()
	}
	if targetVer == "" || targetVer == "latest" {
		if resolved := m.resolveLatestTag(); resolved != "" {
			targetVer = resolved
		} else {
			targetVer = "latest"
		}
	}

	paths := candidatePaths(repo, targetVer)
	var testPath string
	if len(paths) > 0 {
		testPath = paths[0]
	} else {
		testPath = fmt.Sprintf("%s/releases/latest/download/veilink-web.tar.gz", repo)
	}

	results := make([]ProbeResult, len(mirrors))
	var wg sync.WaitGroup
	client := *m.client
	client.Timeout = 5 * time.Second

	for i, mirror := range mirrors {
		wg.Add(1)
		go func(idx int, mir string) {
			defer wg.Done()
			start := time.Now()
			r := ProbeResult{Mirror: mir}
			for _, targetURL := range mirrorURLs(testPath, mir) {
				r.URL = redactURL(targetURL)
				req, err := http.NewRequest(http.MethodHead, targetURL, nil)
				if err != nil {
					r.Error = err.Error()
					continue
				}
				req.Header.Set("User-Agent", "Veilink-Probe/1.0")
				resp, err := client.Do(req)
				if err != nil {
					r.Error = err.Error()
					continue
				}
				resp.Body.Close()
				r.Status = resp.StatusCode
				r.OK = resp.StatusCode >= 200 && resp.StatusCode < 400
				if r.OK {
					r.Error = ""
					break
				}
				r.Error = fmt.Sprintf("status %d", resp.StatusCode)
			}
			r.Elapsed = time.Since(start).Milliseconds()
			results[idx] = r
		}(i, mirror)
	}
	wg.Wait()
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
	if m.ver == "" || m.ver == "prebundled" {
		if buildinfo.Version != "" && buildinfo.Version != "dev" {
			return buildinfo.Version
		}
		if m.ver != "" {
			return m.ver
		}
		return buildinfo.Version
	}
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
	var total int64
	count := 0
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		target := filepath.Join(dest, hdr.Name)
		if filepath.IsAbs(hdr.Name) || (target != filepath.Clean(dest) && !strings.HasPrefix(target, filepath.Clean(dest)+string(os.PathSeparator))) || (target == filepath.Clean(dest) && hdr.Typeflag != tar.TypeDir) {
			return fmt.Errorf("illegal path: %s", hdr.Name)
		}
		total += hdr.Size
		count++
		if total > 128*1024*1024 || count > 10000 {
			return errors.New("web archive exceeds size limit")
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
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return err
			}
			if err := f.Close(); err != nil {
				return err
			}
		default:
			return errors.New("unsupported web archive entry")
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
