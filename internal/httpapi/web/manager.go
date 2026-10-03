package web

import (
	"archive/tar"
	"compress/gzip"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// LoadConfigFromEnv 从环境变量加载配置
func LoadConfigFromEnv() WebConfig {
	return WebConfig{
		Mode:         WebMode(getenv("WEB_MODE", "pull")),
		Version:      os.Getenv("WEB_VERSION"),
		CacheDir:     getenv("WEB_CACHE_DIR", "/data/web"),
		GithubMirror: os.Getenv("WEB_GITHUB_MIRROR"),
		Repo:         getenv("WEB_REPO", "aurorax-neo/veilink"),
		EnableCORS:   getenv("WEB_CORS", "true") == "true",
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
	var path string
	if version == "latest" {
		path = fmt.Sprintf("%s/releases/latest/download/veilink-web.tar.gz", m.cfg.Repo)
	} else {
		path = fmt.Sprintf("%s/releases/download/%s/veilink-web-%s.tar.gz",
			m.cfg.Repo, version, version)
	}
	mirror := strings.TrimRight(m.cfg.GithubMirror, "/")
	if mirror == "" {
		return "https://github.com/" + path
	}
	// 加速地址格式兼容两种写法：
	// 1. https://gh-proxy.com/https://github.com  → 拼接完整 URL
	// 2. https://mirror.ghproxy.com/              → 替换域名
	if strings.Contains(mirror, "://github.com") || strings.HasSuffix(mirror, "github.com") {
		return mirror + "/" + path
	}
	// 纯域名镜像：替换 github.com
	return mirror + "/" + path
}

func (m *WebManager) pull(version, dir string) error {
	url := m.downloadURL(version)
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
	}
	m.mu.Lock()
	m.ver = ""
	m.mu.Unlock()
	_, err := m.ensurePulled()
	return err
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
