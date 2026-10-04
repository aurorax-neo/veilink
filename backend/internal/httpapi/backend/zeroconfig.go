package backend

import (
	"fmt"
	"os"
	"path/filepath"
)

// resolveDataDir 零配置数据目录解析（全平台）
// 优先级：显式配置 > Docker /data > OS 标准目录 > 当前目录
func resolveDataDir() string {
	// 1. 环境变量 / 命令行显式指定
	if d := os.Getenv("DATA_DIR"); d != "" {
		return d
	}
	// 2. Docker 场景：/data 可写就用它
	if isWritable("/data") {
		return "/data"
	}
	// 3. OS 标准目录（跨平台）
	if dir, err := os.UserCacheDir(); err == nil {
		// Linux: ~/.cache/veilink
		// macOS: ~/Library/Caches/veilink
		// Windows: %LocalAppData%\veilink\Cache
		p := filepath.Join(dir, "veilink")
		if mkWritable(p) {
			return p
		}
	}
	// 4. 兜底：当前目录 ./data
	p, _ := filepath.Abs("./data")
	mkWritable(p)
	return p
}

func isWritable(dir string) bool {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return false
	}
	f, err := os.CreateTemp(dir, ".writetest")
	if err != nil {
		return false
	}
	f.Close()
	os.Remove(f.Name())
	return true
}

func mkWritable(dir string) bool {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return false
	}
	return isWritable(dir)
}

// 首次启动打印（只显示一次）
func printFirstRunInfo(apiKey, dataDir, webMode string, port int) {
	fmt.Printf(`
  __   __   _ _ _      _
  \ \ / /__(_) (_)___ | | __
   \ V // _ \ | | / __|| |/ /
    | ||  __/ | | \__ \|   <
    |_| \___|_|_|_|___/|_|\_\

  ✅ Veilink 已启动（零配置模式）

  📂 数据目录: %s
  🔑 管理员 API Key（仅显示一次，请保存）:
     %s
  🌐 管理界面: http://localhost:%d
  📦 前端模式: %s

  下次启动不再显示 Key，可通过以下方式管理：
    veilink keys list     # 查看（仅前缀）
    veilink keys create   # 新建
`, dataDir, apiKey, port, webMode)
}
