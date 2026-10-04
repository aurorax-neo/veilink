package httpapi

import (
	"os"
	"testing"
)

// TestMain 全局禁用测试中的前端拉取，避免网络依赖导致测试缓慢/抖动
func TestMain(m *testing.M) {
	_ = os.Setenv("WEB_MODE", "off")
	os.Exit(m.Run())
}
