//go:build integration

// Package integration 三角色联动测试：master/server/client 真跑起来
package integration

import (
	"fmt"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestThreeRolesCoordinated(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX only")
	}
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "../.."))
	dir := t.TempDir()
	bin := filepath.Join(dir, "veilink")
	command(t, root, nil, "go", "build", "-o", bin, "./cmd/veilink")

	controlPort := freePort(t)
	tunnelPort := freePort(t)
	_ = tunnelPort

	// 启动 master
	masterFlags := []string{
		"-database", filepath.Join(dir, "master.db"),
		"-deployment-key", filepath.Join(dir, "master.key"),
		"-listen-addr", fmt.Sprintf("127.0.0.1:%d", controlPort),
		"-embedded-server-enabled=false",
	}
	master := launch(t, bin, "master", masterFlags...)

	// 等待 master 就绪并获取 API Key
	// master 首次启动会打印 API Key，需要从日志读取
	time.Sleep(2 * time.Second)

	base := fmt.Sprintf("http://127.0.0.1:%d", controlPort)
	// TODO: 从 master 日志提取 API Key

	t.Logf("Master 启动在 %s", base)
	_ = master

	// 测试矩阵：协议 × 传输 × 安全
	matrix := []struct {
		name      string
		protocol  string
		transport string
		security  string
		xhttpMode string
	}{
		{"vless-tcp-tls", "vless", "tcp", "tls", ""},
		{"vless-tcp-reality", "vless", "tcp", "reality", ""},
		{"vless-xhttp-packet-up", "vless", "xhttp", "tls", "packet-up"},
		{"vless-xhttp-auto", "vless", "xhttp", "tls", "auto"},
		{"vless-xhttp-auto-reality", "vless", "xhttp", "reality", "auto"},
	}

	for _, m := range matrix {
		t.Run(m.name, func(t *testing.T) {
			t.Logf("测试组合: %s", m.name)
			// TODO: 创建节点、启动 server/client、验证流量
		})
	}
}
