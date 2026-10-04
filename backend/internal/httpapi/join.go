package httpapi

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// defaultJoinTTL matches frp-panel's quick-join token lifetime in seconds.
const defaultJoinTTL int64 = 1_000_000_000

// shellQuote keeps all generated values data, never executable shell syntax.
func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }

func joinAddress(raw string) (address, serverName string, err error) {
	u, err := url.Parse(raw)
	if err != nil || u == nil || (u.Scheme != "https" && u.Scheme != "http") || u.Opaque != "" || u.User != nil || u.Hostname() == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.ContainsAny(raw, "\r\n\t ") {
		return "", "", fmt.Errorf("master_url must be an HTTP or HTTPS origin")
	}
	host := u.Hostname()
	if net.ParseIP(host) == nil {
		for _, c := range host {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '.') {
				return "", "", fmt.Errorf("invalid hostname")
			}
		}
	}
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", "", fmt.Errorf("invalid port")
	}
	if u.Scheme == "https" {
		serverName = host
	}
	return net.JoinHostPort(host, port), serverName, nil
}

func (a *API) joinCommand(w http.ResponseWriter, r *http.Request, id string) {
	var in struct {
		MasterURL string `json:"master_url"`
		TTL       int64  `json:"ttl_seconds"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.TTL == 0 {
		in.TTL = defaultJoinTTL
	}
	address, serverName, err := joinAddress(in.MasterURL)
	if err != nil || in.TTL < 1 || in.TTL > defaultJoinTTL {
		failure(w, 400)
		return
	}
	nodes, err := a.store.Nodes()
	if err != nil {
		failure(w, 500)
		return
	}
	role := ""
	for _, n := range nodes {
		if n.ID == id && !n.Revoked && !n.Embedded {
			role = n.Role
			break
		}
	}
	if role != "client" && role != "server" {
		failure(w, 400)
		return
	}
	token, err := a.store.EnrollToken(id, time.Duration(in.TTL)*time.Second)
	if err != nil {
		failure(w, 400)
		return
	}
	// IDs may be operator-assigned. A fixed-length digest keeps Docker names
	// and filesystem path components bounded without exposing the identity.
	idHash := sha256.Sum256([]byte(id))
	app := "veilink-" + role + "-" + hex.EncodeToString(idHash[:16])
	root := "/opt/docker/" + app
	config := root + "/config"
	data := root + "/data"
	prepare := "mkdir -p " + shellQuote(config) + " " + shellQuote(data) + " && chown -R 65532:65532 " + shellQuote(config) + " " + shellQuote(data) + " && chmod 700 " + shellQuote(config) + " " + shellQuote(data)
	var command strings.Builder
	command.WriteString("docker run -itd --restart unless-stopped --name " + shellQuote(app))
	if role == "server" {
		command.WriteString(" --net host")
	}
	command.WriteString(" -v " + shellQuote(config+":/config:ro") + " -v " + shellQuote(data+":/data") + " -e TZ=Asia/Shanghai")
	command.WriteString(" ghcr.io/aurorax-neo/veilink:latest " + role)
	for _, v := range []struct{ flag, value string }{
		{"-master-addr", address}, {"-node-id", id},
		{"-enroll-token", token}, {"-state-dir", "/data/state"},
	} {
		command.WriteString(" " + v.flag + " " + shellQuote(v.value))
	}
	if serverName != "" {
		command.WriteString(" -control-server-name " + shellQuote(serverName))
	}
	warning := "命令包含可重复使用的接入令牌，可能出现在 shell 历史和 Docker inspect 的容器参数中；请勿分享或记录日志。不再需要注册时请撤销令牌。接入成功后保留 /data 状态并重建不带令牌的容器，删除原容器前妥善保护主机访问。"
	if serverName == "" {
		warning += "HTTP/h2c 管理连接不加密，仅用于可信网络；必须填写节点实际可达的 Master 地址，不能用另一台主机的 127.0.0.1。"
	} else {
		warning += "私有 Master CA 时，请将证书放入 " + config + "/ca.pem，并在角色子命令后添加 -control-ca /config/ca.pem；不要关闭 TLS 验证。"
	}
	output(w, 200, map[string]any{"prepare": prepare, "command": command.String(), "token": token, "expires_at": time.Now().Unix() + in.TTL, "warning": warning})
}
