package httpapi

import (
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"veilink/internal/buildinfo"
	"veilink/internal/config"
	"veilink/internal/httpapi/backend"
	"veilink/internal/httpapi/web"
	"veilink/internal/logring"
	"veilink/internal/model"
	"veilink/internal/store"
)

type API struct {
	store      *store.Store
	insecure   bool
	ring       *logring.Ring
	keyStore   *backend.KeyStore
	webManager *web.WebManager
	streamHub  *backend.StreamHub
	tokenStore *backend.StreamTokenStore
	webPersist WebPersistConfig
	authFails  *failWindow
}

// WebPersistConfig 包含服务设置数据库和非持久化的静态资源路径。
type WebPersistConfig struct {
	DBPath  string
	HTMLDir string
}

// New 创建 Master 的 HTTP API 处理器。
// 注意：仅 Master 角色调用此函数，Server/Client 角色不启动 Web/API。
// WebManager 仅在 Master 下提供镜像内置的静态资源。
func New(s *store.Store, insecureLoopback bool, ring *logring.Ring, webPersist WebPersistConfig) http.Handler {
	// API Key 存储初始化（含旧版迁移）
	ks := backend.NewKeyStore(s.DB())
	if err := ks.Migrate(); err != nil {
		slog.Error("api keys migration failed", "err", err)
	}
	if pending, err := ks.LegacyAdminPending(); err != nil {
		slog.Error("legacy admin check failed", "err", err)
	} else if pending {
		slog.Warn("旧版管理员尚未迁移。请执行 veilink keys list，迁移出的 API Key 只在该命令输出中显示一次")
	}

	// WebManager 初始化
	wm := web.NewWebManager(web.WebConfig{PrebundledDir: webPersist.HTMLDir})
	if _, err := wm.Ensure(); err != nil {
		slog.Error("内置前端资源不可用，Web 请求将返回 503", "err", err)
	}

	a := &API{
		store:      s,
		insecure:   insecureLoopback,
		ring:       ring,
		keyStore:   ks,
		webManager: wm,
		streamHub:  backend.NewStreamHub(),
		tokenStore: backend.NewStreamTokenStore(),
		webPersist: webPersist,
		authFails:  newFailWindow(30, time.Minute),
	}
	return a
}

func output(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func failure(w http.ResponseWriter, code int) {
	text := "request failed"
	switch code {
	case 400:
		text = "invalid request or conflicting resource"
	case 401:
		text = "authentication required"
	case 403:
		text = "forbidden"
	case 404:
		text = "not found"
	case 429:
		text = "too many requests"
	}
	output(w, code, map[string]string{"error": text})
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		failure(w, 400)
		return false
	}
	limit := int64(64 << 10)
	if r.URL.Path == "/api/v1/nodes/generate" {
		limit = 4 << 10
	}
	if r.URL.Path == "/api/v1/nodes" || (strings.HasPrefix(r.URL.Path, "/api/v1/nodes/") && r.Method == http.MethodPut) {
		limit = 512 << 10
	}
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if d.Decode(v) != nil {
		failure(w, 400)
		return false
	}
	var more any
	if d.Decode(&more) != io.EOF {
		failure(w, 400)
		return false
	}
	return true
}

// publicPaths 免认证路径
var publicPaths = map[string]bool{
	"/api/version": true,
	"/healthz":     true,
	"/api/health":  true,
}

func (a *API) authenticate(r *http.Request) (backend.KeyRole, bool) {
	if publicPaths[r.URL.Path] {
		return backend.RoleAdmin, true // 公开路径视为通过（不做权限检查）
	}
	key := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if key == "" {
		key = r.Header.Get("X-API-Key")
	}
	if key == "" {
		return "", false
	}
	return a.keyStore.Validate(key)
}

func (a *API) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")

	// 2. 健康检查（免认证）
	if r.URL.Path == "/healthz" || r.URL.Path == "/api/health" {
		output(w, 200, map[string]string{"status": "ok"})
		return
	}

	// 3. 版本契约（免认证）
	if r.URL.Path == "/api/version" {
		output(w, 200, map[string]string{
			"api_version":     "v1",
			"backend_version": buildinfo.Version,
			"web_version":     a.webManager.Version(),
			"web_mode":        "builtin",
		})
		return
	}

	// 4. 老 API 路径 301 重定向到 /api/v1/*
	if strings.HasPrefix(r.URL.Path, "/api/") && !strings.HasPrefix(r.URL.Path, "/api/v1/") {
		http.Redirect(w, r, "/api/v1"+strings.TrimPrefix(r.URL.Path, "/api"), http.StatusMovedPermanently)
		return
	}

	// API 响应一律不缓存（认证前设置，401 也要带）
	if strings.HasPrefix(r.URL.Path, "/api/") {
		w.Header().Set("Cache-Control", "no-store")
	}

	// 5. API Key 认证。只有已签发的一次性 SSE 连接跳过 Key。
	var role backend.KeyRole
	var ok bool
	sse := r.URL.Path == "/api/v1/stream" && r.Method == http.MethodGet
	if !sse {
		role, ok = a.authenticate(r)
		if !ok && strings.HasPrefix(r.URL.Path, "/api/") {
			if !a.authFails.allow(clientIP(r)) {
				failure(w, 429)
				return
			}
			failure(w, 401)
			return
		}
	}

	// 6. SSE 流
	if r.URL.Path == "/api/v1/stream" && r.Method == "GET" {
		// EventSource 不能带 Header，用一次性 token
		if !a.tokenStore.Consume(r.URL.Query().Get("token")) {
			failure(w, 401)
			return
		}
		a.streamHub.ServeHTTP(w, r)
		return
	}
	if r.URL.Path == "/api/v1/stream/token" && r.Method == "POST" {
		token, issued := a.tokenStore.Issue()
		if !issued {
			failure(w, 429)
			return
		}
		output(w, 200, map[string]any{
			"token":      token,
			"expires_in": 60,
		})
		return
	}

	// 7. Key 管理接口（仅 admin）
	if strings.HasPrefix(r.URL.Path, "/api/v1/keys") {
		a.serveKeys(w, r, role)
		return
	}

	// 内置前端状态只读。
	if r.URL.Path == "/api/v1/web/config" {
		if role != backend.RoleAdmin {
			failure(w, 403)
			return
		}
		switch r.Method {
		case http.MethodGet:
			output(w, 200, a.webManager.Status())
			return
		default:
			failure(w, 404)
			return
		}
	}

	// 8d. master 通用配置（仅 admin）
	if r.URL.Path == "/api/v1/master/config" {
		if role != backend.RoleAdmin {
			failure(w, 403)
			return
		}
		if r.Method == "GET" {
			view, err := config.GetMasterConfigView(a.webPersist.DBPath)
			if err != nil {
				failure(w, 500)
				return
			}
			output(w, 200, view)
			return
		}
		if r.Method == "POST" {
			var req config.MasterConfigUpdate
			if !decode(w, r, &req) {
				return
			}
			needRestart, err := config.UpdateMasterConfig(a.webPersist.DBPath, req)
			if err != nil {
				output(w, 400, map[string]string{"error": err.Error()})
				return
			}
			output(w, 200, map[string]any{"ok": true, "need_restart": needRestart})
			return
		}
		failure(w, 405)
		return
	}

	// 9. 业务 API（/api/v1/*）
	if strings.HasPrefix(r.URL.Path, "/api/v1/") {
		a.serveAPI(w, r, role)
		return
	}

	// 11. 前端静态资源
	if root := a.webManager.Root(); root != "" {
		w.Header().Set("Cache-Control", "no-cache")
		p := filepath.Join(root, filepath.Clean(r.URL.Path))
		if info, err := os.Stat(p); err != nil || info.IsDir() {
			if strings.HasPrefix(r.URL.Path, "/assets/") || filepath.Ext(r.URL.Path) != "" {
				http.NotFound(w, r)
				return
			}
			http.ServeFile(w, r, filepath.Join(root, "index.html"))
			return
		}
		http.FileServer(http.Dir(root)).ServeHTTP(w, r)
		return
	}

	output(w, http.StatusServiceUnavailable, map[string]string{"error": "内置 Web 资源不可用，请检查统一镜像是否完整。"})
}

// serveKeys API Key 管理接口
func (a *API) serveKeys(w http.ResponseWriter, r *http.Request, role backend.KeyRole) {
	if role != backend.RoleAdmin {
		failure(w, 403)
		return
	}
	switch {
	case r.URL.Path == "/api/v1/keys" && r.Method == "GET":
		keys, err := a.keyStore.List()
		if err != nil {
			failure(w, 500)
			return
		}
		output(w, 200, keys)
	case r.URL.Path == "/api/v1/keys" && r.Method == "POST":
		var req struct {
			Name string `json:"name"`
			Role string `json:"role"`
		}
		if !decode(w, r, &req) {
			return
		}
		if req.Name == "" {
			req.Name = "key-" + strconv.Itoa(int(a.keyStore.Count()+1))
		}
		r := backend.RoleAdmin
		if req.Role == "readonly" {
			r = backend.RoleReadonly
			} else if req.Role != "" && req.Role != "admin" {
				failure(w, 400)
				return
		}
		plaintext, err := a.keyStore.Create(req.Name, r)
		if err != nil {
			failure(w, 400)
			return
		}
		// 明文仅返回一次
			output(w, 201, map[string]string{"key": plaintext, "name": req.Name, "role": string(r)})
	case strings.HasPrefix(r.URL.Path, "/api/v1/keys/") && r.Method == "DELETE":
		idStr := strings.TrimPrefix(r.URL.Path, "/api/v1/keys/")
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			failure(w, 400)
			return
		}
		if err := a.keyStore.Revoke(id); err != nil {
			failure(w, 400)
			return
		}
		output(w, 200, map[string]bool{"ok": true})
	default:
		failure(w, 404)
	}
}

// serveAPI 业务 API（路径已确认为 /api/v1/* 前缀）
func (a *API) serveAPI(w http.ResponseWriter, r *http.Request, role backend.KeyRole) {
	if r.Method != http.MethodGet && role != backend.RoleAdmin {
		failure(w, 403)
		return
	}
	// 去掉 /api/v1 前缀，复用原有分发逻辑
	p := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/"), "/")
	id := ""
	if len(p) > 1 {
		id = p[1]
	}
	var result any
	var err error
	matched := true
	switch p[0] {
	case "logs":
		if r.Method == "GET" && len(p) == 1 {
			q := r.URL.Query()
			source := q.Get("source")
			nodeID := q.Get("node_id")
			level := q.Get("level")
			limit := 200
			if ls := q.Get("limit"); ls != "" {
				if n, pe := strconv.Atoi(ls); pe == nil && n > 0 {
					limit = n
				}
			}
			if limit > 2000 {
				limit = 2000
			}
			if a.ring != nil {
				result = a.ring.Query(source, nodeID, level, limit)
			} else {
				result = []logring.Entry{}
			}
		} else {
			matched = false
		}
	case "traffic":
		if r.Method == http.MethodGet && len(p) == 1 {
			result, err = a.store.TrafficRows()
		} else {
			matched = false
		}
	case "stats":
		if r.Method == "GET" && len(p) == 1 {
			result, err = a.computeStats()
		} else {
			matched = false
		}
	case "nodes":
		if len(p) == 3 && (p[2] == "join" || p[2] == "enroll") {
			nodes, loadErr := a.store.Nodes()
			if loadErr != nil {
				failure(w, 400)
				return
			}
			for _, n := range nodes {
				if n.ID == id && n.Embedded {
					failure(w, 400)
					return
				}
			}
		}
		switch {
		case len(p) == 2 && id == "generate":
			if r.Method != http.MethodPost {
				failure(w, http.StatusNotFound)
				return
			}
			generate(w, r)
			return
		case r.Method == "GET" && len(p) == 1:
			result, err = a.store.ReportedNodes()
			if err == nil && role != backend.RoleAdmin {
				nodes, _ := result.([]store.ReportedNode)
				for i := range nodes {
					nodes[i] = redactReported(nodes[i])
				}
				result = nodes
			}
		case (r.Method == "POST" && len(p) == 1) || (r.Method == "PUT" && len(p) == 2):
			type nodeInput model.Node
			var in struct {
				nodeInput
				ClientTunnel json.RawMessage `json:"client_tunnel"`
			}
			if !decode(w, r, &in) {
				return
			}
			if in.ClientTunnel != nil {
				failure(w, http.StatusBadRequest)
				return
			}
			n := model.Node(in.nodeInput)
			n.ID = id
			result, err = a.store.SaveNode(n)
		case r.Method == "DELETE" && len(p) == 2:
			err = a.store.RemoveNode(id, true)
		case r.Method == "POST" && len(p) == 3 && p[2] == "refresh":
			var in struct{}
			if !decode(w, r, &in) {
				return
			}
			var connected bool
			connected, err = a.store.RequestRefresh(id)
			result = map[string]bool{"connected": connected}
		case r.Method == "POST" && len(p) == 3 && p[2] == "revoke":
			err = a.store.RemoveNode(id, false)
		case r.Method == "POST" && len(p) == 3 && p[2] == "reset-credential":
			err = a.store.ResetCredential(id)
			if err == nil {
				result = map[string]bool{"ok": true}
			}
		case r.Method == "POST" && len(p) == 3 && p[2] == "disabled":
			var in struct {
				Disabled bool `json:"disabled"`
			}
			if !decode(w, r, &in) {
				return
			}
			err = a.store.SetNodeDisabled(id, in.Disabled)
			if err == nil {
				result = map[string]bool{"connected": a.store.ControlConnected(id)}
			}
		case r.Method == "POST" && len(p) == 3 && p[2] == "join":
			a.joinCommand(w, r, id)
			return
		case r.Method == "DELETE" && len(p) == 3 && p[2] == "enroll":
			err = a.store.RevokeEnrollToken(id)
		case r.Method == "POST" && len(p) == 3 && p[2] == "enroll":
			var in struct {
				TTL int64 `json:"ttl_seconds"`
			}
			if !decode(w, r, &in) {
				return
			}
			if in.TTL == 0 {
				in.TTL = 3600
			}
			if in.TTL < 1 || in.TTL > 86400 {
				failure(w, 400)
				return
			}
			var token string
			token, err = a.store.EnrollToken(id, time.Duration(in.TTL)*time.Second)
			result = map[string]string{"token": token}
		default:
			matched = false
		}
	case "mappings":
		if len(p) == 2 && id == "status" && (r.Method != http.MethodGet || r.URL.RawQuery != "") {
			failure(w, http.StatusNotFound)
			return
		}
		switch {
		case r.Method == "GET" && len(p) == 1:
			result, err = a.store.Mappings()
		case r.Method == http.MethodGet && len(p) == 2 && id == "status":
			result, err = a.store.MappingStatuses()
		case (r.Method == "POST" && len(p) == 1) || (r.Method == "PUT" && len(p) == 2):
			var m model.Mapping
			if !decode(w, r, &m) {
				return
			}
			m.ID = id
			result, err = a.store.SaveMapping(m)
		case r.Method == "DELETE" && len(p) == 2:
			err = a.store.DeleteMapping(id)
		default:
			matched = false
		}
	case "audit":
		if r.Method == "GET" && len(p) == 1 {
			result, err = a.store.Audit()
		} else {
			matched = false
		}
	default:
		matched = false
	}
	if !matched {
		failure(w, 404)
		return
	}
	if err != nil {
		failure(w, 400)
		return
	}
	if r.Method != http.MethodGet {
		switch p[0] {
		case "nodes", "mappings":
			if p[0] == "nodes" && len(p) == 3 && p[2] == "enroll" {
				break
			}
			slog.Info("management operation completed", "resource", p[0], "method", r.Method, "id", id)
		}
	}
	if result == nil {
		result = map[string]bool{"ok": true}
	}
	switch value := result.(type) {
	case model.Mapping:
		value.BindingID = ""
		result = value
	case []model.Mapping:
		for i := range value {
			value[i].BindingID = ""
		}
		result = value
	}
	output(w, 200, result)
}

func (a *API) computeStats() (any, error) {
	nodes, err := a.store.Nodes()
	if err != nil {
		return nil, err
	}
	mappings, err := a.store.Mappings()
	if err != nil {
		return nil, err
	}
	online := 0
	now := time.Now().Unix()
	for _, n := range nodes {
		if n.LastSeen > 0 && now >= n.LastSeen && (now-n.LastSeen) < 90 && !n.Revoked {
			online++
		}
	}
	enabledMappings := 0
	for _, m := range mappings {
		if m.Enabled {
			enabledMappings++
		}
	}
	return map[string]any{
		"total_nodes":      len(nodes),
		"online_nodes":     online,
		"total_mappings":   len(mappings),
		"enabled_mappings": enabledMappings,
	}, nil
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || host == "" {
		host = r.RemoteAddr
	}
	if (host == "127.0.0.1" || host == "::1") && r.Header.Get("X-Forwarded-For") != "" {
		parts := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
		if client := strings.TrimSpace(parts[0]); client != "" {
			return client
		}
	}
	return host
}

type failWindow struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	hits   map[string][]time.Time
}

func newFailWindow(limit int, window time.Duration) *failWindow {
	return &failWindow{limit: limit, window: window, hits: map[string][]time.Time{}}
}

func (f *failWindow) allow(key string) bool {
	if f == nil {
		return true
	}
	now := time.Now()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.hits) > 512 {
		for k, times := range f.hits {
			active := times[:0]
			for _, at := range times {
				if now.Sub(at) < f.window {
					active = append(active, at)
				}
			}
			if len(active) == 0 {
				delete(f.hits, k)
			} else {
				f.hits[k] = active
			}
		}
	}
	kept := f.hits[key][:0]
	for _, at := range f.hits[key] {
		if now.Sub(at) < f.window {
			kept = append(kept, at)
		}
	}
	if len(kept) >= f.limit {
		f.hits[key] = kept
		return false
	}
	if len(kept) == 0 {
		f.hits[key] = []time.Time{now}
	} else {
		f.hits[key] = append(kept, now)
	}
	return true
}

func redactReported(n store.ReportedNode) store.ReportedNode {
	n.Tunnel = redactTunnel(n.Tunnel)
	if n.ClientTunnel != nil {
		copied := redactTunnel(*n.ClientTunnel)
		n.ClientTunnel = &copied
	}
	return n
}

func redactTunnel(t model.LocalTLS) model.LocalTLS {
	t.KeyPEM = ""
	t.Decryption = ""
	t.Reality.PrivateKey = ""
	t.Reality.Mldsa65Seed = ""
	t.Hysteria2.Password = ""
	return t
}
