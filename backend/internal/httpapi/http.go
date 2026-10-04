package httpapi

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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
	webCfg     web.WebConfig
	webPersist WebPersistConfig
}

// WebPersistConfig 前端配置的 DB 持久化参数（master_config 表）
type WebPersistConfig struct {
	Mirrors     []string
	Version     string
	FrontendURL string
	Mode        string
	DBPath      string
	HTMLDir     string
}

// New 创建 Master 的 HTTP API 处理器。
// 注意：仅 Master 角色调用此函数，Server/Client 角色不启动 Web/API。
// WebManager 仅在 Master 下初始化（pull 前端），s/c 二进制不包含也不触发拉取逻辑。
func New(s *store.Store, insecureLoopback bool, ring *logring.Ring, webPersist WebPersistConfig) http.Handler {
	// API Key 存储初始化（含旧版迁移）
	ks := backend.NewKeyStore(s.DB())
	if err := ks.Migrate(); err != nil {
		slog.Error("api keys migration failed", "err", err)
	}
	// 旧版迁移提示
	if mk := ks.MigratedKey(); mk != "" {
		slog.Warn("检测到旧版管理员账号，已自动迁移为 API Key（旧用户名密码已失效）",
			"key", mk, "note", "请妥善保存，此 Key 仅显示一次")
	}
	// 首次启动自动生成
	if plaintext, created, err := ks.EnsureDefaultAdmin(); err != nil {
		slog.Error("ensure default admin key failed", "err", err)
	} else if created {
		slog.Warn("未配置 API Key，已自动生成管理员 Key（仅显示一次，请妥善保存）",
			"key", plaintext)
	}

	// WebManager 初始化
	webCfg := web.LoadConfigFromEnv()
	if webPersist.HTMLDir != "" {
		webCfg.PrebundledDir = webPersist.HTMLDir
	}
	wm := web.NewWebManager(webCfg)
	// DB 持久化的配置覆盖环境变量（设置页/CLI 保存的值优先）
	wm.ApplyPersisted(webPersist.Mirrors, webPersist.Version, webPersist.FrontendURL, webPersist.Mode)
	// 设置页的保存写回 DB 的 master_config 表
	if webPersist.DBPath != "" {
		dbPath := webPersist.DBPath
		wm.SetPersist(func(mirrors []string, version string, frontendURL *string) error {
			return config.UpdateWebConfig(dbPath, mirrors, version, true, frontendURL)
		})
	}
	if _, err := wm.Ensure(); err != nil {
		slog.Error("前端初始化失败，降级为纯 API 模式", "err", err)
	}

	a := &API{
		store:      s,
		insecure:   insecureLoopback,
		ring:       ring,
		keyStore:   ks,
		webManager: wm,
		streamHub:  backend.NewStreamHub(),
		tokenStore: backend.NewStreamTokenStore(),
		webCfg:     webCfg,
		webPersist: webPersist,
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
	// query 参数方式默认关闭，需显式开启
	if key == "" && os.Getenv("WEB_ALLOW_QUERY_KEY") == "true" {
		key = r.URL.Query().Get("api_key")
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

	// 1. CORS
	if a.webCfg.EnableCORS {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "*")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
	}

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
			"web_mode":        string(a.webCfg.Mode),
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

	// 5. API Key 认证（SSE 用一次性 token，跳过 Key 检查）
	var role backend.KeyRole
	var ok bool
	isStream := strings.HasPrefix(r.URL.Path, "/api/v1/stream")
	if !isStream {
		role, ok = a.authenticate(r)
		if !ok && strings.HasPrefix(r.URL.Path, "/api/") {
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
		output(w, 200, map[string]any{
			"token":      a.tokenStore.Issue(),
			"expires_in": 60,
		})
		return
	}

	// 7. Key 管理接口（仅 admin）
	if strings.HasPrefix(r.URL.Path, "/api/v1/keys") {
		a.serveKeys(w, r, role)
		return
	}

	// 8. 前端热更新（仅 admin）
	if r.URL.Path == "/api/v1/web/update" && r.Method == "POST" {
		if role != backend.RoleAdmin {
			failure(w, 403)
			return
		}
		var req struct {
			Version string `json:"version"`
		}
		if !decode(w, r, &req) {
			return
		}
		if err := a.webManager.Update(req.Version); err != nil {
			slog.Error("web update failed", "err", err)
			output(w, 500, map[string]string{"error": "前端更新失败：请检查版本是否存在、镜像连通性及缓存目录写权限。当前前端未切换，详细原因见 Master 日志。"})
			return
		}
		output(w, 200, map[string]bool{"ok": true})
		return
	}

	// 8b. 前端配置查询/更新（仅 admin）
	if r.URL.Path == "/api/v1/web/config" {
		if role != backend.RoleAdmin {
			failure(w, 403)
			return
		}
		switch r.Method {
		case http.MethodGet:
			output(w, 200, a.webManager.Status())
			return
		case http.MethodPost:
			var req struct {
				Mirrors []string `json:"mirrors"`
				// 兼容旧单值字段
				Mirror *string `json:"mirror"`
				// CPA 自定义前端地址（null=不改，""=清空）
				FrontendURL *string `json:"frontend_url"`
			}
			if !decode(w, r, &req) {
				return
			}
			mirrors := req.Mirrors
			if mirrors == nil && req.Mirror != nil {
				if *req.Mirror != "" {
					mirrors = []string{*req.Mirror}
				} else {
					mirrors = []string{}
				}
			}
			if mirrors != nil {
				if err := a.webManager.SetMirrors(mirrors); err != nil {
					slog.Error("web config save failed", "err", err)
					failure(w, 500)
					return
				}
			}
			if req.FrontendURL != nil {
				if err := a.webManager.SetFrontendURL(*req.FrontendURL); err != nil {
					slog.Error("frontend url save failed", "err", err)
					failure(w, 500)
					return
				}
			}
			output(w, 200, a.webManager.Status())
			return
		default:
			failure(w, 404)
			return
		}
	}

	// 8c. 前端下载地址连通性探测（仅 admin）
	if r.URL.Path == "/api/v1/web/probe" && r.Method == "POST" {
		if role != backend.RoleAdmin {
			failure(w, 403)
			return
		}
		var req struct {
			Version string `json:"version"`
		}
		_ = decode(w, r, &req)
		output(w, 200, map[string]any{"results": a.webManager.Probe(req.Version)})
		return
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
			// WebMode 生效：实时更新 webManager
			if req.WebMode != nil {
				a.webManager.ApplyPersisted(nil, "", "", *req.WebMode)
			}
			output(w, 200, map[string]any{"ok": true, "need_restart": needRestart})
			return
		}
		failure(w, 405)
		return
	}

	// 9. 业务 API（/api/v1/*）
	if strings.HasPrefix(r.URL.Path, "/api/v1/") {
		a.serveAPI(w, r)
		return
	}

	// 10. CPA 自定义前端地址：重定向到分离部署的前端
	if redirect := a.webManager.FrontendRedirect(); redirect != "" {
		// 只重定向页面请求，API 请求不受影响（前面已处理）
		if r.URL.Path == "/" || !strings.HasPrefix(r.URL.Path, "/api/") {
			target := strings.TrimRight(redirect, "/")
			if r.URL.Path != "/" {
				target += r.URL.Path
			}
			if r.URL.RawQuery != "" {
				target += "?" + r.URL.RawQuery
			}
			http.Redirect(w, r, target, http.StatusFound)
			return
		}
	}

	// 11. 前端静态资源
	if root := a.webManager.Root(); root != "" {
		p := filepath.Join(root, filepath.Clean(r.URL.Path))
		if info, err := os.Stat(p); os.IsNotExist(err) || info.IsDir() {
			http.ServeFile(w, r, filepath.Join(root, "index.html"))
			return
		}
		http.FileServer(http.Dir(root)).ServeHTTP(w, r)
		return
	}

	// 11. 纯 API 模式兜底
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"mode":"api-only","message":"Web UI not hosted. Set WEB_MODE=pull or deploy veilink-web separately."}`))
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
		}
		plaintext, err := a.keyStore.Create(req.Name, r)
		if err != nil {
			failure(w, 400)
			return
		}
		// 明文仅返回一次
		output(w, 201, map[string]string{"key": plaintext, "name": req.Name})
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
func (a *API) serveAPI(w http.ResponseWriter, r *http.Request) {
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
