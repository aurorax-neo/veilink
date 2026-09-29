package httpapi

import (
	"crypto/subtle"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"veilink/internal/auth"
	"veilink/internal/buildinfo"
	"veilink/internal/logring"
	"veilink/internal/model"
	"veilink/internal/store"
)

type session struct {
	version string
	csrf    string
	expires time.Time
}
type API struct {
	store       *store.Store
	insecure    bool
	web         http.Handler
	ring        *logring.Ring
	mu          sync.Mutex
	sessions    map[string]session
	loginWindow time.Time
	attempts    int
}

func New(s *store.Store, insecureLoopback bool, web http.Handler, ring *logring.Ring) http.Handler {
	if web == nil {
		web = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Write([]byte("Veilink management API\n"))
		})
	}
	return &API{store: s, insecure: insecureLoopback, web: web, ring: ring, sessions: map[string]session{}}
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
		text = "CSRF validation failed"
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
	if r.URL.Path == "/api/nodes/generate" {
		limit = 4 << 10
	}
	// Three PEM fields may each contain up to 64 KiB; JSON escaping adds overhead.
	if r.URL.Path == "/api/nodes" || (strings.HasPrefix(r.URL.Path, "/api/nodes/") && r.Method == http.MethodPut) {
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
func (a *API) cookie(w http.ResponseWriter, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: "veilink_session", Value: value, Path: "/", HttpOnly: true, Secure: !a.insecure, SameSite: http.SameSiteStrictMode, MaxAge: maxAge})
}
func (a *API) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
	if r.URL.Path == "/healthz" || r.URL.Path == "/api/health" {
		output(w, 200, map[string]string{"status": "ok"})
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/api/") {
		a.web.ServeHTTP(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	// Reject browser cross-site mutations, including login CSRF. Same-origin JSON
	// and the CSRF header cannot be sent by an untrusted origin without preflight.
	origin := r.Header.Get("Origin")
	parsed, originErr := url.Parse(origin)
	scheme := "https"
	if a.insecure {
		scheme = "http"
	}
	if r.Method != "GET" && (r.Header.Get("Sec-Fetch-Site") == "cross-site" || (origin != "" && (originErr != nil || parsed.Host != r.Host || parsed.Scheme != scheme))) {
		failure(w, 403)
		return
	}
	if r.URL.Path == "/api/setup" && r.Method == "GET" {
		has, err := a.store.HasAdmin()
		if err != nil {
			failure(w, 503)
			return
		}
		output(w, 200, map[string]bool{"registration_required": !has})
		return
	}
	if (r.URL.Path == "/api/login" || r.URL.Path == "/api/register") && r.Method == "POST" {
		a.mu.Lock()
		now := time.Now()
		if now.Sub(a.loginWindow) > time.Minute {
			a.loginWindow = now
			a.attempts = 0
		}
		a.attempts++
		allowed := a.attempts <= 10
		a.mu.Unlock()
		if !allowed {
			failure(w, 429)
			return
		}
		var in struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if !decode(w, r, &in) {
			return
		}
		if r.URL.Path == "/api/register" {
			err := a.store.InitAdmin(in.Username, in.Password)
			if err == store.ErrRegistrationClosed {
				failure(w, 409)
				return
			}
			if err == store.ErrInvalid {
				failure(w, 400)
				return
			}
			if err != nil {
				failure(w, 503)
				return
			}
			output(w, 201, map[string]bool{"ok": true})
			slog.Info("console account registered")
			return
		}
		version, valid := a.store.LoginVersion(in.Username, in.Password)
		if !valid {
			failure(w, 401)
			return
		}
		token := auth.Token()
		s := session{csrf: auth.Token(), version: version, expires: now.Add(12 * time.Hour)}
		a.mu.Lock()
		for k, v := range a.sessions {
			if now.After(v.expires) || v.version != version {
				delete(a.sessions, k)
			}
		}
		if len(a.sessions) >= 100 {
			a.mu.Unlock()
			failure(w, 429)
			return
		}
		a.sessions[auth.Hash(token)] = s
		a.mu.Unlock()
		slog.Info("console login succeeded")
		a.cookie(w, token, 43200)
		output(w, 200, map[string]string{"csrf": s.csrf})
		return
	}
	c, e := r.Cookie("veilink_session")
	if e != nil {
		failure(w, 401)
		return
	}
	a.mu.Lock()
	s, ok := a.sessions[auth.Hash(c.Value)]
	if time.Now().After(s.expires) {
		delete(a.sessions, auth.Hash(c.Value))
		ok = false
	}
	a.mu.Unlock()
	version, versionErr := a.store.AdminVersion()
	if !ok || versionErr != nil || s.version != version {
		failure(w, 401)
		return
	}
	if r.Method != "GET" && subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(s.csrf)) != 1 {
		failure(w, 403)
		return
	}
	if r.URL.Path == "/api/session" && r.Method == "GET" {
		output(w, 200, map[string]string{"csrf": s.csrf})
		return
	}
	if r.URL.Path == "/api/logout" && r.Method == "POST" {
		a.mu.Lock()
		delete(a.sessions, auth.Hash(c.Value))
		a.mu.Unlock()
		a.cookie(w, "", -1)
		slog.Info("console logout")
		output(w, 200, map[string]bool{"ok": true})
		return
	}
	p := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/"), "/")
	id := ""
	if len(p) > 1 {
		id = p[1]
	}
	var result any
	var err error
	matched := true
	switch p[0] {
	case "version":
		if r.Method == "GET" && len(p) == 1 {
			result = map[string]string{"version": buildinfo.Version, "commit": buildinfo.Commit}
		} else {
			matched = false
		}
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
		// Embedded enrollment belongs exclusively to the local master. Guard all
		// external token operations before they can issue, rotate, or revoke it.
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
			// Shadow the response-only field with RawMessage so even explicit
			// null (and case-insensitive JSON spellings) cannot bypass rejection.
			type nodeInput model.Node // Do not inherit Node.UnmarshalJSON.
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
		switch {
		case r.Method == "GET" && len(p) == 1:
			result, err = a.store.Mappings()
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
	// Session associations belong to node snapshots, never management payloads.
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
