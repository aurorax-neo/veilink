package httpapi

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"veilink/internal/model"
	"veilink/internal/store"
)

func joinAppName(role, id string) string {
	h := sha256.Sum256([]byte(id))
	return "veilink-" + role + "-" + hex.EncodeToString(h[:16])
}

func TestJoinAddress(t *testing.T) {
	for _, tc := range []struct{ raw, address, name string }{
		{"https://panel.example", "panel.example:443", "panel.example"},
		{"https://127.0.0.1:8080", "127.0.0.1:8080", "127.0.0.1"},
		{"https://[::1]:8443/", "[::1]:8443", "::1"},
		{"http://panel.example", "panel.example:80", ""},
		{"http://192.168.1.10:8443", "192.168.1.10:8443", ""},
		{"http://[::1]:8443/", "[::1]:8443", ""},
	} {
		a, n, e := joinAddress(tc.raw)
		if e != nil || a != tc.address || n != tc.name {
			t.Fatalf("%s: %s %s %v", tc.raw, a, n, e)
		}
	}
	for _, raw := range []string{"", "localhost:8443", "ftp://host", "http://user:pass@host", "http://host/api", "http://host?q=1", "http://host/#x", "https://user:pass@host", "https://host/api", "https://host?q=1", "https://host?", "https://host:0", "https://host:65536", "https://evil'$(id)", "https://host\n", "https://host/#x"} {
		if _, _, e := joinAddress(raw); e == nil {
			t.Errorf("accepted %q", raw)
		}
	}
	if shellQuote("a'b") != "'a'\"'\"'b'" {
		t.Fatal("unsafe shell quoting")
	}
}

func TestJoinCommandAuthenticationRotationAndRevocation(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Open(filepath.Join(dir, "db"), filepath.Join(dir, "key"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = s.InitAdmin("admin", "long test password"); err != nil {
		t.Fatal(err)
	}
	n, err := s.SaveNode(model.Node{Name: "join-client", Role: "client"})
	if err != nil {
		t.Fatal(err)
	}
	h := New(s, true, nil, nil)
	var cookie *http.Cookie
	csrf := ""
	call := func(method, path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-CSRF-Token", csrf)
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	path := "/api/nodes/" + n.ID + "/join"
	body := `{"master_url":"https://panel.example:8443","ttl_seconds":60}`
	if w := call("POST", path, body); w.Code != 401 {
		t.Fatal("unauthenticated join", w.Code)
	}
	w := call("POST", "/api/login", `{"username":"admin","password":"long test password"}`)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	cookie = w.Result().Cookies()[0]
	var login map[string]string
	json.Unmarshal(w.Body.Bytes(), &login)
	if w = call("POST", path, body); w.Code != 403 {
		t.Fatal("join missing csrf", w.Code)
	}
	csrf = login["csrf"]
	type response struct {
		Command string `json:"command"`
		Prepare string `json:"prepare"`
		Warning string `json:"warning"`
		Token   string `json:"token"`
		Expires int64  `json:"expires_at"`
	}
	generate := func() response {
		t.Helper()
		w := call("POST", path, body)
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		var r response
		if err := json.Unmarshal(w.Body.Bytes(), &r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	body = `{"master_url":"https://panel.example:8443"}`
	defaultTTL := generate()
	if delta := defaultTTL.Expires - time.Now().Unix(); delta < 999999995 || delta > 1000000000 {
		t.Fatal("omitted join TTL must match frp-panel lifetime")
	}
	body = `{"master_url":"https://panel.example:8443","ttl_seconds":60}`
	old := generate()
	fresh := generate()
	if _, err = s.Enroll(n.ID, old.Token); err == nil {
		t.Fatal("rotated token accepted")
	}
	app := joinAppName("client", n.ID)
	root := "/opt/docker/" + app
	config := root + "/config"
	data := root + "/data"
	if fresh.Prepare != "mkdir -p "+shellQuote(config)+" "+shellQuote(data)+" && chown -R 65532:65532 "+shellQuote(config)+" "+shellQuote(data)+" && chmod 700 "+shellQuote(config)+" "+shellQuote(data) {
		t.Fatalf("bad preparation: %q", fresh.Prepare)
	}
	expected := "docker run -itd --restart unless-stopped --name " + shellQuote(app) +
		" -v " + shellQuote(config+":/config:ro") + " -v " + shellQuote(data+":/data") + " -e TZ=Asia/Shanghai" +
		" ghcr.io/aurorax-neo/veilink:latest client -master-addr " + shellQuote("panel.example:8443") + " -node-id " + shellQuote(n.ID) +
		" -enroll-token " + shellQuote(fresh.Token) + " -state-dir '/data/state' -control-server-name 'panel.example'"
	if fresh.Command != expected || strings.Contains(fresh.Command, "--net") || strings.Contains(fresh.Command, " -p ") {
		t.Fatal("client Docker policy violated", fresh.Command)
	}
	if !strings.Contains(fresh.Warning, "-control-ca /config/ca.pem") || !strings.Contains(fresh.Warning, "shell 历史") || !strings.Contains(fresh.Warning, "Docker inspect") || fresh.Expires < time.Now().Unix()+55 || fresh.Expires > time.Now().Unix()+60 {
		t.Fatal("bad join response metadata")
	}
	if strings.Contains(fresh.Command, "VEILINK_") || strings.Contains(fresh.Command, " -config ") || strings.Contains(fresh.Command, "env -i") || strings.Contains(fresh.Command, "-control-ca") || strings.Contains(fresh.Warning, "-e VEILINK_CONTROL_CA") {
		t.Fatal("join command contains extraneous configuration")
	}
	if strings.Contains(fresh.Command, old.Token) || !strings.Contains(old.Command, shellQuote(old.Token)) {
		t.Fatal("rotation did not replace command credential")
	}
	if w = call("DELETE", "/api/nodes/"+n.ID+"/enroll", ""); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if _, err = s.Enroll(n.ID, fresh.Token); err == nil {
		t.Fatal("revoked token accepted")
	}
	fresh = generate()
	credential, err := s.Enroll(n.ID, fresh.Token)
	if err != nil {
		t.Fatal(err)
	}
	credentialAgain, err := s.Enroll(n.ID, fresh.Token)
	if err != nil || credentialAgain != credential {
		t.Fatal("active join token was not reusable")
	}
	if w = call("DELETE", "/api/nodes/"+n.ID+"/enroll", ""); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if _, err = s.Snapshot(n.ID, credential); err != nil {
		t.Fatal("token revoke revoked active node", err)
	}
	for _, bad := range []string{`{"master_url":"https://host","ttl_seconds":1000000001}`, `{"master_url":"https://host;id"}`, `{"master_url":"ftp://host"}`, `{"master_url":"https://host","ttl_seconds":-1}`} {
		if w = call("POST", path, bad); w.Code != 400 {
			t.Fatal("accepted invalid join", w.Code)
		}
	}
	body = `{"master_url":"http://192.168.1.10:8443","ttl_seconds":60}`
	httpClient := generate()
	if !strings.Contains(httpClient.Command, " -master-addr '192.168.1.10:8443'") || strings.Contains(httpClient.Command, "-control-server-name") || strings.Contains(httpClient.Command, "-control-ca") || !strings.Contains(httpClient.Warning, "HTTP/h2c 管理连接不加密") || strings.Contains(httpClient.Warning, "私有 Master CA") {
		t.Fatal("HTTP client command must use h2c with an explicit warning", httpClient.Command, httpClient.Warning)
	}
	server, err := s.SaveNode(model.Node{Name: "join-server", Role: "server", Address: "example.com", Port: 8443})
	if err != nil {
		t.Fatal(err)
	}
	serverPath := "/api/nodes/" + server.ID + "/join"
	body = `{"master_url":"https://panel.example:8443","ttl_seconds":60}`
	w = call("POST", serverPath, body)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var serverJoin response
	if err := json.Unmarshal(w.Body.Bytes(), &serverJoin); err != nil {
		t.Fatal(err)
	}
	serverApp := joinAppName("server", server.ID)
	serverRoot := "/opt/docker/" + serverApp
	serverExpected := "docker run -itd --restart unless-stopped --name " + shellQuote(serverApp) + " --net host" +
		" -v " + shellQuote(serverRoot+"/config:/config:ro") + " -v " + shellQuote(serverRoot+"/data:/data") + " -e TZ=Asia/Shanghai" +
		" ghcr.io/aurorax-neo/veilink:latest server -master-addr 'panel.example:8443' -node-id " + shellQuote(server.ID) +
		" -enroll-token " + shellQuote(serverJoin.Token) + " -state-dir '/data/state' -control-server-name 'panel.example'"
	if serverJoin.Command != serverExpected || strings.Contains(serverJoin.Command, " -p ") {
		t.Fatal("server Docker network policy violated", serverJoin.Command)
	}
	body = `{"master_url":"http://192.168.1.10:8443","ttl_seconds":60}`
	w = call("POST", serverPath, body)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var httpServer response
	if err := json.Unmarshal(w.Body.Bytes(), &httpServer); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(httpServer.Command, " --net host") || !strings.Contains(httpServer.Command, " -master-addr '192.168.1.10:8443'") || strings.Contains(httpServer.Command, "-control-server-name") || strings.Contains(httpServer.Command, "-control-ca") {
		t.Fatal("HTTP server command must use h2c and host network", httpServer.Command)
	}
	body = `{"master_url":"https://panel.example:8443","ttl_seconds":60}`
	longID := strings.Repeat("x", 600)
	longNode, err := s.SaveNode(model.Node{ID: longID, Name: "long-id", Role: "client"})
	if err != nil {
		t.Fatal(err)
	}
	w = call("POST", "/api/nodes/"+longNode.ID+"/join", body)
	if w.Code != 200 {
		t.Fatal("long ID join failed", w.Code, w.Body.String())
	}
	var longJoin response
	if err := json.Unmarshal(w.Body.Bytes(), &longJoin); err != nil {
		t.Fatal(err)
	}
	if len(joinAppName("client", longID)) > 80 || !strings.Contains(longJoin.Command, "--name "+shellQuote(joinAppName("client", longID))) || !strings.Contains(longJoin.Prepare, "/opt/docker/"+joinAppName("client", longID)+"/data") {
		t.Fatal("long ID produced an unbounded or unsafe Docker path")
	}
	if !strings.Contains(serverJoin.Command, " -v "+shellQuote(serverRoot+"/config:/config:ro")) || !strings.Contains(serverJoin.Command, " -v "+shellQuote(serverRoot+"/data:/data")) || !strings.Contains(serverJoin.Command, " -enroll-token "+shellQuote(serverJoin.Token)) {
		t.Fatal("server lost data or enrollment token")
	}
	if w = call("GET", "/api/bindings", ""); w.Code != 404 {
		t.Fatal("binding management still exposed")
	}
	if err = s.RemoveNode(n.ID, false); err != nil {
		t.Fatal(err)
	}
	if w = call("POST", path, body); w.Code != 400 {
		t.Fatal("revoked node got token")
	}
}
