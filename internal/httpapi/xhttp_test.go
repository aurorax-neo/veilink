package httpapi

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"veilink/internal/model"
	"veilink/internal/store"
	"veilink/internal/tunnel"
)

func TestXHTTPJSONAPI(t *testing.T) {
	d := t.TempDir()
	s, err := store.Open(filepath.Join(d, "db"), filepath.Join(d, "key"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = s.InitAdmin("admin", "long test password"); err != nil {
		t.Fatal(err)
	}
	h := New(s, true, nil, nil)
	var cookie *http.Cookie
	csrf := ""
	call := func(body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/api/nodes", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-CSRF-Token", csrf)
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if w := call(`{"role":"server","name":"xhttp"}`); w.Code != 401 {
		t.Fatal(w.Code)
	}
	r := httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"username":"admin","password":"long test password"}`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	cookie = w.Result().Cookies()[0]
	var login map[string]string
	if err = json.Unmarshal(w.Body.Bytes(), &login); err != nil {
		t.Fatal(err)
	}
	dec, _, _, _, err := tunnel.GenerateVLESSEnc()
	if err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf(`{"name":"xhttp","role":"server","address":"cdn.example.com","port":443,"connect_endpoints":[{"id":"up","name":"上行","host":"cdn.example.com","port":443,"enabled":true},{"id":"down","name":"下行","host":"download.example.com","port":443,"enabled":true},{"id":"off","name":"禁用","host":"off.example.com","port":443,"enabled":false}],"tunnel":{"transport_security":"plain","listen_port":8444,"decryption":%q,"xhttp":{"path":"/cdn/","mode":"packet-up","tls":true,"download_endpoint_id":"down"}}}`, dec)
	h2cBody := fmt.Sprintf(`{"name":"h2c","role":"server","address":"127.0.0.1","port":8445,"tunnel":{"transport_security":"plain","listen_port":8445,"decryption":%q,"xhttp":{"host":"edge.example.com","path":"/h2c/","mode":"packet-up","tls":false,"http_version":"2","uplink_http_method":"PUT"}}}`, dec)
	if w = call(body); w.Code != 403 {
		t.Fatal("CSRF bypass", w.Code)
	}
	csrf = login["csrf"]
	for name, bad := range map[string]string{
		"stream-policy-packet":       strings.Replace(body, `"tls":true`, `"tls":true,"stream_up_server_secs":1`, 1),
		"stream-policy-type":         strings.Replace(body, `"tls":true`, `"tls":true,"stream_up_server_secs":"1"`, 1),
		"buffer-too-large":           strings.Replace(body, `"tls":true`, `"tls":true,"max_buffered_posts":33`, 1),
		"concurrent-window":          strings.Replace(body, `"tls":true`, `"tls":true,"max_buffered_posts":1,"max_concurrent_posts":3`, 1),
		"buffer-wrong-type":          strings.Replace(body, `"tls":true`, `"tls":true,"max_buffered_posts":"4"`, 1),
		"reserved-custom-header":     strings.Replace(body, `"tls":true`, `"tls":true,"headers":{"Cookie":"stolen"}`, 1),
		"duplicate-custom-header":    strings.Replace(body, `"tls":true`, `"tls":true,"headers":{"X-Custom-Key":"a","x-custom-key":"b"}`, 1),
		"wrong-custom-header":        strings.Replace(body, `"tls":true`, `"tls":true,"headers":{"X-Custom-Key":2}`, 1),
		"unpaired-header-value":      strings.Replace(body, `"tls":true`, `"tls":true,"headers":{"X-Custom-Key":"\ud800"}`, 1),
		"unknown-header-option":      strings.Replace(body, `"tls":true`, `"tls":true,"headers":{"User-Agent":"test"},"unsupported":1`, 1),
		"unknown-option":             strings.Replace(body, `"tls":true`, `"tls":true,"host_override":"override.example"`, 1),
		"unsupported-mode":           strings.Replace(body, "packet-up", "stream-one", 1),
		"invalid-host":               strings.Replace(body, `"tls":true`, `"tls":true,"host":"edge.example.com:443"`, 1),
		"wrong-type":                 strings.Replace(body, `"tls":true`, `"tls":"true"`, 1),
		"grpc-header-packet-only":    strings.Replace(body, `"tls":true`, `"tls":true,"no_grpc_header":true`, 1),
		"wrong-header-type":          strings.Replace(body, `"tls":true`, `"tls":true,"no_sse_header":"true"`, 1),
		"header-limit-too-high":      strings.Replace(body, `"tls":true`, `"tls":true,"server_max_header_bytes":32769`, 1),
		"header-limit-wrong-type":    strings.Replace(body, `"tls":true`, `"tls":true,"server_max_header_bytes":"16384"`, 1),
		"get-uplink":                 strings.Replace(body, `"tls":true`, `"tls":true,"uplink_http_method":"GET"`, 1),
		"h2c-without-encryption":     strings.Replace(h2cBody, fmt.Sprintf(`"decryption":%q`, dec), `"decryption":"none"`, 1),
		"h2c-stream":                 strings.Replace(h2cBody, `"mode":"packet-up"`, `"mode":"stream-up"`, 1),
		"interval-negative":          strings.Replace(h2cBody, `"tls":false`, `"tls":false,"min_posts_interval_ms":-1`, 1),
		"interval-wrong-type":        strings.Replace(h2cBody, `"tls":false`, `"tls":false,"min_posts_interval_ms":"45"`, 1),
		"interval-max-without-min":   strings.Replace(body, `"tls":true`, `"tls":true,"max_posts_interval_ms":30`, 1),
		"interval-max-below-min":     strings.Replace(body, `"tls":true`, `"tls":true,"min_posts_interval_ms":40,"max_posts_interval_ms":39`, 1),
		"interval-max-wrong-type":    strings.Replace(body, `"tls":true`, `"tls":true,"min_posts_interval_ms":40,"max_posts_interval_ms":"60"`, 1),
		"post-max-without-min":       strings.Replace(body, `"tls":true`, `"tls":true,"post_bytes_max":4096`, 1),
		"post-max-below-min":         strings.Replace(body, `"tls":true`, `"tls":true,"max_each_post_bytes":2048,"post_bytes_max":2047`, 1),
		"post-max-wrong-type":        strings.Replace(body, `"tls":true`, `"tls":true,"max_each_post_bytes":2048,"post_bytes_max":"4096"`, 1),
		"metadata-cookie-reserved":   strings.Replace(body, `"tls":true`, `"tls":true,"session_id_placement":"cookie","session_id_key":"session"`, 1),
		"metadata-low-entropy":       strings.Replace(body, `"tls":true`, `"tls":true,"session_id_table":"hex","session_id_length":24`, 1),
		"metadata-collision":         strings.Replace(body, `"tls":true`, `"tls":true,"session_id_placement":"header","session_id_key":"X-Veilink-Same","seq_placement":"header","seq_key":"X-Veilink-Same"`, 1),
		"metadata-wrong-type":        strings.Replace(body, `"tls":true`, `"tls":true,"session_id_length":"32"`, 1),
		"padding-legacy-options":     strings.Replace(body, `"tls":true`, `"tls":true,"padding_method":"tokenish"`, 1),
		"padding-invalid-placement":  strings.Replace(body, `"tls":true`, `"tls":true,"padding_obfs_mode":true,"padding_placement":"unknown"`, 1),
		"padding-bad-method":         strings.Replace(body, `"tls":true`, `"tls":true,"padding_obfs_mode":true,"padding_method":"unknown"`, 1),
		"padding-cookie-collision":   strings.Replace(body, `"tls":true`, `"tls":true,"padding_obfs_mode":true,"padding_placement":"cookie","padding_key":"x_session","session_id_placement":"cookie"`, 1),
		"padding-header-reserved":    strings.Replace(body, `"tls":true`, `"tls":true,"padding_obfs_mode":true,"padding_placement":"header","padding_header":"Set-Cookie"`, 1),
		"padding-wrong-type":         strings.Replace(body, `"tls":true`, `"tls":true,"padding_obfs_mode":"true"`, 1),
		"unknown-download-endpoint":  strings.Replace(body, `"download_endpoint_id":"down"`, `"download_endpoint_id":"missing"`, 1),
		"disabled-download-endpoint": strings.Replace(body, `"download_endpoint_id":"down"`, `"download_endpoint_id":"off"`, 1),
		"private-client-template":    strings.TrimSuffix(body, "}") + `,"client_tunnel":{}`,
	} {
		t.Run(name, func(t *testing.T) {
			if got := call(bad); got.Code != 400 {
				t.Fatal(got.Code, got.Body.String())
			}
		})
	}
	w = call(strings.Replace(body, `"tls":true`, `"tls":true,"headers":{"x-custom-route":"east","User-Agent":"Veilink-Test"},"session_id_placement":"header","session_id_key":"X-Veilink-SID","seq_placement":"query","seq_key":"number","session_id_table":"hex","session_id_length":32,"max_each_post_bytes":2048,"post_bytes_max":4096,"min_posts_interval_ms":45,"max_posts_interval_ms":75,"no_sse_header":true,"server_max_header_bytes":16384,"uplink_http_method":"PUT"`, 1))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var n model.Node
	if err = json.Unmarshal(w.Body.Bytes(), &n); err != nil {
		t.Fatal(err)
	}
	if n.Tunnel.XHTTP.SessionIDPlacement != "header" || n.Tunnel.XHTTP.SeqPlacement != "query" || n.Tunnel.XHTTP.SessionIDLength != 32 || n.Tunnel.XHTTP.SessionIDTable != "hex" || n.Tunnel.XHTTP.DownloadEndpointID != "down" || n.ClientTunnel == nil || n.ClientTunnel.XHTTP.DownloadEndpointID != "down" {
		t.Fatal("API metadata or download endpoint lost")
	}
	w = call(strings.Replace(body, `"tls":true`, `"tls":true,"max_buffered_posts":8,"max_concurrent_posts":4`, 1))
	if w.Code != http.StatusOK {
		t.Fatal("buffer API save rejected", w.Code, w.Body.String())
	}
	if err = json.Unmarshal(w.Body.Bytes(), &n); err != nil || n.ClientTunnel == nil || n.Tunnel.XHTTP.MaxBufferedPosts != 8 || n.Tunnel.XHTTP.MaxConcurrentPosts != 4 || n.ClientTunnel.XHTTP != n.Tunnel.XHTTP {
		t.Fatal("buffer API template lost", err)
	}
	w = call(strings.Replace(body, `"tls":true`, `"tls":true,"session_id_placement":"cookie","session_id_key":"x_sid","seq_placement":"cookie","seq_key":"x_seq"`, 1))
	if w.Code != http.StatusOK {
		t.Fatal("private Cookie metadata rejected", w.Code, w.Body.String())
	}
	if err = json.Unmarshal(w.Body.Bytes(), &n); err != nil || n.ClientTunnel == nil || n.Tunnel.XHTTP.SessionIDPlacement != "cookie" || n.Tunnel.XHTTP.SeqPlacement != "cookie" || n.ClientTunnel.XHTTP != n.Tunnel.XHTTP {
		t.Fatal("private Cookie template lost", err)
	}
	w = call(strings.Replace(body, `"tls":true`, `"tls":true,"padding_obfs_mode":true,"padding_placement":"cookie","padding_key":"x_cover","padding_method":"tokenish","session_id_placement":"cookie","session_id_key":"x_sid"`, 1))
	if w.Code != http.StatusOK {
		t.Fatal("padding API save rejected", w.Code, w.Body.String())
	}
	if err = json.Unmarshal(w.Body.Bytes(), &n); err != nil || n.ClientTunnel == nil || !n.Tunnel.XHTTP.PaddingObfsMode || n.Tunnel.XHTTP.PaddingPlacement != "cookie" || n.ClientTunnel.XHTTP != n.Tunnel.XHTTP {
		t.Fatal("padding API template lost", err)
	}
	xmuxBody := strings.Replace(body, "\"tls\":true", "\"tls\":true,\"xmux\":{\"max_concurrency\":2,\"max_connections\":2,\"c_max_reuse_times\":10,\"h_max_request_times\":20,\"h_max_reusable_secs\":60,\"keep_alive_period\":30}", 1)
	w = call(xmuxBody)
	if w.Code != http.StatusOK {
		t.Fatal("xmux API save rejected", w.Code, w.Body.String())
	}
	if err = json.Unmarshal(w.Body.Bytes(), &n); err != nil || n.ClientTunnel == nil || n.Tunnel.XHTTP.Xmux.MaxConcurrency != 2 || n.Tunnel.XHTTP.Xmux.KeepAlivePeriod != 30 || n.ClientTunnel.XHTTP != n.Tunnel.XHTTP {
		t.Fatal("xmux template lost", err)
	}
	dataBody := strings.Replace(body, "\"tls\":true", "\"tls\":true,\"uplink_data_placement\":\"header\",\"uplink_data_key\":\"X-Veilink-Data\",\"uplink_chunk_size\":1024", 1)
	if dataBody == body {
		dataBody = strings.Replace(body, `\"tls\":true`, `\"tls\":true,\"uplink_data_placement\":\"header\",\"uplink_data_key\":\"X-Veilink-Data\",\"uplink_chunk_size\":1024`, 1)
	}
	w = call(dataBody)
	if w.Code != http.StatusOK {
		t.Fatal("uplink data API save rejected", w.Code, w.Body.String())
	}
	if err = json.Unmarshal(w.Body.Bytes(), &n); err != nil || n.ClientTunnel == nil || n.Tunnel.XHTTP.UplinkDataPlacement != "header" || n.Tunnel.XHTTP.UplinkDataKey != "X-Veilink-Data" || n.Tunnel.XHTTP.UplinkChunkSize != 1024 || n.ClientTunnel.XHTTP != n.Tunnel.XHTTP {
		t.Fatal("uplink data template lost", err)
	}
	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	identity := tlsServer.TLS.Certificates[0]
	tlsServer.Close()
	keyDER, keyErr := x509.MarshalPKCS8PrivateKey(identity.PrivateKey)
	if keyErr != nil {
		t.Fatal(keyErr)
	}
	streamTunnel := model.LocalTLS{TransportSecurity: "tls", ListenPort: 9443,
		CertPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: identity.Certificate[0]})),
		CAPEM:   string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: identity.Certificate[0]})),
		KeyPEM:  string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})),
		XHTTP:   model.XHTTP{Path: "/stream/", Mode: "stream-up", TLS: true, StreamUpServerSecs: 1, StreamUpServerMaxSecs: 3}}
	streamBody, marshalErr := json.Marshal(map[string]any{"name": "stream-policy", "role": "server", "address": "127.0.0.1", "port": 9443, "tunnel": streamTunnel})
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	w = call(string(streamBody))
	if w.Code != http.StatusOK {
		t.Fatal("stream policy save", w.Code, w.Body.String())
	}
	if err = json.Unmarshal(w.Body.Bytes(), &n); err != nil || n.ClientTunnel == nil || n.Tunnel.XHTTP.StreamUpServerSecs != 1 || n.Tunnel.XHTTP.StreamUpServerMaxSecs != 3 || n.ClientTunnel.XHTTP != n.Tunnel.XHTTP || n.ClientTunnel.KeyPEM != "" {
		t.Fatal("stream policy derivation", err)
	}
	w = call(strings.Replace(h2cBody, `"tls":false`, `"tls":false,"min_posts_interval_ms":45`, 1))
	if w.Code != http.StatusOK {
		t.Fatal("encrypted h2c API rejected", w.Code, w.Body.String())
	}
	if err = json.Unmarshal(w.Body.Bytes(), &n); err != nil || n.ClientTunnel == nil || n.Tunnel.XHTTP != n.ClientTunnel.XHTTP || n.Tunnel.XHTTP.Host != "edge.example.com" || n.Tunnel.XHTTP.MinPostsIntervalMs != 45 || n.ClientTunnel.Encryption == "" || n.ClientTunnel.Decryption != "" {
		t.Fatal("h2c client derivation failed", err)
	}
}
