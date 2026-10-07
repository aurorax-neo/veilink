package httpapi

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"veilink/internal/httpapi/backend"
	"veilink/internal/store"
)

// newTestAPI 创建带测试 API Key 的处理器
// 返回 handler 和可用于 Authorization 头的明文 key
func newTestAPI(t *testing.T, insecure bool) (http.Handler, string) {
	t.Helper()
	dir := t.TempDir()
	db, key := filepath.Join(dir, "db"), filepath.Join(dir, "key")
	s, err := store.Open(db, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })

	h := New(s, insecure, nil, WebPersistConfig{})
	api := h.(*API)

	// 直接创建测试 key（绕过 EnsureDefaultAdmin 的日志）
	plaintext, err := api.keyStore.Create("test-key", backend.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	return h, plaintext
}

// testCall 构造带 API Key 的请求
func testCall(h http.Handler, apiKey, method, path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	if apiKey != "" {
		r.Header.Set("Authorization", "Bearer "+apiKey)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
