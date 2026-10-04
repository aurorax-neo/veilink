package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestAPIKeyAuth 验证 API Key 认证流程
func TestAPIKeyAuth(t *testing.T) {
	h, apiKey := newTestAPI(t, true)

	// 无 Key 应 401
	if w := testCall(h, "", "GET", "/api/v1/nodes", ""); w.Code != 401 {
		t.Fatalf("expected 401 without key, got %d", w.Code)
	}

	// 错误 Key 应 401
	if w := testCall(h, "vlk_invalid", "GET", "/api/v1/nodes", ""); w.Code != 401 {
		t.Fatalf("expected 401 with invalid key, got %d", w.Code)
	}

	// 正确 Key 应 200
	if w := testCall(h, apiKey, "GET", "/api/v1/nodes", ""); w.Code != 200 {
		t.Fatalf("expected 200 with valid key, got %d: %s", w.Code, w.Body.String())
	}

	// X-API-Key 头也应工作
	r := httptest.NewRequest("GET", "/api/v1/nodes", nil)
	r.Header.Set("X-API-Key", apiKey)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("X-API-Key header failed: %d", w.Code)
	}
}

// TestAPIv1Prefix 验证 /api/v1 前缀和老路径重定向
func TestAPIv1Prefix(t *testing.T) {
	h, apiKey := newTestAPI(t, true)

	// 老路径应 301 重定向到 /api/v1/*
	w := testCall(h, apiKey, "GET", "/api/nodes", "")
	if w.Code != 301 {
		t.Fatalf("expected 301 for legacy path, got %d", w.Code)
	}
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, "/api/v1/nodes") {
		t.Fatalf("unexpected redirect location: %s", loc)
	}

	// /api/version 是公开路径（免认证）
	w = testCall(h, "", "GET", "/api/version", "")
	if w.Code != 200 {
		t.Fatalf("expected 200 for /api/version, got %d", w.Code)
	}
	var ver map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &ver); err != nil {
		t.Fatal(err)
	}
	if ver["api_version"] != "v1" {
		t.Fatalf("expected api_version=v1, got %v", ver)
	}
	if ver["backend_version"] == "" {
		t.Fatal("backend_version missing")
	}
}

// TestKeyManagement 验证 Key 管理接口
func TestKeyManagement(t *testing.T) {
	h, apiKey := newTestAPI(t, true)

	// 列出 keys
	w := testCall(h, apiKey, "GET", "/api/v1/keys", "")
	if w.Code != 200 {
		t.Fatalf("list keys failed: %d", w.Code)
	}

	// 创建新 key
	w = testCall(h, apiKey, "POST", "/api/v1/keys", `{"name":"test2","role":"readonly"}`)
	if w.Code != 201 {
		t.Fatalf("create key failed: %d: %s", w.Code, w.Body.String())
	}
	var created map[string]string
	json.Unmarshal(w.Body.Bytes(), &created)
	newKey := created["key"]
	if !strings.HasPrefix(newKey, "vlk_") {
		t.Fatalf("invalid key format: %s", newKey)
	}

	// 新 key 可用
	w = testCall(h, newKey, "GET", "/api/v1/nodes", "")
	if w.Code != 200 {
		t.Fatalf("new key failed: %d", w.Code)
	}

	// 删除 key（需要 ID，先查列表）
	w = testCall(h, apiKey, "GET", "/api/v1/keys", "")
	var keys []map[string]any
	json.Unmarshal(w.Body.Bytes(), &keys)
	var targetID int64
	for _, k := range keys {
		if k["name"] == "test2" {
			targetID = int64(k["id"].(float64))
		}
	}
	if targetID == 0 {
		t.Fatal("created key not found in list")
	}
	w = testCall(h, apiKey, "DELETE", fmt.Sprintf("/api/v1/keys/%d", targetID), "")
	if w.Code != 200 {
		t.Fatalf("revoke key failed: %d", w.Code)
	}

	// 已删除的 key 应 401
	w = testCall(h, newKey, "GET", "/api/v1/nodes", "")
	if w.Code != 401 {
		t.Fatalf("revoked key should 401, got %d", w.Code)
	}
}
