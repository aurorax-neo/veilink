package httpapi

import (
	"fmt"
	"path/filepath"
	"testing"

	"veilink/internal/httpapi/backend"
	"veilink/internal/store"
)

// TestKeyRevocationIsolation 验证吊销单个 key 不影响其他 key，
// 且 key 存储没有人为的容量上限（替代旧版 100 session 上限测试）。
func TestKeyRevocationIsolation(t *testing.T) {
	d := t.TempDir()
	s, err := store.Open(filepath.Join(d, "db"), filepath.Join(d, "key"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	h := New(s, false, nil)

	// 创建超过旧版 session 上限数量的 key，验证无容量限制
	keys := make([]string, 0, 150)
	for i := 0; i < 150; i++ {
		plaintext, err := h.(*API).keyStore.Create(fmt.Sprintf("key-%d", i), backend.RoleAdmin)
		if err != nil {
			t.Fatalf("key creation failed at %d: %v", i, err)
		}
		keys = append(keys, plaintext)
	}

	// 吊销其中一个
	listed, err := h.(*API).keyStore.List()
	if err != nil {
		t.Fatal(err)
	}
	var revokedID int64
	for _, k := range listed {
		if k.Name == "key-0" {
			revokedID = k.ID
		}
	}
	if err := h.(*API).keyStore.Revoke(revokedID); err != nil {
		t.Fatal(err)
	}

	// 被吊销的 key 应被拒绝
	if w := testCall(h, keys[0], "GET", "/api/v1/nodes", ""); w.Code != 401 {
		t.Fatalf("revoked key accepted: %d", w.Code)
	}
	// 其他 key 仍可用
	for _, k := range keys[1:5] {
		if w := testCall(h, k, "GET", "/api/v1/nodes", ""); w.Code != 200 {
			t.Fatalf("valid key rejected: %d", w.Code)
		}
	}
}
