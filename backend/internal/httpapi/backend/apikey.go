package backend

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// KeyRole API Key 角色
type KeyRole string

const (
	RoleAdmin    KeyRole = "admin"    // 读写所有
	RoleReadonly KeyRole = "readonly" // 只读（面板、日志、状态）
)

// APIKey 数据库中的密钥记录
type APIKey struct {
	ID        int64      `json:"id"`
	Name      string     `json:"name"`
	KeyHash   string     `json:"-"` // 永不序列化
	KeyPrefix string     `json:"key_prefix"`
	Role      KeyRole    `json:"role"`
	CreatedAt time.Time  `json:"created_at"`
	LastUsed  *time.Time `json:"last_used,omitempty"`
}

type KeyStore struct {
	db *sql.DB
}

func NewKeyStore(db *sql.DB) *KeyStore {
	return &KeyStore{db: db}
}

// Migrate 建表，含旧版无痛迁移
func (s *KeyStore) Migrate() error {
	_, err := s.db.Exec(`
	CREATE TABLE IF NOT EXISTS api_keys (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL UNIQUE,
		key_hash TEXT NOT NULL UNIQUE,
		key_prefix TEXT NOT NULL,
		role TEXT NOT NULL DEFAULT 'admin',
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		last_used DATETIME
	);
	CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
	`)
	return err
}

func isNoSuchTable(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "no such table")
}

// LegacyAdminPending reports an old username table that has not been minted into an API key.
func (s *KeyStore) LegacyAdminPending() (bool, error) {
	var adminCount int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM admin`).Scan(&adminCount)
	if isNoSuchTable(err) || (err == nil && adminCount == 0) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var keyCount int
	if err = s.db.QueryRow(`SELECT COUNT(*) FROM api_keys`).Scan(&keyCount); err != nil {
		return false, err
	}
	return keyCount == 0, nil
}

// CommitLegacyMigration prints a migrated admin key once, then commits it.
// A write failure rolls the new key back so it cannot exist unseen.
func (s *KeyStore) CommitLegacyMigration(w io.Writer) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var adminCount int
	err = tx.QueryRow(`SELECT COUNT(*) FROM admin`).Scan(&adminCount)
	if isNoSuchTable(err) || (err == nil && adminCount == 0) {
		return nil
	}
	if err != nil {
		return err
	}
	var keyCount int
	if err = tx.QueryRow(`SELECT COUNT(*) FROM api_keys`).Scan(&keyCount); err != nil {
		return err
	}
	if keyCount > 0 {
		return nil
	}
	plaintext, err := generateKey()
	if err != nil {
		return err
	}
	if _, err = tx.Exec(
		`INSERT INTO api_keys (name, key_hash, key_prefix, role) VALUES (?, ?, ?, ?)`,
		"migrated-admin", hashKey(plaintext), plaintext[:8], string(RoleAdmin),
	); err != nil {
		return fmt.Errorf("migrate legacy admin: %w", err)
	}
	if _, err = fmt.Fprintf(w, "Migrated API key (shown only once):\n%s\n", plaintext); err != nil {
		return err
	}
	return tx.Commit()
}

func hashKey(key string) string {
	h := sha256.Sum256([]byte(key))
	return hex.EncodeToString(h[:])
}

// generateKey 生成 vlk_ 前缀的随机 key
func generateKey() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "vlk_" + hex.EncodeToString(b), nil
}

// Create 生成新 key 并落库，返回明文（仅此一次可见）
func (s *KeyStore) Create(name string, role KeyRole) (plaintext string, err error) {
	plaintext, err = generateKey()
	if err != nil {
		return "", err
	}
	_, err = s.db.Exec(
		`INSERT INTO api_keys (name, key_hash, key_prefix, role) VALUES (?, ?, ?, ?)`,
		name, hashKey(plaintext), plaintext[:8], string(role),
	)
	if err != nil {
		return "", fmt.Errorf("create api key: %w", err)
	}
	return plaintext, nil
}

// Validate 校验 key，返回角色
func (s *KeyStore) Validate(key string) (KeyRole, bool) {
	var role string
	h := hashKey(key)
	err := s.db.QueryRow(
		`SELECT role FROM api_keys WHERE key_hash = ?`,
		h,
	).Scan(&role)
	if err != nil {
		return "", false
	}
	_, _ = s.db.Exec(`UPDATE api_keys SET last_used = CURRENT_TIMESTAMP WHERE key_hash = ?`, h)
	return KeyRole(role), true
}

// List 列出所有 key（不含明文）
func (s *KeyStore) List() ([]APIKey, error) {
	rows, err := s.db.Query(
		`SELECT id, name, key_prefix, role, created_at, last_used FROM api_keys ORDER BY id`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []APIKey
	for rows.Next() {
		var k APIKey
		var role string
		if err := rows.Scan(&k.ID, &k.Name, &k.KeyPrefix, &role, &k.CreatedAt, &k.LastUsed); err != nil {
			return nil, err
		}
		k.Role = KeyRole(role)
		out = append(out, k)
	}
	return out, rows.Err()
}

// Count 返回 key 总数
func (s *KeyStore) Count() int64 {
	var n int64
	s.db.QueryRow(`SELECT COUNT(*) FROM api_keys`).Scan(&n)
	return n
}

// Revoke deletes one key without allowing the last admin key to disappear.
// The predicate and delete are a single statement so concurrent revokes cannot
// both observe "more than one admin" and then remove all of them.
func (s *KeyStore) Revoke(id int64) error {
	res, err := s.db.Exec(`
		DELETE FROM api_keys
		WHERE id=?
		  AND (role <> 'admin' OR (SELECT COUNT(*) FROM api_keys WHERE role='admin') > 1)`, id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 1 {
		return nil
	}
	var role string
	err = s.db.QueryRow(`SELECT role FROM api_keys WHERE id=?`, id).Scan(&role)
	if err == sql.ErrNoRows {
		return fmt.Errorf("api key not found")
	}
	if err != nil {
		return err
	}
	if role == string(RoleAdmin) {
		return fmt.Errorf("cannot revoke the last admin key")
	}
	return fmt.Errorf("api key not found")
}

// --- 中间件 ---

type ctxKey string

const ctxRoleKey ctxKey = "api_key_role"

// APIKeyAuth 中间件：校验 Authorization: Bearer <key> 或 X-API-Key
// publicPaths 不需要认证（如 /api/version、/healthz）
func APIKeyAuth(store *KeyStore, publicPaths []string) func(http.Handler) http.Handler {
	public := make(map[string]bool, len(publicPaths))
	for _, p := range publicPaths {
		public[p] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if public[r.URL.Path] {
				next.ServeHTTP(w, r)
				return
			}
			key := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if key == "" {
				key = r.Header.Get("X-API-Key")
			}
			role, ok := store.Validate(key)
			if !ok {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte(`{"error":"unauthorized","message":"invalid or missing API key"}`))
				return
			}
			ctx := context.WithValue(r.Context(), ctxRoleKey, role)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireRole 要求特定角色
func RequireRole(role KeyRole) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rRole, _ := r.Context().Value(ctxRoleKey).(KeyRole)
			if rRole != RoleAdmin && rRole != role {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte(`{"error":"forbidden"}`))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RoleFromContext 从请求上下文取角色
func RoleFromContext(ctx context.Context) KeyRole {
	r, _ := ctx.Value(ctxKey(ctxRoleKey)).(KeyRole)
	return r
}
