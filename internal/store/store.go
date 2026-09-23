package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	_ "modernc.org/sqlite"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"veilink/internal/auth"
	"veilink/internal/model"
)

var ErrAuth = errors.New("unauthorized")
var ErrInvalid = errors.New("invalid request or conflicting resource")

type state struct {
	Revision int64
	Nodes    map[string]model.Node
	Bindings map[string]model.Binding
	Mappings map[string]model.Mapping
	Secrets  map[string][]byte
}
type Store struct {
	mu  sync.Mutex
	db  *sql.DB
	key []byte
}

func Open(path, keyPath string) (*Store, error) {
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return nil, e
	}
	if e := os.MkdirAll(filepath.Dir(keyPath), 0700); e != nil {
		return nil, e
	}
	key, e := os.ReadFile(keyPath)
	if os.IsNotExist(e) {
		key = make([]byte, 32)
		if _, e = rand.Read(key); e != nil {
			return nil, e
		}
		f, er := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if er != nil {
			return nil, er
		}
		_, e = f.Write(key)
		ce := f.Close()
		if e == nil {
			e = ce
		}
	}
	if e != nil {
		return nil, e
	}
	if len(key) != 32 {
		return nil, errors.New("deployment key must be 32 bytes")
	}
	if e = os.Chmod(keyPath, 0600); e != nil {
		return nil, e
	}
	f, e := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	f.Close()
	os.Chmod(path, 0600)
	db, e := sql.Open("sqlite", path)
	if e != nil {
		return nil, e
	}
	db.SetMaxOpenConns(1)
	_, e = db.Exec(`PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000; CREATE TABLE IF NOT EXISTS schema_version(version INTEGER PRIMARY KEY); INSERT OR IGNORE INTO schema_version VALUES(1); CREATE TABLE IF NOT EXISTS config(id INTEGER PRIMARY KEY CHECK(id=1),data BLOB NOT NULL); CREATE TABLE IF NOT EXISTS admin(username TEXT PRIMARY KEY,password TEXT NOT NULL); CREATE TABLE IF NOT EXISTS credentials(node TEXT PRIMARY KEY,hash TEXT NOT NULL); CREATE TABLE IF NOT EXISTS enroll(node TEXT PRIMARY KEY,hash TEXT NOT NULL,expires INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS audit(at INTEGER NOT NULL,action TEXT NOT NULL,object TEXT NOT NULL);`)
	if e != nil {
		db.Close()
		return nil, e
	}
	s := &Store{db: db, key: key}
	st := state{Nodes: map[string]model.Node{}, Bindings: map[string]model.Binding{}, Mappings: map[string]model.Mapping{}, Secrets: map[string][]byte{}}
	b, _ := json.Marshal(st)
	_, e = db.Exec("INSERT OR IGNORE INTO config VALUES(1,?)", b)
	return s, e
}
func (s *Store) Close() error { return s.db.Close() }
func (s *Store) load() (state, error) {
	var b []byte
	var st state
	e := s.db.QueryRow("SELECT data FROM config WHERE id=1").Scan(&b)
	if e == nil {
		e = json.Unmarshal(b, &st)
	}
	return st, e
}
func (s *Store) mutate(action, id string, fn func(*state) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, e := s.load()
	if e != nil {
		return e
	}
	if e = fn(&st); e != nil {
		return e
	}
	st.Revision++
	for id, n := range st.Nodes {
		n.DesiredRevision = st.Revision
		st.Nodes[id] = n
	}
	b, e := json.Marshal(st)
	if e != nil {
		return e
	}
	tx, e := s.db.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if _, e = tx.Exec("UPDATE config SET data=? WHERE id=1", b); e != nil {
		return e
	}
	if _, e = tx.Exec("INSERT INTO audit VALUES(?,?,?)", time.Now().Unix(), action, id); e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Store) InitAdmin(user, password string) error {
	if strings.TrimSpace(user) == "" {
		return ErrInvalid
	}
	h, e := auth.Password(password)
	if e != nil {
		return e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var count int
	if e = s.db.QueryRow("SELECT count(*) FROM admin").Scan(&count); e != nil {
		return e
	}
	if count != 0 {
		return errors.New("administrator already initialized")
	}
	_, e = s.db.Exec("INSERT INTO admin VALUES(?,?)", user, h)
	return e
}
func (s *Store) HasAdmin() (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var count int
	if err := s.db.QueryRow("SELECT count(*) FROM admin").Scan(&count); err != nil {
		return false, err
	}
	return count > 0, nil
}
func (s *Store) FindNodeByName(name string) (model.Node, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.load()
	if err != nil {
		return model.Node{}, false, err
	}
	for _, n := range st.Nodes {
		if n.Name == name {
			return n, true, nil
		}
	}
	return model.Node{}, false, nil
}
func (s *Store) Login(user, password string) bool {
	var h string
	e := s.db.QueryRow("SELECT password FROM admin WHERE username=?", user).Scan(&h)
	if e != nil {
		auth.Check("$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy", password)
		return false
	}
	return auth.Check(h, password)
}
func (s *Store) Nodes() ([]model.Node, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, e := s.load()
	out := []model.Node{}
	for _, n := range st.Nodes {
		out = append(out, n)
	}
	return out, e
}
func (s *Store) SaveNode(n model.Node) (model.Node, error) {
	if n.ID == "" {
		n.ID = auth.Token()
	}
	e := s.mutate("node.save", n.ID, func(st *state) error {
		if n.Name == "" || len(n.Name) > 128 || (n.Role != "server" && n.Role != "client") {
			return ErrInvalid
		}
		if n.Role == "server" && (!host(n.Address) || n.Port < 1 || n.Port > 65535 || !host(n.ServerName)) {
			return ErrInvalid
		}
		if old, ok := st.Nodes[n.ID]; ok {
			if old.Role != n.Role || old.Revoked {
				return ErrInvalid
			}
			n.AppliedRevision = old.AppliedRevision
			n.LastSeen = old.LastSeen
			n.Error = old.Error
		}
		n.Revoked = false
		st.Nodes[n.ID] = n
		return validate(st)
	})
	return n, e
}
func (s *Store) RemoveNode(id string, remove bool) error {
	return s.mutate("node.revoke", id, func(st *state) error {
		n, ok := st.Nodes[id]
		if !ok {
			return ErrInvalid
		}
		n.Revoked = true
		st.Nodes[id] = n
		if remove {
			delete(st.Nodes, id)
			for bid, b := range st.Bindings {
				if b.ServerID == id || b.ClientID == id {
					removeBinding(st, bid)
				}
			}
		}
		return nil
	})
}
func (s *Store) EnrollToken(id string, ttl time.Duration) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, e := s.load()
	if e != nil {
		return "", e
	}
	n, ok := st.Nodes[id]
	if !ok || n.Revoked || ttl <= 0 || ttl > 24*time.Hour {
		return "", ErrInvalid
	}
	token := auth.Token()
	_, e = s.db.Exec("INSERT OR REPLACE INTO enroll VALUES(?,?,?)", id, auth.Hash(token), time.Now().Add(ttl).Unix())
	return token, e
}
func (s *Store) Enroll(id, token string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, e := s.load()
	if e != nil {
		return "", e
	}
	n, ok := st.Nodes[id]
	if !ok || n.Revoked {
		return "", ErrAuth
	}
	tx, e := s.db.Begin()
	if e != nil {
		return "", e
	}
	defer tx.Rollback()
	r, e := tx.Exec("DELETE FROM enroll WHERE node=? AND hash=? AND expires>?", id, auth.Hash(token), time.Now().Unix())
	if e != nil {
		return "", e
	}
	count, _ := r.RowsAffected()
	if count != 1 {
		return "", ErrAuth
	}
	credential := auth.Token()
	if _, e = tx.Exec("INSERT OR REPLACE INTO credentials VALUES(?,?)", id, auth.Hash(credential)); e != nil {
		return "", e
	}
	return credential, tx.Commit()
}
func (s *Store) authorized(st state, id, credential string) bool {
	n, ok := st.Nodes[id]
	if !ok || n.Revoked || credential == "" {
		return false
	}
	var h string
	return s.db.QueryRow("SELECT hash FROM credentials WHERE node=?", id).Scan(&h) == nil && h == auth.Hash(credential)
}
func (s *Store) Snapshot(id, credential string) (model.Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, e := s.load()
	if e != nil {
		return model.Snapshot{}, e
	}
	if !s.authorized(st, id, credential) {
		return model.Snapshot{}, ErrAuth
	}
	out := model.Snapshot{Revision: st.Revision, Node: st.Nodes[id], Nodes: []model.Node{}, Bindings: []model.Binding{}, Mappings: []model.Mapping{}}
	peers := map[string]bool{}
	for bid, b := range st.Bindings {
		a, aok := st.Nodes[b.ServerID]
		c, cok := st.Nodes[b.ClientID]
		if !aok || !cok || a.Revoked || c.Revoked || (b.ServerID != id && b.ClientID != id) {
			continue
		}
		b.UUID, e = auth.Open(s.key, st.Secrets[bid])
		if e != nil {
			return model.Snapshot{}, e
		}
		out.Bindings = append(out.Bindings, b)
		peers[b.ServerID] = true
		for _, m := range st.Mappings {
			if m.BindingID == bid {
				out.Mappings = append(out.Mappings, m)
			}
		}
	}
	for peer := range peers {
		out.Nodes = append(out.Nodes, st.Nodes[peer])
	}
	return out, nil
}
func (s *Store) Heartbeat(id, credential string, applied int64, failed bool) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, e := s.load()
	if e != nil {
		return 0, e
	}
	if !s.authorized(st, id, credential) {
		return 0, ErrAuth
	}
	n := st.Nodes[id]
	if applied < 0 || applied > st.Revision {
		return 0, ErrInvalid
	}
	n.AppliedRevision = applied
	n.LastSeen = time.Now().Unix()
	n.Error = ""
	if failed {
		n.Error = "runtime configuration application failed"
	}
	st.Nodes[id] = n
	b, _ := json.Marshal(st)
	_, e = s.db.Exec("UPDATE config SET data=? WHERE id=1", b)
	return st.Revision, e
}
func (s *Store) Bindings() ([]model.Binding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, e := s.load()
	out := []model.Binding{}
	for _, b := range st.Bindings {
		b.UUID = ""
		out = append(out, b)
	}
	return out, e
}
func (s *Store) SaveBinding(b model.Binding) (model.Binding, error) {
	b.ID = auth.Token()
	b.UUID = ""
	b.Domain = "b-" + strings.ToLower(auth.Hash(b.ID)[:24]) + ".veilink.internal"
	e := s.mutate("binding.create", b.ID, func(st *state) error {
		a, ok := st.Nodes[b.ServerID]
		c, ok2 := st.Nodes[b.ClientID]
		if !ok || !ok2 || a.Role != "server" || c.Role != "client" || a.Revoked || c.Revoked {
			return ErrInvalid
		}
		for _, old := range st.Bindings {
			if old.ServerID == b.ServerID && old.ClientID == b.ClientID {
				return ErrInvalid
			}
		}
		u := make([]byte, 16)
		if _, e := rand.Read(u); e != nil {
			return e
		}
		u[6] = (u[6] & 15) | 64
		u[8] = (u[8] & 63) | 128
		uuid := fmt.Sprintf("%x-%x-%x-%x-%x", u[:4], u[4:6], u[6:8], u[8:10], u[10:])
		secret, e := auth.Seal(s.key, uuid)
		if e != nil {
			return e
		}
		st.Bindings[b.ID] = b
		st.Secrets[b.ID] = secret
		return nil
	})
	return b, e
}
func removeBinding(st *state, id string) {
	delete(st.Bindings, id)
	delete(st.Secrets, id)
	for mid, m := range st.Mappings {
		if m.BindingID == id {
			delete(st.Mappings, mid)
		}
	}
}
func (s *Store) DeleteBinding(id string) error {
	return s.mutate("binding.delete", id, func(st *state) error {
		if _, ok := st.Bindings[id]; !ok {
			return ErrInvalid
		}
		removeBinding(st, id)
		return nil
	})
}
func (s *Store) Mappings() ([]model.Mapping, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, e := s.load()
	out := []model.Mapping{}
	for _, m := range st.Mappings {
		out = append(out, m)
	}
	return out, e
}
func host(h string) bool {
	if h == "" || len(h) > 253 || strings.ContainsAny(h, " /\\\t\r\n:@") {
		return net.ParseIP(h) != nil
	}
	return true
}
func wildcard(h string) bool { return h == "" || h == "0.0.0.0" || h == "::" }
func mappingNet(s string) string {
	if strings.EqualFold(strings.TrimSpace(s), "udp") {
		return "udp"
	}
	return "tcp"
}

func validate(st *state) error {
	for id, m := range st.Mappings {
		b, ok := st.Bindings[m.BindingID]
		if !ok || m.Name == "" || len(m.Name) > 128 || (m.Network != "" && m.Network != "tcp" && m.Network != "udp") || m.ListenPort < 1 || m.ListenPort > 65535 || m.TargetPort < 1 || m.TargetPort > 65535 || !host(m.TargetHost) || net.ParseIP(m.ListenHost) == nil {
			return ErrInvalid
		}
		n := st.Nodes[b.ServerID]
		if mappingNet(m.Network) != "udp" && m.ListenPort == n.Port {
			return ErrInvalid
		}
		for oid, o := range st.Mappings {
			if oid != id && m.Enabled && o.Enabled && st.Bindings[o.BindingID].ServerID == b.ServerID && o.ListenPort == m.ListenPort && mappingNet(o.Network) == mappingNet(m.Network) && (o.ListenHost == m.ListenHost || wildcard(o.ListenHost) || wildcard(m.ListenHost)) {
				return ErrInvalid
			}
		}
	}
	return nil
}
func (s *Store) SaveMapping(m model.Mapping) (model.Mapping, error) {
	m.Network = mappingNet(m.Network)
	if m.ID == "" {
		m.ID = auth.Token()
	}
	e := s.mutate("mapping.save", m.ID, func(st *state) error {
		b, ok := st.Bindings[m.BindingID]
		if !ok || st.Nodes[b.ServerID].Revoked || st.Nodes[b.ClientID].Revoked {
			return ErrInvalid
		}
		st.Mappings[m.ID] = m
		return validate(st)
	})
	return m, e
}
func (s *Store) DeleteMapping(id string) error {
	return s.mutate("mapping.delete", id, func(st *state) error {
		if _, ok := st.Mappings[id]; !ok {
			return ErrInvalid
		}
		delete(st.Mappings, id)
		return nil
	})
}

type Audit struct {
	At     int64  `json:"at"`
	Action string `json:"action"`
	Object string `json:"object"`
}

func (s *Store) Audit() ([]Audit, error) {
	rows, e := s.db.Query("SELECT at,action,object FROM audit ORDER BY rowid DESC LIMIT 500")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []Audit{}
	for rows.Next() {
		var a Audit
		if e = rows.Scan(&a.At, &a.Action, &a.Object); e != nil {
			return nil, e
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
