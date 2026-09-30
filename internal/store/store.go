package store

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	_ "modernc.org/sqlite"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
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
	mu          sync.Mutex
	db          *sql.DB
	key         []byte
	software    map[string]SoftwareReport
	listeners   map[chan int64]string
	traffic     map[string]trafficNode
	mappingAcks map[string]map[string]mappingAck
}

// MappingStatus represents in-process configuration acknowledgement, not reachability.
type MappingStatus struct {
	Server MappingEndpointStatus `json:"server"`
	Client MappingEndpointStatus `json:"client"`
}
type MappingEndpointStatus struct {
	Acknowledged bool   `json:"acknowledged"`
	Reason       string `json:"reason"`
}
type mappingAck struct {
	Policy string
	Failed bool
}

// Include binding-wide effective session settings, but exclude administrative labels.
func mappingPolicy(st state, m model.Mapping) string {
	b := st.Bindings[m.BindingID]
	b.UUID = ""
	pool := 0
	mux := map[string]bool{}
	for _, other := range st.Mappings {
		if other.BindingID != m.BindingID || !other.Enabled {
			continue
		}
		if other.Pool > pool {
			pool = other.Pool
		}
		if other.Mux {
			mux[other.MuxType] = true
		}
	}
	var types []string
	for kind := range mux {
		types = append(types, kind)
	}
	sort.Strings(types)
	m.Name = ""
	data, _ := json.Marshal(struct {
		Mapping model.Mapping
		Binding model.Binding
		Server  model.Node
		Client  model.Node
		Pool    int
		Mux     []string
	}{m, b, nodeRuntimeConfig(st.Nodes[m.ServerID]), nodeRuntimeConfig(st.Nodes[m.ClientID]), pool, types})
	return fmt.Sprintf("%x", sha256.Sum256(data))
}

// MappingStatuses never returns internal policy, credentials, or a target probe.
func (s *Store) MappingStatuses() (map[string]MappingStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.load()
	if err != nil {
		return nil, err
	}
	out := make(map[string]MappingStatus, len(st.Mappings))
	for id, m := range st.Mappings {
		policy := mappingPolicy(st, m)
		endpoint := func(nodeID string) MappingEndpointStatus {
			status := MappingEndpointStatus{Reason: "unknown"}
			if n, ok := st.Nodes[nodeID]; !ok || n.Revoked {
				status.Reason = "node_unavailable"
				return status
			}
			if !m.Enabled {
				status.Reason = "disabled"
				return status
			}
			ack, ok := s.mappingAcks[id][nodeID]
			if !ok || ack.Policy != policy {
				return status
			}
			if ack.Failed {
				status.Reason = "apply_failed"
				return status
			}
			status.Acknowledged, status.Reason = true, "acknowledged"
			return status
		}
		out[id] = MappingStatus{Server: endpoint(m.ServerID), Client: endpoint(m.ClientID)}
	}
	return out, nil
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
	if e = initializeSchema(db); e != nil {
		db.Close()
		return nil, e
	}
	return &Store{db: db, key: key}, nil
}

// OpenExisting never creates a database or deployment key (administrator reset commands only).
func OpenExisting(path, keyPath string) (*Store, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() == 0 {
		return nil, ErrInvalid
	}
	key, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	if len(key) != 32 {
		return nil, ErrInvalid
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	u := url.URL{Scheme: "file", Path: abs, RawQuery: "mode=rw"}
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	var version int
	if err = db.QueryRow("SELECT version FROM schema_version").Scan(&version); err != nil || version != schemaVersion {
		db.Close()
		return nil, errors.New("unsupported or missing database schema")
	}
	if _, err = db.Exec("PRAGMA busy_timeout=5000"); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db, key: key}, nil
}

const schemaVersion = 5

// Only fresh databases and this exact schema are supported. Never migrate or
// discard an existing deployment implicitly.
func initializeSchema(db *sql.DB) error {
	var tables, versions int
	if err := db.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").Scan(&tables); err != nil {
		return err
	}
	if tables != 0 {
		var version int
		err := db.QueryRow("SELECT count(*), COALESCE(max(version),0) FROM schema_version").Scan(&versions, &version)
		if err != nil || versions != 1 || version != schemaVersion {
			return fmt.Errorf("unsupported database schema: expected version %d; back up and explicitly reset the database to continue (automatic migration is not supported)", schemaVersion)
		}
	}
	if _, err := db.Exec("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;"); err != nil {
		return err
	}
	if tables != 0 {
		return nil
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`CREATE TABLE schema_version(version INTEGER PRIMARY KEY);
CREATE TABLE config(id INTEGER PRIMARY KEY CHECK(id=1),data BLOB NOT NULL CHECK(json_valid(data)));
CREATE TABLE admin(username TEXT PRIMARY KEY,password TEXT NOT NULL);
CREATE TABLE credentials(node TEXT PRIMARY KEY,hash TEXT NOT NULL,expires INTEGER NOT NULL);
CREATE TABLE enroll(node TEXT PRIMARY KEY,hash TEXT NOT NULL,expires INTEGER NOT NULL);
CREATE TABLE audit(at INTEGER NOT NULL,action TEXT NOT NULL,object TEXT NOT NULL);`); err != nil {
		return err
	}
	if _, err = tx.Exec("INSERT INTO schema_version VALUES(?)", schemaVersion); err != nil {
		return err
	}
	st := state{Nodes: map[string]model.Node{}, Bindings: map[string]model.Binding{}, Mappings: map[string]model.Mapping{}, Secrets: map[string][]byte{}}
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	if _, err = tx.Exec("INSERT INTO config VALUES(1,?)", b); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) Close() error { return s.db.Close() }

// Subscribe returns coalescing configuration-change notifications for one node.
// The revision is only a wake-up hint; callers must Pull the authorized snapshot.
func (s *Store) Subscribe(nodeID string) (<-chan int64, func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listeners == nil {
		s.listeners = make(map[chan int64]string)
	}
	ch := make(chan int64, 1)
	s.listeners[ch] = nodeID
	return ch, func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if _, ok := s.listeners[ch]; ok {
			delete(s.listeners, ch)
			close(ch)
		}
	}
}

func (s *Store) notifyLocked(revision int64, affected map[string]bool) {
	for ch, nodeID := range s.listeners {
		if !affected[nodeID] {
			continue
		}
		select {
		case ch <- revision:
		default:
		}
	}
}

// RequestRefresh wakes one connected node without changing persisted state.
func (s *Store) RequestRefresh(id string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.load()
	if err != nil {
		return false, err
	}
	n, ok := st.Nodes[id]
	if !ok || n.Revoked {
		return false, ErrInvalid
	}
	connected := false
	for _, nodeID := range s.listeners {
		connected = connected || nodeID == id
	}
	s.notifyLocked(n.DesiredRevision, map[string]bool{id: true})
	return connected, nil
}
func (s *Store) load() (state, error) {
	var b []byte
	var st state
	e := s.db.QueryRow("SELECT data FROM config WHERE id=1").Scan(&b)
	if e == nil {
		decoder := json.NewDecoder(bytes.NewReader(b))
		decoder.DisallowUnknownFields()
		e = decoder.Decode(&st)
		if e == nil {
			for _, node := range st.Nodes {
				if node.Role == "server" {
					if _, err := publicTunnel(node); err != nil {
						e = fmt.Errorf("server %q has invalid or custom client_tunnel: %w", node.ID, err)
						break
					}
				}
			}
		}
		if e != nil {
			e = fmt.Errorf("unsupported persisted configuration: %w; back up before explicitly resetting obsolete data", e)
		}
	}
	return st, e
}
func cloneState(in state) state {
	out := in
	out.Nodes = make(map[string]model.Node, len(in.Nodes))
	for id, n := range in.Nodes {
		out.Nodes[id] = n
	}
	out.Bindings = make(map[string]model.Binding, len(in.Bindings))
	for id, b := range in.Bindings {
		out.Bindings[id] = b
	}
	out.Mappings = make(map[string]model.Mapping, len(in.Mappings))
	for id, m := range in.Mappings {
		out.Mappings[id] = m
	}
	out.Secrets = make(map[string][]byte, len(in.Secrets))
	for id, secret := range in.Secrets {
		out.Secrets[id] = append([]byte(nil), secret...)
	}
	return out
}

// Display labels and heartbeat status never change the runtime configuration.
func nodeRuntimeConfig(n model.Node) model.Node {
	n.Name = ""
	n.DesiredRevision, n.AppliedRevision, n.LastSeen, n.Error = 0, 0, 0, ""
	n.ConnectEndpoints = append([]model.ConnectEndpoint(nil), n.ConnectEndpoints...)
	for i := range n.ConnectEndpoints {
		n.ConnectEndpoints[i].Name = ""
	}
	return n
}
func nodeConfigEqual(a, b model.Node) bool {
	return reflect.DeepEqual(nodeRuntimeConfig(a), nodeRuntimeConfig(b))
}

// A Client consumes the Server's public template and dial candidates, not its
// private listener/certificate or administrative labels.
func serverClientConfigEqual(a, b model.Node) bool {
	a, b = nodeRuntimeConfig(a), nodeRuntimeConfig(b)
	return a.Address == b.Address && a.Port == b.Port &&
		reflect.DeepEqual(a.ConnectEndpoints, b.ConnectEndpoints) &&
		reflect.DeepEqual(a.ClientTunnel, b.ClientTunnel)
}

func bindingPeers(st state, nodeID string) map[string]bool {
	peers := map[string]bool{}
	for _, b := range st.Bindings {
		if b.ServerID == nodeID {
			peers[b.ClientID] = true
		}
		if b.ClientID == nodeID {
			peers[b.ServerID] = true
		}
	}
	return peers
}

// Mapping names are administrative labels, not tunnel policy.
func mappingConfigEqual(a, b model.Mapping) bool {
	a.Name, b.Name = "", ""
	return reflect.DeepEqual(a, b)
}

func affectedNodes(before, after state) map[string]bool {
	affected := map[string]bool{}
	for id, n := range before.Nodes {
		if next, ok := after.Nodes[id]; !ok || !nodeConfigEqual(n, next) {
			affected[id] = true
		}
	}
	for id, n := range after.Nodes {
		if old, ok := before.Nodes[id]; !ok || !nodeConfigEqual(old, n) {
			affected[id] = true
		}
	}
	// Binding and mapping changes alter the authorized snapshot at both ends.
	for id, b := range before.Bindings {
		if next, ok := after.Bindings[id]; !ok || !reflect.DeepEqual(b, next) {
			affected[b.ServerID], affected[b.ClientID] = true, true
			if next, ok := after.Bindings[id]; ok {
				affected[next.ServerID], affected[next.ClientID] = true, true
			}
		}
	}
	for id, b := range after.Bindings {
		if old, ok := before.Bindings[id]; !ok || !reflect.DeepEqual(old, b) {
			affected[b.ServerID], affected[b.ClientID] = true, true
		}
	}
	for id, m := range before.Mappings {
		if next, ok := after.Mappings[id]; !ok || !mappingConfigEqual(m, next) {
			if b, ok := before.Bindings[m.BindingID]; ok {
				affected[b.ServerID], affected[b.ClientID] = true, true
			}
			if next, ok := after.Mappings[id]; ok {
				if b, ok := after.Bindings[next.BindingID]; ok {
					affected[b.ServerID], affected[b.ClientID] = true, true
				}
			}
		}
	}
	for id, m := range after.Mappings {
		if old, ok := before.Mappings[id]; !ok || !mappingConfigEqual(old, m) {
			if b, ok := after.Bindings[m.BindingID]; ok {
				affected[b.ServerID], affected[b.ClientID] = true, true
			}
		}
	}
	// Propagate node configuration changes only, not a mapping's revision bump.
	for id, old := range before.Nodes {
		next, exists := after.Nodes[id]
		if exists && nodeConfigEqual(old, next) {
			continue
		}
		if !exists || old.Revoked != next.Revoked || (old.Role == "server" && !serverClientConfigEqual(old, next)) {
			for peer := range bindingPeers(before, id) {
				affected[peer] = true
			}
			for peer := range bindingPeers(after, id) {
				affected[peer] = true
			}
		}
	}
	return affected
}

func (s *Store) mutate(action, id string, fn func(*state) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	before, e := s.load()
	if e != nil {
		return e
	}
	st := cloneState(before)
	if e = fn(&st); e != nil {
		return e
	}
	affected := affectedNodes(before, st)
	st.Revision++
	for nodeID, n := range st.Nodes {
		n.DesiredRevision = before.Nodes[nodeID].DesiredRevision
		if affected[nodeID] {
			n.DesiredRevision = st.Revision
		}
		st.Nodes[nodeID] = n
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
	if e = tx.Commit(); e == nil {
		s.notifyLocked(st.Revision, affected)
		// A revision bump alone does not invalidate unrelated mappings. Drop only
		// acknowledgements whose effective mapping or shared binding policy changed.
		for mid, endpoints := range s.mappingAcks {
			m, exists := st.Mappings[mid]
			if !exists {
				delete(s.mappingAcks, mid)
				continue
			}
			policy := mappingPolicy(st, m)
			for nodeID, ack := range endpoints {
				if ack.Policy != policy || (nodeID != m.ServerID && nodeID != m.ClientID) {
					delete(endpoints, nodeID)
				}
			}
		}
		for mid, old := range before.Mappings {
			newMapping, exists := st.Mappings[mid]
			if !exists || !newMapping.Enabled || old.ServerID != newMapping.ServerID {
				for nodeID, report := range s.traffic {
					delete(report.totals, mid)
					s.traffic[nodeID] = report
				}
			}
		}
	}
	return e
}

var ErrRegistrationClosed = errors.New("registration is closed")

func (s *Store) InitAdmin(user, password string) error {
	if strings.TrimSpace(user) == "" || len(user) > 128 || len(password) > 72 {
		return ErrInvalid
	}
	h, err := auth.Password(password)
	if err != nil {
		return ErrInvalid
	}
	result, err := s.db.Exec("INSERT INTO admin(username,password) SELECT ?,? WHERE NOT EXISTS (SELECT 1 FROM admin)", user, h)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err == nil && n != 1 {
		return ErrRegistrationClosed
	}
	return err
}

// ResetAdminUsername changes only the existing sole administrator's name.
// A persistent random audit marker prevents a rename back from reviving sessions.
func (s *Store) ResetAdminUsername(user string) error {
	if strings.TrimSpace(user) == "" || len(user) > 128 {
		return ErrInvalid
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.Exec("UPDATE admin SET username=? WHERE username<>? AND (SELECT count(*) FROM admin)=1", user, user)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return errors.New("rename requires exactly one existing administrator and a different username")
	}
	if _, err = tx.Exec("INSERT INTO audit(at,action,object) VALUES(?,?,?)", time.Now().Unix(), "admin.rename", auth.Token()); err != nil {
		return err
	}
	return tx.Commit()
}

// ResetAdminPassword preserves the username; a fresh bcrypt salt revokes sessions.
func (s *Store) ResetAdminPassword(password string) error {
	if len(password) < 12 || len(password) > 72 {
		return ErrInvalid
	}
	h, err := auth.Password(password)
	if err != nil {
		return ErrInvalid
	}
	result, err := s.db.Exec("UPDATE admin SET password=? WHERE (SELECT count(*) FROM admin)=1", h)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err == nil && n != 1 {
		return errors.New("reset requires exactly one existing administrator")
	}
	return err
}

// adminVersion length-prefixes every component to prevent ambiguous encodings.
func adminVersion(user, hash, marker string) string {
	return auth.Hash(fmt.Sprintf("%d:%s%d:%s%d:%s", len(user), user, len(hash), hash, len(marker), marker))
}

const adminCredentials = "SELECT username,password,COALESCE((SELECT object FROM audit WHERE action='admin.rename' ORDER BY rowid DESC LIMIT 1),'') FROM admin"

func (s *Store) AdminVersion() (string, error) {
	var user, h, marker string
	err := s.db.QueryRow(adminCredentials+" WHERE (SELECT count(*) FROM admin)=1").Scan(&user, &h, &marker)
	return adminVersion(user, h, marker), err
}

// LoginVersion returns the version of the exact credential verified, avoiding
// a reset racing between password verification and session creation.
func (s *Store) LoginVersion(user, password string) (string, bool) {
	if len(user) > 128 || len(password) > 72 {
		return "", false
	}
	var storedUser, h, marker string
	err := s.db.QueryRow(adminCredentials+" WHERE username=? AND (SELECT count(*) FROM admin)=1", user).Scan(&storedUser, &h, &marker)
	if err != nil {
		auth.Check("$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy", password)
		return "", false
	}
	return adminVersion(storedUser, h, marker), auth.Check(h, password)
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
	_, ok := s.LoginVersion(user, password)
	return ok
}
func (s *Store) Nodes() ([]model.Node, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, e := s.load()
	out := []model.Node{}
	for _, n := range st.Nodes {
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].ID < out[j].ID
	})
	return out, e
}
func (s *Store) SaveNode(n model.Node) (model.Node, error) {
	return s.saveNode(n, false)
}

// EnsureEmbeddedNode is reserved for master registration. Existing embedded
// identity and database settings win even if its display name was edited.
func (s *Store) EnsureEmbeddedNode(seed model.Node) (model.Node, error) {
	if seed.Role != "server" {
		return seed, ErrInvalid
	}
	// Registration must never accept an external identity supplied by the caller.
	seed.ID = ""
	return s.saveNode(seed, true)
}

func connectEndpoints(n model.Node) []model.ConnectEndpoint {
	if len(n.ConnectEndpoints) != 0 {
		return n.ConnectEndpoints
	}
	if n.Address == "" || n.Port == 0 {
		return nil
	}
	return []model.ConnectEndpoint{{ID: "primary", Name: "首选", Host: n.Address, Port: n.Port, Enabled: true}}
}

// Empty selection explicitly means all enabled candidates, in list order.
func validEndpointSelection(n model.Node, id string) bool {
	if id == "" {
		return true
	}
	matches := 0
	valid := false
	for _, ep := range connectEndpoints(n) {
		if ep.ID == id {
			matches++
			valid = ep.Enabled && host(ep.Host) && ep.Port > 0 && ep.Port <= 65535
		}
	}
	return matches == 1 && valid
}

func mappingMatchesBinding(m model.Mapping, b model.Binding) bool {
	return m.ServerID == b.ServerID && m.ClientID == b.ClientID && m.ConnectEndpointID == b.ConnectEndpointID
}

func validateConnectEndpoints(n model.Node) error {
	seen := map[string]bool{}
	enabled := 0
	for _, ep := range connectEndpoints(n) {
		if ep.ID == "" || len(ep.ID) > 128 || seen[ep.ID] || ep.Name == "" || len(ep.Name) > 128 || !host(ep.Host) || ep.Port < 1 || ep.Port > 65535 {
			return ErrInvalid
		}
		seen[ep.ID] = true
		if ep.Enabled {
			enabled++
		}
	}
	if enabled == 0 {
		return ErrInvalid
	}
	return nil
}

func (s *Store) saveNode(n model.Node, embedded bool) (model.Node, error) {
	if n.ID == "" {
		n.ID = auth.Token()
	}
	e := s.mutate("node.save", n.ID, func(st *state) error {
		if embedded {
			// Prefer the registered identity over mutable display metadata.
			var existing *model.Node
			for _, candidate := range st.Nodes {
				if candidate.Embedded {
					if existing != nil {
						return ErrInvalid
					}
					copy := candidate
					existing = &copy
				}
			}
			if existing != nil {
				if existing.Role != "server" || existing.Revoked {
					return ErrInvalid
				}
				n = *existing
			}
		}
		if !embedded && n.Embedded && !st.Nodes[n.ID].Embedded {
			return ErrInvalid
		}
		n.Embedded = embedded
		if n.Role == "client" && (n.Tunnel != (model.LocalTLS{}) || n.ClientTunnel != nil) {
			return ErrInvalid
		}
		if err := validateTunnel(n.Role, n.Tunnel); err != nil {
			return err
		}
		if n.Name == "" || len(n.Name) > 128 || (n.Role != "server" && n.Role != "client") {
			return ErrInvalid
		}
		if n.Role == "server" {
			if !host(n.Address) || n.Port < 1 || n.Port > 65535 || validateConnectEndpoints(n) != nil {
				return ErrInvalid
			}
			n.ConnectEndpoints = connectEndpoints(n)
		}
		if old, ok := st.Nodes[n.ID]; ok {
			if old.Role != n.Role || old.Revoked {
				return ErrInvalid
			}
			n.AppliedRevision = old.AppliedRevision
			n.LastSeen = old.LastSeen
			n.Error = old.Error
			n.Embedded = old.Embedded || embedded
		}
		if n.Role == "server" {
			if n.Tunnel.Reality.PrivateKey != "" {
				public := model.DeriveX25519Public(n.Tunnel.Reality.PrivateKey)
				if n.Tunnel.Reality.PublicKey != "" && n.Tunnel.Reality.PublicKey != public {
					return ErrInvalid
				}
				n.Tunnel.Reality.PublicKey = public
			}
			paired, err := clientTemplate(n)
			if err != nil {
				return err
			}
			n.ClientTunnel = paired
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
		if !ok || n.Embedded {
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
		delete(s.software, id)
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
	if !ok || n.Revoked || ttl <= 0 || ttl > time.Duration(1_000_000_000)*time.Second {
		return "", ErrInvalid
	}
	token := auth.Token()
	_, e = s.db.Exec("INSERT OR REPLACE INTO enroll VALUES(?,?,?)", id, auth.Hash(token), time.Now().Add(ttl).Unix())
	return token, e
}
func enrollmentCredentialKey(id string) string { return "credential:" + id }

func (s *Store) Enroll(id, token string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, e := s.db.Begin()
	if e != nil {
		return "", e
	}
	defer tx.Rollback()
	// Acquire a database write lock before checking state, including across Store instances.
	// This validates but does not consume or extend the enrollment token.
	checked, e := tx.Exec("UPDATE enroll SET hash=hash WHERE node=? AND hash=? AND expires>?", id, auth.Hash(token), time.Now().Unix())
	if e != nil {
		return "", e
	}
	count, e := checked.RowsAffected()
	if e != nil {
		return "", e
	}
	if count != 1 {
		return "", ErrAuth
	}
	var raw []byte
	if e = tx.QueryRow("SELECT data FROM config WHERE id=1").Scan(&raw); e != nil {
		return "", e
	}
	var st state
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if e = decoder.Decode(&st); e != nil {
		return "", e
	}
	n, ok := st.Nodes[id]
	if !ok || n.Revoked {
		return "", ErrAuth
	}
	var credentialHash string
	var credentialExpires int64
	credentialErr := tx.QueryRow("SELECT hash,expires FROM credentials WHERE node=?", id).Scan(&credentialHash, &credentialExpires)
	if credentialErr != nil && !errors.Is(credentialErr, sql.ErrNoRows) {
		return "", credentialErr
	}
	if credentialErr == nil && credentialExpires > time.Now().Unix() {
		sealed, exists := st.Secrets[enrollmentCredentialKey(id)]
		if !exists {
			return "", errors.New("existing credential is hash-only; reusable enrollment cannot replace an active credential")
		}
		credential, openErr := auth.Open(s.key, sealed)
		if openErr != nil || auth.Hash(credential) != credentialHash {
			return "", ErrAuth
		}
		return credential, tx.Commit()
	}
	credential := auth.Token()
	sealed, e := auth.Seal(s.key, credential)
	if e != nil {
		return "", e
	}
	if st.Secrets == nil {
		st.Secrets = map[string][]byte{}
	}
	st.Secrets[enrollmentCredentialKey(id)] = sealed
	if _, e = tx.Exec("INSERT OR REPLACE INTO credentials(node,hash,expires) VALUES(?,?,?)", id, auth.Hash(credential), time.Now().Add(30*24*time.Hour).Unix()); e != nil {
		return "", e
	}
	b, e := json.Marshal(st)
	if e != nil {
		return "", e
	}
	if _, e = tx.Exec("UPDATE config SET data=? WHERE id=1", b); e != nil {
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
	var expires int64
	return s.db.QueryRow("SELECT hash,expires FROM credentials WHERE node=?", id).Scan(&h, &expires) == nil && h == auth.Hash(credential) && expires > time.Now().Unix()
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
	currentNode := st.Nodes[id]
	currentNode.ClientTunnel = nil
	if currentNode.Role == "client" {
		currentNode.Tunnel = model.LocalTLS{}
	}
	out := model.Snapshot{Revision: currentNode.DesiredRevision, Node: currentNode, Nodes: []model.Node{}, Bindings: []model.Binding{}, Mappings: []model.Mapping{}}
	peers := map[string]bool{}
	for bid, b := range st.Bindings {
		a, aok := st.Nodes[b.ServerID]
		c, cok := st.Nodes[b.ClientID]
		if !aok || !cok || a.Revoked || c.Revoked || (b.ServerID != id && b.ClientID != id) {
			continue
		}
		if !validEndpointSelection(a, b.ConnectEndpointID) {
			return model.Snapshot{}, ErrInvalid
		}
		b.UUID, e = auth.Open(s.key, st.Secrets[bid])
		if e != nil {
			return model.Snapshot{}, e
		}
		out.Bindings = append(out.Bindings, b)
		peers[b.ServerID] = true
		for _, m := range st.Mappings {
			if m.BindingID == bid {
				if !mappingMatchesBinding(m, b) {
					return model.Snapshot{}, ErrInvalid
				}
				out.Mappings = append(out.Mappings, m)
			}
		}
	}
	for peer := range peers {
		peerNode := st.Nodes[peer]
		if id != peer {
			// Send public endpoints and the persisted template, never local bind data.
			peerNode.Tunnel, e = publicTunnel(peerNode)
			if e != nil {
				return model.Snapshot{}, e
			}
			peerNode.Tunnel.ListenHost = ""
			peerNode.Tunnel.ListenPort = 0
		}
		peerNode.ClientTunnel = nil
		out.Nodes = append(out.Nodes, peerNode)
	}
	return out, nil
}
func (s *Store) Heartbeat(id, credential string, applied int64, failed bool) (int64, error) {
	return s.HeartbeatSoftware(id, credential, applied, failed, SoftwareReport{})
}

// HeartbeatSoftware records authenticated, bounded software metadata only in memory.
func (s *Store) HeartbeatSoftware(id, credential string, applied int64, failed bool, software SoftwareReport) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, e := s.load()
	if e != nil {
		return 0, e
	}
	if !s.authorized(st, id, credential) {
		return 0, ErrAuth
	}
	if !validSoftwareLabel(software.SoftwareVersion) || !validSoftwareLabel(software.SoftwareCommit) {
		return 0, ErrInvalid
	}
	n := st.Nodes[id]
	if applied < 0 || applied > n.DesiredRevision {
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
	if e == nil {
		if s.software == nil {
			s.software = make(map[string]SoftwareReport)
		}
		s.software[id] = software
		if s.mappingAcks == nil {
			s.mappingAcks = make(map[string]map[string]mappingAck)
		}
		for mid, m := range st.Mappings {
			if !m.Enabled || (id != m.ServerID && id != m.ClientID) {
				continue
			}
			policy := mappingPolicy(st, m)
			if s.mappingAcks[mid] == nil {
				s.mappingAcks[mid] = make(map[string]mappingAck)
			}
			old := s.mappingAcks[mid][id]
			if !failed && applied == n.DesiredRevision {
				s.mappingAcks[mid][id] = mappingAck{Policy: policy}
			} else if failed && old.Policy != policy {
				// A failed apply never erases an earlier successful acknowledgement.
				s.mappingAcks[mid][id] = mappingAck{Policy: policy, Failed: true}
			}
		}
	}
	return n.DesiredRevision, e
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
func (s *Store) Mappings() ([]model.Mapping, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, e := s.load()
	if e != nil {
		return nil, e
	}
	out := make([]model.Mapping, 0, len(st.Mappings))
	for _, m := range st.Mappings {
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}
func host(h string) bool {
	if net.ParseIP(h) != nil {
		return true
	}
	if len(h) == 0 || len(h) > 253 || strings.ToLower(h) != h {
		return false
	}
	for _, label := range strings.Split(h, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}
func listenOverlap(a, b string) bool {
	a, b = listenHostForStore(a), listenHostForStore(b)
	aIP, bIP := net.ParseIP(a), net.ParseIP(b)
	return aIP != nil && bIP != nil && (aIP.Equal(bIP) || aIP.IsUnspecified() || bIP.IsUnspecified())
}
func wildcard(h string) bool { return h == "" || h == "0.0.0.0" || h == "::" }
func listenHostForStore(h string) string {
	if h == "" {
		return "127.0.0.1"
	}
	return h
}

func mappingNet(s string) string {
	if strings.EqualFold(strings.TrimSpace(s), "udp") {
		return "udp"
	}
	return "tcp"
}

func validate(st *state) error {
	pairs := map[[3]string]bool{}
	for _, b := range st.Bindings {
		pair := [3]string{b.ServerID, b.ClientID, b.ConnectEndpointID}
		if pairs[pair] || !validEndpointSelection(st.Nodes[b.ServerID], b.ConnectEndpointID) {
			return ErrInvalid
		}
		pairs[pair] = true
	}
	for id, m := range st.Mappings {
		if _, err := m.EffectiveMuxType(); err != nil {
			return ErrInvalid
		}
		b, ok := st.Bindings[m.BindingID]
		if !ok || m.Name == "" || len(m.Name) > 128 || (m.Network != "" && m.Network != "tcp" && m.Network != "udp") || m.ListenPort < 1 || m.ListenPort > 65535 || m.TargetPort < 1 || m.TargetPort > 65535 || !host(m.TargetHost) || net.ParseIP(m.ListenHost) == nil {
			return ErrInvalid
		}
		if !mappingMatchesBinding(m, b) || m.Pool < 1 || m.Pool > 32 || st.Nodes[b.ServerID].Role != "server" || st.Nodes[b.ClientID].Role != "client" {
			return ErrInvalid
		}
		n := st.Nodes[b.ServerID]
		// Even disabled mappings create a live binding. Do not attach one to
		// an unconfigured server, or clear settings while it remains bound.
		if n.Tunnel == (model.LocalTLS{}) || validateTunnel("server", n.Tunnel) != nil {
			return ErrInvalid
		}
		if n.Tunnel.ListenPort == 0 {
			return ErrInvalid
		}
		transportNet := "tcp"
		if n.Tunnel.Hysteria2.Enabled() {
			transportNet = "udp"
		}
		transportHost := listenHostForStore(n.Tunnel.ListenHost)
		if m.Enabled && mappingNet(m.Network) == transportNet && m.ListenPort == n.Tunnel.ListenPort && listenOverlap(m.ListenHost, transportHost) {
			return ErrInvalid
		}
		for oid, o := range st.Mappings {
			if oid != id && m.Enabled && o.Enabled && st.Bindings[o.BindingID].ServerID == b.ServerID && o.ListenPort == m.ListenPort && mappingNet(o.Network) == mappingNet(m.Network) && listenOverlap(o.ListenHost, m.ListenHost) {
				return ErrInvalid
			}
		}
	}
	return nil
}
func (s *Store) SaveMapping(m model.Mapping) (model.Mapping, error) {
	network := strings.ToLower(strings.TrimSpace(m.Network))
	if network != "" && network != "tcp" && network != "udp" {
		return m, ErrInvalid
	}
	m.Network = mappingNet(network)
	muxType, err := m.EffectiveMuxType()
	if err != nil {
		return m, ErrInvalid
	}
	m.MuxType = muxType
	if m.BindingID != "" || m.ServerID == "" || m.ClientID == "" || m.Pool < 1 || m.Pool > 32 {
		return m, ErrInvalid
	}
	if m.ID == "" {
		m.ID = auth.Token()
	}
	e := s.mutate("mapping.save", m.ID, func(st *state) error {
		old := st.Mappings[m.ID]
		if !validPair(st, m.ServerID, m.ClientID) || !validEndpointSelection(st.Nodes[m.ServerID], m.ConnectEndpointID) {
			return ErrInvalid
		}
		for _, b := range st.Bindings {
			if mappingMatchesBinding(m, b) {
				m.BindingID = b.ID
				break
			}
		}
		if m.BindingID == "" {
			b, err := s.createBinding(st, m.ServerID, m.ClientID, m.ConnectEndpointID)
			if err != nil {
				return err
			}
			m.BindingID = b.ID
		}
		st.Mappings[m.ID] = m
		if err := validate(st); err != nil {
			return err
		}
		if old.BindingID != "" && old.BindingID != m.BindingID {
			cleanupBinding(st, old.BindingID)
		}
		return nil
	})
	return m, e
}
func (s *Store) DeleteMapping(id string) error {
	return s.mutate("mapping.delete", id, func(st *state) error {
		m, ok := st.Mappings[id]
		if !ok {
			return ErrInvalid
		}
		delete(st.Mappings, id)
		cleanupBinding(st, m.BindingID)
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
