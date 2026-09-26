package httpapi

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"veilink/internal/model"
	"veilink/internal/store"
	"veilink/internal/tunnel"
)

func TestStatsHeartbeatAndMappingLifecycle(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "db")
	s, err := store.Open(path, filepath.Join(dir, "key"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.InitAdmin("admin", "long test password"); err != nil {
		t.Fatal(err)
	}
	h := New(s, true, nil, nil)
	var cookie *http.Cookie
	call := func(method, path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if w := call("GET", "/api/stats", ""); w.Code != http.StatusUnauthorized {
		t.Fatal("stats accessible without login", w.Code)
	}
	w := call("POST", "/api/login", `{"username":"admin","password":"long test password"}`)
	if w.Code != http.StatusOK {
		t.Fatal("login failed", w.Code)
	}
	cookie = w.Result().Cookies()[0]
	check := func(t *testing.T, nodes, online, mappings, enabled int) {
		t.Helper()
		w := call("GET", "/api/stats", "")
		if w.Code != http.StatusOK {
			t.Fatal("stats failed", w.Code)
		}
		var got map[string]int
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		want := map[string]int{"total_nodes": nodes, "online_nodes": online, "total_mappings": mappings, "enabled_mappings": enabled}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("stats=%v want=%v", got, want)
		}
	}
	check(t, 0, 0, 0, 0)
	dec, _, _, _, err := tunnel.GenerateVLESSEnc()
	if err != nil {
		t.Fatal(err)
	}
	server, err := s.SaveNode(model.Node{Name: "gateway", Role: "server", Address: "localhost", Port: 8444, Tunnel: model.LocalTLS{TransportSecurity: "plain", Decryption: dec, ListenHost: "127.0.0.1", ListenPort: 8444}})
	if err != nil {
		t.Fatal(err)
	}
	client, err := s.SaveNode(model.Node{Name: "client", Role: "client"})
	if err != nil {
		t.Fatal(err)
	}
	token, err := s.EnrollToken(client.ID, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := s.Enroll(client.ID, token)
	if err != nil {
		t.Fatal(err)
	}
	m, err := s.SaveMapping(model.Mapping{Name: "mapping", ServerID: server.ID, ClientID: client.ID, Pool: 1, ListenHost: "127.0.0.1", ListenPort: 18080, TargetHost: "127.0.0.1", TargetPort: 80, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	check(t, 2, 0, 1, 1)
	snap, err := s.Snapshot(client.ID, credential)
	if err != nil {
		t.Fatal(err)
	}
	before := time.Now().Unix()
	if _, err := s.Heartbeat(client.ID, credential, snap.Revision, false); err != nil {
		t.Fatal(err)
	}
	check(t, 2, 1, 1, 1)
	n, found, err := s.FindNodeByName(client.Name)
	if err != nil || !found || n.LastSeen < before || n.LastSeen > time.Now().Unix() || n.AppliedRevision != snap.Revision || n.Error != "" {
		t.Fatal("successful heartbeat metadata mismatch", err)
	}
	m.Enabled, m.BindingID = false, ""
	if _, err := s.SaveMapping(m); err != nil {
		t.Fatal(err)
	}
	desired, err := s.Heartbeat(client.ID, credential, snap.Revision, true)
	if err != nil {
		t.Fatal(err)
	}
	n, found, err = s.FindNodeByName(client.Name)
	if err != nil || !found || desired <= snap.Revision || n.DesiredRevision != desired || n.AppliedRevision != snap.Revision || n.Error == "" {
		t.Fatal("failed Apply reported as success", err)
	}
	check(t, 2, 1, 1, 0) // Heartbeat presence is not configuration/target health.
	if _, err := s.Heartbeat(client.ID, credential, desired, false); err != nil {
		t.Fatal(err)
	}
	n, found, err = s.FindNodeByName(client.Name)
	if err != nil || !found || n.AppliedRevision != desired || n.Error != "" {
		t.Fatal("recovery did not clear failure", err)
	}
	// Set timestamps only in this test's private database; never sleep 90 seconds.
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	setSeen := func(t *testing.T, seen int64) {
		t.Helper()
		var raw []byte
		if err := db.QueryRow("SELECT data FROM config WHERE id=1").Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var state map[string]json.RawMessage
		if err := json.Unmarshal(raw, &state); err != nil {
			t.Fatal(err)
		}
		var nodes map[string]model.Node
		if err := json.Unmarshal(state["Nodes"], &nodes); err != nil {
			t.Fatal(err)
		}
		n := nodes[client.ID]
		n.LastSeen = seen
		nodes[client.ID] = n
		state["Nodes"], err = json.Marshal(nodes)
		if err != nil {
			t.Fatal(err)
		}
		raw, err = json.Marshal(state)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec("UPDATE config SET data=? WHERE id=1", raw); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name   string
		seen   int64
		online int
	}{
		{"recent", time.Now().Unix() - 75, 1},
		{"expired", time.Now().Unix() - 91, 0},
		{"future", time.Now().Unix() + 60, 0},
		{"never", 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) { setSeen(t, tc.seen); check(t, 2, tc.online, 1, 0) })
	}
	setSeen(t, time.Now().Unix())
	if err := s.RemoveNode(client.ID, false); err != nil {
		t.Fatal(err)
	}
	check(t, 2, 0, 1, 0)
	if err := s.RemoveNode(client.ID, true); err != nil {
		t.Fatal(err)
	}
	check(t, 1, 0, 0, 0)
}
