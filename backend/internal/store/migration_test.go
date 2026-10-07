package store

import (
	"bytes"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"veilink/internal/model"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

func TestPreviousReleaseMigrationPreservesDataAndRepairsMLDSA(t *testing.T) {
	s, path, key := testStore(t)
	server := testNode(t, s, "server", "custom gateway")
	client := testNode(t, s, "client", "client")
	public, private, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	seed := base64.RawURLEncoding.EncodeToString(private.Bytes())
	server.Tunnel = model.LocalTLS{ListenPort: 8444, Reality: model.Reality{PrivateKey: "4A39kZk0Nvd5uD3fXJbF2WvJqCq23xQ3_gL7_J0mE1s", Dest: "example.com:443", ServerNames: "example.com", ShortIDs: "aa", Mldsa65Seed: seed}}
	server.ClientTunnel = nil
	server, err = s.SaveNode(server)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.InitAdmin("admin", "test password long"); err != nil {
		t.Fatal(err)
	}
	credential := testCredential(t, s, client.ID)
	m, err := s.SaveMapping(testMapping(server.ID, client.ID, 18080))
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := s.Snapshot(client.ID, credential)
	if err != nil {
		t.Fatal(err)
	}
	st, err := s.load()
	if err != nil {
		t.Fatal(err)
	}
	n := st.Nodes[server.ID]
	legacy := *n.ClientTunnel
	legacy.Reality.Mldsa65Verify = ""
	n.ClientTunnel = &legacy
	st.Nodes[server.ID] = n
	previous, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("UPDATE config SET data=?; UPDATE schema_version SET version=5", previous); err != nil {
		t.Fatal(err)
	}
	master := []byte(`{"ListenAddr":"127.0.0.1:2545","Scheme":"http","WebMode":"pull","WebVersion":"web-v0.4.2","WebMirror":"https://example.com","WebMirrors":["https://example.com"],"HTMLDir":"/data/web"}`)
	if _, err := s.db.Exec("CREATE TABLE master_config(id INTEGER PRIMARY KEY,data BLOB); INSERT INTO master_config VALUES(1,?)", master); err != nil {
		t.Fatal(err)
	}
	// Reopen while WAL still contains the committed legacy state.
	upgraded, err := Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	defer upgraded.Close()
	after, err := upgraded.load()
	if err != nil {
		t.Fatal(err)
	}
	if after.Nodes[server.ID].ID != server.ID || after.Nodes[server.ID].Name != server.Name || after.Nodes[server.ID].Tunnel != server.Tunnel {
		t.Fatal("server identity/private settings changed")
	}
	if after.Nodes[server.ID].ClientTunnel.Reality.Mldsa65Verify != base64.RawURLEncoding.EncodeToString(public.Bytes()) {
		t.Fatal("MLDSA verification key not repaired")
	}
	if !reflect.DeepEqual(st.Secrets, after.Secrets) || !reflect.DeepEqual(st.Mappings, after.Mappings) || !reflect.DeepEqual(st.Bindings, after.Bindings) || after.Mappings[m.ID].ID != m.ID {
		t.Fatal("migration changed authorization or mappings")
	}
	if after.Revision != st.Revision+1 || after.Nodes[client.ID].DesiredRevision != after.Revision || after.Nodes[client.ID].AppliedRevision != st.Nodes[client.ID].AppliedRevision {
		t.Fatal("incorrect desired/applied revisions")
	}
	if !upgraded.Login("admin", "test password long") {
		t.Fatal("administrator lost")
	}
	got, err := upgraded.Snapshot(client.ID, credential)
	if err != nil || got.Bindings[0].UUID != snapshot.Bindings[0].UUID {
		t.Fatal("credential or binding secret lost", err)
	}
	publicTunnel := got.Nodes[0].Tunnel
	if publicTunnel.Reality.Mldsa65Seed != "" || publicTunnel.Reality.PrivateKey != "" || publicTunnel.Decryption != "" || publicTunnel.KeyPEM != "" {
		t.Fatal("snapshot leaked secrets")
	}
	backups, err := filepath.Glob(path + ".pre-upgrade-*.db")
	if err != nil || len(backups) != 1 {
		t.Fatal("missing backup", backups, err)
	}
	backup, err := sql.Open("sqlite", backups[0])
	if err != nil {
		t.Fatal(err)
	}
	defer backup.Close()
	var version int
	var raw []byte
	if err := backup.QueryRow("SELECT version FROM schema_version").Scan(&version); err != nil || version != 5 {
		t.Fatal("backup has incorrect schema", err)
	}
	if err := backup.QueryRow("SELECT data FROM config").Scan(&raw); err != nil || !bytes.Equal(raw, previous) {
		t.Fatal("backup missing WAL data", err)
	}
	if err := backup.QueryRow("SELECT data FROM master_config").Scan(&raw); err != nil || !bytes.Equal(raw, master) {
		t.Fatal("backup lost web config", err)
	}
	keyBytes, err := os.ReadFile(key)
	if err != nil {
		t.Fatal(err)
	}
	backupKey, err := os.ReadFile(backups[0] + ".key")
	if err != nil || !bytes.Equal(keyBytes, backupKey) {
		t.Fatal("backup key missing", err)
	}
	for _, name := range []string{backups[0], backups[0] + ".key"} {
		info, err := os.Stat(name)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatal("unsafe backup permissions", err)
		}
	}
	reopened, err := Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	again, err := reopened.load()
	if err != nil || !reflect.DeepEqual(after, again) {
		t.Fatal("migration not idempotent", err)
	}
	backups, _ = filepath.Glob(path + ".pre-upgrade-*.db")
	if len(backups) != 1 {
		t.Fatal("restart made another backup")
	}
}

func TestMigrationRejectsCustomOrCorruptDataWithoutWriting(t *testing.T) {
	for _, kind := range []string{"custom-template", "private-client", "bad-secret", "unknown-field", "null", "missing-nodes", "missing-binding-secret", "wrong-mapping-id"} {
		t.Run(kind, func(t *testing.T) {
			s, path, key := testStore(t)
			server := testNode(t, s, "server", "gateway")
			client := testNode(t, s, "client", "client")
			st, err := s.load()
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "custom-template":
				n := st.Nodes[server.ID]
				paired := *n.ClientTunnel
				paired.CAPEM = "wrong trust"
				n.ClientTunnel = &paired
				st.Nodes[server.ID] = n
			case "private-client":
				n := st.Nodes[client.ID]
				n.Tunnel = testTLS(t)
				st.Nodes[client.ID] = n
			case "bad-secret":
				st.Secrets["broken"] = []byte("bad")
			case "missing-nodes":
				st.Nodes = nil
			case "missing-binding-secret", "wrong-mapping-id":
				m, err := s.SaveMapping(testMapping(server.ID, client.ID, 18080))
				if err != nil {
					t.Fatal(err)
				}
				st, err = s.load()
				if err != nil {
					t.Fatal(err)
				}
				if kind == "missing-binding-secret" {
					delete(st.Secrets, m.BindingID)
				} else {
					m.ID = "wrong"
					st.Mappings["wrong-map-key"] = m
				}
			}
			raw, err := json.Marshal(st)
			if err != nil {
				t.Fatal(err)
			}
			if kind == "unknown-field" {
				raw = append([]byte(`{"Unknown":true,`), raw[1:]...)
			}
			if kind == "null" {
				raw = []byte("null")
			}
			if _, err := s.db.Exec("UPDATE config SET data=?; UPDATE schema_version SET version=5", raw); err != nil {
				t.Fatal(err)
			}
			if opened, err := Open(path, key); err == nil {
				opened.Close()
				t.Fatal("unsafe migration accepted")
			}
			var got []byte
			var version int
			if err := s.db.QueryRow("SELECT data FROM config").Scan(&got); err != nil || !bytes.Equal(raw, got) {
				t.Fatal("failed migration changed data", err)
			}
			if err := s.db.QueryRow("SELECT version FROM schema_version").Scan(&version); err != nil || version != 5 {
				t.Fatal("failed migration advanced schema", err)
			}
		})
	}
}

func TestExistingDatabaseNeverReplacesMissingDeploymentKey(t *testing.T) {
	s, path, key := testStore(t)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(key); err != nil {
		t.Fatal(err)
	}
	if opened, err := Open(path, key); err == nil {
		opened.Close()
		t.Fatal("replaced missing deployment key")
	}
	if _, err := os.Stat(key); !os.IsNotExist(err) {
		t.Fatal("created a new key for existing data", err)
	}
}
