package config

import (
	"database/sql"
	"path/filepath"
	"testing"
)

func TestPersistedRemovedWebFieldsMigrateAfterCommit(t *testing.T) {
	for _, field := range []string{"WebMode", "WebVersion", "WebMirrors", "FrontendURL", "web_mode", "frontend_url"} {
		t.Run(field, func(t *testing.T) {
			dir := t.TempDir()
			c, err := ParseFlags("master", []string{"-database", filepath.Join(dir, "db"), "-deployment-key", filepath.Join(dir, "key")})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := PersistMaster(c); err != nil {
				t.Fatal(err)
			}
			db, err := sql.Open("sqlite", c.Database)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			raw := `{"` + field + `":null}`
			if _, err := db.Exec("UPDATE master_config SET data=? WHERE id=1", []byte(raw)); err != nil {
				t.Fatal(err)
			}
			_, commit, err := ResolveMaster(c)
			if err != nil {
				t.Fatal(err)
			}
			var got string
			if err := db.QueryRow("SELECT data FROM master_config WHERE id=1").Scan(&got); err != nil || got != raw {
				t.Fatalf("configuration changed: %q %v", got, err)
			}
			if err := commit(); err != nil {
				t.Fatal(err)
			}
			backups, err := filepath.Glob(c.Database + ".pre-upgrade-*.db")
			if err != nil || len(backups) != 1 {
				t.Fatalf("missing backup: %v %v", backups, err)
			}
			backup, err := sql.Open("sqlite", backups[0])
			if err != nil {
				t.Fatal(err)
			}
			defer backup.Close()
			if err := backup.QueryRow("SELECT data FROM master_config WHERE id=1").Scan(&got); err != nil || got != raw {
				t.Fatal("backup lost old settings", err)
			}
			if _, _, err := ResolveMaster(c); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestMasterMigrationRejectsUnknownAndInvalidDocuments(t *testing.T) {
	for _, raw := range []string{`null`, `{"WebMode":"pull","surprise":true}`, `{"Scheme":123}`, `{} {}`} {
		if _, _, err := UpgradeMasterDocument([]byte(raw)); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
}
