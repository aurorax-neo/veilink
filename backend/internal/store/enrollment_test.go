package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestReusableEnrollmentRestartAndConcurrency(t *testing.T) {
	s, db, key := testStore(t)
	n := testNode(t, s, "client", "reusable")
	other := testNode(t, s, "client", "other")
	token, err := s.EnrollToken(n.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Enroll(other.ID, token); !errors.Is(err, ErrAuth) {
		t.Fatal("cross-node token accepted", err)
	}
	second, err := Open(db, key)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	const workers = 16
	credentials := make([]string, workers)
	errs := make([]error, workers)
	var wg sync.WaitGroup
	for i := range credentials {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			target := s
			if i%2 != 0 {
				target = second
			}
			credentials[i], errs[i] = target.Enroll(n.ID, token)
		}(i)
	}
	wg.Wait()
	for i, credential := range credentials {
		if errs[i] != nil || credential == "" || credential != credentials[0] {
			t.Fatalf("concurrent enrollment %d: %v, stable=%v", i, errs[i], credential == credentials[0])
		}
	}
	var raw []byte
	if err := s.db.QueryRow("SELECT data FROM config WHERE id=1").Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(credentials[0])) || bytes.Contains(raw, []byte(token)) {
		t.Fatal("plaintext enrollment secret persisted")
	}
	var expires int64
	if err := s.db.QueryRow("SELECT expires FROM credentials WHERE node=?", n.ID).Scan(&expires); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(db, key)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	credential, err := reopened.Enroll(n.ID, token)
	if err != nil || credential != credentials[0] {
		t.Fatal("restart changed credential", err)
	}
	var afterExpires int64
	if err := reopened.db.QueryRow("SELECT expires FROM credentials WHERE node=?", n.ID).Scan(&afterExpires); err != nil || afterExpires != expires {
		t.Fatal("reuse extended credential lifetime", err)
	}
	if _, err := reopened.Snapshot(n.ID, credentials[0]); err != nil {
		t.Fatal("original credential invalidated", err)
	}
	if err := reopened.RevokeEnrollToken(n.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.Enroll(n.ID, token); !errors.Is(err, ErrAuth) {
		t.Fatal("revoked token accepted", err)
	}
	if _, err := reopened.Snapshot(n.ID, credentials[0]); err != nil {
		t.Fatal("token revocation invalidated credential", err)
	}
}

func TestReusableEnrollmentLifecycle(t *testing.T) {
	for _, action := range []string{"replace", "expire", "revoke-node", "delete-node", "expire-credential", "hash-only", "corrupt-seal"} {
		t.Run(action, func(t *testing.T) {
			s, _, _ := testStore(t)
			n := testNode(t, s, "client", action)
			token, err := s.EnrollToken(n.ID, time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			credential, err := s.Enroll(n.ID, token)
			if err != nil {
				t.Fatal(err)
			}
			switch action {
			case "replace":
				replacement, err := s.EnrollToken(n.ID, time.Hour)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := s.Enroll(n.ID, token); !errors.Is(err, ErrAuth) {
					t.Fatal("replaced token accepted", err)
				}
				reused, err := s.Enroll(n.ID, replacement)
				if err != nil || reused != credential {
					t.Fatal("replacement invalidated credential", err)
				}
				return
			case "expire":
				if _, err := s.db.Exec("UPDATE enroll SET expires=0 WHERE node=?", n.ID); err != nil {
					t.Fatal(err)
				}
			case "revoke-node", "delete-node":
				if err := s.RemoveNode(n.ID, action == "delete-node"); err != nil {
					t.Fatal(err)
				}
			case "expire-credential":
				if _, err := s.db.Exec("UPDATE credentials SET expires=0 WHERE node=?", n.ID); err != nil {
					t.Fatal(err)
				}
				renewed, err := s.Enroll(n.ID, token)
				if err != nil || renewed == credential {
					t.Fatal("expired credential not rotated", err)
				}
				if _, err := s.Snapshot(n.ID, credential); !errors.Is(err, ErrAuth) {
					t.Fatal("expired credential accepted", err)
				}
				if _, err := s.Snapshot(n.ID, renewed); err != nil {
					t.Fatal(err)
				}
				return
			case "hash-only", "corrupt-seal":
				st, err := s.load()
				if err != nil {
					t.Fatal(err)
				}
				if action == "hash-only" {
					delete(st.Secrets, enrollmentCredentialKey(n.ID))
				} else {
					st.Secrets[enrollmentCredentialKey(n.ID)] = []byte("corrupt")
				}
				raw, err := json.Marshal(st)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := s.db.Exec("UPDATE config SET data=? WHERE id=1", raw); err != nil {
					t.Fatal(err)
				}
			}
			reused, err := s.Enroll(n.ID, token)
			if reused != "" || err == nil {
				t.Fatal("invalid enrollment accepted")
			}
			if action == "hash-only" && !strings.Contains(err.Error(), "hash-only") {
				t.Fatal("missing actionable error", err)
			}
			if action != "hash-only" && !errors.Is(err, ErrAuth) {
				t.Fatal(err)
			}
			_, snapshotErr := s.Snapshot(n.ID, credential)
			if action == "revoke-node" || action == "delete-node" {
				if !errors.Is(snapshotErr, ErrAuth) {
					t.Fatal("revoked credential accepted", snapshotErr)
				}
			} else if snapshotErr != nil {
				t.Fatal("failed enrollment invalidated active credential", snapshotErr)
			}
		})
	}
}

func TestReusableEnrollmentSQLRollback(t *testing.T) {
	s, _, _ := testStore(t)
	n := testNode(t, s, "client", "rollback")
	token, err := s.EnrollToken(n.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("CREATE TRIGGER fail_config BEFORE UPDATE ON config BEGIN SELECT RAISE(ABORT,'test rollback'); END"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Enroll(n.ID, token); err == nil {
		t.Fatal("expected SQL failure")
	}
	var count int
	if err := s.db.QueryRow("SELECT count(*) FROM credentials").Scan(&count); err != nil || count != 0 {
		t.Fatal("partial credential persisted", err)
	}
	if _, err := s.db.Exec("DROP TRIGGER fail_config"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Enroll(n.ID, token); err != nil {
		t.Fatal("failed enrollment consumed token", err)
	}
}
