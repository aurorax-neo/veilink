package store

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

func TestPersistedEndpointKindRejectedWithoutMutation(t *testing.T) {
	for _, kind := range []string{"direct", "nat", "cdn"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			s, err := Open(filepath.Join(dir, "state.db"), filepath.Join(dir, "state.key"))
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			body := fmt.Sprintf(`{"Revision":7,"Nodes":{"server":{"id":"server","connect_endpoints":[{"kind":%q}]}},"Bindings":{},"Mappings":{},"Secrets":{}}`, kind)
			if _, err := s.db.Exec("UPDATE config SET data=? WHERE id=1", body); err != nil {
				t.Fatal(err)
			}
			if _, err := s.load(); err == nil || !strings.Contains(err.Error(), `unknown field "kind"`) {
				t.Fatalf("obsolete field accepted: %v", err)
			}
			var after string
			if err := s.db.QueryRow("SELECT data FROM config WHERE id=1").Scan(&after); err != nil || after != body {
				t.Fatalf("obsolete data changed: %v", err)
			}
		})
	}
}
