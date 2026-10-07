package store

import (
	"errors"
	"reflect"
	"testing"
)

func TestMappingBandwidthPersistsDisablesAndScopesRevisions(t *testing.T) {
	s, db, key := testStore(t)
	server := testNode(t, s, "server", "server")
	client := testNode(t, s, "client", "client")
	unrelated := testNode(t, s, "client", "unrelated")
	m, err := s.SaveMapping(testMapping(server.ID, client.ID, 18080))
	if err != nil {
		t.Fatal(err)
	}
	credentials := map[string]string{}
	for _, id := range []string{server.ID, client.ID, unrelated.ID} {
		credentials[id] = testCredential(t, s, id)
	}
	for _, value := range []string{" 48Mbps ", "24Mbps", "0", "48Mbps", "0Mbps", "24Mbps", ""} {
		before, err := s.load()
		if err != nil {
			t.Fatal(err)
		}
		m.BandwidthLimit = value
		m.BindingID = ""
		m, err = s.SaveMapping(m)
		if err != nil {
			t.Fatal(err)
		}
		want := value
		if value == " 48Mbps " {
			want = "48Mbps"
		}
		if value == "0" || value == "0Mbps" {
			want = ""
		}
		if m.BandwidthLimit != want {
			t.Fatalf("saved bandwidth = %q, want %q", m.BandwidthLimit, want)
		}
		after, err := s.load()
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(before.Nodes[unrelated.ID], after.Nodes[unrelated.ID]) {
			t.Fatal("bandwidth change affected unrelated node")
		}
		for _, id := range []string{server.ID, client.ID} {
			if after.Nodes[id].DesiredRevision <= before.Nodes[id].DesiredRevision {
				t.Fatal("bandwidth change did not advance endpoint revision")
			}
			snapshot, err := s.Snapshot(id, credentials[id])
			if err != nil {
				t.Fatal(err)
			}
			if len(snapshot.Mappings) != 1 || snapshot.Mappings[0].BandwidthLimit != want {
				t.Fatal("snapshot lost bandwidth limit")
			}
		}
		reopened, err := Open(db, key)
		if err != nil {
			t.Fatal(err)
		}
		stored, readErr := reopened.Mappings()
		_ = reopened.Close()
		if readErr != nil || len(stored) != 1 || stored[0].BandwidthLimit != want {
			t.Fatalf("bandwidth did not survive reopen: %v, %v", stored, readErr)
		}
	}
	before, err := s.load()
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"48MBps", "100.001Gbps", "-1Mbps"} {
		invalid := m
		invalid.BindingID = ""
		invalid.BandwidthLimit = value
		if _, err := s.SaveMapping(invalid); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid bandwidth %q accepted: %v", value, err)
		}
	}
	after, err := s.load()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatal("invalid bandwidth changed persisted configuration")
	}
}
