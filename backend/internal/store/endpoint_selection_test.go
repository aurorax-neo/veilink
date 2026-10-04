package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"veilink/internal/model"
	"veilink/internal/tunnel"
)

func TestMappingEndpointSelection(t *testing.T) {
	s, db, key := testStore(t)
	server := testNode(t, s, "server", "gateway")
	client := testNode(t, s, "client", "client")
	other := testNode(t, s, "server", "other")
	idle := testNode(t, s, "client", "idle")
	server.ConnectEndpoints = []model.ConnectEndpoint{
		{ID: "a", Name: "A", Host: "localhost", Port: 443, Enabled: true},
		{ID: "b", Name: "B", Host: "localhost", Port: 444, Enabled: true},
		{ID: "off", Name: "Off", Host: "localhost", Port: 445},
	}
	var err error
	server, err = s.SaveNode(server)
	if err != nil {
		t.Fatal(err)
	}
	other.ConnectEndpoints = []model.ConnectEndpoint{{ID: "foreign", Name: "Foreign", Host: "localhost", Port: 443, Enabled: true}}
	if _, err = s.SaveNode(other); err != nil {
		t.Fatal(err)
	}
	creds := map[string]string{}
	for _, n := range []model.Node{server, client, other, idle} {
		creds[n.ID] = testCredential(t, s, n.ID)
	}
	save := func(selection string, port int) model.Mapping {
		t.Helper()
		m := testMapping(server.ID, client.ID, port)
		m.Name = fmt.Sprint(port)
		m.ConnectEndpointID = selection
		m, err := s.SaveMapping(m)
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	auto := save("", 18080)
	a := save("a", 18081)
	shared := save("a", 18082)
	b := save("b", 18083)
	if a.BindingID != shared.BindingID || a.BindingID == b.BindingID || auto.BindingID == a.BindingID || auto.BindingID == b.BindingID {
		t.Fatal("incorrect endpoint grouping")
	}
	before, err := s.load()
	if err != nil {
		t.Fatal(err)
	}
	for _, selection := range []string{"unknown", "off", "foreign", " a", "primary"} {
		bad := testMapping(server.ID, client.ID, 18084)
		bad.ConnectEndpointID = selection
		for _, enabled := range []bool{true, false} {
			bad.Enabled = enabled
			if _, err := s.SaveMapping(bad); !errors.Is(err, ErrInvalid) {
				t.Fatalf("accepted %q: %v", selection, err)
			}
		}
	}
	after, _ := s.load()
	if !reflect.DeepEqual(before, after) {
		t.Fatal("invalid selection mutated storage")
	}
	// A disabled mapping still pins its endpoint, even when it is the only reference.
	b.Enabled, b.BindingID = false, ""
	b, err = s.SaveMapping(b)
	if err != nil {
		t.Fatal(err)
	}
	for _, remove := range []bool{false, true} {
		edited := server
		edited.ConnectEndpoints = append([]model.ConnectEndpoint(nil), server.ConnectEndpoints...)
		if remove {
			edited.ConnectEndpoints = append(edited.ConnectEndpoints[:1], edited.ConnectEndpoints[2:]...)
		} else {
			edited.ConnectEndpoints[1].Enabled = false
		}
		if _, err := s.SaveNode(edited); !errors.Is(err, ErrInvalid) {
			t.Fatalf("referenced endpoint edit accepted: %v", err)
		}
	}
	// Selection-only edits notify just the two affected nodes and reuse an existing group.
	before, _ = s.load()
	a.BindingID, a.ConnectEndpointID = "", "b"
	a, err = s.SaveMapping(a)
	if err != nil {
		t.Fatal(err)
	}
	if a.BindingID != b.BindingID {
		t.Fatal("selection change did not reuse group")
	}
	after, _ = s.load()
	for _, n := range []model.Node{server, client} {
		if after.Nodes[n.ID].DesiredRevision <= before.Nodes[n.ID].DesiredRevision {
			t.Fatal("revision not advanced")
		}
	}
	for _, n := range []model.Node{other, idle} {
		if after.Nodes[n.ID].DesiredRevision != before.Nodes[n.ID].DesiredRevision {
			t.Fatal("unrelated revision advanced")
		}
	}
	oldBinding := shared.BindingID
	shared.BindingID, shared.ConnectEndpointID = "", "b"
	shared, err = s.SaveMapping(shared)
	if err != nil {
		t.Fatal(err)
	}
	after, _ = s.load()
	if _, ok := after.Bindings[oldBinding]; ok {
		t.Fatal("orphan binding retained")
	}
	if _, ok := after.Secrets[oldBinding]; ok {
		t.Fatal("orphan credential retained")
	}
	reopened, err := Open(db, key)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	stored, err := reopened.load()
	if err != nil || !reflect.DeepEqual(after, stored) {
		t.Fatal("selection persistence", err)
	}
	for _, id := range []string{server.ID, client.ID} {
		snap, err := reopened.Snapshot(id, creds[id])
		if err != nil {
			t.Fatal(err)
		}
		if len(snap.Bindings) != 2 || len(snap.Mappings) != 4 {
			t.Fatal("snapshot groups missing")
		}
		bindings := map[string]model.Binding{}
		for _, binding := range snap.Bindings {
			bindings[binding.ID] = binding
		}
		for _, m := range snap.Mappings {
			if !mappingMatchesBinding(m, bindings[m.BindingID]) {
				t.Fatal("snapshot selection mismatch")
			}
		}
		if id == server.ID {
			if _, err := tunnel.Build(snap, snap.Node.Tunnel); err != nil {
				t.Fatal("snapshot rejected by runtime", err)
			}
		}
		if id == client.ID {
			for _, n := range snap.Nodes {
				if n.Tunnel.KeyPEM != "" || n.Tunnel.CertPEM != "" || n.Tunnel.Decryption != "" || n.Tunnel.Reality.PrivateKey != "" || n.ClientTunnel != nil {
					t.Fatal("private fields leaked")
				}
			}
		}
	}
	// Fail closed on persisted mismatches/stale references, not only API input.
	for name, mutate := range map[string]func(*state){
		"mismatch": func(st *state) { m := st.Mappings[a.ID]; m.ConnectEndpointID = "a"; st.Mappings[a.ID] = m },
		"stale":    func(st *state) { n := st.Nodes[server.ID]; n.ConnectEndpoints[1].Enabled = false; st.Nodes[n.ID] = n },
	} {
		t.Run(name, func(t *testing.T) {
			bad := cloneState(after)
			mutate(&bad)
			if validate(&bad) == nil {
				t.Fatal("invalid persisted selection accepted")
			}
			data, err := json.Marshal(bad)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = s.db.Exec("UPDATE config SET data=? WHERE id=1", data); err != nil {
				t.Fatal(err)
			}
			for _, id := range []string{server.ID, client.ID} {
				if _, err = s.Snapshot(id, creds[id]); !errors.Is(err, ErrInvalid) {
					t.Fatal("bad snapshot delivered", err)
				}
			}
		})
	}
}
