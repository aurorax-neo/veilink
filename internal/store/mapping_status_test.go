package store

import (
	"path/filepath"
	"testing"
)

func TestMappingStatusIndependentAcknowledgements(t *testing.T) {
	s, db, key := testStore(t)
	server := testNode(t, s, "server", "s")
	client := testNode(t, s, "client", "c")
	a, err := s.SaveMapping(testMapping(server.ID, client.ID, 18080))
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.SaveMapping(testMapping(server.ID, client.ID, 18081))
	if err != nil {
		t.Fatal(err)
	}
	creds := map[string]string{server.ID: testCredential(t, s, server.ID), client.ID: testCredential(t, s, client.ID)}
	check := func(id string, ready bool, reason string) {
		t.Helper()
		statuses, err := s.MappingStatuses()
		if err != nil {
			t.Fatal(err)
		}
		got := statuses[id]
		if got.Server.Acknowledged != ready || got.Client.Acknowledged != ready || got.Server.Reason != reason || got.Client.Reason != reason {
			t.Fatalf("%s: %+v; expected %v %s", id, got, ready, reason)
		}
	}
	heartbeat := func(failed bool) {
		t.Helper()
		st, err := s.load()
		if err != nil {
			t.Fatal(err)
		}
		for id, credential := range creds {
			if _, err := s.Heartbeat(id, credential, st.Nodes[id].DesiredRevision, failed); err != nil {
				t.Fatal(err)
			}
		}
	}
	check(a.ID, false, "unknown")
	check(b.ID, false, "unknown")
	heartbeat(false)
	check(a.ID, true, "acknowledged")
	check(b.ID, true, "acknowledged")
	// Saving a label changes neither mapping's effective policy.
	a.BindingID = ""
	a.Name = "renamed"
	if _, err = s.SaveMapping(a); err != nil {
		t.Fatal(err)
	}
	check(a.ID, true, "acknowledged")
	check(b.ID, true, "acknowledged")
	a.TargetPort++
	if _, err = s.SaveMapping(a); err != nil {
		t.Fatal(err)
	}
	check(a.ID, false, "unknown")
	check(b.ID, true, "acknowledged")
	st, _ := s.load()
	for id, credential := range creds {
		if _, err = s.Heartbeat(id, credential, st.Nodes[id].DesiredRevision-1, true); err != nil {
			t.Fatal(err)
		}
	}
	check(a.ID, false, "apply_failed")
	check(b.ID, true, "acknowledged")
	// A stale successful heartbeat cannot acknowledge the newly changed policy.
	for id, credential := range creds {
		if _, err = s.Heartbeat(id, credential, st.Nodes[id].DesiredRevision-1, false); err != nil {
			t.Fatal(err)
		}
	}
	check(a.ID, false, "apply_failed")
	check(b.ID, true, "acknowledged")
	heartbeat(false)
	check(a.ID, true, "acknowledged")
	// Shared effective pool growth must invalidate both mappings.
	a.Pool = 3
	if _, err = s.SaveMapping(a); err != nil {
		t.Fatal(err)
	}
	check(a.ID, false, "unknown")
	check(b.ID, false, "unknown")
	heartbeat(false)
	// Tunnel policy invalidates each mapping on this endpoint, unlike a label.
	server.Name = "renamed server"
	if _, err = s.SaveNode(server); err != nil {
		t.Fatal(err)
	}
	check(a.ID, true, "acknowledged")
	check(b.ID, true, "acknowledged")
	server.ClientTunnel = nil
	server.Tunnel.Flow = "xtls-rprx-vision"
	if _, err = s.SaveNode(server); err != nil {
		t.Fatal(err)
	}
	check(a.ID, false, "unknown")
	check(b.ID, false, "unknown")
	heartbeat(false)
	a.Mux, a.MuxType = true, "smux"
	if _, err = s.SaveMapping(a); err != nil {
		t.Fatal(err)
	}
	check(a.ID, false, "unknown")
	check(b.ID, false, "unknown")
	heartbeat(false)
	reopened, err := Open(filepath.Clean(db), filepath.Clean(key))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	statuses, err := reopened.MappingStatuses()
	if err != nil {
		t.Fatal(err)
	}
	if statuses[a.ID].Server.Acknowledged || statuses[b.ID].Client.Acknowledged {
		t.Fatal("acknowledgements persisted across restart")
	}
}

func TestMappingStatusEndpointAcknowledgements(t *testing.T) {
	s, _, _ := testStore(t)
	server := testNode(t, s, "server", "s")
	client := testNode(t, s, "client", "c")
	m, err := s.SaveMapping(testMapping(server.ID, client.ID, 18080))
	if err != nil {
		t.Fatal(err)
	}
	credential := testCredential(t, s, server.ID)
	st, _ := s.load()
	if _, err = s.Heartbeat(server.ID, "wrong credential", st.Nodes[server.ID].DesiredRevision, false); err != ErrAuth {
		t.Fatal("unauthorized heartbeat", err)
	}
	prior, err := s.MappingStatuses()
	if err != nil || prior[m.ID].Server.Acknowledged {
		t.Fatal("unauthorized heartbeat acknowledged mapping", err)
	}
	if _, err = s.Heartbeat(server.ID, credential, st.Nodes[server.ID].DesiredRevision, false); err != nil {
		t.Fatal(err)
	}
	statuses, err := s.MappingStatuses()
	if err != nil {
		t.Fatal(err)
	}
	if !statuses[m.ID].Server.Acknowledged || statuses[m.ID].Client.Acknowledged {
		t.Fatal("one-sided acknowledgement treated as ready", statuses[m.ID])
	}
}
