package store

import (
	"errors"
	"reflect"
	"sync"
	"testing"
	"veilink/internal/model"
)

func TestScopedRevisionsAndDerivedClients(t *testing.T) {
	s, db, key := testStore(t)
	a := testNode(t, s, "server", "a")
	b := testNode(t, s, "server", "b")
	c := testNode(t, s, "client", "shared")
	d := testNode(t, s, "client", "only-b")
	idle := testNode(t, s, "client", "idle")
	ma, err := s.SaveMapping(testMapping(a.ID, c.ID, 18080))
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range []model.Mapping{testMapping(b.ID, c.ID, 18081), testMapping(b.ID, d.ID, 18082)} {
		if _, err = s.SaveMapping(m); err != nil {
			t.Fatal(err)
		}
	}
	creds := map[string]string{}
	for _, n := range []model.Node{a, b, c, d, idle} {
		creds[n.ID] = testCredential(t, s, n.ID)
	}
	before, err := s.load()
	if err != nil {
		t.Fatal(err)
	}
	ac, stopA := s.Subscribe(a.ID)
	defer stopA()
	bc, stopB := s.Subscribe(b.ID)
	defer stopB()
	cc, stopC := s.Subscribe(c.ID)
	defer stopC()
	dc, stopD := s.Subscribe(d.ID)
	defer stopD()
	a.ClientTunnel = nil
	a.Tunnel.Flow = "xtls-rprx-vision"
	if _, err = s.SaveNode(a); err != nil {
		t.Fatal(err)
	}
	after, err := s.load()
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{a.ID, c.ID} {
		if after.Nodes[id].DesiredRevision <= before.Nodes[id].DesiredRevision {
			t.Fatal("related revision unchanged", id)
		}
	}
	for _, id := range []string{b.ID, d.ID, idle.ID} {
		if !reflect.DeepEqual(before.Nodes[id], after.Nodes[id]) {
			t.Fatal("unrelated node changed", id)
		}
	}
	for _, ch := range []<-chan int64{ac, cc} {
		select {
		case <-ch:
		default:
			t.Fatal("missing notification")
		}
	}
	for _, ch := range []<-chan int64{bc, dc} {
		select {
		case <-ch:
			t.Fatal("unrelated notification")
		default:
		}
	}
	snap, err := s.Snapshot(c.ID, creds[c.ID])
	if err != nil {
		t.Fatal(err)
	}
	for _, peer := range snap.Nodes {
		if peer.ID == a.ID && (peer.Tunnel.Flow != "xtls-rprx-vision" || peer.Tunnel.KeyPEM != "" || peer.Tunnel.Decryption != "" || peer.Tunnel.Reality.PrivateKey != "") {
			t.Fatal("derived template not updated or private material leaked")
		}
	}
	// Adding a completely separate server does not change existing snapshots.
	testNode(t, s, "server", "new")
	for _, id := range []string{a.ID, b.ID, c.ID, d.ID, idle.ID} {
		got, err := s.Snapshot(id, creds[id])
		if err != nil {
			t.Fatal(err)
		}
		if got.Revision != after.Nodes[id].DesiredRevision {
			t.Fatal("global revision leaked")
		}
		rev, err := s.Heartbeat(id, creds[id], got.Revision, false)
		if err != nil || rev != got.Revision {
			t.Fatal("heartbeat revision mismatch", err)
		}
	}
	if _, err = s.Heartbeat(b.ID, creds[b.ID], after.Revision, false); !errors.Is(err, ErrInvalid) {
		t.Fatal("accepted another node revision", err)
	}
	// Same config and a forged revision cannot reset or advance desired state.
	same := after.Nodes[a.ID]
	same.DesiredRevision = 99999
	if _, err = s.SaveNode(same); err != nil {
		t.Fatal(err)
	}
	unchanged, _ := s.load()
	if unchanged.Nodes[a.ID].DesiredRevision != after.Nodes[a.ID].DesiredRevision {
		t.Fatal("no-op save changed revision")
	}
	// A mapping edit affects only its two endpoints, not every peer of the server.
	ma.BindingID = ""
	ma.Pool = 2
	before, _ = s.load()
	if _, err = s.SaveMapping(ma); err != nil {
		t.Fatal(err)
	}
	after, _ = s.load()
	for _, id := range []string{b.ID, d.ID, idle.ID} {
		if after.Nodes[id].DesiredRevision != before.Nodes[id].DesiredRevision {
			t.Fatal("mapping changed unrelated revision")
		}
	}
	// Rebinding must remove old authorization and install the new one.
	ma.BindingID = ""
	ma.ServerID = b.ID
	ma.ClientID = d.ID
	ma.ListenPort = 18083
	before, _ = s.load()
	ma, err = s.SaveMapping(ma)
	if err != nil {
		t.Fatal(err)
	}
	after, _ = s.load()
	for _, id := range []string{a.ID, b.ID, c.ID, d.ID} {
		if after.Nodes[id].DesiredRevision <= before.Nodes[id].DesiredRevision {
			t.Fatal("rebind failed to update endpoint", id)
		}
	}
	if err = s.DeleteMapping(ma.ID); err != nil {
		t.Fatal(err)
	}
	before, _ = s.load()
	if err = s.RemoveNode(c.ID, false); err != nil {
		t.Fatal(err)
	}
	after, _ = s.load()
	if after.Nodes[b.ID].DesiredRevision <= before.Nodes[b.ID].DesiredRevision || after.Nodes[d.ID].DesiredRevision != before.Nodes[d.ID].DesiredRevision {
		t.Fatal("revocation propagation")
	}
	reopened, err := Open(db, key)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	stored, err := reopened.load()
	if err != nil || stored.Nodes[b.ID].DesiredRevision != after.Nodes[b.ID].DesiredRevision {
		t.Fatal("scoped revision persistence", err)
	}
}

func TestMetadataAndPrivateListenerDoNotInvalidateUnrelatedNodes(t *testing.T) {
	s, _, _ := testStore(t)
	a := testNode(t, s, "server", "a")
	b := testNode(t, s, "server", "b")
	c := testNode(t, s, "client", "c")
	d := testNode(t, s, "client", "d")
	for _, pair := range []struct {
		server, client string
		port           int
	}{{a.ID, c.ID, 18080}, {b.ID, d.ID, 18081}} {
		if _, err := s.SaveMapping(testMapping(pair.server, pair.client, pair.port)); err != nil {
			t.Fatal(err)
		}
	}
	ids := []string{a.ID, b.ID, c.ID, d.ID}
	creds := map[string]string{}
	for _, id := range ids {
		creds[id] = testCredential(t, s, id)
	}
	baseline, err := s.load()
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		if _, err := s.Heartbeat(id, creds[id], baseline.Nodes[id].DesiredRevision, false); err != nil {
			t.Fatal(err)
		}
	}
	baseline, _ = s.load()
	channels := map[string]<-chan int64{}
	for _, id := range ids {
		ch, stop := s.Subscribe(id)
		channels[id] = ch
		defer stop()
	}
	check := func(want ...string) {
		t.Helper()
		after, err := s.load()
		if err != nil {
			t.Fatal(err)
		}
		changed := map[string]bool{}
		for _, id := range want {
			changed[id] = true
		}
		for _, id := range ids {
			if (after.Nodes[id].DesiredRevision != baseline.Nodes[id].DesiredRevision) != changed[id] {
				t.Fatalf("unexpected revision change %q: %t", id, changed[id])
			}
			select {
			case <-channels[id]:
				if !changed[id] {
					t.Fatalf("unexpected push to %q", id)
				}
			default:
				if changed[id] {
					t.Fatalf("missing push to %q", id)
				}
			}
		}
		baseline = after
	}
	a.Name = "renamed-server"
	a.ConnectEndpoints = append([]model.ConnectEndpoint(nil), a.ConnectEndpoints...)
	a.ConnectEndpoints[0].Name = "renamed-endpoint"
	if _, err := s.SaveNode(a); err != nil {
		t.Fatal(err)
	}
	check()
	stored, _ := s.load()
	if stored.Nodes[a.ID].Name != a.Name || stored.Nodes[a.ID].ConnectEndpoints[0].Name != a.ConnectEndpoints[0].Name {
		t.Fatal("metadata lost")
	}
	c.Name = "renamed-client"
	if _, err := s.SaveNode(c); err != nil {
		t.Fatal(err)
	}
	check()
	a.Tunnel.ListenHost = "127.0.0.1"
	if _, err := s.SaveNode(a); err != nil {
		t.Fatal(err)
	}
	check(a.ID)
	a.ClientTunnel = nil
	a.Tunnel.Flow = "xtls-rprx-vision"
	if _, err := s.SaveNode(a); err != nil {
		t.Fatal(err)
	}
	check(a.ID, c.ID)
	if got, err := s.Snapshot(c.ID, creds[c.ID]); err != nil || got.Revision != baseline.Nodes[c.ID].DesiredRevision {
		t.Fatalf("client snapshot: %v", err)
	}
}

func TestMappingRenameDoesNotInvalidateRuntime(t *testing.T) {
	s, _, _ := testStore(t)
	a := testNode(t, s, "server", "a")
	b := testNode(t, s, "server", "b")
	c := testNode(t, s, "client", "c")
	d := testNode(t, s, "client", "d")
	first, err := s.SaveMapping(testMapping(a.ID, c.ID, 18080))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SaveMapping(testMapping(b.ID, d.ID, 18081)); err != nil {
		t.Fatal(err)
	}
	ids := []string{a.ID, b.ID, c.ID, d.ID}
	creds := map[string]string{}
	for _, id := range ids {
		creds[id] = testCredential(t, s, id)
	}
	before, err := s.load()
	if err != nil {
		t.Fatal(err)
	}
	channels := map[string]<-chan int64{}
	for _, id := range ids {
		ch, stop := s.Subscribe(id)
		channels[id] = ch
		defer stop()
	}
	first.Name = "renamed"
	first.BindingID = ""
	if _, err := s.SaveMapping(first); err != nil {
		t.Fatal(err)
	}
	after, err := s.load()
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		if !reflect.DeepEqual(before.Nodes[id], after.Nodes[id]) {
			t.Fatalf("rename changed node state %q", id)
		}
		select {
		case <-channels[id]:
			t.Fatalf("rename notified %q", id)
		default:
		}
		snap, err := s.Snapshot(id, creds[id])
		if err != nil {
			t.Fatal(err)
		}
		if snap.Revision != before.Nodes[id].DesiredRevision {
			t.Fatalf("rename revised %q", id)
		}
	}
	first.Pool = 2
	if _, err := s.SaveMapping(first); err != nil {
		t.Fatal(err)
	}
	after, err = s.load()
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		changed := id == a.ID || id == c.ID
		if (before.Nodes[id].DesiredRevision != after.Nodes[id].DesiredRevision) != changed {
			t.Fatalf("pool changed wrong node %q", id)
		}
	}
}

func TestRefreshTargetingAndConcurrentUnsubscribe(t *testing.T) {
	s, _, _ := testStore(t)
	a := testNode(t, s, "client", "a")
	b := testNode(t, s, "client", "b")
	before, _ := s.load()
	if connected, err := s.RequestRefresh(a.ID); err != nil || connected {
		t.Fatal("offline refresh", connected, err)
	}
	ch, stop := s.Subscribe(a.ID)
	other, stopOther := s.Subscribe(b.ID)
	defer stopOther()
	for range 10 {
		if connected, err := s.RequestRefresh(a.ID); err != nil || !connected {
			t.Fatal("connected refresh", err)
		}
	}
	select {
	case <-ch:
	default:
		t.Fatal("no refresh")
	}
	select {
	case <-other:
		t.Fatal("wrong node notified")
	default:
	}
	after, _ := s.load()
	if !reflect.DeepEqual(before, after) {
		t.Fatal("refresh fabricated state")
	}
	var wg sync.WaitGroup
	for range 10 {
		wg.Go(func() {
			for range 10 {
				_, _ = s.RequestRefresh(a.ID)
			}
		})
	}
	stop()
	stop()
	wg.Wait()
	if connected, err := s.RequestRefresh(a.ID); err != nil || connected {
		t.Fatal("subscription retained")
	}
	if _, err := s.RequestRefresh("missing"); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	if err := s.RemoveNode(a.ID, false); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RequestRefresh(a.ID); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
}
