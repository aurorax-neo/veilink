package store

import (
	"errors"
	"testing"
)

func TestTrafficOwnershipReplayAndProcessReset(t *testing.T) {
	s, _, _ := testStore(t)
	server := testNode(t, s, "server", "traffic-server")
	other := testNode(t, s, "server", "other-server")
	client := testNode(t, s, "client", "traffic-client")
	mapping, err := s.SaveMapping(testMapping(server.ID, client.ID, 18099))
	if err != nil {
		t.Fatal(err)
	}
	credential := testCredential(t, s, server.ID)
	otherCredential := testCredential(t, s, other.ID)
	clientCredential := testCredential(t, s, client.ID)
	epoch, next := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	totals := map[string]TrafficBytes{mapping.ID: {Up: 15, Down: 22}}
	for _, attempt := range []struct {
		id, credential string
		err            error
	}{
		{server.ID, "wrong", ErrAuth}, {other.ID, otherCredential, ErrInvalid}, {client.ID, clientCredential, ErrInvalid},
	} {
		if err := s.ReportTraffic(attempt.id, attempt.credential, epoch, 1, totals); !errors.Is(err, attempt.err) {
			t.Fatalf("unauthorized report: %v", err)
		}
	}
	if err := s.ReportTraffic(server.ID, credential, epoch, 1, totals); err != nil {
		t.Fatal(err)
	}
	rows, err := s.TrafficRows()
	if err != nil || len(rows) != 1 || rows[0].Up != 15 || rows[0].Down != 22 || rows[0].ReportedAt == nil {
		t.Fatalf("unexpected traffic rows: %+v %v", rows, err)
	}
	for _, report := range []struct {
		epoch  string
		seq    uint64
		values map[string]TrafficBytes
	}{
		{epoch, 1, totals}, {epoch, 2, map[string]TrafficBytes{mapping.ID: {Up: 14, Down: 22}}},
		{epoch, 2, map[string]TrafficBytes{}},
		{epoch, 2, map[string]TrafficBytes{"foreign": {Up: 1}}},
	} {
		if err := s.ReportTraffic(server.ID, credential, report.epoch, report.seq, report.values); !errors.Is(err, ErrInvalid) {
			t.Fatalf("accepted invalid report: %v", err)
		}
	}
	if err := s.ReportTraffic(server.ID, credential, next, 1, map[string]TrafficBytes{}); err != nil {
		t.Fatal(err)
	}
	rows, err = s.TrafficRows()
	if err != nil || rows[0].ReportedAt != nil || rows[0].Up != 0 {
		t.Fatalf("process reset kept previous totals: %+v %v", rows, err)
	}
	if err := s.ReportTraffic(server.ID, credential, epoch, 3, totals); !errors.Is(err, ErrInvalid) {
		t.Fatalf("replayed old epoch: %v", err)
	}
	mapping.Enabled = false
	mapping.BindingID = ""
	if _, err := s.SaveMapping(mapping); err != nil {
		t.Fatal(err)
	}
	rows, err = s.TrafficRows()
	if err != nil || len(rows) != 0 {
		t.Fatalf("disabled mapping exposed traffic: %+v %v", rows, err)
	}
}
