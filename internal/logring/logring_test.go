package logring

import "testing"

func TestRingBasic(t *testing.T) {
	r := New(5)
	for i := 0; i < 7; i++ {
		r.Append(Entry{At: int64(i), Level: "INFO", Message: "m", Source: "master"})
	}
	got := r.Query("", "", "", 0)
	if len(got) != 5 {
		t.Fatalf("expected 5 entries, got %d", len(got))
	}
	if got[0].At != 6 {
		t.Fatalf("newest should be 6, got %d", got[0].At)
	}
}

func TestRingFilter(t *testing.T) {
	r := New(10)
	r.Append(Entry{At: 1, Level: "INFO", Source: "master", Message: "a"})
	r.Append(Entry{At: 2, Level: "ERROR", Source: "node", NodeID: "n1", Message: "b"})
	r.Append(Entry{At: 3, Level: "WARN", Source: "node", NodeID: "n2", Message: "c"})
	if got := r.Query("node", "", "", 0); len(got) != 2 {
		t.Fatalf("expected 2 node entries, got %d", len(got))
	}
	if got := r.Query("", "n1", "", 0); len(got) != 1 {
		t.Fatalf("expected 1 n1 entry, got %d", len(got))
	}
	if got := r.Query("", "", "ERROR", 0); len(got) != 1 {
		t.Fatalf("expected 1 ERROR entry, got %d", len(got))
	}
}
func TestRingDrain(t *testing.T) {
	r := New(5)
	if got := r.Drain(); got != nil {
		t.Fatalf("expected nil from empty ring drain, got %v", got)
	}
	r.Append(Entry{At: 1, Message: "m1"})
	r.Append(Entry{At: 2, Message: "m2"})
	got := r.Drain()
	if len(got) != 2 || got[0].Message != "m1" || got[1].Message != "m2" {
		t.Fatalf("unexpected drained entries: %+v", got)
	}
	if drainedAgain := r.Drain(); drainedAgain != nil {
		t.Fatalf("expected nil after drain, got %v", drainedAgain)
	}
}
