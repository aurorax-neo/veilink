package tunnel

import (
	"sync"
	"testing"
	"veilink/internal/model"
)

func TestTrafficConcurrentAndDisable(t *testing.T) {
	var traffic Traffic
	traffic.setActive([]model.Mapping{{ID: "map", Enabled: true}}, true)
	const workers, writes = 16, 1000
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < writes; j++ {
				traffic.add("map", 100, 25)
				_ = traffic.Snapshot()
			}
		}()
	}
	wg.Wait()
	got := traffic.Snapshot()["map"]
	if got.Up != workers*writes*100 || got.Down != workers*writes*25 {
		t.Fatal(got)
	}
	traffic.setActive(nil, true)
	traffic.add("map", 100, 100)
	if len(traffic.Snapshot()) != 0 {
		t.Fatal("disabled mapping counted")
	}
	traffic.setActive([]model.Mapping{{ID: "map", Enabled: true}}, true)
	traffic.add("map", 3, 4)
	if got := traffic.Snapshot()["map"]; got.Up != 3 || got.Down != 4 {
		t.Fatal(got)
	}
}
func TestTrafficPendingApplyRollbackAndCommit(t *testing.T) {
	var traffic Traffic
	old := []model.Mapping{{ID: "old", Enabled: true}}
	next := []model.Mapping{{ID: "new", Enabled: true}}
	traffic.setActive(old, true)
	traffic.add("old", 10, 0)
	traffic.prepareActive(next, true)
	traffic.add("new", 7, 2)     // A new listener may accept before Apply commits.
	traffic.setActive(old, true) // Failed Apply restores only the last good configuration.
	if got := traffic.Snapshot(); len(got) != 1 || got["old"].Up != 10 {
		t.Fatal(got)
	}
	traffic.prepareActive(next, true)
	traffic.add("new", 3, 1)
	traffic.setActive(next, true)
	if got := traffic.Snapshot(); len(got) != 1 || got["new"].Up != 3 {
		t.Fatal(got)
	}
}

func BenchmarkTrafficConcurrent(b *testing.B) {
	for _, mappings := range []int{1, 16} {
		b.Run(map[bool]string{true: "one-mapping", false: "sixteen-mappings"}[mappings == 1], func(b *testing.B) {
			var traffic Traffic
			names := make([]model.Mapping, mappings)
			for i := range names {
				names[i] = model.Mapping{ID: string(rune('a' + i)), Enabled: true}
			}
			traffic.setActive(names, true)
			b.ReportAllocs()
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				n := 0
				for pb.Next() {
					id := names[n%mappings].ID
					n++
					traffic.add(id, 1024, 0)
				}
			})
		})
	}
}

// BenchmarkTrafficGlobalMutexBaseline models the previous shared mutex/map hot path.
func BenchmarkTrafficGlobalMutexBaseline(b *testing.B) {
	for _, mappings := range []int{1, 16} {
		b.Run(map[bool]string{true: "one-mapping", false: "sixteen-mappings"}[mappings == 1], func(b *testing.B) {
			var mu sync.Mutex
			names := make([]string, mappings)
			totals := make(map[string]TrafficBytes, mappings)
			for i := range names {
				names[i] = string(rune('a' + i))
			}
			b.ReportAllocs()
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				n := 0
				for pb.Next() {
					id := names[n%mappings]
					n++
					mu.Lock()
					value := totals[id]
					value.Up += 1024
					totals[id] = value
					mu.Unlock()
				}
			})
		})
	}
}
