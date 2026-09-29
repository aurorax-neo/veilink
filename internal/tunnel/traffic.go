package tunnel

import (
	"net"
	"sync"

	"veilink/internal/model"
)

// Traffic counts public-side payload in the current node process only.
type Traffic struct {
	mu     sync.Mutex
	totals map[string]TrafficBytes
	active map[string]bool
}

type TrafficBytes struct {
	Up   uint64 `json:"up"`
	Down uint64 `json:"down"`
}

func (t *Traffic) add(id string, up, down int) {
	if t == nil || (up <= 0 && down <= 0) {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.active != nil && !t.active[id] {
		return
	}
	if t.totals == nil {
		t.totals = make(map[string]TrafficBytes)
	}
	v := t.totals[id]
	// Integers remain exactly representable by structpb's number transport.
	const max = uint64(1<<53 - 1)
	if up > 0 && uint64(up) <= max-v.Up {
		v.Up += uint64(up)
	}
	if down > 0 && uint64(down) <= max-v.Down {
		v.Down += uint64(down)
	}
	t.totals[id] = v
}

// Snapshot returns an independent copy; it never reads from the socket goroutines.
func (t *Traffic) Snapshot() map[string]TrafficBytes {
	out := make(map[string]TrafficBytes)
	if t == nil {
		return out
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for k, v := range t.totals {
		out[k] = v
	}
	return out
}

// setActive removes deleted/disabled mappings and excludes late old-Apply flows.
func (t *Traffic) setActive(mappings []model.Mapping, server bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	active := make(map[string]bool)
	if server {
		for _, m := range mappings {
			if m.Enabled {
				active[m.ID] = true
			}
		}
	}
	for id := range t.totals {
		if !active[id] {
			delete(t.totals, id)
		}
	}
	t.active = active
}

type countedConn struct {
	net.Conn
	traffic *Traffic
	id      string
}

func (c *countedConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.traffic.add(c.id, n, 0)
	return n, err
}
func (c *countedConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.traffic.add(c.id, 0, n)
	return n, err
}

func (c *countedConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok { return cw.CloseWrite() }
	return c.Conn.Close()
}
