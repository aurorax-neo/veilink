package store

import (
	"time"
)

const maxTrafficEntries = 128
const maxTrafficByte = uint64(1<<53 - 1)

type TrafficBytes struct {
	Up   uint64 `json:"up_bytes"`
	Down uint64 `json:"down_bytes"`
}
type TrafficRow struct {
	MappingID   string     `json:"mapping_id"`
	Up          uint64     `json:"up_bytes"`
	Down        uint64     `json:"down_bytes"`
	ReportedAt  *time.Time `json:"reported_at"`
	HasTransfer bool       `json:"has_transfer"`
}
type trafficNode struct {
	epoch  string
	seq    uint64
	seen   map[string]bool
	totals map[string]TrafficBytes
	at     time.Time
}

// ReportTraffic accepts absolute process-local counters only from the authenticated
// owning server. A changed epoch replaces, never adds to, previous process totals.
func (s *Store) ReportTraffic(id, credential, epoch string, seq uint64, totals map[string]TrafficBytes) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.load()
	if err != nil {
		return err
	}
	if !s.authorized(st, id, credential) {
		return ErrAuth
	}
	if st.Nodes[id].Role != "server" || len(epoch) != 32 || seq == 0 || len(totals) > maxTrafficEntries {
		return ErrInvalid
	}
	for _, c := range epoch {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return ErrInvalid
		}
	}
	for mid, v := range totals {
		m, ok := st.Mappings[mid]
		if !ok || !m.Enabled || m.ServerID != id || v.Up > maxTrafficByte || v.Down > maxTrafficByte || v.Up+v.Down == 0 {
			return ErrInvalid
		}
	}
	if s.traffic == nil {
		s.traffic = make(map[string]trafficNode)
	}
	prev := s.traffic[id]
	if prev.seen[epoch] && prev.epoch != epoch {
		return ErrInvalid
	}
	if prev.epoch == epoch {
		if seq <= prev.seq {
			return ErrInvalid
		}
		for mid, v := range totals {
			old := prev.totals[mid]
			if v.Up < old.Up || v.Down < old.Down {
				return ErrInvalid
			}
		}
		// An omitted active mapping cannot lose its previous absolute total.
		for mid := range prev.totals {
			if _, ok := totals[mid]; !ok {
				if m, exists := st.Mappings[mid]; exists && m.Enabled && m.ServerID == id {
					return ErrInvalid
				}
			}
		}
	}
	if prev.seen == nil {
		prev.seen = make(map[string]bool)
	}
	// Bounded replay memory. A credential holder may rotate epochs, but cannot
	// resurrect an old process after its successor within the retained window.
	if len(prev.seen) >= 32 {
		prev.seen = map[string]bool{prev.epoch: true}
	}
	prev.seen[epoch] = true
	prev.epoch, prev.seq, prev.totals, prev.at = epoch, seq, totals, time.Now().UTC()
	s.traffic[id] = prev
	return nil
}

// TrafficRows does not persist historical traffic. Master restart returns no
// report; disabled/deleted mappings disappear until enabled and reported again.
func (s *Store) TrafficRows() ([]TrafficRow, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.load()
	if err != nil {
		return nil, err
	}
	rows := make([]TrafficRow, 0, len(st.Mappings))
	for _, m := range st.Mappings {
		if !m.Enabled {
			continue
		}
		row := TrafficRow{MappingID: m.ID}
		if report, ok := s.traffic[m.ServerID]; ok && !st.Nodes[m.ServerID].Revoked {
			if v, ok := report.totals[m.ID]; ok {
				row.Up, row.Down = v.Up, v.Down
				at := report.at
				row.ReportedAt = &at
				row.HasTransfer = v.Up > 0 || v.Down > 0
			}
		}
		rows = append(rows, row)
	}
	return rows, nil
}
