package store

import "veilink/internal/model"

// SoftwareReport is node-reported identity, not a desired configuration or proof
// of the binary's authenticity. Empty fields mean not reported.
type SoftwareReport struct {
	SoftwareVersion string `json:"software_version,omitempty"`
	SoftwareCommit  string `json:"software_commit,omitempty"`
}

// ReportedNode is a management response only; model.Node and snapshots do not
// accept these fields. Reports are deliberately lost when the Master restarts.
type ReportedNode struct {
	model.Node
	SoftwareReport
}

func validSoftwareLabel(s string) bool {
	if len(s) > 128 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_' || c == '+') {
			return false
		}
	}
	return true
}

func (s *Store) ReportedNodes() ([]ReportedNode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.load()
	if err != nil {
		return nil, err
	}
	out := make([]ReportedNode, 0, len(st.Nodes))
	for _, n := range st.Nodes {
		out = append(out, ReportedNode{Node: n, SoftwareReport: s.software[n.ID]})
	}
	return out, nil
}
