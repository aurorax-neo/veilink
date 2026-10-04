package model

import "fmt"

const (
	MuxTypeSMux  = "smux"
	MuxTypeYAMux = "yamux"
	MuxTypeH2Mux = "h2mux"
)

// EffectiveMuxType validates even disabled selectors; legacy private-session
// is deliberately not accepted. An enabled empty selector defaults to smux.
func (m Mapping) EffectiveMuxType() (string, error) {
	switch m.MuxType {
	case "", MuxTypeSMux, MuxTypeYAMux, MuxTypeH2Mux:
	default:
		return "", fmt.Errorf("unsupported mux_type %q", m.MuxType)
	}
	if !m.Mux {
		return "", nil
	}
	if m.Network != "" && m.Network != "tcp" {
		return "", fmt.Errorf("mux requires TCP mapping")
	}
	if m.MuxType == "" {
		return MuxTypeSMux, nil
	}
	return m.MuxType, nil
}
