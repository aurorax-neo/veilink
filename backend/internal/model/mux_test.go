package model

import "testing"

func TestMappingMuxType(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mapping Mapping
		want    string
		invalid bool
	}{
		{"off", Mapping{}, "", false},
		{"off-known", Mapping{MuxType: MuxTypeSMux}, "", false},
		{"default", Mapping{Mux: true}, MuxTypeSMux, false},
		{"smux", Mapping{Mux: true, MuxType: MuxTypeSMux, Network: "tcp"}, MuxTypeSMux, false},
		{"yamux", Mapping{Mux: true, MuxType: MuxTypeYAMux}, MuxTypeYAMux, false},
		{"h2mux", Mapping{Mux: true, MuxType: MuxTypeH2Mux}, MuxTypeH2Mux, false},
		{"legacy-off", Mapping{MuxType: "private-session"}, "", true},
		{"legacy-on", Mapping{Mux: true, MuxType: "private-session"}, "", true},
		{"unknown-on", Mapping{Mux: true, MuxType: "unknown"}, "", true},
		{"unknown-off", Mapping{MuxType: "unknown"}, "", true},
		{"udp", Mapping{Network: "udp"}, "", false},
		{"udp-mux", Mapping{Network: "udp", Mux: true}, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.mapping.EffectiveMuxType()
			if (err != nil) != tc.invalid || got != tc.want {
				t.Fatalf("got %q, %v", got, err)
			}
		})
	}
}
