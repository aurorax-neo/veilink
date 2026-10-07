package model

import "testing"

func TestBandwidthBytes(t *testing.T) {
	for value, want := range map[string]int64{"": 0, "0": 0, "0Mbps": 0, "0.000Gbps": 0, " 48Mbps ": 6000000, "1Kbps": 125, "1.234Mbps": 154250, "100Gbps": 12500000000} {
		got, err := BandwidthBytes(value)
		if err != nil || got != want {
			t.Fatalf("%q: %d %v, want %d", value, got, err, want)
		}
	}
	for _, value := range []string{"48MBps", "-1Mbps", "NaNMbps", "0.999Kbps", "100.001Gbps", "1.2345Mbps", "1 Mbps", "1e3Mbps"} {
		if _, err := BandwidthBytes(value); err == nil {
			t.Fatalf("accepted %q", value)
		}
	}
}
