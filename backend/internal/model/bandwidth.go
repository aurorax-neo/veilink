package model

import (
	"errors"
	"regexp"
	"strconv"
	"strings"
)

var bandwidthPattern = regexp.MustCompile(`^([0-9]+(?:\.[0-9]{1,3})?)(Kbps|Mbps|Gbps)$`)

// BandwidthBytes parses decimal bits/second, not binary bytes/second. Empty or zero disables shaping.
func BandwidthBytes(value string) (int64, error) {
	value = strings.TrimSpace(value)
	if value == "" || value == "0" {
		return 0, nil
	}
	parts := bandwidthPattern.FindStringSubmatch(value)
	if parts == nil {
		return 0, errors.New("bandwidth_limit must be empty or a positive Kbps, Mbps or Gbps value")
	}
	n, err := strconv.ParseFloat(parts[1], 64)
	if err == nil && n == 0 {
		return 0, nil
	}
	multiplier := map[string]float64{"Kbps": 1e3, "Mbps": 1e6, "Gbps": 1e9}[parts[2]]
	bits := n * multiplier
	if err != nil || bits < 1000 || bits > 100e9 {
		return 0, errors.New("bandwidth_limit must be between 1Kbps and 100Gbps")
	}
	return int64(bits / 8), nil
}
