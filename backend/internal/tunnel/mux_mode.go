package tunnel

// tcpModeAllowed checks both target authorization and the requested reverse
// connection role. A stale peer must not silently fall back to the other mode.
func (s *service) tcpModeAllowed(binding, host string, port int, mux bool) bool {
	policy := s.policy.Load()
	if policy == nil {
		policy = &s.snapshot
	}
	for _, m := range policy.Mappings {
		if m.Enabled && m.BindingID == binding && mappingNet(m.Network) == "tcp" && m.TargetHost == host && m.TargetPort == port && m.Mux == mux {
			return true
		}
	}
	return false
}
