package tunnel

import (
	"fmt"
	"net"
	"regexp"
	"strings"

	"veilink/internal/model"
)

var identifier = regexp.MustCompile(`^[A-Za-z0-9_-][A-Za-z0-9_.-]{0,127}$`)
var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

func hostOK(h string) bool {
	if net.ParseIP(h) != nil {
		return true
	}
	if len(h) == 0 || len(h) > 253 || strings.ToLower(h) != h {
		return false
	}
	for _, p := range strings.Split(h, ".") {
		if len(p) == 0 || len(p) > 63 || p[0] == '-' || p[len(p)-1] == '-' {
			return false
		}
		for _, c := range p {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

func listenHost(h string) string {
	if h == "" {
		return "127.0.0.1"
	}
	return h
}

func portOK(p int) bool { return p > 0 && p <= 65535 }

// Only a wholly unconfigured, unbound server may idle. A reserved local bind
// endpoint alone does not activate crypto or listeners.
func idleServer(s model.Snapshot, local model.LocalTLS) bool {
	unconfigured := local
	unconfigured.ListenHost, unconfigured.ListenPort = "", 0
	return s.Node.Role == "server" && len(s.Bindings) == 0 && len(s.Mappings) == 0 && unconfigured == (model.LocalTLS{})
}

func validate(s model.Snapshot, local model.LocalTLS) error {
	bad := func(msg string) error { return fmt.Errorf("invalid snapshot: %s", msg) }
	if s.Node.Role == "client" && (local != (model.LocalTLS{}) || s.Node.Tunnel != (model.LocalTLS{}) || s.Node.ClientTunnel != nil) {
		return bad("client-local tunnel settings are not allowed; use gateway templates")
	}
	if err := checkExclusive(s.Node.Role, local); err != nil {
		return bad(err.Error())
	}
	// Clients consume complete authoritative per-gateway public templates.
	if !idleServer(s, local) && (s.Node.Role != "client" || len(s.Bindings) == 0) {
		if err := CheckBootstrap(s.Node.Role, local); err != nil {
			return bad(err.Error())
		}
	}
	if local.Reality.Enabled() && (local.CertPEM != "" || local.KeyPEM != "" || local.CAPEM != "") {
		return bad("REALITY cannot be combined with data-plane certificate PEM")
	}
	if s.Revision < 0 || !identifier.MatchString(s.Node.ID) || s.Node.Revoked || (s.Node.Role != "server" && s.Node.Role != "client") {
		return bad("node or revision")
	}
	gateways := map[string]model.Node{}
	for _, n := range s.Nodes {
		if !identifier.MatchString(n.ID) || n.Role != "server" || n.Revoked {
			return bad("related gateway")
		}
		if _, ok := gateways[n.ID]; ok {
			return bad("duplicate gateway")
		}
		gateways[n.ID] = n
	}
	if s.Node.Role == "server" {
		gateways[s.Node.ID] = s.Node
	}
	bindings := map[string]model.Binding{}
	domains := map[string]bool{}
	users := map[string]bool{}
	pairs := map[[3]string]bool{}
	for _, b := range s.Bindings {
		if !identifier.MatchString(b.ID) || !identifier.MatchString(b.ServerID) || !identifier.MatchString(b.ClientID) || !uuidPattern.MatchString(b.UUID) || !hostOK(b.Domain) || net.ParseIP(b.Domain) != nil || !strings.Contains(b.Domain, ".") {
			return bad("binding identity or domain")
		}
		pair := [3]string{b.ServerID, b.ClientID, b.ConnectEndpointID}
		if _, ok := bindings[b.ID]; ok || domains[b.Domain] || users[strings.ToLower(b.UUID)] || pairs[pair] {
			return bad("duplicate binding, domain, identity or association")
		}
		if s.Node.Role == "server" && b.ServerID != s.Node.ID || s.Node.Role == "client" && b.ClientID != s.Node.ID {
			return bad("foreign binding")
		}
		n, ok := gateways[b.ServerID]
		if !ok {
			return bad("missing gateway")
		}
		n, err := bindingGateway(n, b)
		if err != nil {
			return bad(err.Error())
		}
		if s.Node.Role == "client" && len(enabledEndpoints(n)) == 0 {
			return bad("gateway has no enabled connect endpoint")
		}
		if s.Node.Role == "client" {
			if _, err := gatewayClientConfig(local, n); err != nil {
				return bad("gateway " + n.ID + ": " + err.Error())
			}
		}
		if s.Node.Role == "client" && local.XHTTP.DownloadEndpointID != "" {
			found := false
			for _, ep := range enabledEndpoints(n) {
				if ep.ID == local.XHTTP.DownloadEndpointID {
					found = true
					break
				}
			}
			if !found {
				return bad("xhttp download endpoint is not an enabled authorized gateway endpoint")
			}
		}
		bindings[b.ID] = b
		domains[b.Domain] = true
		users[strings.ToLower(b.UUID)] = true
		pairs[pair] = true
	}
	type endpoint struct {
		host    string
		port    int
		network string
	}
	var listeners []endpoint
	if s.Node.Role == "server" {
		listenPort := local.ListenPort
		if len(s.Bindings) > 0 && !portOK(listenPort) {
			return bad("transport listen port")
		}
		if net.ParseIP(listenHost(local.ListenHost)) == nil {
			return bad("transport listen IP")
		}
		if len(s.Bindings) > 0 {
			if local.Reality.Enabled() {
				if err := checkRealityServer(local.Reality, s.Node.Address); err != nil {
					return bad(err.Error())
				}
			} else if (local.Hysteria2.Enabled() || local.TransportSecurity == "tls") && (local.CertPEM == "" || local.KeyPEM == "") {
				return bad("server TLS certificate and key required")
			}
		}
		if len(s.Bindings) > 0 {
			network := "tcp"
			if local.Hysteria2.Enabled() {
				network = "udp"
			}
			listeners = append(listeners, endpoint{listenHost(local.ListenHost), listenPort, network})
		}
	}
	ids := map[string]bool{}
	names := map[string]bool{}
	for _, m := range s.Mappings {
		if _, err := m.EffectiveMuxType(); err != nil {
			return bad(err.Error())
		}
		if !identifier.MatchString(m.ID) || strings.TrimSpace(m.Name) == "" || ids[m.ID] || names[m.Name] {
			return bad("mapping ID or name")
		}
		ids[m.ID] = true
		names[m.Name] = true
		if _, ok := bindings[m.BindingID]; !ok {
			return bad("mapping references missing binding")
		}
		if m.ConnectEndpointID != bindings[m.BindingID].ConnectEndpointID {
			return bad("mapping connect endpoint differs from binding")
		}
		if m.Pool < 1 || m.Pool > 32 {
			return bad("mapping pool must be from 1 to 32")
		}
		if m.Network != "" && m.Network != "tcp" && m.Network != "udp" {
			return bad("mapping network")
		}
		if !portOK(m.ListenPort) || !portOK(m.TargetPort) || !hostOK(m.TargetHost) || net.ParseIP(listenHost(m.ListenHost)) == nil {
			return bad("mapping host or port")
		}
		if domains[m.TargetHost] {
			return bad("target overlaps reverse control domain")
		}
		if m.Enabled && s.Node.Role == "server" {
			h := listenHost(m.ListenHost)
			ip := net.ParseIP(h)
			network := mappingNet(m.Network)
			for _, e := range listeners {
				if e.network == network && e.port == m.ListenPort && (ip.Equal(net.ParseIP(e.host)) || ip.IsUnspecified() || net.ParseIP(e.host).IsUnspecified()) {
					return bad("overlapping listeners")
				}
			}
			listeners = append(listeners, endpoint{h, m.ListenPort, network})
		}
	}
	if s.Node.Role == "client" && len(s.Bindings) == 0 && local.Reality.Enabled() {
		if err := checkRealityClient(local.Reality); err != nil {
			return bad(err.Error())
		}
	}
	return nil
}
