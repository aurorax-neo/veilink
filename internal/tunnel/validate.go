package tunnel

import (
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"

	"veilink/internal/model"
)

var identifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
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

func validate(s model.Snapshot, local model.LocalTLS) error {
	bad := func(msg string) error { return fmt.Errorf("invalid snapshot: %s", msg) }
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
	pairs := map[string]bool{}
	for _, b := range s.Bindings {
		if !identifier.MatchString(b.ID) || !identifier.MatchString(b.ServerID) || !identifier.MatchString(b.ClientID) || !uuidPattern.MatchString(b.UUID) || !hostOK(b.Domain) || net.ParseIP(b.Domain) != nil || !strings.Contains(b.Domain, ".") {
			return bad("binding identity or domain")
		}
		if _, ok := bindings[b.ID]; ok || domains[b.Domain] || users[strings.ToLower(b.UUID)] || pairs[b.ServerID+"/"+b.ClientID] {
			return bad("duplicate binding, domain, identity or association")
		}
		if s.Node.Role == "server" && b.ServerID != s.Node.ID || s.Node.Role == "client" && b.ClientID != s.Node.ID {
			return bad("foreign binding")
		}
		n, ok := gateways[b.ServerID]
		if !ok || !portOK(n.Port) {
			return bad("missing gateway or transport port")
		}
		if s.Node.Role == "client" && (!hostOK(n.Address) || !hostOK(n.ServerName)) {
			return bad("gateway address or verified server name")
		}
		bindings[b.ID] = b
		domains[b.Domain] = true
		users[strings.ToLower(b.UUID)] = true
		pairs[b.ServerID+"/"+b.ClientID] = true
	}
	type endpoint struct {
		host string
		port int
	}
	var listeners []endpoint
	if s.Node.Role == "server" {
		if len(s.Bindings) > 0 && !portOK(s.Node.Port) {
			return bad("transport port")
		}
		if net.ParseIP(listenHost(local.ListenHost)) == nil {
			return bad("transport listen IP")
		}
		if len(s.Bindings) > 0 && (local.CertFile == "" || local.KeyFile == "") {
			return bad("server TLS certificate and key required")
		}
		if len(s.Bindings) > 0 {
			listeners = append(listeners, endpoint{listenHost(local.ListenHost), s.Node.Port})
		}
	}
	ids := map[string]bool{}
	names := map[string]bool{}
	for _, m := range s.Mappings {
		if !identifier.MatchString(m.ID) || strings.TrimSpace(m.Name) == "" || ids[m.ID] || names[m.Name] {
			return bad("mapping ID or name")
		}
		ids[m.ID] = true
		names[m.Name] = true
		if _, ok := bindings[m.BindingID]; !ok {
			return bad("mapping references missing binding")
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
			for _, e := range listeners {
				if e.port == m.ListenPort && (ip.Equal(net.ParseIP(e.host)) || ip.IsUnspecified() || net.ParseIP(e.host).IsUnspecified()) {
					return bad("overlapping listeners")
				}
			}
			listeners = append(listeners, endpoint{h, m.ListenPort})
		}
	}
	return nil
}

func readFile(path string) ([]byte, error) { return os.ReadFile(path) }
