package tunnel

import (
	"errors"
	"net"
	"strconv"
	"strings"
	"time"

	"veilink/internal/model"
)

func validateFlow(c model.LocalTLS) error {
	flow := strings.TrimSpace(c.Flow)
	if flow == "" || flow == "none" {
		return nil
	}
	if c.EffectiveProtocol() != "vless" || c.XHTTP.Enabled() || c.TransportSecurity == "plain" || (!c.Reality.Enabled() && c.TransportSecurity != "tls") {
		return errors.New("Vision requires VLESS TCP with TLS or REALITY")
	}
	return nil
}

func checkProtocol(c model.LocalTLS) error {
	if err := validateFlow(c); err != nil {
		return err
	}
	switch c.EffectiveProtocol() {
	case "vless":
		if c.Hysteria2.Enabled() {
			return errors.New("vless cannot contain hysteria2 settings")
		}
	case "hysteria2":
		if !c.Hysteria2.Enabled() {
			return errors.New("hysteria2 requires a password")
		}
		if c.Reality.Enabled() {
			return errors.New("REALITY and Hysteria2 cannot both be set")
		}
		if c.XHTTP.Enabled() {
			return errors.New("Hysteria2 cannot use XHTTP")
		}
		if c.TransportSecurity == "plain" {
			return errors.New("Hysteria2 cannot use plain security")
		}
		if c.Flow != "" && c.Flow != "none" {
			return errors.New("Hysteria2 cannot use Vision")
		}
		if c.Encryption != "" || c.Decryption != "" {
			return errors.New("Hysteria2 cannot use VLESS Encryption/decryption")
		}
	default:
		return errors.New("protocol must be vless or hysteria2")
	}
	return nil
}

// dialProtocol selects the wire handshake. The Hysteria2 Auth and TCP request
// fields are standard; their target is an authorized Veilink reverse session,
// not an arbitrary forward-proxy destination.
func (s *service) dialProtocol(gateway model.Node, peer *clientGateway, b model.Binding, port uint16) (conn net.Conn, dialErr error) {
	defer func() { s.dialLog.report(s.ctx, b, gateway, dialErr) }()
	// All control, mux, dedicated TCP and XUDP sessions enter here, including
	// HY2. Recheck even if the caller already scoped its gateway at startup.
	gateway, err := bindingGateway(gateway, b)
	if err != nil {
		return nil, err
	}
	if peer.local.EffectiveProtocol() == "hysteria2" {
		var last error
		for _, ep := range enabledEndpoints(gateway) {
			c, err := dialHysteriaSession(s.ctx, net.JoinHostPort(ep.Host, strconv.Itoa(ep.Port)), ep.Host, peer.local, b.UUID, net.JoinHostPort(b.Domain, strconv.Itoa(int(port))))
			if err == nil {
				return c, nil
			}
			last = err
		}
		if last == nil {
			last = errors.New("gateway has no enabled connect endpoint")
		}
		return nil, last
	}
	c, err := s.dialGateway(gateway, peer)
	if err != nil {
		return nil, err
	}
	raw := c
	// Cancellation must interrupt handshake reads, not wait for their deadline.
	if !s.track(raw) {
		raw.Close()
		return nil, errors.New("runtime stopped")
	}
	defer s.untrack(raw)
	c.SetDeadline(time.Now().Add(15 * time.Second))
	if peer.outbound != nil {
		c, err = peer.outbound.Handshake(c)
	}
	if err == nil {
		id, _ := parseUUID(b.UUID)
		err = writeVLESS(c, id, b.Domain, port, peer.flow)
	}
	if err == nil {
		err = readVLESSResponse(c)
	}
	if err != nil {
		raw.Close()
		return nil, err
	}
	return c, nil
}

// serveAuthorized starts only a session selected by an authenticated protocol.
func (s *service) serveAuthorized(conn net.Conn, id [16]byte, binding model.Binding, port uint16) {
	defer conn.Close()
	remote := ""
	if conn.RemoteAddr() != nil {
		remote = conn.RemoteAddr().String()
	}
	s.noteSession("accepted", binding.ID, remote)
	defer s.noteSession("closed", binding.ID, remote)
	if port == singMuxPort {
		s.acceptSingMux(conn, id, binding)
		return
	}
	if port == applicationPort {
		s.acceptApplication(conn, id, binding)
		return
	}
	if s.flow != "" {
		conn = newVision(conn, id)
	}
	conn.SetDeadline(time.Time{})
	sess := newSession(conn)
	s.mu.Lock()
	count := 0
	for _, existing := range s.sessions[binding.ID] {
		if existing.available() {
			count++
		}
	}
	if count >= bindingPool(s.policy.Load().Mappings, binding.ID) {
		s.mu.Unlock()
		sess.close()
		return
	}
	s.sessions[binding.ID] = append(s.sessions[binding.ID], sess)
	s.mu.Unlock()
	sess.readLoop(nil)
	s.removeSession(binding.ID, sess)
}
