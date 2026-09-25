package tunnel

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"time"

	"veilink/internal/model"
)

// Private reverse-application role, distinct from port-zero mux/control. This is
// a Veilink protocol extension, not a general-purpose VLESS destination port.
const applicationPort = 1

var applicationMagic = []byte("veilink-application/2\x00")

const applicationWait = 10 * time.Second
const applicationQueueLimit = 64

type applicationRequest struct {
	conn     net.Conn
	mapping  model.Mapping
	ready    chan bool // false means no public bytes consumed: safe to retry
	done     chan struct{}
	deadline time.Time
}
type applicationSlot struct{ request chan applicationRequest }

func (s *service) acceptApplication(conn net.Conn, id [16]byte, binding model.Binding) {
	magic := make([]byte, len(applicationMagic))
	if _, err := io.ReadFull(conn, magic); err != nil || !bytes.Equal(magic, applicationMagic) {
		return
	}
	slot := &applicationSlot{request: make(chan applicationRequest, 1)}
	s.mu.Lock()
	if s.ctx.Err() != nil || len(s.applications[binding.ID]) >= bindingPool(s.snapshot.Mappings, binding.ID) {
		s.mu.Unlock()
		return
	}
	s.applications[binding.ID] = append(s.applications[binding.ID], slot)
	close(s.applicationChanged)
	s.applicationChanged = make(chan struct{})
	s.mu.Unlock()
	// This is the only reader until the target ACK. While idle it detects EOF
	// immediately; after ACK it exits before Vision can read application bytes.
	_ = conn.SetDeadline(time.Now().Add(45 * time.Second))
	ack := make(chan error, 1)
	go func() {
		var b [1]byte
		_, err := io.ReadFull(conn, b[:])
		if err == nil && b[0] != 0 {
			err = io.ErrUnexpectedEOF
		}
		ack <- err
	}()
	var req applicationRequest
	accepted := false
	defer func() {
		s.mu.Lock()
		for i, item := range s.applications[binding.ID] {
			if item == slot {
				s.applications[binding.ID] = append(s.applications[binding.ID][:i], s.applications[binding.ID][i+1:]...)
				break
			}
		}
		// Consumption and removal use the same lock, including a disconnect
		// racing with assignment. Never orphan an assigned public connection.
		if req.conn == nil {
			select {
			case req = <-slot.request:
			default:
			}
		}
		s.mu.Unlock()
		if req.conn != nil {
			if !accepted {
				req.ready <- false
			}
			close(req.done)
		}
		conn.Close() // interrupts the idle reader on cancellation
	}()
	select {
	case req = <-slot.request:
	case <-ack:
		return // EOF, timeout, or unsolicited ACK while idle
	case <-s.ctx.Done():
		return
	}
	m := req.mapping
	if m.BindingID != binding.ID || !s.allowed[binding.ID]["tcp\n"+m.TargetHost+"\n"+strconv.Itoa(m.TargetPort)] {
		return
	}
	_ = conn.SetDeadline(req.deadline)
	payload := append([]byte{byte(m.TargetPort >> 8), byte(m.TargetPort)}, m.TargetHost...)
	wire := append([]byte{byte(len(payload) >> 8), byte(len(payload))}, payload...)
	if err := writeAll(conn, wire); err != nil {
		return
	}
	select {
	case err := <-ack:
		if err != nil {
			return
		}
	case <-s.ctx.Done():
		return
	}
	accepted = true
	req.ready <- true
	_ = conn.SetDeadline(time.Time{})
	if s.flow != "" {
		conn = newApplicationVision(conn, id)
	}
	relayApplication(conn, req.conn)
}

func (s *service) openApplication(conn net.Conn, m model.Mapping) {
	defer conn.Close()
	s.mu.Lock()
	if s.applicationWaiting[m.BindingID] >= applicationQueueLimit || s.ctx.Err() != nil {
		s.mu.Unlock()
		return
	}
	s.applicationWaiting[m.BindingID]++
	s.mu.Unlock()
	waiting := true
	release := func() {
		if waiting {
			s.mu.Lock()
			s.applicationWaiting[m.BindingID]--
			s.mu.Unlock()
			waiting = false
		}
	}
	defer release()
	deadline := time.Now().Add(applicationWait)
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	for {
		s.mu.Lock()
		list := s.applications[m.BindingID]
		changed := s.applicationChanged
		if len(list) == 0 || s.ctx.Err() != nil {
			s.mu.Unlock()
			select {
			case <-changed:
				continue
			case <-timer.C:
				return
			case <-s.ctx.Done():
				return
			}
		}
		req := applicationRequest{conn: conn, mapping: m, ready: make(chan bool, 1), done: make(chan struct{}), deadline: deadline}
		slot := list[0]
		s.applications[m.BindingID] = list[1:]
		slot.request <- req
		s.mu.Unlock()
		select {
		case accepted := <-req.ready:
			if accepted {
				release()
				select {
				case <-req.done:
				case <-s.ctx.Done():
				}
				return
			}
		case <-timer.C:
			return
		case <-s.ctx.Done():
			return
		}
		// Failed idle peers have not consumed any public bytes. Retry another
		// slot, but never extend the original bounded acquisition window.
		select {
		case <-timer.C:
			return
		default:
		}
	}
}

func (s *service) maintainApplication(b model.Binding, gateway model.Node, peer *clientGateway) {
	id, err := parseUUID(b.UUID)
	if err != nil {
		return
	}
	for s.ctx.Err() == nil {
		conn, err := s.dialGateway(gateway, peer)
		if err != nil {
			if !sleep(s.ctx, 200*time.Millisecond) {
				return
			}
			continue
		}
		// Track before Encryption/VLESS/idle reads so cancellation interrupts all
		// authenticated and unauthenticated stages, including consumed slots.
		tracked := conn
		if !s.track(tracked) {
			conn.Close()
			return
		}
		_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
		if peer.outbound != nil {
			conn, err = peer.outbound.Handshake(conn)
		}
		if err == nil {
			err = writeVLESS(conn, id, b.Domain, applicationPort, peer.flow)
		}
		if err == nil {
			err = readVLESSResponse(conn)
		}
		if err == nil {
			err = writeAll(conn, applicationMagic)
		}
		if err == nil {
			_ = conn.SetDeadline(time.Now().Add(60 * time.Second))
			var size [2]byte
			_, err = io.ReadFull(conn, size[:])
			if err == nil {
				n := int(binary.BigEndian.Uint16(size[:]))
				if n < 3 || n > 257 {
					err = io.ErrUnexpectedEOF
				} else {
					payload := make([]byte, n)
					_, err = io.ReadFull(conn, payload)
					if err == nil {
						host, port, udp, parseErr := parseOpen(payload)
						if parseErr != nil || udp || !s.tcpModeAllowed(b.ID, host, port, false) {
							err = io.ErrUnexpectedEOF
						} else {
							// The idle slot has been consumed. Replenish immediately,
							// while this independently tracked connection serves one TCP flow.
							go s.serveApplication(conn, tracked, id, host, port, peer.flow)
							continue
						}
					}
				}
			}
		}
		tracked.Close()
		s.untrack(tracked)
		if !sleep(s.ctx, 200*time.Millisecond) {
			return
		}
	}
}

func (s *service) serveApplication(conn, tracked net.Conn, id [16]byte, host string, port int, flow string) {
	defer tracked.Close()
	defer s.untrack(tracked)
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	target, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(s.ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return
	}
	defer target.Close()
	if !s.track(target) {
		return
	}
	defer s.untrack(target)
	if err = writeAll(conn, []byte{0}); err != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})
	if flow != "" {
		conn = newApplicationVision(conn, id)
	}
	relayApplication(conn, target)
}

func relayApplication(a, b net.Conn) {
	done := make(chan struct{})
	go func() {
		_, err := io.Copy(a, b)
		if err != nil {
			a.Close()
			b.Close()
		} else {
			closeWrite(a)
		}
		close(done)
	}()
	_, err := io.Copy(b, a)
	if err != nil {
		a.Close()
		b.Close()
	} else {
		closeWrite(b)
	}
	<-done
}
