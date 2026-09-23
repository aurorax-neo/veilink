package tunnel

import (
	"crypto/rand"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"veilink/internal/model"
)

const maxDatagram = maxPayload - 64

// xudpConn presents one UDP association as a byte stream of XUDP records so the
// existing mux can carry it. On the gateway, queue is filled by the shared
// listener and replies go back to peer. On the client, udp is a connected socket.
type xudpConn struct {
	host   string
	port   int
	global [8]byte
	udp    *net.UDPConn
	back   *net.UDPConn
	peer   *net.UDPAddr
	queue  chan []byte
	done   chan struct{}
	once   sync.Once
	mu     sync.Mutex
	buf    []byte
	fresh  bool
	seen   time.Time
}

func newClientUDP(conn *net.UDPConn, host string, port int) *xudpConn {
	c := &xudpConn{host: host, port: port, udp: conn, done: make(chan struct{}), fresh: true, seen: time.Now()}
	_, _ = rand.Read(c.global[:])
	return c
}

func newGatewayUDP(pc *net.UDPConn, peer *net.UDPAddr, host string, port int) *xudpConn {
	c := &xudpConn{host: host, port: port, back: pc, peer: peer, queue: make(chan []byte, 32), done: make(chan struct{}), fresh: true, seen: time.Now()}
	_, _ = rand.Read(c.global[:])
	return c
}

func (c *xudpConn) push(p []byte) bool {
	c.mu.Lock()
	c.seen = time.Now()
	c.mu.Unlock()
	select {
	case <-c.done:
		return false
	case c.queue <- append([]byte(nil), p...):
		return true
	default:
		return true
	}
}

func (c *xudpConn) idle(limit time.Duration) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return time.Since(c.seen) > limit
}

func (c *xudpConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	if len(c.buf) > 0 {
		n := copy(p, c.buf)
		c.buf = c.buf[n:]
		c.mu.Unlock()
		return n, nil
	}
	c.mu.Unlock()
	var raw []byte
	if c.queue != nil {
		select {
		case <-c.done:
			return 0, io.EOF
		case raw = <-c.queue:
		}
	} else {
		buf := make([]byte, 64<<10)
		n, err := c.udp.Read(buf)
		if n == 0 {
			return 0, err
		}
		if n > maxDatagram {
			return c.Read(p)
		}
		raw = buf[:n]
	}
	c.mu.Lock()
	first := c.fresh
	c.fresh = false
	c.seen = time.Now()
	c.mu.Unlock()
	rec, err := encodeXUDP(first, c.host, c.port, c.global, raw)
	if err != nil {
		return 0, err
	}
	n := copy(p, rec)
	if n < len(rec) {
		c.mu.Lock()
		c.buf = append([]byte(nil), rec[n:]...)
		c.mu.Unlock()
	}
	return n, nil
}

func (c *xudpConn) Write(p []byte) (int, error) {
	host, port, payload, err := decodeXUDP(p)
	if err != nil {
		return 0, err
	}
	if payload == nil {
		return len(p), nil
	}
	if host != "" && !sameUDPTarget(host, port, c.host, c.port) {
		return len(p), nil
	}
	c.mu.Lock()
	c.seen = time.Now()
	c.mu.Unlock()
	if c.peer != nil {
		_, err = c.back.WriteToUDP(payload, c.peer)
	} else {
		_, err = c.udp.Write(payload)
	}
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func sameUDPTarget(got string, gotPort int, want string, wantPort int) bool {
	if gotPort != wantPort {
		return false
	}
	a, b := net.ParseIP(got), net.ParseIP(want)
	if a != nil && b != nil {
		return a.Equal(b)
	}
	return got == want
}

func (c *xudpConn) Close() error {
	c.once.Do(func() { close(c.done) })
	if c.udp != nil {
		return c.udp.Close()
	}
	return nil
}

func (c *xudpConn) LocalAddr() net.Addr {
	if c.udp != nil {
		return c.udp.LocalAddr()
	}
	return c.back.LocalAddr()
}

func (c *xudpConn) RemoteAddr() net.Addr {
	if c.peer != nil {
		return c.peer
	}
	return c.udp.RemoteAddr()
}

func (c *xudpConn) SetDeadline(t time.Time) error {
	if c.udp != nil {
		return c.udp.SetDeadline(t)
	}
	return nil
}

func (c *xudpConn) SetReadDeadline(t time.Time) error {
	if c.udp != nil {
		return c.udp.SetReadDeadline(t)
	}
	return nil
}

func (c *xudpConn) SetWriteDeadline(t time.Time) error {
	if c.udp != nil {
		return c.udp.SetWriteDeadline(t)
	}
	return nil
}

func (s *service) serveUDP(pc *net.UDPConn, m model.Mapping) {
	peers := map[string]*xudpConn{}
	var mu sync.Mutex
	buf := make([]byte, 64<<10)
	for {
		n, addr, err := pc.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if n == 0 || n > maxDatagram {
			continue
		}
		key := addr.String()
		mu.Lock()
		peer := peers[key]
		if peer != nil && peer.idle(2*time.Minute) {
			_ = peer.Close()
			delete(peers, key)
			peer = nil
		}
		if peer == nil {
			peer = newGatewayUDP(pc, addr, m.TargetHost, m.TargetPort)
			if !s.openUDP(peer, m) {
				_ = peer.Close()
				mu.Unlock()
				continue
			}
			peers[key] = peer
			go func(key string, peer *xudpConn) {
				<-peer.done
				mu.Lock()
				if peers[key] == peer {
					delete(peers, key)
				}
				mu.Unlock()
			}(key, peer)
		}
		link := peer
		mu.Unlock()
		link.push(buf[:n])
	}
}

func (s *service) openUDP(conn net.Conn, m model.Mapping) bool {
	sess := s.pick(m.BindingID)
	if sess == nil {
		return false
	}
	id := atomic.AddUint32(&sess.next, 1)
	if !sess.track(&stream{id: id, conn: conn}) {
		return false
	}
	payload := append([]byte{0, 0, 'u', byte(m.TargetPort >> 8), byte(m.TargetPort)}, m.TargetHost...)
	if err := sess.writeFrame(frameOpen, id, payload); err != nil {
		if old := sess.forget(id); old != nil {
			_ = old.conn.Close()
		}
		return false
	}
	go sess.pump(conn, id)
	return true
}
