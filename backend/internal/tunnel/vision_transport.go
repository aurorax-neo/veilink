package tunnel

import (
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"

	utls "github.com/refraction-networking/utls"
	"github.com/xtls/reality"
)

// recordBoundaryConn is installed BEFORE the handshake. It never reads ahead
// across a TLS record, even when the TLS implementation asks for a larger buffer.
// Its state belongs to the single TLS reader; switching also holds that lock.
type recordBoundaryConn struct {
	net.Conn
	header   [5]byte
	head     int
	left     int
	writeMu  sync.Mutex
	rawWrite bool
	ordinary bool // immutable before handshake; never eligible for raw handoff
}

func (c *recordBoundaryConn) CloseWrite() error {
	if w, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return w.CloseWrite()
	}
	return c.Conn.Close()
}

// A TLS read can itself emit post-handshake alerts/KeyUpdate responses. Once
// the write direction is raw, reject those writes rather than corrupting the
// application's TLS stream with an outer TLS record.
func (c *recordBoundaryConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.rawWrite {
		return 0, errors.New("outer TLS write after Vision handoff")
	}
	return c.Conn.Write(p)
}

func (c *recordBoundaryConn) Read(p []byte) (int, error) {
	if c.ordinary {
		return c.Conn.Read(p)
	}
	if len(p) == 0 {
		return 0, nil
	}
	if c.head < 5 {
		p = p[:min(len(p), 5-c.head)]
		n, err := c.Conn.Read(p)
		copy(c.header[c.head:], p[:n])
		c.head += n
		if c.head == 5 {
			c.left = int(binary.BigEndian.Uint16(c.header[3:]))
			if c.left > 18432 {
				return n, errors.New("outer TLS record too large")
			}
			if c.left == 0 {
				c.head = 0
			}
		}
		return n, err
	}
	p = p[:min(len(p), c.left)]
	n, err := c.Conn.Read(p)
	c.left -= n
	if c.left == 0 {
		c.head = 0
	}
	return n, err
}

// ownedTLSConn uses only public APIs and known adapters. In particular, a
// recordConn (optional VLESS Encryption) is NOT an unwrap-able adapter: its
// secret metadata, padding and XOR state must remain protected.
type ownedTLSConn struct {
	net.Conn
	gate                        *recordBoundaryConn
	rmu, wmu                    sync.Mutex
	pending                     []byte
	readBuf                     [18432]byte
	pendingErr                  error
	rd, wd                      bool
	readSwitches, writeSwitches atomic.Uint64
	rawRead, rawWritten         atomic.Uint64
	tls13                       bool
}

func ownTLS(conn net.Conn, gate *recordBoundaryConn) *ownedTLSConn {
	var bottom net.Conn
	var version uint16
	switch c := conn.(type) {
	case *tls.Conn:
		bottom = c.NetConn()
		version = c.ConnectionState().Version
	case *utls.UConn:
		bottom = c.NetConn()
		version = c.ConnectionState().Version
	case *reality.Conn:
		bottom = c.NetConn()
		version = c.ConnectionState().Version
	default:
		panic("unowned TLS adapter")
	}
	if bottom != gate {
		panic("TLS adapter does not own record gate")
	}
	return &ownedTLSConn{Conn: conn, gate: gate, tls13: version == tls.VersionTLS13}
}

func (c *ownedTLSConn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	if c.gate.ordinary {
		return c.Conn.Read(p)
	}
	if len(p) == 0 {
		return 0, nil
	}
	if len(c.pending) == 0 && c.pendingErr != nil {
		return 0, c.pendingErr
	}
	if len(c.pending) == 0 {
		if c.rd {
			n, err := c.gate.Conn.Read(p)
			c.rawRead.Add(uint64(n))
			return n, err
		}
		// Own ALL plaintext in the current outer record, not just the caller's
		// requested prefix. The raw gate prevents TLS from owning the next record.
		n, err := c.Conn.Read(c.readBuf[:])
		c.pending, c.pendingErr = c.readBuf[:n], err
	}
	n := copy(p, c.pending)
	c.pending = c.pending[n:]
	if n > 0 {
		return n, nil
	}
	return 0, c.pendingErr
}

func (c *ownedTLSConn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.wd {
		n, err := c.gate.Conn.Write(p)
		c.rawWritten.Add(uint64(n))
		return n, err
	}
	return c.Conn.Write(p)
}

func (c *ownedTLSConn) switchRead() error {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	if c.gate.ordinary || c.rd || c.gate.head != 0 || c.gate.left != 0 || len(c.pending) != 0 || c.pendingErr != nil {
		return errors.New("unsafe TLS read handoff")
	}
	// No plaintext may trail command 2 inside its authenticated outer record.
	c.rd = true
	c.readSwitches.Add(1)
	return nil
}

func (c *ownedTLSConn) switchWrite() error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.gate.ordinary || c.wd {
		return errors.New("duplicate TLS write handoff")
	}
	c.gate.writeMu.Lock()
	c.gate.rawWrite = true
	c.gate.writeMu.Unlock()
	c.wd = true
	c.writeSwitches.Add(1)
	return nil
}

// Never emit an outer close_notify after direct-copy has started.
func (c *ownedTLSConn) Close() error { return c.gate.Conn.Close() }
func (c *ownedTLSConn) CloseWrite() error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.wd {
		if w, ok := c.gate.Conn.(interface{ CloseWrite() error }); ok {
			return w.CloseWrite()
		}
		return c.gate.Conn.Close()
	}
	if w, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return w.CloseWrite()
	}
	return c.gate.Conn.Close()
}

func writeAll(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		p = p[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}
