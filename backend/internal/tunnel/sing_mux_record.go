package tunnel

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
)

// singRecordConn carries Veilink application records INSIDE one real sing-mux
// TCP stream. This is not a multiplex/session layer: no stream IDs, routing, or
// goroutines. smux and h2mux at the pinned versions lack half-close APIs, so an
// explicit zero-length FIN preserves TCP half-close without closing both halves.
// All three types use the same payload contract, advertised by singMagic /1.
type singRecordConn struct {
	net.Conn
	wmu         sync.Mutex
	writeBuf    [2 + maxPayload]byte
	writeClosed bool
	readClosed  bool
	remaining   int
}

func (c *singRecordConn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	if c.readClosed {
		return 0, io.EOF
	}
	if c.remaining == 0 {
		var head [2]byte
		if _, err := io.ReadFull(c.Conn, head[:]); err != nil {
			return 0, err
		}
		c.remaining = int(binary.BigEndian.Uint16(head[:]))
		if c.remaining == 0 {
			c.readClosed = true
			return 0, io.EOF
		}
		if c.remaining > maxPayload {
			return 0, errors.New("oversize mux application record")
		}
	}
	n, err := c.Conn.Read(b[:min(len(b), c.remaining)])
	c.remaining -= n
	return n, err
}
func (c *singRecordConn) Write(b []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.writeClosed {
		return 0, net.ErrClosed
	}
	total := 0
	for len(b) > 0 {
		n := min(len(b), maxPayload)
		// Keep the header and payload in one write: packet-up transports await
		// acknowledgement after each write, even for a header-only record.
		packet := c.writeBuf[:2+n]
		binary.BigEndian.PutUint16(packet[:2], uint16(n))
		copy(packet[2:], b[:n])
		if err := writeAll(c.Conn, packet); err != nil {
			return total, err
		}
		total += n
		b = b[n:]
	}
	return total, nil
}
func (c *singRecordConn) CloseWrite() error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.writeClosed {
		return nil
	}
	c.writeClosed = true
	return writeAll(c.Conn, []byte{0, 0})
}
