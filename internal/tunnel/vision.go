package tunnel

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
)

func encodeFlow(flow string) []byte {
	if flow == "" {
		return nil
	}
	out := []byte{0x0a, byte(len(flow))}
	return append(out, flow...)
}

func decodeFlow(raw []byte) (string, error) {
	var flow string
	for len(raw) > 0 {
		key, n := readProtoVarint(raw)
		if n <= 0 {
			return "", errors.New("invalid VLESS flow")
		}
		raw = raw[n:]
		field, kind := int(key>>3), int(key&7)
		switch kind {
		case 0:
			_, n = readProtoVarint(raw)
			if n <= 0 {
				return "", errors.New("invalid VLESS flow")
			}
			raw = raw[n:]
		case 2:
			length, n := readProtoVarint(raw)
			if n <= 0 || int(length) > len(raw[n:]) {
				return "", errors.New("invalid VLESS flow")
			}
			raw = raw[n:]
			if field == 1 {
				flow = string(raw[:length])
			}
			raw = raw[length:]
		default:
			return "", errors.New("invalid VLESS flow")
		}
	}
	return flow, nil
}

func readProtoVarint(b []byte) (uint64, int) {
	var value uint64
	for i := 0; i < len(b) && i < 10; i++ {
		value |= uint64(b[i]&0x7f) << (7 * i)
		if b[i] < 0x80 {
			return value, i + 1
		}
	}
	return 0, -1
}

type visionConn struct {
	net.Conn
	uuid []byte

	writeMu sync.Mutex
	padding bool
	sentID  bool
	filter  int

	readMu     sync.Mutex
	raw        []byte
	plain      []byte
	remCmd     int
	remContent int
	remPad     int
	curCmd     int
	direct     bool
	readErr    error
}

func newVision(conn net.Conn, id [16]byte) *visionConn {
	return &visionConn{
		Conn: conn, uuid: append([]byte{}, id[:]...), padding: true, filter: 8,
		remCmd: -1, remContent: -1, remPad: -1,
	}
}

func (c *visionConn) camouflage() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.writeBlock(nil, 0)
}

func (c *visionConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if !c.padding {
		return c.Conn.Write(p)
	}
	written := 0
	for len(p) > 0 {
		n := len(p)
		if n > visionChunkLimit {
			n = visionChunkLimit
		}
		chunk := p[:n]
		p = p[n:]
		c.filter--
		command := byte(0)
		if c.filter <= 1 {
			command = 1
			c.padding = false
		}
		if err := c.writeBlock(chunk, command); err != nil {
			return written, err
		}
		written += n
		if command == 1 && len(p) > 0 {
			k, err := c.Conn.Write(p)
			return written + k, err
		}
	}
	return written, nil
}

func (c *visionConn) writeBlock(content []byte, command byte) error {
	padding := visionPadding(len(content))
	var buf bytes.Buffer
	if !c.sentID {
		buf.Write(c.uuid)
		c.sentID = true
	}
	buf.WriteByte(command)
	buf.WriteByte(byte(len(content) >> 8))
	buf.WriteByte(byte(len(content)))
	buf.WriteByte(byte(padding >> 8))
	buf.WriteByte(byte(padding))
	buf.Write(content)
	buf.Write(make([]byte, padding))
	_, err := c.Conn.Write(buf.Bytes())
	return err
}

func visionPadding(content int) int {
	var padding int
	if content < 900 {
		padding = int(randBetween(0, 500)) + 900 - content
	} else {
		padding = int(randBetween(0, 256))
	}
	if limit := visionChunkLimit - content; padding > limit {
		padding = limit
	}
	if padding < 0 {
		return 0
	}
	return padding
}

func (c *visionConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	for {
		if len(c.plain) > 0 {
			n := copy(p, c.plain)
			c.plain = append([]byte{}, c.plain[n:]...)
			return n, nil
		}
		if c.readErr != nil {
			return 0, c.readErr
		}
		if c.direct {
			return c.Conn.Read(p)
		}
		buf := make([]byte, 4096)
		n, err := c.Conn.Read(buf)
		if n > 0 {
			c.raw = append(c.raw, buf[:n]...)
			if pullErr := c.pull(); pullErr != nil {
				c.readErr = pullErr
			}
		}
		if err != nil && len(c.plain) == 0 {
			if c.readErr == nil {
				c.readErr = err
			}
			return 0, c.readErr
		}
		if n == 0 && err == nil && len(c.plain) == 0 {
			return 0, io.ErrNoProgress
		}
	}
}

func (c *visionConn) pull() error {
	for len(c.raw) > 0 && !c.direct {
		if c.remCmd < 0 && c.remContent < 0 && c.remPad < 0 {
			if len(c.raw) < 21 {
				return nil
			}
			if !bytes.Equal(c.raw[:16], c.uuid) {
				return errors.New("VLESS flow header mismatch")
			}
			c.raw = c.raw[16:]
			c.remCmd = 5
		}
		if c.remCmd > 0 {
			b := c.raw[0]
			c.raw = c.raw[1:]
			switch c.remCmd {
			case 5:
				c.curCmd = int(b)
			case 4:
				c.remContent = int(b) << 8
			case 3:
				c.remContent |= int(b)
			case 2:
				c.remPad = int(b) << 8
			case 1:
				c.remPad |= int(b)
			}
			c.remCmd--
			if c.remCmd == 0 && c.remContent == 0 && c.remPad == 0 {
				if err := c.finishBlock(); err != nil {
					return err
				}
			}
			continue
		}
		if c.remContent > 0 {
			n := c.remContent
			if n > len(c.raw) {
				n = len(c.raw)
			}
			c.plain = append(c.plain, c.raw[:n]...)
			c.raw = c.raw[n:]
			c.remContent -= n
			if c.remContent == 0 && c.remPad == 0 {
				if err := c.finishBlock(); err != nil {
					return err
				}
			}
			continue
		}
		if c.remPad > 0 {
			n := c.remPad
			if n > len(c.raw) {
				n = len(c.raw)
			}
			c.raw = c.raw[n:]
			c.remPad -= n
			if c.remPad == 0 && c.remContent == 0 {
				if err := c.finishBlock(); err != nil {
					return err
				}
			}
			continue
		}
		return errors.New("VLESS flow desync")
	}
	return nil
}

func (c *visionConn) finishBlock() error {
	if c.curCmd == 0 {
		c.remCmd = 5
		return nil
	}
	if c.curCmd != 1 && c.curCmd != 2 {
		return errors.New("VLESS flow command rejected")
	}
	c.plain = append(c.plain, c.raw...)
	c.raw = nil
	c.direct = true
	c.remCmd, c.remContent, c.remPad = -1, -1, -1
	return nil
}
