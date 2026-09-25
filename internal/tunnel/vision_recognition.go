package tunnel

import (
	"bytes"
	"encoding/binary"
	"sync"
)

// tlsRecognition is a bounded, structural recognizer, not a TLS authenticator.
// Only dedicated, already authenticated application connections may use it.
// The application's TLS stack remains responsible for authenticating its peer.
type tlsRecognition struct {
	mu             sync.Mutex
	dirs           [2]tlsDirection
	client, server *visionHello
}

type tlsDirection struct {
	header                 [5]byte
	head                   int
	body                   []byte
	left                   int
	hello                  []byte
	seenHello, application bool
	budget                 int
	failed                 bool
}

type visionHello struct {
	kind    byte
	session []byte
	suites  []byte
}

// observe accepts arbitrarily fragmented records. Eligibility requires both
// complete hellos and an application-data record ending exactly at this boundary.
func (r *tlsRecognition) observe(direction int, p []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	d := &r.dirs[direction]
	if d.failed {
		return
	}
	d.budget += len(p)
	if d.budget > 128<<10 {
		d.failed = true
		return
	}
	for len(p) > 0 {
		if d.head < 5 {
			n := copy(d.header[d.head:], p)
			d.head += n
			p = p[n:]
			if (!d.seenHello && d.header[0] != 22) || (d.header[0] != 22 && d.header[0] != 23 && d.header[0] != 20) {
				d.failed = true
				return
			}
			if d.head < 5 {
				continue
			}
			d.left = int(binary.BigEndian.Uint16(d.header[3:]))
			if d.header[1] != 3 || d.header[2] < 1 || d.header[2] > 3 || d.left == 0 || d.left > 18432 {
				d.failed = true
				return
			}
			d.body = d.body[:0]
		}
		n := min(d.left, len(p))
		d.body = append(d.body, p[:n]...)
		d.left -= n
		p = p[n:]
		if d.left != 0 {
			continue
		}
		switch d.header[0] {
		case 22:
			if d.seenHello {
				d.failed = true
				return
			}
			if !d.seenHello {
				d.hello = append(d.hello, d.body...)
				if len(d.hello) > 65536 {
					d.failed = true
					return
				}
				if len(d.hello) >= 4 {
					size := int(d.hello[1])<<16 | int(d.hello[2])<<8 | int(d.hello[3])
					if size > 65532 {
						d.failed = true
						return
					}
					if len(d.hello) >= size+4 {
						if len(d.hello) != size+4 {
							d.failed = true
							return
						}
						h := parseVisionHello(d.hello[0], d.hello[4:4+size])
						if h == nil {
							d.failed = true
							return
						}
						if h.kind == 1 {
							if r.client != nil {
								d.failed = true
								return
							}
							r.client = h
						} else {
							if r.server != nil {
								d.failed = true
								return
							}
							r.server = h
						}
						d.seenHello = true
						d.hello = nil
					}
				}
			}
		case 20:
			if !d.seenHello || !bytes.Equal(d.body, []byte{1}) {
				d.failed = true
				return
			}
		case 23:
			if !d.seenHello || len(d.body) < 17 {
				d.failed = true
				return
			}
			d.application = true
		}
		d.head = 0
	}
}

func (r *tlsRecognition) eligible(direction int) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.dirs[direction].failed || r.client == nil || r.server == nil {
		return false
	}
	if !bytes.Equal(r.client.session, r.server.session) {
		return false
	}
	found := false
	for i := 0; i+1 < len(r.client.suites); i += 2 {
		if bytes.Equal(r.client.suites[i:i+2], r.server.suites) {
			found = true
		}
	}
	d := &r.dirs[direction]
	return found && d.application && d.head == 0 && d.left == 0
}

func (r *tlsRecognition) fallback(direction int) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.dirs[direction].failed
}

// Bound each write to the next inner header/body boundary. Arbitrary caller
// chunks must not skip every eligible record end and exhaust recognition.
func (r *tlsRecognition) writeChunk(n int) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	d := &r.dirs[1]
	if d.failed {
		return n
	}
	if d.head < 5 {
		return min(n, 5-d.head)
	}
	return min(n, d.left)
}

// parseVisionHello walks every length-delimited field. Byte patterns occurring
// inside random/session/cipher/unknown-extension data never count as versions.
func parseVisionHello(kind byte, p []byte) *visionHello {
	if (kind != 1 && kind != 2) || len(p) < 35 || p[0] != 3 || p[1] != 3 {
		return nil
	}
	// HelloRetryRequest requires a second hello exchange; conservatively retain TLS.
	hrr := []byte{0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c}
	if kind == 2 && bytes.Equal(p[2:34], hrr) {
		return nil
	}
	sid := int(p[34])
	p = p[35:]
	if sid > 32 || len(p) < sid {
		return nil
	}
	h := &visionHello{kind: kind, session: append([]byte(nil), p[:sid]...)}
	p = p[sid:]
	if kind == 1 {
		if len(p) < 2 {
			return nil
		}
		n := int(binary.BigEndian.Uint16(p))
		p = p[2:]
		if n < 2 || n%2 != 0 || len(p) < n+2 {
			return nil
		}
		h.suites = append([]byte(nil), p[:n]...)
		p = p[n:]
		if p[0] != 1 || p[1] != 0 {
			return nil
		}
		p = p[2:]
	} else {
		if len(p) < 3 || p[0] != 0x13 || p[1] < 1 || p[1] > 3 || p[2] != 0 {
			return nil
		}
		h.suites = append([]byte(nil), p[:2]...)
		p = p[3:]
	}
	if len(p) < 2 || int(binary.BigEndian.Uint16(p)) != len(p)-2 {
		return nil
	}
	p = p[2:]
	version := false
	seen := map[uint16]bool{}
	for len(p) > 0 {
		if len(p) < 4 {
			return nil
		}
		key, n := binary.BigEndian.Uint16(p), int(binary.BigEndian.Uint16(p[2:]))
		p = p[4:]
		if seen[key] || n > len(p) {
			return nil
		}
		seen[key] = true
		ext := p[:n]
		p = p[n:]
		if key != 43 {
			continue
		}
		if kind == 2 {
			version = bytes.Equal(ext, []byte{3, 4})
		} else {
			if len(ext) < 3 || int(ext[0]) != len(ext)-1 || ext[0]%2 != 0 {
				return nil
			}
			for i := 1; i < len(ext); i += 2 {
				if ext[i] == 3 && ext[i+1] == 4 {
					version = true
				}
			}
		}
	}
	if !version {
		return nil
	}
	return h
}
