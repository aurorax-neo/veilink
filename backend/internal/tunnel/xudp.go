package tunnel

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
)

// XUDP records carry one UDP datagram inside a stream. The layout follows the
// common XUDP metadata record: a 16-bit metadata length, metadata, then a
// 16-bit payload length and the datagram when the data option is set.
// Metadata starts with a 16-bit session id, a status byte (1 new, 2 keep) and
// an option byte. A UDP target is network byte 2, then port, then address.
// This is not an Xray session and does not accept arbitrary destinations.

func encodeXUDP(first bool, host string, port int, global [8]byte, payload []byte) ([]byte, error) {
	if port < 1 || port > 65535 || len(payload) > maxDatagram {
		return nil, errors.New("udp datagram is too large")
	}
	meta := make([]byte, 0, 32+len(host))
	meta = append(meta, 0, 0)
	if first {
		meta = append(meta, 1, 1, 2)
	} else {
		meta = append(meta, 2, 1, 2)
	}
	var err error
	meta, err = appendXUDPAddr(meta, host, port)
	if err != nil {
		return nil, err
	}
	if first {
		meta = append(meta, global[:]...)
	}
	out := make([]byte, 2+len(meta)+2+len(payload))
	binary.BigEndian.PutUint16(out[:2], uint16(len(meta)))
	copy(out[2:], meta)
	binary.BigEndian.PutUint16(out[2+len(meta):], uint16(len(payload)))
	copy(out[4+len(meta):], payload)
	return out, nil
}

func decodeXUDP(record []byte) (host string, port int, payload []byte, err error) {
	if len(record) < 4 {
		return "", 0, nil, errors.New("short xudp record")
	}
	metaLen := int(binary.BigEndian.Uint16(record[:2]))
	if metaLen < 4 || metaLen > 512 || len(record) < 2+metaLen {
		return "", 0, nil, errors.New("invalid xudp metadata")
	}
	meta := record[2 : 2+metaLen]
	rest := record[2+metaLen:]
	status, option := meta[2], meta[3]
	if status == 4 {
		if option == 1 {
			if len(rest) < 2 {
				return "", 0, nil, io.ErrUnexpectedEOF
			}
			n := int(binary.BigEndian.Uint16(rest[:2]))
			if len(rest) != 2+n {
				return "", 0, nil, errors.New("truncated xudp payload")
			}
		}
		return "", 0, nil, nil
	}
	if status != 1 && status != 2 {
		return "", 0, nil, errors.New("unsupported xudp status")
	}
	if len(meta) > 4 && meta[4] == 2 {
		host, port, err = takeXUDPAddr(meta[5:])
		if err != nil {
			return "", 0, nil, err
		}
	}
	if option != 1 {
		return host, port, []byte{}, nil
	}
	if len(rest) < 2 {
		return "", 0, nil, io.ErrUnexpectedEOF
	}
	n := int(binary.BigEndian.Uint16(rest[:2]))
	if n > maxDatagram || len(rest) != 2+n {
		return "", 0, nil, errors.New("invalid xudp payload")
	}
	return host, port, rest[2:], nil
}

func appendXUDPAddr(dst []byte, host string, port int) ([]byte, error) {
	dst = append(dst, byte(port>>8), byte(port))
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return append(append(dst, 1), v4...), nil
		}
		return append(append(dst, 3), ip.To16()...), nil
	}
	if len(host) == 0 || len(host) > 253 {
		return nil, errors.New("invalid xudp address")
	}
	dst = append(dst, 2, byte(len(host)))
	return append(dst, host...), nil
}

func takeXUDPAddr(p []byte) (string, int, error) {
	if len(p) < 3 {
		return "", 0, errors.New("short xudp address")
	}
	port := int(binary.BigEndian.Uint16(p[:2]))
	switch p[2] {
	case 1:
		if len(p) < 7 {
			return "", 0, errors.New("short xudp address")
		}
		return net.IP(p[3:7]).String(), port, nil
	case 3:
		if len(p) < 19 {
			return "", 0, errors.New("short xudp address")
		}
		return net.IP(p[3:19]).String(), port, nil
	case 2:
		if len(p) < 4 || len(p) < 4+int(p[3]) {
			return "", 0, errors.New("short xudp address")
		}
		return string(p[4 : 4+int(p[3])]), port, nil
	default:
		return "", 0, errors.New("unknown xudp address")
	}
}
