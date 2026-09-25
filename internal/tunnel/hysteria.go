package tunnel

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/quicvarint"

	"veilink/internal/model"
)

const hysteriaTCP = 0x401

func checkExclusive(role string, local model.LocalTLS) error {
	reality := local.Reality.Enabled()
	hy := local.Hysteria2.Enabled()
	certs := local.CertPEM != "" || local.KeyPEM != "" || local.CAPEM != ""
	if reality && hy {
		return errors.New("REALITY and Hysteria2 cannot both be set")
	}
	if reality && certs {
		return errors.New("REALITY cannot be combined with data-plane certificate PEM")
	}
	if (local.CertPEM == "") != (local.KeyPEM == "") {
		return errors.New("data-plane certificate and key must be paired")
	}
	if role == "server" && hy && (local.CertPEM == "" || local.KeyPEM == "") {
		return errors.New("Hysteria2 requires cert_pem and key_pem")
	}
	if hy && len(local.Hysteria2.Password) > 128 {
		return errors.New("Hysteria2 password must be at most 128 bytes")
	}
	if local.CertPEM != "" {
		if _, err := tls.X509KeyPair([]byte(local.CertPEM), []byte(local.KeyPEM)); err != nil {
			return errors.New("invalid data-plane certificate or key PEM")
		}
	}
	if _, err := roots(local.CAPEM); err != nil {
		return err
	}
	return nil
}

func (s *service) listenHysteria() error {
	addr := net.JoinHostPort(listenHost(s.local.ListenHost), strconv.Itoa(s.local.ListenPort))
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}
	udp, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}
	cert, err := tls.X509KeyPair([]byte(s.local.CertPEM), []byte(s.local.KeyPEM))
	if err != nil {
		_ = udp.Close()
		return err
	}
	ln, err := quic.Listen(udp, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, NextProtos: []string{"h3"}}, hysteriaQUIC)
	if err != nil {
		_ = udp.Close()
		return err
	}
	s.quic = ln
	go s.acceptHysteria(ln)
	return nil
}

func (s *service) acceptHysteria(ln *quic.Listener) {
	for {
		conn, err := ln.Accept(s.ctx)
		if err != nil {
			return
		}
		go s.serveHysteria(conn)
	}
}

func (s *service) serveHysteria(conn *quic.Conn) {
	defer conn.CloseWithError(0, "")
	go discardUni(s.ctx, conn)
	_ = writeControl(conn)
	authed := false
	for {
		stream, err := conn.AcceptStream(s.ctx)
		if err != nil {
			return
		}
		kind, err := readVarint(stream)
		if err != nil {
			_ = stream.Close()
			return
		}
		switch kind {
		case 0x1:
			ok, err := s.hysteriaAuth(stream)
			_ = stream.Close()
			if err != nil || !ok {
				return
			}
			if !authed {
				enableHysteriaBBR(conn)
			}
			authed = true
		case hysteriaTCP:
			if !authed {
				_ = stream.Close()
				return
			}
			if err = readTCPRequest(stream); err != nil {
				_ = stream.Close()
				return
			}
			if err = writeTCPResponse(stream); err != nil {
				_ = stream.Close()
				return
			}
			wrapped := &quicConn{Stream: stream, local: conn.LocalAddr(), remote: conn.RemoteAddr()}
			if !s.track(wrapped) {
				_ = wrapped.Close()
				return
			}
			s.authenticate(wrapped)
			return
		default:
			_ = stream.Close()
			return
		}
	}
}

func (s *service) hysteriaAuth(stream *quic.Stream) (bool, error) {
	n, err := readVarint(stream)
	if err != nil {
		return false, err
	}
	payload, err := readLimited(stream, int(n), 8192)
	if err != nil {
		return false, err
	}
	fields := decodeQPACK(payload)
	ok := fields[":path"] == "/auth" && fields[":method"] == "POST" && subtle.ConstantTimeCompare([]byte(fields["hysteria-auth"]), []byte(s.local.Hysteria2.Password)) == 1
	status := "404"
	headers := [][2]string{{":status", status}}
	if ok {
		headers = [][2]string{{":status", "233"}, {"hysteria-udp", "false"}, {"hysteria-cc-rx", "auto"}, {"hysteria-padding", paddingString()}}
	}
	_, err = stream.Write(http3Headers(encodeFields(headers)))
	return ok, err
}

func dialHysteria(ctx context.Context, addr, serverName string, local model.LocalTLS) (net.Conn, error) {
	pool, err := roots(local.CAPEM)
	if err != nil {
		return nil, err
	}
	remote, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	udp, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}
	dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, err := quic.Dial(dialCtx, udp, remote, &tls.Config{MinVersion: tls.VersionTLS13, ServerName: serverName, RootCAs: pool, NextProtos: []string{"h3"}}, hysteriaQUIC)
	if err != nil {
		_ = udp.Close()
		return nil, err
	}
	cleanup := func() {
		_ = conn.CloseWithError(0, "")
		_ = udp.Close()
	}
	go discardUni(ctx, conn)
	if err = writeControl(conn); err != nil {
		cleanup()
		return nil, err
	}
	auth, err := conn.OpenStreamSync(dialCtx)
	if err != nil {
		cleanup()
		return nil, err
	}
	fields := encodeFields([][2]string{{":method", "POST"}, {":scheme", "https"}, {":path", "/auth"}, {":authority", "hysteria"}, {"hysteria-auth", local.Hysteria2.Password}, {"hysteria-cc-rx", "0"}, {"hysteria-padding", paddingString()}})
	if _, err = auth.Write(http3Headers(fields)); err != nil {
		cleanup()
		return nil, err
	}
	_ = auth.Close()
	if err = readAuthStatus(auth); err != nil {
		cleanup()
		return nil, err
	}
	enableHysteriaBBR(conn)
	stream, err := conn.OpenStreamSync(dialCtx)
	if err != nil {
		cleanup()
		return nil, err
	}
	if err = writeTCPRequest(stream, addr); err != nil || readTCPResponse(stream) != nil {
		if err == nil {
			err = errors.New("Hysteria2 tunnel was rejected")
		}
		cleanup()
		return nil, err
	}
	return &quicConn{Stream: stream, local: conn.LocalAddr(), remote: conn.RemoteAddr(), done: cleanup}, nil
}

var hysteriaQUIC = &quic.Config{EnableDatagrams: true, MaxIdleTimeout: time.Minute}

type quicConn struct {
	*quic.Stream
	local, remote net.Addr
	done          func()
	once          sync.Once
}

func (c *quicConn) LocalAddr() net.Addr  { return c.local }
func (c *quicConn) RemoteAddr() net.Addr { return c.remote }
func (c *quicConn) Close() error {
	err := c.Stream.Close()
	c.once.Do(func() {
		if c.done != nil {
			c.done()
		}
	})
	return err
}

func writeControl(conn *quic.Conn) error {
	stream, err := conn.OpenUniStream()
	if err != nil {
		return err
	}
	var buf []byte
	buf = quicvarint.Append(buf, 0)
	buf = quicvarint.Append(buf, 0x4)
	buf = quicvarint.Append(buf, 0)
	_, err = stream.Write(buf)
	return err
}

func discardUni(ctx context.Context, conn *quic.Conn) {
	for {
		stream, err := conn.AcceptUniStream(ctx)
		if err != nil {
			return
		}
		go func(s *quic.ReceiveStream) { _, _ = io.Copy(io.Discard, s) }(stream)
	}
}

func writeTCPRequest(w io.Writer, addr string) error {
	var buf []byte
	buf = quicvarint.Append(buf, hysteriaTCP)
	buf = quicvarint.Append(buf, uint64(len(addr)))
	buf = append(buf, addr...)
	pad := paddingString()
	buf = quicvarint.Append(buf, uint64(len(pad)))
	buf = append(buf, pad...)
	_, err := w.Write(buf)
	return err
}

func readTCPRequest(r io.Reader) error {
	n, err := readVarint(r)
	if err != nil {
		return err
	}
	if _, err = readLimited(r, int(n), 512); err != nil {
		return err
	}
	n, err = readVarint(r)
	if err != nil {
		return err
	}
	_, err = readLimited(r, int(n), 4096)
	return err
}

func writeTCPResponse(w io.Writer) error {
	pad := paddingString()
	var buf []byte
	buf = append(buf, 0)
	buf = quicvarint.Append(buf, 0)
	buf = quicvarint.Append(buf, uint64(len(pad)))
	buf = append(buf, pad...)
	_, err := w.Write(buf)
	return err
}

func readTCPResponse(r io.Reader) error {
	var status [1]byte
	if _, err := io.ReadFull(r, status[:]); err != nil {
		return err
	}
	if status[0] != 0 {
		return errors.New("Hysteria2 tunnel was rejected")
	}
	n, err := readVarint(r)
	if err != nil {
		return err
	}
	if _, err = readLimited(r, int(n), 512); err != nil {
		return err
	}
	n, err = readVarint(r)
	if err != nil {
		return err
	}
	_, err = readLimited(r, int(n), 4096)
	return err
}

func readAuthStatus(r io.Reader) error {
	kind, err := readVarint(r)
	if err != nil {
		return err
	}
	if kind != 0x1 {
		return errors.New("Hysteria2 authentication failed")
	}
	n, err := readVarint(r)
	if err != nil {
		return err
	}
	payload, err := readLimited(r, int(n), 8192)
	if err != nil {
		return err
	}
	if decodeQPACK(payload)[":status"] != "233" {
		return errors.New("Hysteria2 authentication failed")
	}
	return nil
}

func http3Headers(fields []byte) []byte {
	var buf []byte
	buf = quicvarint.Append(buf, 0x1)
	buf = quicvarint.Append(buf, uint64(len(fields)))
	return append(buf, fields...)
}

func encodeFields(headers [][2]string) []byte {
	out := []byte{0, 0}
	for _, h := range headers {
		switch h[0] + " " + h[1] {
		case ":method POST":
			out = append(out, 0xC0|20)
			continue
		case ":scheme https":
			out = append(out, 0xC0|23)
			continue
		}
		out = append(out, qpackLiteral(h[0], h[1])...)
	}
	return out
}

func qpackLiteral(name, value string) []byte {
	out := []byte{0x20 | byte(len(name))}
	out = append(out, name...)
	out = append(out, byte(len(value)))
	return append(out, value...)
}

func decodeQPACK(b []byte) map[string]string {
	out := map[string]string{}
	if len(b) < 2 {
		return out
	}
	b = b[2:]
	for len(b) > 0 {
		switch {
		case b[0]&0xC0 == 0xC0:
			out[staticName(int(b[0]&0x3f))] = staticValue(int(b[0] & 0x3f))
			b = b[1:]
		case b[0]&0xE0 == 0x20:
			nameLen := int(b[0] & 0x1f)
			b = b[1:]
			if nameLen > len(b) {
				return out
			}
			name := string(b[:nameLen])
			b = b[nameLen:]
			if len(b) == 0 {
				return out
			}
			valueLen := int(b[0])
			b = b[1:]
			if valueLen > len(b) {
				return out
			}
			out[strings.ToLower(name)] = string(b[:valueLen])
			b = b[valueLen:]
		default:
			return out
		}
	}
	return out
}

func staticName(i int) string {
	switch i {
	case 20:
		return ":method"
	case 23:
		return ":scheme"
	default:
		return ""
	}
}

func staticValue(i int) string {
	switch i {
	case 20:
		return "POST"
	case 23:
		return "https"
	default:
		return ""
	}
}

func readVarint(r io.Reader) (uint64, error) {
	var first [1]byte
	if _, err := io.ReadFull(r, first[:]); err != nil {
		return 0, err
	}
	n := 1 << (first[0] >> 6)
	buf := make([]byte, n)
	buf[0] = first[0]
	if n > 1 {
		if _, err := io.ReadFull(r, buf[1:]); err != nil {
			return 0, err
		}
	}
	v, _, err := quicvarint.Parse(buf)
	return v, err
}

func readLimited(r io.Reader, n, max int) ([]byte, error) {
	if n < 0 || n > max {
		return nil, errors.New("Hysteria2 field is too large")
	}
	buf := make([]byte, n)
	_, err := io.ReadFull(r, buf)
	return buf, err
}

func paddingString() string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	raw := make([]byte, 16)
	_, _ = rand.Read(raw)
	for i := range raw {
		raw[i] = alphabet[int(raw[i])%len(alphabet)]
	}
	return string(raw)
}
