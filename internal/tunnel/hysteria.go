package tunnel

import (
	"bytes"
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
	"sync/atomic"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/quicvarint"
	"github.com/quic-go/qpack"

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
	s.packets = append(s.packets, udp)
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
	stopCancel := context.AfterFunc(s.ctx, func() { _ = conn.CloseWithError(0, "") })
	defer stopCancel()
	go discardUni(s.ctx, conn)
	_ = writeControl(conn)
	authed := false
	var authenticated model.Binding
	for {
		stream, err := conn.AcceptStream(s.ctx)
		if err != nil {
			return
		}
		_ = stream.SetDeadline(time.Now().Add(15 * time.Second))
		kind, err := readVarint(stream)
		if err != nil {
			_ = stream.Close()
			return
		}
		switch kind {
		case 0x1:
			binding, ok, err := s.hysteriaAuth(stream)
			_ = stream.Close()
			if err != nil || !ok {
				return
			}
			authenticated = binding
			if !authed {
				enableHysteriaBBR(conn)
			}
			authed = true
		case hysteriaTCP:
			if !authed {
				_ = stream.Close()
				return
			}
			target, requestErr := readTCPRequest(stream)
			host, portText, splitErr := net.SplitHostPort(target)
			port, portErr := strconv.ParseUint(portText, 10, 16)
			var binding model.Binding
			known := false
			for _, candidate := range s.byUser {
				if candidate.ID == authenticated.ID && candidate.Domain == host {
					binding, known = candidate, true
					break
				}
			}
			if requestErr != nil || splitErr != nil || portErr != nil || !known || (port != 0 && port != applicationPort && port != singMuxPort) {
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
			defer s.untrack(wrapped)
			id, _ := parseUUID(binding.UUID)
			s.serveAuthorized(wrapped, id, binding, uint16(port))
			return
		default:
			_ = stream.Close()
			return
		}
	}
}

func (s *service) hysteriaAuth(stream *quic.Stream) (model.Binding, bool, error) {
	n, err := readVarint(stream)
	if err != nil {
		return model.Binding{}, false, err
	}
	payload, err := readLimited(stream, int(n), 8192)
	if err != nil {
		return model.Binding{}, false, err
	}
	fields := decodeQPACK(payload)
	ok := fields != nil && fields[":authority"] == "hysteria" && fields[":scheme"] == "https" && fields[":path"] == "/auth" && fields[":method"] == "POST"
	var binding model.Binding
	if ok {
		for _, candidate := range s.byUser {
			if subtle.ConstantTimeCompare([]byte(fields["hysteria-auth"]), []byte(candidate.UUID)) == 1 {
				binding = candidate
				break
			}
		}
		ok = binding.ID != ""
	}
	status := "404"
	headers := [][2]string{{":status", status}}
	if ok {
		headers = [][2]string{{":status", "233"}, {"hysteria-udp", "false"}, {"hysteria-cc-rx", "auto"}, {"hysteria-padding", paddingString()}}
	}
	_, err = stream.Write(http3Headers(encodeFields(headers)))
	return binding, ok, err

}

func dialHysteriaSession(ctx context.Context, addr, serverName string, local model.LocalTLS, credential, target string) (net.Conn, error) {
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
	stopCancel := context.AfterFunc(dialCtx, cleanup)
	defer stopCancel()
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
	_ = auth.SetDeadline(time.Now().Add(10 * time.Second))
	fields := encodeFields([][2]string{{":method", "POST"}, {":scheme", "https"}, {":path", "/auth"}, {":authority", "hysteria"}, {"hysteria-auth", credential}, {"hysteria-cc-rx", "0"}, {"hysteria-padding", paddingString()}})
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
	_ = stream.SetDeadline(time.Now().Add(10 * time.Second))
	err = writeTCPRequest(stream, target)
	if err == nil {
		err = readTCPResponse(stream)
	}
	if err != nil {
		cleanup()
		return nil, err
	}
	_ = stream.SetDeadline(time.Time{})
	graceful := func() {
		go finishQUIC(ctx, conn.Context(), hysteriaQUIC.MaxIdleTimeout, cleanup)
	}
	return &quicConn{Stream: stream, local: conn.LocalAddr(), remote: conn.RemoteAddr(), done: cleanup, graceful: graceful}, nil
}

// The reverse server closes QUIC after consuming response FIN. Until then keep
// queued bytes alive, bounded by runtime cancellation and the idle timeout.
func finishQUIC(runtime, peer context.Context, timeout time.Duration, cleanup func()) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-peer.Done():
	case <-runtime.Done():
	case <-timer.C:
	}
	cleanup()
}

var hysteriaQUIC = &quic.Config{EnableDatagrams: true, MaxIdleTimeout: time.Minute}

type quicConn struct {
	*quic.Stream
	local, remote net.Addr
	done          func()
	once          sync.Once
	graceful      func()
	readEOF       atomic.Bool
}

func (c *quicConn) Read(p []byte) (int, error) {
	n, err := c.Stream.Read(p)
	if err == io.EOF {
		c.readEOF.Store(true)
	}
	return n, err
}
func (c *quicConn) LocalAddr() net.Addr  { return c.local }
func (c *quicConn) RemoteAddr() net.Addr { return c.remote }

// QUIC Stream.Close sends FIN on the write direction only. Keep the connection
// and read direction alive so a TCP half-close can still receive its response.
func (c *quicConn) CloseWrite() error { return c.Stream.Close() }
func (c *quicConn) Close() error {
	err := c.Stream.Close()
	c.once.Do(func() {
		if c.graceful != nil && c.readEOF.Load() {
			c.graceful()
		} else if c.done != nil {
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

func readTCPRequest(r io.Reader) (string, error) {
	n, err := readVarint(r)
	if err != nil {
		return "", err
	}
	addr, err := readLimited(r, int(n), 512)
	if err != nil {
		return "", err
	}
	n, err = readVarint(r)
	if err != nil {
		return "", err
	}
	_, err = readLimited(r, int(n), 4096)
	return string(addr), err
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
	var out bytes.Buffer
	encoder := qpack.NewEncoder(&out)
	for _, h := range headers {
		_ = encoder.WriteField(qpack.HeaderField{Name: h[0], Value: h[1]})
	}
	_ = encoder.Close()
	return out.Bytes()
}

func decodeQPACK(b []byte) map[string]string {
	out := map[string]string{}
	next := qpack.NewDecoder().Decode(b)
	for {
		h, err := next()
		if err == io.EOF {
			return out
		}
		if err != nil || len(out) >= 32 {
			return nil
		}
		name := strings.ToLower(h.Name)
		if _, duplicate := out[name]; duplicate {
			return nil
		}
		out[name] = h.Value
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
