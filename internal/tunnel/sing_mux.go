package tunnel

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	mux "github.com/metacubex/sing-mux"
	"github.com/metacubex/sing/common/logger"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
	"veilink/internal/model"
)

const singMuxPort = 2

var singMagic = []byte("veilink-sing-mux/1\x00")
var singKinds = []string{model.MuxTypeSMux, model.MuxTypeYAMux, model.MuxTypeH2Mux}

func singPoolSize(ms []model.Mapping, binding, kind string) int {
	n := 0
	for _, m := range ms {
		k, err := m.EffectiveMuxType()
		if err == nil && m.Enabled && m.BindingID == binding && k == kind {
			n = max(n, max(1, min(32, m.Pool)))
		}
	}
	return n
}
func singKey(binding, kind string) string { return binding + "\n" + kind }

type singPool struct {
	ctx    context.Context
	queue  chan *singReverseConn
	slots  chan struct{}
	client interface {
		DialContext(context.Context, string, M.Socksaddr) (net.Conn, error)
		Close() error
	}
	mu    sync.Mutex
	count int
	limit int
}

func (s *service) initSingPools() {
	for _, b := range s.snapshot.Bindings {
		for _, kind := range singKinds {
			n := singPoolSize(s.snapshot.Mappings, b.ID, kind)
			if n == 0 {
				continue
			}
			p := &singPool{ctx: s.ctx, queue: make(chan *singReverseConn, n), slots: make(chan struct{}, 64), limit: n}
			p.client, _ = mux.NewClient(mux.Options{Dialer: p, Logger: logger.NOP(), Protocol: kind, MaxConnections: n, MinStreams: 8, TCPTimeout: 5 * time.Second})
			if kind == model.MuxTypeH2Mux {
				p.client = &singH2Client{pool: p}
			}
			s.singPools[singKey(b.ID, kind)] = p
		}
	}
}
func (p *singPool) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if network != "tcp" || destination != mux.Destination {
		return nil, errors.New("invalid mux transport destination")
	}
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-p.ctx.Done():
			return nil, p.ctx.Err()
		case c := <-p.queue:
			select {
			case <-c.done:
				continue
			default:
			}
			close(c.claimed)
			return c, nil
		}
	}
}
func (p *singPool) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("TCP mux only")
}

type singReverseConn struct {
	net.Conn
	once    sync.Once
	done    chan struct{}
	claimed chan struct{}
}

func (c *singReverseConn) Close() error { c.once.Do(func() { close(c.done) }); return c.Conn.Close() }
func (c *singReverseConn) Read(b []byte) (int, error) {
	n, e := c.Conn.Read(b)
	if e != nil {
		c.Close()
	}
	return n, e
}
func (c *singReverseConn) Write(b []byte) (int, error) {
	n, e := c.Conn.Write(b)
	if e != nil {
		c.Close()
	}
	return n, e
}

func (s *service) acceptSingMux(conn net.Conn, id [16]byte, b model.Binding) {
	magic := make([]byte, len(singMagic)+1)
	if _, err := io.ReadFull(conn, magic); err != nil || !bytes.Equal(magic[:len(singMagic)], singMagic) || int(magic[len(singMagic)]) >= len(singKinds) {
		return
	}
	kind := singKinds[magic[len(singMagic)]]
	p := s.singPools[singKey(b.ID, kind)]
	if p == nil {
		return
	}
	p.mu.Lock()
	if p.count >= p.limit {
		p.mu.Unlock()
		return
	}
	p.count++
	p.mu.Unlock()
	defer func() { p.mu.Lock(); p.count--; p.mu.Unlock() }()
	if s.flow != "" {
		conn = newVision(conn, id)
	}
	conn.SetDeadline(time.Time{})
	c := &singReverseConn{Conn: conn, done: make(chan struct{}), claimed: make(chan struct{})}
	defer c.Close()
	select {
	case p.queue <- c:
	default:
		return
	}
	timer := time.NewTimer(30 * time.Second)
	defer timer.Stop()
	select {
	case <-c.claimed:
	case <-timer.C:
		return
	case <-s.ctx.Done():
		return
	}
	select {
	case <-c.done:
	case <-s.ctx.Done():
	}
}

func (s *service) openSingMux(conn net.Conn, m model.Mapping) {
	defer conn.Close()
	kind, err := m.EffectiveMuxType()
	if err != nil {
		return
	}
	p := s.singPools[singKey(m.BindingID, kind)]
	if p == nil {
		return
	}
	// Bound acquisition waiters AND active streams, including upstream's serialized dial.
	select {
	case p.slots <- struct{}{}:
	default:
		return
	}
	defer func() { <-p.slots }()
	ctx, cancel := context.WithTimeout(s.ctx, applicationWait)
	defer cancel()
	stream, err := p.client.DialContext(ctx, "tcp", M.ParseSocksaddrHostPort(m.TargetHost, uint16(m.TargetPort)))
	if err != nil {
		return
	}
	defer stream.Close()
	if !s.track(stream) {
		return
	}
	defer s.untrack(stream)
	// Flush the real sing-mux stream request before bidirectional relay (server-first TCP).
	if _, err = stream.Write(nil); err != nil {
		return
	}
	relayApplication(&singRecordConn{Conn: stream}, conn)
}

func (s *service) maintainSingMux(b model.Binding, gateway model.Node, peer *clientGateway, kind string) {
	id, _ := parseUUID(b.UUID)
	for s.ctx.Err() == nil {
		s.runSingMux(b, gateway, peer, kind, id)
		if !sleep(s.ctx, 200*time.Millisecond) {
			return
		}
	}
}
func (s *service) runSingMux(b model.Binding, gateway model.Node, peer *clientGateway, kind string, id [16]byte) {
	conn, err := s.dialProtocol(gateway, peer, b, singMuxPort)
	if err != nil {
		return
	}
	tracked := conn
	defer tracked.Close()
	if !s.track(tracked) {
		return
	}
	defer s.untrack(tracked)
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	var protocol byte
	for i, k := range singKinds {
		if k == kind {
			protocol = byte(i)
		}
	}
	if writeAll(conn, append(append([]byte(nil), singMagic...), protocol)) != nil {
		return
	}
	if peer.flow != "" {
		v := newVision(conn, id)
		if v.camouflage() != nil {
			return
		}
		conn = v
	}
	conn.SetDeadline(time.Now().Add(45 * time.Second))
	// Validate the actual sing-mux Request, not only the authorized outer selector.
	checked, err := checkSingRequest(conn, protocol)
	if err != nil {
		return
	}
	conn.SetDeadline(time.Time{})
	handler := &singHandler{s: s, binding: b.ID, kind: kind}
	service, err := mux.NewService(mux.ServiceOptions{Logger: logger.NOP(), Handler: handler, NewStreamContext: func(ctx context.Context, c net.Conn) context.Context {
		c.SetReadDeadline(time.Now().Add(15 * time.Second))
		return ctx
	}})
	if err != nil {
		return
	}
	// Transport closure drives session shutdown. Passing cancellation as well
	// races upstream h2MuxServerSession.Close (non-atomic done-channel close).
	// All transports and target sockets remain tracked by this service.
	_ = service.NewConnection(context.WithoutCancel(s.ctx), checked, M.Metadata{})
}

type singReplayConn struct {
	net.Conn
	prefix io.Reader
}

func (c *singReplayConn) Read(b []byte) (int, error) { return c.prefix.Read(b) }
func checkSingRequest(c net.Conn, protocol byte) (net.Conn, error) {
	var header bytes.Buffer
	req, err := mux.ReadRequest(io.TeeReader(c, &header))
	if err != nil {
		return nil, err
	}
	if req.Protocol != protocol {
		return nil, errors.New("mux protocol differs from authorization")
	}
	return &singReplayConn{Conn: c, prefix: io.MultiReader(bytes.NewReader(header.Bytes()), c)}, nil
}

type singHandler struct {
	s             *service
	binding, kind string
}

func (h *singHandler) NewConnection(ctx context.Context, c net.Conn, metadata M.Metadata) error {
	defer c.Close()
	if !h.s.singTargetAllowed(h.binding, h.kind, metadata.Destination.AddrString(), int(metadata.Destination.Port)) {
		return errors.New("unauthorized mux target")
	}
	p := h.s.singPools[singKey(h.binding, h.kind)]
	select {
	case p.slots <- struct{}{}:
	default:
		return errors.New("mux stream limit")
	}
	defer func() { <-p.slots }()
	target, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(h.s.ctx, "tcp", metadata.Destination.String())
	if err != nil {
		return err
	}
	defer target.Close()
	if !h.s.track(target) {
		return context.Canceled
	}
	defer h.s.untrack(target)
	c.SetReadDeadline(time.Time{})
	if _, err = c.Write(nil); err != nil {
		return err
	}
	relayApplication(&singRecordConn{Conn: c}, target)
	return nil
}
func (h *singHandler) NewPacketConnection(_ context.Context, c N.PacketConn, _ M.Metadata) error {
	c.Close()
	return errors.New("TCP mux only")
}
func (s *service) singTargetAllowed(binding, kind, host string, port int) bool {
	for _, m := range s.snapshot.Mappings {
		k, e := m.EffectiveMuxType()
		if e == nil && m.Enabled && m.Mux && mappingNet(m.Network) == "tcp" && m.BindingID == binding && k == kind && m.TargetHost == host && m.TargetPort == port {
			return true
		}
	}
	return false
}
