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
	mu      sync.Mutex
	dialMu  sync.Mutex
	count   int
	limit   int
	kind    string
	lanes   []*singLane
	reverse map[*singReverseConn]bool
}

type singClient interface {
	DialContext(context.Context, string, M.Socksaddr) (net.Conn, error)
	Close() error
}

type singLane struct {
	client   singClient
	conn     *singReverseConn
	active   int
	draining bool
}

func (s *service) initSingPools() {
	for _, b := range s.snapshot.Bindings {
		for _, kind := range singKinds {
			n := singPoolSize(s.snapshot.Mappings, b.ID, kind)
			p := &singPool{ctx: s.ctx, queue: make(chan *singReverseConn, 32), slots: make(chan struct{}, 64), limit: n, kind: kind, reverse: map[*singReverseConn]bool{}}
			p.client = p
			s.singPools[singKey(b.ID, kind)] = p
		}
	}
}
func (p *singPool) take(ctx context.Context) (*singReverseConn, error) {
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
			p.mu.Lock()
			if _, ok := p.reverse[c]; !ok {
				p.mu.Unlock()
				continue
			}
			p.reverse[c] = true
			close(c.claimed)
			p.mu.Unlock()
			return c, nil
		}
	}
}

// Each upstream client owns exactly one transport. Scheduling outside the
// library makes resize and drain explicit without modifying its private state.
func (p *singPool) DialContext(ctx context.Context, network string, dst M.Socksaddr) (net.Conn, error) {
	if network != "tcp" {
		return nil, errors.New("TCP mux only")
	}
	p.dialMu.Lock()
	p.mu.Lock()
	var best *singLane
	n := 0
	for _, lane := range p.lanes {
		if !lane.draining && !lane.conn.closed() {
			n++
			if best == nil || lane.active < best.active {
				best = lane
			}
		}
	}
	limit := p.limit
	if limit == 0 {
		p.mu.Unlock()
		p.dialMu.Unlock()
		return nil, net.ErrClosed
	}
	expand := best == nil || (n < limit && best.active >= 8 && len(p.queue) > 0)
	if expand {
		p.mu.Unlock()
		acquire := ctx
		cancel := func() {}
		if best != nil {
			acquire, cancel = context.WithTimeout(ctx, 20*time.Millisecond)
		}
		conn, err := p.take(acquire)
		cancel()
		if err != nil {
			if best == nil || ctx.Err() != nil {
				p.dialMu.Unlock()
				return nil, err
			}
			p.mu.Lock()
		} else {
			dialer := &singLaneDialer{conn: conn}
			client, _ := mux.NewClient(mux.Options{Dialer: dialer, Logger: logger.NOP(), Protocol: p.kind, MaxConnections: 1, MinStreams: 8, TCPTimeout: 5 * time.Second})
			best = &singLane{client: client, conn: conn}
			if p.kind == model.MuxTypeH2Mux {
				best.client = &singH2Client{pool: p, dial: dialer.DialContext}
			}
			p.mu.Lock()
			current := 0
			for _, lane := range p.lanes {
				if !lane.draining && !lane.conn.closed() {
					current++
				}
			}
			if current >= p.limit || conn.closed() {
				p.mu.Unlock()
				best.client.Close()
				conn.Close()
				p.mu.Lock()
				best = nil
			} else {
				p.lanes = append(p.lanes, best)
			}
		}
	}
	// Resize may retire the selected lane while transport acquisition waits.
	if best == nil || best.draining || best.conn.closed() {
		best = nil
		for _, lane := range p.lanes {
			if !lane.draining && !lane.conn.closed() && (best == nil || lane.active < best.active) {
				best = lane
			}
		}
		if best == nil {
			p.mu.Unlock()
			p.dialMu.Unlock()
			return nil, net.ErrClosed
		}
	}
	best.active++
	p.mu.Unlock()
	p.dialMu.Unlock()
	stream, err := best.client.DialContext(ctx, network, dst)
	if err != nil {
		p.release(best)
		return nil, err
	}
	return &singPoolStream{Conn: stream, release: func() { p.release(best) }}, nil
}

type singLaneDialer struct {
	mu   sync.Mutex
	conn net.Conn
	used bool
}

func (d *singLaneDialer) DialContext(ctx context.Context, network string, dst M.Socksaddr) (net.Conn, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if d.used || network != "tcp" || dst != mux.Destination {
		return nil, net.ErrClosed
	}
	d.used = true
	return d.conn, nil
}
func (*singLaneDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("TCP mux only")
}

type singPoolStream struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *singPoolStream) Close() error { err := c.Conn.Close(); c.once.Do(c.release); return err }
func (c *singPoolStream) CloseWrite() error {
	if c, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return c.CloseWrite()
	}
	return c.Close()
}

func (p *singPool) release(lane *singLane) {
	p.mu.Lock()
	lane.active--
	closeLane := lane.active == 0 && (lane.draining || lane.conn.closed())
	if closeLane {
		p.removeLane(lane)
	}
	p.mu.Unlock()
	if closeLane {
		lane.client.Close()
		lane.conn.Close()
	}
}
func (p *singPool) removeLane(lane *singLane) {
	for i, l := range p.lanes {
		if l == lane {
			p.lanes = append(p.lanes[:i], p.lanes[i+1:]...)
			break
		}
	}
}
func (p *singPool) resize(n int) {
	p.mu.Lock()
	p.limit = n
	var retired []*singLane
	keep := n
	for _, lane := range append([]*singLane(nil), p.lanes...) {
		if !lane.draining && !lane.conn.closed() && keep > 0 {
			keep--
			continue
		}
		lane.draining = true
		if lane.active == 0 {
			p.removeLane(lane)
			retired = append(retired, lane)
		}
	}
	var idle []*singReverseConn
	for conn, claimed := range p.reverse {
		if claimed {
			continue
		}
		if keep > 0 {
			keep--
			continue
		}
		delete(p.reverse, conn)
		idle = append(idle, conn)
	}
	// Remove closed/retired queued transports so resize cycles cannot fill the
	// bounded queue with stale entries before the next stream is requested.
	queued := len(p.queue)
	for range queued {
		select {
		case conn := <-p.queue:
			if _, ok := p.reverse[conn]; ok && !conn.closed() {
				p.queue <- conn
			}
		default:
		}
	}
	p.mu.Unlock()
	for _, lane := range retired {
		lane.client.Close()
		lane.conn.Close()
	}
	for _, conn := range idle {
		conn.Close()
	}
}
func (p *singPool) Close() error {
	p.resize(0)
	p.mu.Lock()
	lanes := append([]*singLane(nil), p.lanes...)
	p.mu.Unlock()
	for _, lane := range lanes {
		lane.conn.Close()
	}
	return nil
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

func (c *singReverseConn) closed() bool {
	select {
	case <-c.done:
		return true
	default:
		return false
	}
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
	active := 0
	for conn := range p.reverse {
		if conn.closed() {
			continue
		}
		draining := false
		for _, lane := range p.lanes {
			if lane.conn == conn {
				draining = lane.draining
				break
			}
		}
		if !draining {
			active++
		}
	}
	if active >= p.limit {
		p.mu.Unlock()
		return
	}
	if s.flow != "" {
		conn = newVision(conn, id)
	}
	conn.SetDeadline(time.Time{})
	c := &singReverseConn{Conn: conn, done: make(chan struct{}), claimed: make(chan struct{})}
	p.count++
	p.reverse[c] = false
	select {
	case p.queue <- c:
	default:
		p.count--
		delete(p.reverse, c)
		p.mu.Unlock()
		c.Close()
		return
	}
	p.mu.Unlock()
	defer func() { p.mu.Lock(); p.count--; delete(p.reverse, c); p.mu.Unlock() }()
	defer c.Close()
	timer := time.NewTimer(30 * time.Second)
	defer timer.Stop()
	select {
	case <-c.claimed:
	case <-c.done:
		return
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

func (s *service) maintainSingMux(b model.Binding, gateway model.Node, peer *clientGateway, kind string, worker *poolWorker) {
	id, _ := parseUUID(b.UUID)
	attempt := 1
	for s.ctx.Err() == nil {
		ctx := worker.ready(s.ctx)
		if ctx.Err() != nil {
			return
		}
		if s.dialLog != nil {
			s.dialLog.noteAttempt(b.ID, attempt)
		}
		started := time.Now()
		s.runSingMux(b, gateway, peer, kind, id, worker, ctx)
		var ok bool
		attempt, ok = s.afterShortContext(ctx, b, gateway, started, attempt)
		if !ok {
			continue
		}
	}
}
func (s *service) runSingMux(b model.Binding, gateway model.Node, peer *clientGateway, kind string, id [16]byte, worker *poolWorker, ctx context.Context) {
	conn, err := s.dialProtocol(gateway, peer, b, singMuxPort)
	if err != nil {
		return
	}
	tracked := conn
	handedOff := false
	defer func() {
		if !handedOff {
			tracked.Close()
			s.untrack(tracked)
		}
	}()
	if !worker.assign(ctx, tracked) {
		return
	}
	defer worker.release(tracked)
	if !s.track(tracked) {
		return
	}
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	var protocol byte
	for i, k := range singKinds {
		if k == kind {
			protocol = byte(i)
		}
	}
	// Assignment can begin immediately after the selector reaches the gateway.
	worker.release(tracked)
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
	worker.release(tracked)
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
	done := make(chan struct{})
	handedOff = true
	go func() {
		defer close(done)
		defer tracked.Close()
		defer s.untrack(tracked)
		_ = service.NewConnection(context.WithoutCancel(s.ctx), checked, M.Metadata{})
	}()
	select {
	case <-done:
	case <-ctx.Done():
	}
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
	if !h.s.trackTarget(target, targetPolicy{binding: h.binding, host: metadata.Destination.AddrString(), port: int(metadata.Destination.Port), network: "tcp", mux: true, kind: h.kind}) {
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
	return s.targetAllowed(binding, host, port, "tcp", true, kind)
}
