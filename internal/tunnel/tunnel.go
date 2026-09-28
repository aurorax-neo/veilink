// Package tunnel is Veilink's VLESS reverse-TCP core. It speaks the VLESS
// version-0 header, then a small Veilink multiplex framing; it is intentionally
// not a general-purpose proxy and does not embed another proxy stack.
package tunnel

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/apernet/quic-go"
	"github.com/xtls/reality"

	"veilink/internal/model"
)

const (
	frameOpen  byte = 1
	frameData  byte = 2
	frameHalf  byte = 3
	frameReset byte = 4
	framePing  byte = 5
	framePong  byte = 6

	maxPayload = 32 << 10
	maxStreams = 512
)

type inbound struct {
	Tag    string `json:"tag"`
	Listen string `json:"listen"`
	Port   int    `json:"port"`
}

type muxSetting struct {
	Enabled bool `json:"enabled"`
}

type outbound struct {
	Protocol      string      `json:"protocol"`
	Tag           string      `json:"tag,omitempty"`
	AllowInsecure *bool       `json:"allowInsecure,omitempty"`
	Mux           *muxSetting `json:"mux,omitempty"`
}

type rule struct {
	InboundTag  []string `json:"inboundTag,omitempty"`
	User        []string `json:"user,omitempty"`
	Domain      []string `json:"domain,omitempty"`
	Network     string   `json:"network,omitempty"`
	Port        string   `json:"port,omitempty"`
	OutboundTag string   `json:"outboundTag"`
}

type policy struct {
	Inbounds  []inbound  `json:"inbounds"`
	Outbounds []outbound `json:"outbounds"`
	Routing   struct {
		Rules []rule `json:"rules"`
	} `json:"routing"`
}

// Build validates a snapshot and returns its deny-by-default routing policy.
// Only the validated server-owned protocol/template selects the data plane.
func Build(s model.Snapshot, local model.LocalTLS) ([]byte, error) {
	s = orderedSnapshot(s)
	if err := validate(s, local); err != nil {
		return nil, err
	}
	falseValue := false
	doc := policy{Outbounds: []outbound{{Protocol: "blackhole", Tag: "reject"}}}
	if s.Node.Role == "server" && len(s.Bindings) > 0 {
		doc.Inbounds = append(doc.Inbounds, inbound{Tag: "transport", Listen: listenHost(local.ListenHost), Port: local.ListenPort})
	}
	for _, b := range s.Bindings {
		if s.Node.Role == "server" {
			doc.Routing.Rules = append(doc.Routing.Rules, rule{
				InboundTag: []string{"transport"}, User: []string{strings.ToLower(b.UUID)},
				Domain: []string{"full:" + b.Domain}, Network: "tcp", Port: "0", OutboundTag: "portal-" + b.ID,
			})
		} else {
			protocol := "vless"
			for _, gateway := range s.Nodes {
				if gateway.ID == b.ServerID {
					protocol = gateway.Tunnel.EffectiveProtocol()
					break
				}
			}
			doc.Outbounds = append(doc.Outbounds, outbound{
				Protocol: protocol, Tag: "tunnel-" + b.ID, AllowInsecure: &falseValue, Mux: &muxSetting{Enabled: bindingMux(s.Mappings, b.ID)},
			})
			doc.Routing.Rules = append(doc.Routing.Rules, rule{
				InboundTag: []string{"bridge-" + b.ID}, Domain: []string{"full:" + b.Domain},
				Network: "tcp", Port: "0", OutboundTag: "tunnel-" + b.ID,
			})
		}
	}
	for _, m := range s.Mappings {
		if !m.Enabled {
			continue
		}
		item := rule{Network: "tcp", Port: strconv.Itoa(m.TargetPort), OutboundTag: "authorized"}
		if net.ParseIP(m.TargetHost) != nil {
			item.Domain = []string{"ip:" + m.TargetHost}
		} else {
			item.Domain = []string{"full:" + m.TargetHost}
		}
		if s.Node.Role == "server" {
			tag := "mapping-" + m.ID
			doc.Inbounds = append(doc.Inbounds, inbound{Tag: tag, Listen: listenHost(m.ListenHost), Port: m.ListenPort})
			item.InboundTag = []string{tag}
			item.OutboundTag = "portal-" + m.BindingID
		} else {
			item.InboundTag = []string{"bridge-" + m.BindingID}
		}
		doc.Routing.Rules = append(doc.Routing.Rules, item)
	}
	doc.Routing.Rules = append(doc.Routing.Rules, rule{Network: "tcp,udp", OutboundTag: "reject"})
	return json.Marshal(doc)
}

// Runtime serializes configuration replacement. A replacement interrupts flows
// on that node. Revision is -1 when nothing is running. Do not copy a Runtime.
type Runtime struct {
	mu        sync.Mutex
	local     model.LocalTLS
	instance  *service
	good      *model.Snapshot
	goodLocal model.LocalTLS
	document  []byte
	revision  int64
	highWater int64
	closed    bool
}

func New(local model.LocalTLS) *Runtime {
	return &Runtime{local: local, revision: -1, highWater: -1}
}

// Apply prevalidates before touching listeners. A failed start restores the
// last running configuration when one exists.
func (r *Runtime) Apply(s model.Snapshot) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return errors.New("tunnel runtime is closed")
	}
	if s.Revision < r.highWater {
		return fmt.Errorf("stale revision %d (last successful %d)", s.Revision, r.highWater)
	}
	effective := s.Node.Tunnel.Merge(r.local)
	document, err := Build(s, effective)
	if err != nil {
		return err
	}
	// Routing policy omits keys, gateway settings and mapping pool sizes. Compare
	// the full runtime inputs too, or those changes would silently be ignored.
	same := r.good != nil && sameConfiguration(*r.good, s) && r.goodLocal == effective
	if s.Revision == r.highWater && !same {
		return errors.New("revision reused with different configuration")
	}
	if r.instance != nil && same && bytes.Equal(document, r.document) {
		r.revision = s.Revision
		r.highWater = s.Revision
		return nil
	}
	oldRevision := r.revision
	if r.instance != nil {
		r.instance.stop()
		r.instance = nil
		r.revision = -1
	}
	instance, err := start(s, effective)
	if err != nil {
		if r.good != nil {
			restored, rollbackErr := start(*r.good, r.goodLocal)
			if rollbackErr != nil {
				return fmt.Errorf("start failed: %w; rollback failed: %v", err, rollbackErr)
			}
			r.instance = restored
			r.revision = oldRevision
			if r.revision < 0 {
				r.revision = r.highWater
			}
			return fmt.Errorf("start failed (restored revision %d): %w", r.revision, err)
		}
		return fmt.Errorf("start tunnel: %w", err)
	}
	r.instance = instance
	saved := cloneSnapshot(s)
	r.good = &saved
	r.goodLocal = effective
	r.document = document
	r.revision = s.Revision
	r.highWater = s.Revision
	return nil
}

func (r *Runtime) Revision() int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.revision
}

func (r *Runtime) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	r.revision = -1
	if r.instance != nil {
		r.instance.stop()
		r.instance = nil
	}
	return nil
}

func cloneSnapshot(s model.Snapshot) model.Snapshot {
	encoded, _ := json.Marshal(s)
	var out model.Snapshot
	_ = json.Unmarshal(encoded, &out)
	return out
}

// orderedSnapshot copies the slices before sorting, leaving the caller's view intact.
// Build uses the same ordering so equivalent inputs also produce identical policy.
func orderedSnapshot(s model.Snapshot) model.Snapshot {
	s.Nodes = append([]model.Node(nil), s.Nodes...)
	s.Bindings = append([]model.Binding(nil), s.Bindings...)
	s.Mappings = append([]model.Mapping(nil), s.Mappings...)
	sort.Slice(s.Nodes, func(i, j int) bool { return s.Nodes[i].ID < s.Nodes[j].ID })
	sort.Slice(s.Bindings, func(i, j int) bool { return s.Bindings[i].ID < s.Bindings[j].ID })
	sort.Slice(s.Mappings, func(i, j int) bool { return s.Mappings[i].ID < s.Mappings[j].ID })
	return s
}

func sameConfiguration(a, b model.Snapshot) bool {
	canonical := func(s model.Snapshot) model.Snapshot {
		s = orderedSnapshot(s)
		s.Revision = 0
		// Administrative metadata on local and related nodes is not data-plane
		// configuration. Keep mapping names: validation requires unique names.
		clearStatus := func(n *model.Node) {
			n.Name = ""
			n.DesiredRevision, n.AppliedRevision, n.LastSeen = 0, 0, 0
			n.Error = ""
		}
		clearStatus(&s.Node)
		for i := range s.Nodes {
			clearStatus(&s.Nodes[i])
		}
		return s
	}
	return reflect.DeepEqual(canonical(a), canonical(b))
}

type clientGateway struct {
	local    model.LocalTLS
	flow     string
	outbound *encClient
}

func gatewayClientConfig(local model.LocalTLS, gateway model.Node) (model.LocalTLS, error) {
	if local != (model.LocalTLS{}) {
		return model.LocalTLS{}, errors.New("client-local tunnel overrides are not allowed")
	}
	// Related gateways carry the exact, server-owned public template. Never
	// rederive it: selected REALITY names/IDs and operator CA trust must survive.
	config := gateway.Tunnel
	if err := requireTransportSecurity(config); err != nil {
		return model.LocalTLS{}, err
	}
	if err := ValidateClientTemplate(config); err != nil {
		return model.LocalTLS{}, err
	}
	if config.Reality.Enabled() {
		if _, err := realityNames(config.Reality, gateway.Address); err != nil {
			return model.LocalTLS{}, err
		}
	}
	return config, nil
}

func newClientGateway(local model.LocalTLS, gateway model.Node) (*clientGateway, error) {
	config, err := gatewayClientConfig(local, gateway)
	if err != nil {
		return nil, err
	}
	flow, _ := normalizeFlow(config.Flow)
	peer := &clientGateway{local: config, flow: flow}
	if config.EffectiveProtocol() == "hysteria2" {
		return peer, nil
	}
	spec, err := parseEncryption(config.Encryption)
	if err == nil && spec != nil {
		peer.outbound, err = spec.newClient()
	}
	return peer, err
}

// bindingPool is a shared session pool, not a dedicated pool per mapping. All
// enabled mappings on the binding use round-robin sessions; the largest requested
// size wins. Bindings without enabled mappings retain one control session.
func bindingPool(mappings []model.Mapping, binding string) int {
	n := 0
	for _, m := range mappings {
		if m.Enabled && m.BindingID == binding {
			n = max(n, m.Pool)
		}
	}
	return max(1, min(n, 32))
}

func bindingMux(mappings []model.Mapping, binding string) bool {
	for _, m := range mappings {
		if m.Enabled && m.BindingID == binding && mappingNet(m.Network) == "tcp" && m.Mux {
			return true
		}
	}
	return false
}

func bindingDedicated(mappings []model.Mapping, binding string) bool {
	for _, m := range mappings {
		if m.Enabled && m.BindingID == binding && mappingNet(m.Network) == "tcp" && !m.Mux {
			return true
		}
	}
	return false
}

type service struct {
	ctx                context.Context
	cancel             context.CancelFunc
	once               sync.Once
	local              model.LocalTLS
	snapshot           model.Snapshot
	byUser             map[string]model.Binding
	allowed            map[string]map[string]bool
	listeners          []net.Listener
	packets            []net.PacketConn
	mu                 sync.Mutex
	sessions           map[string][]*session
	conns              map[net.Conn]struct{}
	next               uint32
	reality            *reality.Config
	quic               *quic.Listener
	flow               string
	inbound            *encServer
	tlsConfig          *tls.Config
	xhttpClose         func()
	applicationChanged chan struct{}
	applicationWaiting map[string]int
	applications       map[string][]*applicationSlot
	singPools          map[string]*singPool
}

func start(s model.Snapshot, local model.LocalTLS) (*service, error) {
	if err := validate(s, local); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	svc := &service{
		ctx: ctx, cancel: cancel, local: local, snapshot: cloneSnapshot(s),
		byUser: map[string]model.Binding{}, allowed: map[string]map[string]bool{},
		sessions: map[string][]*session{}, conns: map[net.Conn]struct{}{},
		applications:       map[string][]*applicationSlot{},
		applicationChanged: make(chan struct{}), applicationWaiting: map[string]int{},
		singPools: map[string]*singPool{},
	}
	var err error
	defer func() {
		if err != nil {
			svc.stop()
		}
	}()
	gateways := map[string]model.Node{}
	for _, n := range s.Nodes {
		gateways[n.ID] = n
	}
	if s.Node.Role == "server" {
		gateways[s.Node.ID] = s.Node
	}
	for _, b := range s.Bindings {
		svc.byUser[userKey(b.UUID)] = b
		svc.allowed[b.ID] = map[string]bool{}
	}
	for _, m := range s.Mappings {
		if m.Enabled {
			svc.allowed[m.BindingID][mappingNet(m.Network)+"\n"+m.TargetHost+"\n"+strconv.Itoa(m.TargetPort)] = true
		}
	}
	svc.initSingPools()
	if err = svc.prepareReality(); err != nil {
		return nil, err
	}
	if s.Node.Role == "server" {
		if err = svc.prepareCrypto(); err != nil {
			return nil, err
		}
	}
	if s.Node.Role == "server" {
		err = svc.listenServer()
	} else {
		peers := map[string]*clientGateway{}
		for _, b := range s.Bindings {
			peer := peers[b.ServerID]
			if peer == nil {
				peer, err = newClientGateway(local, gateways[b.ServerID])
				if err != nil {
					return nil, err
				}
				peers[b.ServerID] = peer
			}
			for _, kind := range singKinds {
				for range singPoolSize(s.Mappings, b.ID, kind) {
					go svc.maintainSingMux(b, gateways[b.ServerID], peer, kind)
				}
			}
			for range bindingPool(s.Mappings, b.ID) {
				go svc.maintain(b, gateways[b.ServerID], peer)
				if bindingDedicated(s.Mappings, b.ID) {
					go svc.maintainApplication(b, gateways[b.ServerID], peer)
				}
			}
		}
	}
	return svc, err
}

func (s *service) stop() {
	s.once.Do(func() {
		if s.inbound != nil {
			s.inbound.Close()
		}
		if s.quic != nil {
			_ = s.quic.Close()
		}
		s.cancel()
		if s.xhttpClose != nil {
			s.xhttpClose()
		}
		for _, ln := range s.listeners {
			_ = ln.Close()
		}
		for _, pc := range s.packets {
			_ = pc.Close()
		}
		s.mu.Lock()
		conns := s.conns
		s.conns = nil
		s.mu.Unlock()
		for conn := range conns {
			_ = conn.Close()
		}
		for _, pool := range s.singPools {
			pool.client.Close()
		}
	})
}

func (s *service) listenServer() error {
	if len(s.snapshot.Bindings) > 0 {
		if s.local.EffectiveProtocol() == "hysteria2" {
			if err := s.listenHysteria(); err != nil {
				return err
			}
		} else {
			addr := net.JoinHostPort(listenHost(s.local.ListenHost), strconv.Itoa(s.local.ListenPort))
			var ln net.Listener
			var err error
			min := uint16(tls.VersionTLS12)
			if s.flow != "" {
				min = tls.VersionTLS13
			}
			if s.reality != nil || s.local.TransportSecurity == "plain" {
				ln, err = net.Listen("tcp", addr)
			} else {
				cert, loadErr := tls.X509KeyPair([]byte(s.local.CertPEM), []byte(s.local.KeyPEM))
				if loadErr != nil {
					return loadErr
				}
				s.tlsConfig = &tls.Config{MinVersion: min, Certificates: []tls.Certificate{cert}, SessionTicketsDisabled: true}
				ln, err = net.Listen("tcp", addr)
			}
			if err != nil {
				return err
			}
			s.listeners = append(s.listeners, ln)
			if s.reality != nil && s.local.XHTTP.Enabled() {
				ln = reality.NewListener(ln, s.reality)
			}
			if s.local.XHTTP.Enabled() {
				s.serveXHTTP(ln)
			} else {
				go s.acceptTransport(ln)
			}
		}
	}

	for _, m := range s.snapshot.Mappings {
		if !m.Enabled {
			continue
		}
		if mappingNet(m.Network) == "udp" {
			pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(listenHost(m.ListenHost)), Port: m.ListenPort})
			if err != nil {
				return err
			}
			s.packets = append(s.packets, pc)
			go s.serveUDP(pc, m)
			continue
		}
		ln, err := net.Listen("tcp", net.JoinHostPort(listenHost(m.ListenHost), strconv.Itoa(m.ListenPort)))
		if err != nil {
			return err
		}
		s.listeners = append(s.listeners, ln)
		go s.acceptMapping(ln, m)
	}
	return nil
}

func (s *service) acceptTransport(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		if !s.track(conn) {
			_ = conn.Close()
			continue
		}
		go s.acceptOne(conn)
	}
}

func (s *service) acceptMapping(ln net.Listener, m model.Mapping) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		if !s.track(conn) {
			_ = conn.Close()
			continue
		}
		go s.openPublic(conn, m)
	}
}

func (s *service) authenticate(conn net.Conn) {
	tracked := conn
	defer s.untrack(tracked)
	defer func() {
		if conn != nil {
			_ = conn.Close()
		}
	}()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	if s.inbound != nil {
		wrapped, err := s.inbound.Handshake(conn)
		if err != nil {
			return
		}
		if !s.track(wrapped) {
			_ = wrapped.Close()
			return
		}
		s.untrack(conn)
		conn = wrapped
		defer s.untrack(wrapped)
	}
	id, host, port, flow, err := readVLESS(conn)
	if err != nil {
		return
	}
	got, flowErr := normalizeFlow(flow)
	binding, ok := s.byUser[hex.EncodeToString(id[:])]
	if flowErr != nil || got != s.flow || !ok || (port != 0 && port != applicationPort && port != singMuxPort) || !strings.EqualFold(host, binding.Domain) {
		return
	}
	if err = writeVLESSResponse(conn); err != nil {
		return
	}
	s.serveAuthorized(conn, id, binding, port)
}

func (s *service) openPublic(conn net.Conn, m model.Mapping) {
	defer s.untrack(conn)
	if !m.Mux {
		s.openApplication(conn, m)
		return
	}
	s.openSingMux(conn, m)
}

func (s *service) maintain(b model.Binding, gateway model.Node, peer *clientGateway) {
	user, err := parseUUID(b.UUID)
	if err != nil {
		return
	}
	for {
		if s.ctx.Err() != nil {
			return
		}
		conn, err := s.dialProtocol(gateway, peer, b, 0)
		if err == nil && peer.flow != "" {
			vc := newVision(conn, user)
			if err = vc.camouflage(); err != nil {
				_ = conn.Close()
				conn = nil
			} else {
				conn = vc
			}
		}
		if err == nil {
			_ = conn.SetDeadline(time.Time{})
		}
		if err != nil {
			if conn != nil {
				_ = conn.Close()
			}
			if !sleep(s.ctx, 200*time.Millisecond) {
				return
			}
			continue
		}
		if !s.track(conn) {
			_ = conn.Close()
			return
		}
		sess := newSession(conn)
		s.addSession(b.ID, sess)
		sess.readLoop(func(host string, port int, udp bool) (net.Conn, error) {
			if !udp || !s.allowed[b.ID]["udp\n"+host+"\n"+strconv.Itoa(port)] {
				return nil, errors.New("target is not authorized")
			}
			dialer := net.Dialer{Timeout: 5 * time.Second}
			network := "tcp"
			if udp {
				network = "udp"
			}
			conn, err := dialer.DialContext(s.ctx, network, net.JoinHostPort(host, strconv.Itoa(port)))
			if err != nil || !udp {
				return conn, err
			}
			uc, ok := conn.(*net.UDPConn)
			if !ok {
				_ = conn.Close()
				return nil, errors.New("udp dial failed")
			}
			return newClientUDP(uc, host, port), nil
		})
		s.removeSession(b.ID, sess)
		s.untrack(conn)
		if !sleep(s.ctx, 200*time.Millisecond) {
			return
		}
	}
}

func roots(caPEM string) (*x509.CertPool, error) {
	if caPEM == "" {
		return nil, nil
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(caPEM)) {
		return nil, errors.New("ca_pem contains no valid certificates")
	}
	return pool, nil
}

func (s *service) track(conn net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conns == nil {
		return false
	}
	s.conns[conn] = struct{}{}
	return true
}

func (s *service) untrack(conn net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.conns, conn)
}

func (s *service) addSession(binding string, sess *session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sessions == nil {
		sess.close()
		return
	}
	s.sessions[binding] = append(s.sessions[binding], sess)
}

func (s *service) removeSession(binding string, sess *session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	list := s.sessions[binding]
	for i, item := range list {
		if item == sess {
			s.sessions[binding] = append(list[:i], list[i+1:]...)
			return
		}
	}
}

func (s *service) pick(binding string) *session {
	s.mu.Lock()
	defer s.mu.Unlock()
	list := s.sessions[binding]
	for i := 0; i < len(list); i++ {
		index := int((atomic.AddUint32(&s.next, 1) - 1) % uint32(len(list)))
		if list[index].alive() {
			return list[index]
		}
	}
	return nil
}

type chunk struct {
	data []byte
	half bool
}

type stream struct {
	id        uint32
	conn      net.Conn
	in        chan chunk
	stop      chan struct{}
	once      sync.Once
	readDone  bool
	writeDone bool
}

func (st *stream) halt() {
	st.once.Do(func() { close(st.stop) })
}

type session struct {
	conn     net.Conn
	wmu      sync.Mutex
	writeBuf [7 + maxPayload]byte // owned by wmu until the synchronous write returns
	mu       sync.Mutex
	streams  map[uint32]*stream
	next     uint32
	done     chan struct{}
	once     sync.Once
}

func newSession(conn net.Conn) *session {
	sess := &session{conn: conn, streams: map[uint32]*stream{}, done: make(chan struct{})}
	go sess.keepalive()
	return sess
}

func (s *session) alive() bool {
	select {
	case <-s.done:
		return false
	default:
		return true
	}
}

func (s *session) close() {
	s.once.Do(func() {
		close(s.done)
		_ = s.conn.Close()
		s.mu.Lock()
		streams := s.streams
		s.streams = nil
		s.mu.Unlock()
		for _, st := range streams {
			st.halt()
			_ = st.conn.Close()
		}
	})
}

func (s *session) keepalive() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			if s.writeFrame(framePing, 0, nil) != nil {
				s.close()
				return
			}
		}
	}
}

func (s *session) track(st *stream) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.streams == nil || len(s.streams) >= maxStreams {
		return false
	}
	if st.in == nil {
		st.in = make(chan chunk, 64)
	}
	if st.stop == nil {
		st.stop = make(chan struct{})
	}
	s.streams[st.id] = st
	go s.writeLoop(st)
	return true
}

func (s *session) writeLoop(st *stream) {
	for {
		select {
		case <-s.done:
			return
		case <-st.stop:
			return
		case c := <-st.in:
			if c.half {
				closeWrite(st.conn)
				s.markWrite(st.id)
				continue
			}
			if _, err := st.conn.Write(c.data); err != nil {
				if s.forget(st.id) != nil {
					_ = st.conn.Close()
					_ = s.writeFrame(frameReset, st.id, nil)
				}
				return
			}
		}
	}
}

func closeWrite(conn net.Conn) {
	if cw, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = conn.Close()
}

func (s *session) deliver(id uint32, c chunk) {
	s.mu.Lock()
	st := s.streams[id]
	s.mu.Unlock()
	if st == nil {
		return
	}
	select {
	case <-s.done:
	case <-st.stop:
	case st.in <- c:
	}
}

func (s *session) markRead(id uint32) {
	s.mu.Lock()
	st := s.streams[id]
	if st == nil {
		s.mu.Unlock()
		return
	}
	st.readDone = true
	both := st.writeDone
	s.mu.Unlock()
	if both {
		if old := s.forget(id); old != nil {
			_ = old.conn.Close()
		}
	}
}

func (s *session) markWrite(id uint32) {
	s.mu.Lock()
	st := s.streams[id]
	if st == nil {
		s.mu.Unlock()
		return
	}
	st.writeDone = true
	both := st.readDone
	s.mu.Unlock()
	if both {
		if old := s.forget(id); old != nil {
			_ = old.conn.Close()
		}
	}
}

func (s *session) forget(id uint32) *stream {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.streams == nil {
		return nil
	}
	st := s.streams[id]
	if st == nil {
		return nil
	}
	delete(s.streams, id)
	st.halt()
	return st
}

func (s *session) readLoop(open func(string, int, bool) (net.Conn, error)) {
	defer s.close()
	for {
		_ = s.conn.SetReadDeadline(time.Now().Add(45 * time.Second))
		kind, id, payload, err := readFrame(s.conn)
		if err != nil {
			return
		}
		switch kind {
		case frameOpen:
			host, port, udp, err := parseOpen(payload)
			conn, dialErr := net.Conn(nil), err
			if err == nil && open != nil {
				conn, dialErr = open(host, port, udp)
			} else if err == nil {
				dialErr = errors.New("peer cannot open streams")
			}
			if dialErr != nil {
				_ = s.writeFrame(frameReset, id, nil)
				continue
			}
			if !s.track(&stream{id: id, conn: conn}) {
				_ = conn.Close()
				_ = s.writeFrame(frameReset, id, nil)
				continue
			}
			go s.pump(conn, id)
		case frameData:
			s.deliver(id, chunk{data: payload})
		case frameHalf:
			s.deliver(id, chunk{half: true})
		case frameReset:
			if st := s.forget(id); st != nil {
				_ = st.conn.Close()
			}
		case framePing:
			_ = s.writeFrame(framePong, 0, nil)
		case framePong:
		default:
			return
		}
	}
}

func (s *session) pump(conn net.Conn, id uint32) {
	buf := make([]byte, maxPayload)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			if werr := s.writeFrame(frameData, id, buf[:n]); werr != nil {
				_ = conn.Close()
				s.forget(id)
				return
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				_ = s.writeFrame(frameHalf, id, nil)
				s.markRead(id)
				return
			}
			_ = s.writeFrame(frameReset, id, nil)
			_ = conn.Close()
			s.forget(id)
			return
		}
	}
}

func (s *session) writeFrame(kind byte, id uint32, payload []byte) error {
	if len(payload) > maxPayload {
		return errors.New("frame too large")
	}
	s.wmu.Lock()
	defer s.wmu.Unlock()
	buf := s.writeBuf[:7+len(payload)]
	buf[0] = kind
	binary.BigEndian.PutUint32(buf[1:5], id)
	binary.BigEndian.PutUint16(buf[5:7], uint16(len(payload)))
	copy(buf[7:], payload)
	_, err := s.conn.Write(buf)
	return err
}

func parseOpen(payload []byte) (string, int, bool, error) {
	if len(payload) >= 6 && payload[0] == 0 && payload[1] == 0 && payload[2] == 'u' {
		port := int(binary.BigEndian.Uint16(payload[3:5]))
		host := string(payload[5:])
		if port == 0 || len(host) > 253 || !hostOK(host) {
			return "", 0, true, errors.New("invalid stream target")
		}
		return host, port, true, nil
	}
	if len(payload) < 3 || len(payload) > 2+253 {
		return "", 0, false, errors.New("invalid stream open")
	}
	port := int(binary.BigEndian.Uint16(payload[:2]))
	host := string(payload[2:])
	if port == 0 || !hostOK(host) {
		return "", 0, false, errors.New("invalid stream target")
	}
	return host, port, false, nil
}

func mappingNet(network string) string {
	if network == "udp" {
		return "udp"
	}
	return "tcp"
}

func mappingNetBool(udp bool) string {
	if udp {
		return "udp"
	}
	return "tcp"
}

func readVLESS(r io.Reader) ([16]byte, string, uint16, string, error) {
	var id [16]byte
	head := make([]byte, 18)
	if _, err := io.ReadFull(r, head); err != nil {
		return id, "", 0, "", err
	}
	if head[0] != 0 {
		return id, "", 0, "", errors.New("unsupported vless version")
	}
	copy(id[:], head[1:17])
	var flow string
	if addons := int(head[17]); addons > 0 {
		raw := make([]byte, addons)
		if _, err := io.ReadFull(r, raw); err != nil {
			return id, "", 0, "", err
		}
		parsed, err := decodeFlow(raw)
		if err != nil {
			return id, "", 0, "", err
		}
		flow = parsed
	}
	var rest [4]byte
	if _, err := io.ReadFull(r, rest[:]); err != nil {
		return id, "", 0, flow, err
	}
	if rest[0] != 1 {
		return id, "", 0, flow, errors.New("only tcp is supported")
	}
	port := binary.BigEndian.Uint16(rest[1:3])
	host, err := readAddr(r, rest[3])
	return id, host, port, flow, err
}

func writeVLESS(w io.Writer, id [16]byte, host string, port uint16, flow string) error {
	var buf bytes.Buffer
	buf.WriteByte(0)
	buf.Write(id[:])
	addon := encodeFlow(flow)
	buf.WriteByte(byte(len(addon)))
	buf.Write(addon)
	buf.WriteByte(1)
	_ = binary.Write(&buf, binary.BigEndian, port)
	if err := writeAddr(&buf, host); err != nil {
		return err
	}
	_, err := w.Write(buf.Bytes())
	return err
}

func writeVLESSResponse(w io.Writer) error {
	_, err := w.Write([]byte{0, 0})
	return err
}

func readVLESSResponse(r io.Reader) error {
	var response [2]byte
	if _, err := io.ReadFull(r, response[:]); err != nil {
		return err
	}
	if response[0] != 0 || response[1] != 0 {
		return errors.New("vless handshake rejected")
	}
	return nil
}

func writeAddr(buf *bytes.Buffer, host string) error {
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			buf.WriteByte(1)
			buf.Write(v4)
			return nil
		}
		buf.WriteByte(3)
		buf.Write(ip.To16())
		return nil
	}
	if len(host) == 0 || len(host) > 253 {
		return errors.New("invalid address")
	}
	buf.WriteByte(2)
	buf.WriteByte(byte(len(host)))
	buf.WriteString(host)
	return nil
}

func readAddr(r io.Reader, kind byte) (string, error) {
	switch kind {
	case 1:
		var ip [4]byte
		if _, err := io.ReadFull(r, ip[:]); err != nil {
			return "", err
		}
		return net.IP(ip[:]).String(), nil
	case 3:
		var ip [16]byte
		if _, err := io.ReadFull(r, ip[:]); err != nil {
			return "", err
		}
		return net.IP(ip[:]).String(), nil
	case 2:
		var n [1]byte
		if _, err := io.ReadFull(r, n[:]); err != nil {
			return "", err
		}
		if n[0] == 0 || n[0] > 253 {
			return "", errors.New("invalid domain")
		}
		name := make([]byte, n[0])
		if _, err := io.ReadFull(r, name); err != nil {
			return "", err
		}
		return string(name), nil
	default:
		return "", errors.New("invalid address type")
	}
}

func readFrame(r io.Reader) (byte, uint32, []byte, error) {
	var head [7]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return 0, 0, nil, err
	}
	n := int(binary.BigEndian.Uint16(head[5:7]))
	if n > maxPayload {
		return 0, 0, nil, errors.New("frame too large")
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, 0, nil, err
	}
	return head[0], binary.BigEndian.Uint32(head[1:5]), payload, nil
}

func parseUUID(text string) ([16]byte, error) {
	var id [16]byte
	raw, err := hex.DecodeString(strings.ReplaceAll(text, "-", ""))
	if err != nil || len(raw) != 16 {
		return id, errors.New("invalid uuid")
	}
	copy(id[:], raw)
	return id, nil
}

func userKey(text string) string {
	raw, err := hex.DecodeString(strings.ReplaceAll(text, "-", ""))
	if err != nil || len(raw) != 16 {
		return ""
	}
	return hex.EncodeToString(raw)
}

func sleep(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
