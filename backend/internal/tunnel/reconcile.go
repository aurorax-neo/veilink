package tunnel

import (
	"errors"
	"fmt"
	"net"
	"reflect"
	"strconv"
	"sync"
	"sync/atomic"

	"veilink/internal/model"
)

type bindingServices map[string]*service

var errRollbackFailed = errors.New("configuration rollback failed")

type mappingListener struct {
	mapping atomic.Pointer[model.Mapping]
	tcp     net.Listener
	udp     *net.UDPConn
	closed  atomic.Bool
}

func (l *mappingListener) close() {
	l.closed.Store(true)
	if l.tcp != nil {
		_ = l.tcp.Close()
	}
	if l.udp != nil {
		_ = l.udp.Close()
	}
}

func sameRuntimeNode(a, b model.Node) bool {
	return sameConfiguration(model.Snapshot{Node: a}, model.Snapshot{Node: b})
}

func bindingSnapshot(s model.Snapshot, b model.Binding) model.Snapshot {
	out := cloneSnapshot(s)
	out.Bindings = []model.Binding{b}
	out.Mappings = nil
	for _, m := range s.Mappings {
		if m.BindingID == b.ID {
			out.Mappings = append(out.Mappings, m)
		}
	}
	out.Nodes = nil
	for _, n := range s.Nodes {
		if n.ID == b.ServerID {
			out.Nodes = append(out.Nodes, n)
		}
	}
	return out
}

// Only wire handshakes and peer identity require a replacement. Mapping pool
// sizes and modes are reconciled without discarding unrelated active streams.
func sameBindingTransport(a, b model.Snapshot) bool {
	if len(a.Bindings) != 1 || len(b.Bindings) != 1 || a.Bindings[0] != b.Bindings[0] {
		return false
	}
	a.Mappings, b.Mappings = nil, nil
	return sameConfiguration(a, b)
}

func (s *service) bindingOwner(user string) (*service, model.Binding, bool) {
	if owners := s.userOwners.Load(); owners != nil {
		if child := (*owners)[user]; child != nil && child.ctx.Err() == nil {
			return child, child.byUser[user], true
		}
		return nil, model.Binding{}, false
	}
	b, ok := s.byUser[user]
	return s, b, ok && s.ctx.Err() == nil
}

// Publish an immutable authentication index; stopped owners reject admission
// while a replacement or rollback is being prepared.
func (s *service) publishChildren(children bindingServices) {
	owners := make(map[string]*service, len(children))
	for _, child := range children {
		for user := range child.byUser {
			owners[user] = child
		}
	}
	s.children.Store(&children)
	s.userOwners.Store(&owners)
}

func (s *service) linkedBindings() []string {
	if children := s.children.Load(); children != nil {
		var ids []string
		for _, child := range *children {
			ids = append(ids, child.linkedBindings()...)
		}
		return ids
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var ids []string
	for id, sessions := range s.sessions {
		for _, sess := range sessions {
			if sess.alive() {
				ids = append(ids, id)
				break
			}
		}
	}
	return ids
}

func (s *service) reconcile(next model.Snapshot) error {
	old := *s.children.Load()
	wanted := map[string]model.Snapshot{}
	for _, b := range next.Bindings {
		wanted[b.ID] = bindingSnapshot(next, b)
	}
	current := bindingServices{}
	replaced := map[string]bool{}
	updated := map[string]model.Snapshot{}
	for id, child := range old {
		n, exists := wanted[id]
		if exists && sameBindingTransport(*child.policy.Load(), n) {
			current[id] = child
			updated[id] = *child.policy.Load()
		} else {
			replaced[id] = true
			child.stop()
		}
	}
	// Release changed ports across all bindings before acquiring replacements.
	// A mapping can move to another client while retaining its public port.
	for id, child := range current {
		child.releaseChangedListeners(wanted[id])
	}
	rollback := func(cause error) error {
		var failures []error
		for id, child := range current {
			if old[id] != child {
				child.stop()
			}
		}
		for id, prior := range updated {
			old[id].releaseChangedListeners(prior)
		}
		for id, prior := range updated {
			if err := old[id].reconcileMappings(prior); err != nil {
				failures = append(failures, err)
			}
		}
		restored := bindingServices{}
		for id, child := range old {
			if replaced[id] {
				var err error
				child, err = startService(*child.policy.Load(), s.local, s.dialLog, true, s.traffic)
				if err != nil {
					failures = append(failures, err)
					continue
				}
			}
			restored[id] = child
		}
		s.publishChildren(restored)
		if len(failures) > 0 {
			return fmt.Errorf("%w; %w: %v", cause, errRollbackFailed, errors.Join(failures...))
		}
		return cause
	}
	for id, n := range wanted {
		if child := current[id]; child != nil {
			if err := child.reconcileMappings(n); err != nil {
				return rollback(err)
			}
		} else {
			child, err := startService(n, s.local, s.dialLog, true, s.traffic)
			if err != nil {
				return rollback(err)
			}
			current[id] = child
		}
	}
	s.publishChildren(current)
	return nil
}

func sameMapping(a, b model.Mapping) bool {
	a.Name, b.Name = "", ""
	a.Pool, b.Pool = 0, 0
	return reflect.DeepEqual(a, b)
}

func (s *service) newMappingListener(m model.Mapping) (*mappingListener, error) {
	l := &mappingListener{}
	l.mapping.Store(&m)
	addr := net.JoinHostPort(listenHost(m.ListenHost), strconv.Itoa(m.ListenPort))
	var err error
	if mappingNet(m.Network) == "udp" {
		l.udp, err = net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(listenHost(m.ListenHost)), Port: m.ListenPort})
		if err == nil {
			go s.serveUDP(l.udp, m)
		}
	} else {
		l.tcp, err = net.Listen("tcp", addr)
		if err == nil {
			go s.acceptMapping(l.tcp, l)
		}
	}
	return l, err
}

func (s *service) reconcileMappings(next model.Snapshot) error {
	if next.Node.Role != "server" && sameConfiguration(*s.policy.Load(), next) {
		return nil
	}
	wanted := map[string]model.Mapping{}
	for _, m := range next.Mappings {
		if m.Enabled {
			wanted[m.ID] = m
		}
	}
	if next.Node.Role == "server" {
		changed := map[string]model.Mapping{}
		for id, listener := range s.mappingListeners {
			m := *listener.mapping.Load()
			if n, ok := wanted[id]; !ok || !sameMapping(m, n) {
				changed[id] = m
				listener.close()
				delete(s.mappingListeners, id)
				s.closeMapping(id)
			}
		}
		created := map[string]*mappingListener{}
		for id, m := range wanted {
			if s.mappingListeners[id] != nil {
				continue
			}
			listener, err := s.newMappingListener(m)
			if err != nil {
				for _, l := range created {
					l.close()
				}
				var failures []error
				for restoreID, old := range changed {
					l, restoreErr := s.newMappingListener(old)
					if restoreErr != nil {
						failures = append(failures, restoreErr)
					} else {
						s.mappingListeners[restoreID] = l
					}
				}
				if len(failures) > 0 {
					return fmt.Errorf("%w; %w: %v", err, errRollbackFailed, errors.Join(failures...))
				}
				return err
			}
			created[id] = listener
		}
		for id, l := range created {
			s.mappingListeners[id] = l
		}
		for id, m := range wanted {
			m := m
			s.mappingListeners[id].mapping.Store(&m)
		}
	}
	// Publication and target admission share the same lock. A stale peer cannot
	// race withdrawal by opening a newly unauthorized target after this point.
	saved := cloneSnapshot(next)
	s.mu.Lock()
	s.policy.Store(&saved)
	var withdrawn []net.Conn
	for conn, target := range s.targetConns {
		if !s.targetAllowed(target.binding, target.host, target.port, target.network, target.mux, target.kind) {
			withdrawn = append(withdrawn, conn)
		}
	}
	s.mu.Unlock()
	for _, conn := range withdrawn {
		_ = conn.Close()
	}
	s.resizePools(next)
	return nil
}

func (s *service) releaseChangedListeners(next model.Snapshot) {
	wanted := make(map[string]model.Mapping, len(next.Mappings))
	for _, m := range next.Mappings {
		if m.Enabled {
			wanted[m.ID] = m
		}
	}
	for id, listener := range s.mappingListeners {
		m, ok := wanted[id]
		if !ok || !sameMapping(*listener.mapping.Load(), m) {
			listener.close()
			delete(s.mappingListeners, id)
			s.closeMapping(id)
		}
	}
}

func (s *service) trackMapping(conn net.Conn, m model.Mapping, listener *mappingListener) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conns == nil || listener.closed.Load() {
		return false
	}
	if s.mappingConns[m.ID] == nil {
		s.mappingConns[m.ID] = map[net.Conn]struct{}{}
	}
	s.mappingConns[m.ID][conn] = struct{}{}
	s.conns[conn] = struct{}{}
	return true
}

func (s *service) untrackMapping(conn net.Conn, id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.mappingConns[id], conn)
}

func (s *service) closeMapping(id string) {
	s.mu.Lock()
	var conns []net.Conn
	for conn := range s.mappingConns[id] {
		conns = append(conns, conn)
	}
	s.mu.Unlock()
	for _, conn := range conns {
		_ = conn.Close()
	}
}

type targetPolicy struct {
	binding, host, network, kind string
	port                         int
	mux                          bool
}

func (s *service) targetAllowed(binding, host string, port int, network string, mux bool, kind string) bool {
	policy := s.policy.Load()
	if policy == nil {
		policy = &s.snapshot
	}
	for _, m := range policy.Mappings {
		if !m.Enabled || m.BindingID != binding || mappingNet(m.Network) != network || m.TargetHost != host || m.TargetPort != port {
			continue
		}
		if network == "udp" {
			return true
		}
		if m.Mux != mux {
			continue
		}
		if mux {
			k, err := m.EffectiveMuxType()
			if err != nil || k != kind {
				continue
			}
		}
		return true
	}
	return false
}

func (s *service) trackTarget(conn net.Conn, target targetPolicy) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conns == nil || !s.targetAllowed(target.binding, target.host, target.port, target.network, target.mux, target.kind) {
		return false
	}
	s.targetConns[conn] = target
	s.conns[conn] = struct{}{}
	return true
}

type policyConn struct {
	net.Conn
	service *service
	once    sync.Once
}

func (c *policyConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { c.service.untrack(c.Conn) })
	return err
}
