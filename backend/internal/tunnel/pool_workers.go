package tunnel

import (
	"context"
	"net"
	"sync"

	"veilink/internal/model"
)

// A slot survives resize cycles. Retiring stops replenishment, not an active
// transport; only unassigned application connections may be interrupted.
type poolWorker struct {
	mu      sync.Mutex
	ctx     context.Context
	cancel  context.CancelFunc
	changed chan struct{}
	idle    net.Conn
}

func newPoolWorker(parent context.Context) *poolWorker {
	ctx, cancel := context.WithCancel(parent)
	cancel()
	return &poolWorker{ctx: ctx, cancel: cancel, changed: make(chan struct{})}
}

func (w *poolWorker) enable(parent context.Context, enabled bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if enabled == (w.ctx.Err() == nil) {
		return
	}
	w.cancel()
	if enabled {
		w.ctx, w.cancel = context.WithCancel(parent)
	} else if w.idle != nil {
		w.idle.Close()
		w.idle = nil
	}
	close(w.changed)
	w.changed = make(chan struct{})
}

func (w *poolWorker) ready(parent context.Context) context.Context {
	for parent.Err() == nil {
		w.mu.Lock()
		ctx, changed := w.ctx, w.changed
		w.mu.Unlock()
		if ctx.Err() == nil {
			return ctx
		}
		select {
		case <-parent.Done():
			return parent
		case <-changed:
		}
	}
	return parent
}

func (w *poolWorker) assign(ctx context.Context, conn net.Conn) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if ctx.Err() != nil {
		return false
	}
	w.idle = conn
	return true
}

func (w *poolWorker) release(conn net.Conn) {
	w.mu.Lock()
	if w.idle == conn {
		w.idle = nil
	}
	w.mu.Unlock()
}

func (s *service) resizeWorkers(key string, n int, run func(*poolWorker)) {
	workers := s.poolWorkers[key]
	for len(workers) < n {
		w := newPoolWorker(s.ctx)
		workers = append(workers, w)
		go run(w)
	}
	s.poolWorkers[key] = workers
	for i, w := range workers {
		w.enable(s.ctx, i < n)
	}
}

func (s *service) resizePools(next model.Snapshot) {
	for _, b := range next.Bindings {
		for _, kind := range singKinds {
			s.singPools[singKey(b.ID, kind)].resize(singPoolSize(next.Mappings, b.ID, kind))
		}
		if next.Node.Role == "server" {
			// The gateway owns UDP assignment. Its peer must not close a locally
			// idle session while a previously assigned OPEN is still in flight.
			s.mu.Lock()
			sessions := append([]*session(nil), s.sessions[b.ID]...)
			s.mu.Unlock()
			keep := bindingPool(next.Mappings, b.ID)
			for _, sess := range sessions {
				if sess.available() && keep > 0 {
					keep--
				} else {
					sess.drain()
				}
			}
			s.mu.Lock()
			var idle []net.Conn
			n := 0
			if bindingDedicated(next.Mappings, b.ID) {
				n = bindingPool(next.Mappings, b.ID)
			}
			for _, slot := range s.applications[b.ID][min(n, len(s.applications[b.ID])):] {
				idle = append(idle, slot.conn)
			}
			s.applications[b.ID] = s.applications[b.ID][:min(n, len(s.applications[b.ID]))]
			s.mu.Unlock()
			for _, conn := range idle {
				conn.Close()
			}
		}
	}
	if s.updateClientPools != nil {
		s.updateClientPools(next)
	}
}
