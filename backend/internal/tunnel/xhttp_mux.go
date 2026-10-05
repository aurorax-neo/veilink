package tunnel

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"
	"veilink/internal/model"
)

type xhttpMuxEntry struct {
	transport               xhttpCloser
	created                 time.Time
	running, uses, requests int
	retired                 bool
}
type xhttpMuxPool struct {
	mu      sync.Mutex
	entries map[[32]byte][]*xhttpMuxEntry
}

var globalXHTTPMuxPool = &xhttpMuxPool{entries: make(map[[32]byte][]*xhttpMuxEntry)}

func checkXHTTPMux(x model.XHTTP) error {
	m := x.Xmux
	if m.MaxConcurrency < 0 || m.MaxConnections < 0 || m.CMaxReuseTimes < 0 || m.HMaxRequestTimes < 0 || m.HMaxReusableSecs < 0 || m.KeepAlivePeriod < 0 {
		return errors.New("xhttp xmux values cannot be negative")
	}
	if m.MaxConcurrency > 1024 || m.MaxConnections > 128 || m.CMaxReuseTimes > 100000 || m.HMaxRequestTimes > 100000 || m.HMaxReusableSecs > 86400 || m.KeepAlivePeriod > 3600 {
		return errors.New("xhttp xmux value exceeds limit")
	}
	return nil
}
func xhttpMuxKey(addr, serverName string, local model.LocalTLS) [32]byte {
	b, _ := json.Marshal(struct {
		Addr, ServerName string
		Local            model.LocalTLS
	}{addr, serverName, local})
	return sha256.Sum256(b)
}
func (p *xhttpMuxPool) acquire(ctx context.Context, key [32]byte, x model.XHTTP, create func() (xhttpCloser, error)) (*xhttpMuxLease, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	m := x.Xmux
	list := p.entries[key]
	alive := list[:0]
	now := time.Now()
	for _, e := range list {
		if m.CMaxReuseTimes > 0 && e.uses >= m.CMaxReuseTimes || m.HMaxRequestTimes > 0 && e.requests >= m.HMaxRequestTimes || m.HMaxReusableSecs > 0 && now.Sub(e.created) >= time.Duration(m.HMaxReusableSecs)*time.Second {
			e.retired = true
		}
		if e.retired {
			if e.running == 0 {
				closeXHTTPTransport(e.transport)
			}
			continue
		}
		alive = append(alive, e)
	}
	clear(list[len(alive):])
	list = alive
	var chosen *xhttpMuxEntry
	// Reference maxConnections is an expansion target, not a hard limit:
	// maxConcurrency may require further transports when all are occupied.
	if m.MaxConnections == 0 || len(list) >= m.MaxConnections {
		for _, e := range list {
			if m.MaxConcurrency == 0 || e.running < m.MaxConcurrency {
				if chosen == nil || e.running < chosen.running {
					chosen = e
				}
			}
		}
	}
	if chosen == nil {
		if len(list) >= 128 {
			p.entries[key] = list
			return nil, errors.New("xhttp xmux transport budget reached")
		}
		tr, err := create()
		if err != nil {
			if len(list) == 0 {
				delete(p.entries, key)
			} else {
				p.entries[key] = list
			}
			return nil, err
		}
		chosen = &xhttpMuxEntry{transport: tr, created: now}
		list = append(list, chosen)
	}
	chosen.running++
	chosen.uses++
	p.entries[key] = list
	return &xhttpMuxLease{pool: p, key: key, entry: chosen}, nil
}

type xhttpMuxLease struct {
	pool  *xhttpMuxPool
	key   [32]byte
	entry *xhttpMuxEntry
	once  sync.Once
}

func (l *xhttpMuxLease) RoundTrip(r *http.Request) (*http.Response, error) {
	l.pool.mu.Lock()
	l.entry.requests++
	l.pool.mu.Unlock()
	return l.entry.transport.RoundTrip(r)
}
func (l *xhttpMuxLease) CloseIdleConnections() { /* A lease must not close another session's idle connections. */
}
func (l *xhttpMuxLease) Close() error {
	l.once.Do(func() {
		l.pool.mu.Lock()
		l.entry.running--
		var closing xhttpCloser
		if l.entry.running == 0 {
			// Keep sharing while leases are active, but do not retain sockets and
			// configuration keys after the last authorized session has closed.
			l.entry.retired = true
			list := l.pool.entries[l.key]
			for i, entry := range list {
				if entry == l.entry {
					copy(list[i:], list[i+1:])
					list[len(list)-1] = nil
					list = list[:len(list)-1]
					break
				}
			}
			if len(list) == 0 {
				delete(l.pool.entries, l.key)
			} else {
				l.pool.entries[l.key] = list
			}
			closing = l.entry.transport
		}
		l.pool.mu.Unlock()
		if closing != nil {
			closeXHTTPTransport(closing)
		}
	})
	return nil
}
func (p *xhttpMuxPool) closeAll() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for key, list := range p.entries {
		for _, e := range list {
			e.retired = true
			if e.running == 0 {
				closeXHTTPTransport(e.transport)
			}
		}
		delete(p.entries, key)
	}
}
