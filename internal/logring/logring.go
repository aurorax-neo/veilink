// Package logring provides a thread-safe ring buffer that captures structured
// log records via the slog.Handler interface. The master injects it so the
// admin console can stream recent log lines without touching the filesystem.
package logring

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// Entry is a single log record stored in the ring buffer.
type Entry struct {
	At      int64  `json:"at"`
	Level   string `json:"level"`
	Message string `json:"message"`
	Source  string `json:"source"`
	NodeID  string `json:"node_id,omitempty"`
}

// Ring is a fixed-capacity ring buffer of log entries.
type Ring struct {
	mu   sync.Mutex
	buf  []Entry
	pos  int
	full bool
	cap  int
}

// New creates a ring buffer that holds up to cap entries.
func New(cap int) *Ring {
	if cap < 1 {
		cap = 2000
	}
	return &Ring{buf: make([]Entry, cap), cap: cap}
}

// Append adds one entry to the ring.
func (r *Ring) Append(e Entry) {
	r.mu.Lock()
	r.buf[r.pos] = e
	r.pos = (r.pos + 1) % r.cap
	if r.pos == 0 {
		r.full = true
	}
	r.mu.Unlock()
}

// AppendBatch adds multiple entries.
func (r *Ring) AppendBatch(entries []Entry) {
	r.mu.Lock()
	for _, e := range entries {
		r.buf[r.pos] = e
		r.pos = (r.pos + 1) % r.cap
		if r.pos == 0 {
			r.full = true
		}
	}
	r.mu.Unlock()
}

// Query returns the most recent entries matching the filters.
// Empty source/nodeID/level matches everything.
func (r *Ring) Query(source, nodeID, level string, limit int) []Entry {
	r.mu.Lock()
	n := r.pos
	if r.full {
		n = r.cap
	}
	// Snapshot the buffer in order (oldest first).
	ordered := make([]Entry, 0, n)
	if r.full {
		ordered = append(ordered, r.buf[r.pos:]...)
		ordered = append(ordered, r.buf[:r.pos]...)
	} else {
		ordered = append(ordered, r.buf[:r.pos]...)
	}
	r.mu.Unlock()

	if limit <= 0 || limit > len(ordered) {
		limit = len(ordered)
	}
	// Walk backwards to get newest first up to limit.
	out := make([]Entry, 0, limit)
	for i := len(ordered) - 1; i >= 0 && len(out) < limit; i-- {
		e := ordered[i]
		if source != "" && e.Source != source {
			continue
		}
		if nodeID != "" && e.NodeID != nodeID {
			continue
		}
		if level != "" && e.Level != level {
			continue
		}
		out = append(out, e)
	}
	return out
}

// Drain returns and removes all entries accumulated so far in oldest-first order.
func (r *Ring) Drain() []Entry {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := r.pos
	if r.full {
		n = r.cap
	}
	if n == 0 {
		return nil
	}
	out := make([]Entry, 0, n)
	if r.full {
		out = append(out, r.buf[r.pos:]...)
		out = append(out, r.buf[:r.pos]...)
	} else {
		out = append(out, r.buf[:r.pos]...)
	}
	r.pos = 0
	r.full = false
	return out
}

// Handler returns an slog.Handler that writes records both to the ring and
// to an optional downstream handler. Records stored in the ring use the
// given source tag (typically "master").
type handler struct {
	ring   *Ring
	source string
	nodeID string
	next   slog.Handler
}

// NewHandler creates a dual-write slog handler.
func NewHandler(r *Ring, source string, next slog.Handler) slog.Handler {
	return &handler{ring: r, source: source, next: next}
}

// NewNodeHandler records an embedded node in the shared Master ring without
// replacing the process-wide logger or forwarding its entries twice.
func NewNodeHandler(r *Ring, nodeID string, next slog.Handler) slog.Handler {
	return &handler{ring: r, source: "node", nodeID: nodeID, next: next}
}

func (h *handler) Enabled(_ context.Context, level slog.Level) bool {
	return h.next.Enabled(context.Background(), level)
}

func (h *handler) Handle(_ context.Context, rec slog.Record) error {
	lvl := "INFO"
	switch {
	case rec.Level >= slog.LevelError:
		lvl = "ERROR"
	case rec.Level >= slog.LevelWarn:
		lvl = "WARN"
	case rec.Level < slog.LevelInfo:
		lvl = "DEBUG"
	}
	// Only include known non-secret diagnostic fields in the web log.
	message := rec.Message
	var details []string
	rec.Attrs(func(a slog.Attr) bool {
		switch a.Key {
		case "role", "revision", "resource", "method", "id", "node_id", "addr", "scheme", "port", "attempt":
			value := fmt.Sprint(a.Value.Any())
			value = strings.Map(func(c rune) rune {
				if c < 32 || c == 127 {
					return ' '
				}
				return c
			}, value)
			if len(value) > 128 {
				value = value[:128]
			}
			details = append(details, a.Key+"="+value)
		}
		return true
	})
	if len(details) > 0 {
		message += " (" + strings.Join(details, ", ") + ")"
	}
	h.ring.Append(Entry{At: rec.Time.Unix(), Level: lvl, Message: message, Source: h.source, NodeID: h.nodeID})
	return h.next.Handle(context.Background(), rec)
}

func (h *handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &handler{ring: h.ring, source: h.source, nodeID: h.nodeID, next: h.next.WithAttrs(attrs)}
}

func (h *handler) WithGroup(name string) slog.Handler {
	return &handler{ring: h.ring, source: h.source, nodeID: h.nodeID, next: h.next.WithGroup(name)}
}

// NodeRing stores per-node log entries in SQLite and an in-memory cache.
// For simplicity the implementation just wraps the main Ring with a
// "node" source tag.
type NodeRing struct {
	ring *Ring
}

// NewNodeRing creates a node log ring.
func NewNodeRing(r *Ring) *NodeRing { return &NodeRing{ring: r} }

// Ingest stores node-reported log entries.
func (n *NodeRing) Ingest(nodeID string, entries []Entry) {
	for i := range entries {
		entries[i].Source = "node"
		entries[i].NodeID = nodeID
		if entries[i].At == 0 {
			entries[i].At = time.Now().Unix()
		}
	}
	n.ring.AppendBatch(entries)
}
