package tunnel

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/juju/ratelimit"
	"veilink/internal/model"
)

// One outgoing payload bucket per mapping on each endpoint. It is shared by all
// streams, independent of Pool, mux and transport; control frames are not shaped.
type bandwidthBucket struct {
	mu     sync.Mutex
	rate   int64
	bucket *ratelimit.Bucket
}

func (b *bandwidthBucket) update(value string) {
	n, _ := model.BandwidthBytes(value) // snapshots are validated before publication
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.rate == n {
		return
	}
	b.rate = n
	if n == 0 {
		b.bucket = nil
	} else {
		// At most 50ms of burst, never a full second of queued video.
		b.bucket = ratelimit.NewBucketWithRate(float64(n), max(1, n/20))
	}
}

func (b *bandwidthBucket) readSize(size int) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.rate == 0 {
		return size
	}
	return min(size, int(max(1, min(32<<10, b.rate/20))))
}

func (b *bandwidthBucket) wait(ctx context.Context, n int) error {
	return b.waitRead(ctx, n, nil)
}

func (b *bandwidthBucket) waitRead(ctx context.Context, n int, deadline func() time.Time) error {
	for n > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		if deadline != nil {
			if d := deadline(); !d.IsZero() && !time.Now().Before(d) {
				return os.ErrDeadlineExceeded
			}
		}
		b.mu.Lock()
		if b.bucket == nil {
			b.mu.Unlock()
			return nil
		}
		taken := b.bucket.TakeAvailable(int64(n))
		b.mu.Unlock()
		n -= int(taken)
		if n == 0 {
			return nil
		}
		timer := time.NewTimer(5 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return nil
}

type shapedConn struct {
	net.Conn
	bucket       *bandwidthBucket
	ctx          context.Context
	cancel       context.CancelFunc
	readMu       sync.Mutex
	deadlineMu   sync.Mutex
	readDeadline time.Time
	pending      []byte
	pendingErr   error
}

func shapeConn(ctx context.Context, conn net.Conn, bucket *bandwidthBucket) *shapedConn {
	ctx, cancel := context.WithCancel(ctx)
	return &shapedConn{Conn: conn, bucket: bucket, ctx: ctx, cancel: cancel}
}

func (c *shapedConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	var n int
	var err error
	if len(c.pending) > 0 {
		n = copy(p[:c.bucket.readSize(len(p))], c.pending)
		err = c.pendingErr
	} else {
		n, err = c.Conn.Read(p[:c.bucket.readSize(len(p))])
	}
	if waitErr := c.bucket.waitRead(c.ctx, n, c.deadline); waitErr != nil {
		if len(c.pending) == 0 {
			c.pending = append([]byte(nil), p[:n]...)
			c.pendingErr = err
		}
		return 0, waitErr
	}
	if len(c.pending) > 0 {
		c.pending = c.pending[n:]
		if len(c.pending) > 0 {
			err = nil
		}
	}
	return n, err
}
func (c *shapedConn) deadline() time.Time {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	return c.readDeadline
}
func (c *shapedConn) SetReadDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	c.readDeadline = t
	c.deadlineMu.Unlock()
	return c.Conn.SetReadDeadline(t)
}
func (c *shapedConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.Conn.SetWriteDeadline(t)
}
func (c *shapedConn) Close() error { c.cancel(); return c.Conn.Close() }
func (c *shapedConn) CloseWrite() error {
	if conn, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return conn.CloseWrite()
	}
	return c.Close()
}

func (s *service) mappingBucket(m model.Mapping) *bandwidthBucket {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.bandwidth == nil {
		s.bandwidth = make(map[string]*bandwidthBucket)
	}
	b := s.bandwidth[m.ID]
	if b == nil {
		b = &bandwidthBucket{}
		if p := s.policy.Load(); p != nil {
			for _, current := range p.Mappings {
				if current.ID == m.ID {
					m = current
					break
				}
			}
		}
		b.update(m.BandwidthLimit)
		s.bandwidth[m.ID] = b
	}
	return b
}

// IDs are authenticated against the snapshot, including target and mux mode.
func (s *service) mappingFor(id, binding, host string, port int, network string, multiplex bool, kind string) (model.Mapping, bool) {
	p := s.policy.Load()
	if p == nil {
		p = &s.snapshot
	}
	for _, m := range p.Mappings {
		if m.ID != id || !m.Enabled || m.BindingID != binding || m.TargetHost != host || m.TargetPort != port || mappingNet(m.Network) != network {
			continue
		}
		if network == "tcp" {
			k, err := m.EffectiveMuxType()
			if err != nil || m.Mux != multiplex || k != kind {
				continue
			}
		}
		return m, true
	}
	return model.Mapping{}, false
}

func writeMappingID(w io.Writer, id string) error {
	if len(id) == 0 || len(id) > 128 {
		return errors.New("invalid mapping ID")
	}
	return writeAll(w, append([]byte{byte(len(id))}, id...))
}
func readMappingID(r io.Reader) (string, error) {
	var size [1]byte
	if _, err := io.ReadFull(r, size[:]); err != nil {
		return "", err
	}
	if size[0] == 0 || size[0] > 128 {
		return "", errors.New("invalid mapping ID")
	}
	id := make([]byte, int(size[0]))
	_, err := io.ReadFull(r, id)
	return string(id), err
}

// h2mux streams do not support socket deadlines; close only the incomplete
// stream, never its shared transport, if authorization headers stall.
func readMappingIDTimeout(c net.Conn, timeout time.Duration) (string, error) {
	timer := time.AfterFunc(timeout, func() { _ = c.Close() })
	id, err := readMappingID(c)
	if !timer.Stop() {
		return "", os.ErrDeadlineExceeded
	}
	return id, err
}
