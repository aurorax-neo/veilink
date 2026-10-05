package tunnel

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	mrand "math/rand/v2"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"veilink/internal/model"
)

func checkXHTTPBuffer(x model.XHTTP, mode string) error {
	if x.MaxBufferedPosts < 0 || x.MaxBufferedPosts > 32 || x.MaxConcurrentPosts < 0 || x.MaxConcurrentPosts > 8 {
		return errors.New("xhttp buffered/concurrent posts out of range")
	}
	if (x.MaxBufferedPosts != 0 || x.MaxConcurrentPosts != 0) && mode != "packet-up" {
		return errors.New("xhttp buffered/concurrent posts require packet-up")
	}
	if x.MaxConcurrentPosts > x.MaxBufferedPosts+1 {
		return errors.New("xhttp concurrent posts exceed buffer window")
	}
	return nil
}

type xhttpBufferedState struct {
	pending  map[uint64]struct{}
	changed  chan struct{}
	terminal *uint64
}

// Each pending HTTP handler owns one bounded body. No acknowledgement is sent
// before the application consumes it, and the sequence window bounds memory.
func (h *xhttpHandler) bufferedUpload(w http.ResponseWriter, r *http.Request, s *xhttpSession, seq uint64) {
	s.mu.Lock()
	if s.buffer == nil {
		s.buffer = &xhttpBufferedState{pending: make(map[uint64]struct{}), changed: make(chan struct{})}
	}
	b := s.buffer
	_, duplicate := b.pending[seq]
	if s.eof || seq < s.next || seq-s.next > uint64(h.settings.MaxBufferedPosts) || duplicate || len(b.pending) >= h.settings.MaxBufferedPosts+1 || (b.terminal != nil && seq > *b.terminal) {
		s.mu.Unlock()
		http.Error(w, "unexpected sequence", http.StatusConflict)
		return
	}
	b.pending[seq] = struct{}{}
	s.mu.Unlock()
	defer func() { s.mu.Lock(); delete(b.pending, seq); s.mu.Unlock() }()
	rc := http.NewResponseController(w)
	if rc.SetReadDeadline(time.Now().Add(h.timeout)) != nil {
		http.Error(w, "deadline unavailable", 500)
		return
	}
	defer rc.SetReadDeadline(time.Time{})
	body, err := xhttpReadData(r, h.settings, h.maxPost)
	if err != nil {
		http.Error(w, "invalid body", 400)
		return
	}
	if len(body) > h.maxPost {
		http.Error(w, "body too large", 413)
		return
	}
	eofValues := r.Header.Values("X-Veilink-EOF")
	eof := r.Header.Get("X-Veilink-EOF")
	if len(eofValues) > 1 || (eof != "" && eof != "1") || (eof == "1" && len(body) != 0) || (eof == "" && len(body) == 0) {
		http.Error(w, "invalid EOF", 400)
		return
	}
	timer := time.NewTimer(h.timeout)
	defer timer.Stop()
	s.mu.Lock()
	if eof == "1" {
		if b.terminal != nil {
			s.mu.Unlock()
			http.Error(w, "duplicate EOF", 409)
			return
		}
		for n := range b.pending {
			if n > seq {
				s.mu.Unlock()
				http.Error(w, "EOF precedes upload", 409)
				return
			}
		}
		terminal := seq
		b.terminal = &terminal
	}
	for seq != s.next && !s.eof {
		changed := b.changed
		s.mu.Unlock()
		select {
		case <-changed:
		case <-r.Context().Done():
			_ = s.wire.Close()
			return
		case <-timer.C:
			_ = s.wire.Close()
			http.Error(w, "sequence timeout", 408)
			return
		}
		s.mu.Lock()
	}
	if s.eof {
		s.mu.Unlock()
		http.Error(w, "upload closed", 410)
		return
	}
	_ = s.wire.SetWriteDeadline(time.Now().Add(h.timeout))
	if eof == "1" {
		err = s.wire.CloseWrite()
	} else {
		_, err = s.wire.Write(body)
	}
	if err != nil {
		s.eof = true
		_ = s.wire.Close()
	} else {
		s.next++
		s.eof = eof == "1"
	}
	close(b.changed)
	b.changed = make(chan struct{})
	s.mu.Unlock()
	if err != nil {
		http.Error(w, "upload closed", 410)
		return
	}
	w.WriteHeader(http.StatusOK)
}

type xhttpBufferedClient struct {
	*xhttpClientConn
	client      *http.Client
	ctx         context.Context
	base, id    string
	settings    model.XHTTP
	headers     http.Header
	seq         uint64
	lastPost    time.Time
	deadline    time.Time
	deadlineMu  sync.Mutex
	writeCtx    context.Context
	writeCancel context.CancelFunc
	writeTimer  *time.Timer
	closedWrite bool
}

func (c *xhttpBufferedClient) SetWriteDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	c.deadline = t
	c.armWriteDeadline()
	return nil
}

// Deadlines remain mutable while an HTTP request or pacing wait is blocked.
func (c *xhttpBufferedClient) armWriteDeadline() {
	if c.writeTimer != nil {
		c.writeTimer.Stop()
		c.writeTimer = nil
	}
	if c.writeCancel == nil || c.deadline.IsZero() {
		return
	}
	if !time.Now().Before(c.deadline) {
		c.writeCancel()
		return
	}
	ctx := c.writeCtx
	c.writeTimer = time.AfterFunc(time.Until(c.deadline), func() {
		c.deadlineMu.Lock()
		defer c.deadlineMu.Unlock()
		if c.writeCtx == ctx && !c.deadline.IsZero() && !time.Now().Before(c.deadline) {
			c.writeCancel()
		}
	})
}
func (c *xhttpBufferedClient) beginWrite() (context.Context, func()) {
	c.deadlineMu.Lock()
	ctx, cancel := context.WithCancel(c.ctx)
	c.writeCtx, c.writeCancel = ctx, cancel
	c.armWriteDeadline()
	c.deadlineMu.Unlock()
	return ctx, func() {
		c.deadlineMu.Lock()
		if c.writeTimer != nil {
			c.writeTimer.Stop()
			c.writeTimer = nil
		}
		c.writeCtx, c.writeCancel = nil, nil
		c.deadlineMu.Unlock()
		cancel()
	}
}
func (c *xhttpBufferedClient) writeError(err error) error {
	c.deadlineMu.Lock()
	expired := !c.deadline.IsZero() && !time.Now().Before(c.deadline)
	c.deadlineMu.Unlock()
	if expired {
		return context.DeadlineExceeded
	}
	return err
}
func (c *xhttpBufferedClient) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}
func (c *xhttpBufferedClient) post(parent context.Context, body []byte, seq uint64, eof bool) error {
	ctx, cancel := context.WithTimeout(parent, xhttpRequestTimeout(c.settings))
	defer cancel()
	text := strconv.FormatUint(seq, 10)
	req, err := http.NewRequestWithContext(ctx, xhttpUplinkMethod(c.settings), xhttpMetaPath(c.base, c.settings, c.id, text), bytes.NewReader(body))
	if err != nil {
		return err
	}
	if c.settings.Host != "" {
		req.Host = c.settings.Host
	}
	xhttpApplyHeaders(req, c.headers)
	xhttpSetMeta(req, c.settings, c.id, text)
	if err = xhttpSetPadding(req, c.settings); err != nil {
		return err
	}
	if err = xhttpEncodeData(req, body, c.settings); err != nil {
		return err
	}
	if eof {
		req.Header.Set("X-Veilink-EOF", "1")
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !xhttpCheckResponsePadding(resp, c.settings) {
		return fmt.Errorf("xhttp upload status %d", resp.StatusCode)
	}
	return nil
}
func (c *xhttpBufferedClient) pace(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	interval := c.settings.MinPostsIntervalMs
	if c.settings.MaxPostsIntervalMs > interval {
		interval += mrand.IntN(c.settings.MaxPostsIntervalMs - interval + 1)
	}
	if !c.lastPost.IsZero() && interval > 0 {
		delay := time.Until(c.lastPost.Add(time.Duration(interval) * time.Millisecond))
		if delay > 0 {
			timer := time.NewTimer(delay)
			defer timer.Stop()
			select {
			case <-timer.C:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	c.lastPost = time.Now()
	return nil
}
func (c *xhttpBufferedClient) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.closedWrite {
		return 0, net.ErrClosed
	}
	if len(p) == 0 {
		return 0, nil
	}
	ctx, finish := c.beginWrite()
	defer finish()
	concurrency := c.settings.MaxConcurrentPosts
	if concurrency == 0 {
		concurrency = 1
	}
	nextSize := func() int {
		n := c.postSize
		if max := c.postMax; max > n {
			n += mrand.IntN(max - n + 1)
		}
		return min(n, len(p))
	}
	total := 0
	// Serial uploads need no helper goroutine or local pipe acknowledgement.
	if concurrency == 1 {
		for len(p) > 0 {
			n := nextSize()
			err := c.pace(ctx)
			if err == nil {
				err = c.post(ctx, p[:n], c.seq, false)
			}
			if err != nil {
				_ = c.Close()
				return total, c.writeError(err)
			}
			c.seq++
			total += n
			p = p[n:]
		}
		return total, nil
	}
	type pendingPost struct {
		size int
		done chan error
	}
	window := make([]pendingPost, concurrency)
	head, count := 0, 0
	var wg sync.WaitGroup
	// Workers must stop before returning: callers may immediately reuse p.
	defer wg.Wait()
	for len(p) > 0 || count > 0 {
		for len(p) > 0 && count < concurrency {
			if err := c.pace(ctx); err != nil {
				_ = c.Close()
				return total, c.writeError(err)
			}
			n := nextSize()
			body, seq := p[:n], c.seq
			p = p[n:]
			c.seq++
			done := make(chan error, 1)
			window[(head+count)%concurrency] = pendingPost{n, done}
			count++
			wg.Add(1)
			go func() {
				defer wg.Done()
				err := c.post(ctx, body, seq, false)
				if err != nil {
					_ = c.Close()
				}
				done <- err
			}()
		}
		// Reap in sequence order so the outstanding sequence window stays bounded
		// and Write only reports a contiguous, remotely acknowledged prefix.
		post := window[head]
		if err := <-post.done; err != nil {
			_ = c.Close()
			return total, c.writeError(err)
		}
		total += post.size
		head = (head + 1) % concurrency
		count--
	}
	return total, nil
}
func (c *xhttpBufferedClient) CloseWrite() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.closedWrite {
		return nil
	}
	c.closedWrite = true
	ctx, finish := c.beginWrite()
	defer finish()
	if err := c.pace(ctx); err != nil {
		_ = c.Close()
		return c.writeError(err)
	}
	err := c.post(ctx, nil, c.seq, true)
	if err != nil {
		_ = c.Close()
		return c.writeError(err)
	}
	return err
}
