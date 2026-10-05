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
	closedWrite bool
}

func (c *xhttpBufferedClient) SetWriteDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	c.deadline = t
	c.deadlineMu.Unlock()
	return nil
}
func (c *xhttpBufferedClient) writeDeadline() time.Time {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	return c.deadline
}
func (c *xhttpBufferedClient) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}
func (c *xhttpBufferedClient) post(body []byte, seq uint64, eof bool, deadline time.Time) error {
	ctx, cancel := context.WithTimeout(c.ctx, xhttpRequestTimeout(c.settings))
	defer cancel()
	if !deadline.IsZero() {
		var stop context.CancelFunc
		ctx, stop = context.WithDeadline(ctx, deadline)
		defer stop()
	}
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
func (c *xhttpBufferedClient) pace() error {
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
			case <-c.ctx.Done():
				return c.ctx.Err()
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
	concurrency := c.settings.MaxConcurrentPosts
	if concurrency == 0 {
		concurrency = 1
	}
	total := 0
	for len(p) > 0 {
		var wg sync.WaitGroup
		results := make([]error, concurrency)
		sizes := make([]int, 0, concurrency)
		deadline := c.writeDeadline()
		for i := 0; i < concurrency && len(p) > 0; i++ {
			n := c.postSize
			if max := c.postMax; max > n {
				n += mrand.IntN(max - n + 1)
			}
			if n > len(p) {
				n = len(p)
			}
			if err := c.pace(); err != nil {
				_ = c.Close()
				wg.Wait()
				return total, err
			}
			body := p[:n]
			p = p[n:]
			seq := c.seq
			c.seq++
			sizes = append(sizes, n)
			index := len(sizes) - 1
			wg.Add(1)
			go func() {
				defer wg.Done()
				results[index] = c.post(body, seq, false, deadline)
				if results[index] != nil {
					_ = c.Close()
				}
			}()
		}
		wg.Wait()
		for i, err := range results[:len(sizes)] {
			if err != nil {
				_ = c.Close()
				return total, err
			}
			total += sizes[i]
		}
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
	if err := c.pace(); err != nil {
		_ = c.Close()
		return err
	}
	err := c.post(nil, c.seq, true, c.writeDeadline())
	if err != nil {
		_ = c.Close()
	}
	return err
}
