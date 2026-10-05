package tunnel

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"veilink/internal/model"
)

func TestXHTTPBufferedConcurrentRoundTrip(t *testing.T) {
	x := model.XHTTP{Path: "/buffer/", Mode: "packet-up", MaxEachPostBytes: 1024, MaxBufferedPosts: 4, MaxConcurrentPosts: 4}
	received := make(chan []byte, 1)
	h := newXHTTPHandler(x.Path, func(c net.Conn) {
		defer c.Close()
		b, e := io.ReadAll(c)
		if e == nil {
			received <- b
			_, _ = c.Write([]byte("done"))
		}
	})
	h.settings = x
	defer h.Close()
	var active, peak atomic.Int32
	first := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			n := active.Add(1)
			defer active.Add(-1)
			for {
				old := peak.Load()
				if n <= old || peak.CompareAndSwap(old, n) {
					break
				}
			}
			_, seq, e := xhttpGetMeta(r, x, x.Path, true)
			if e == nil && seq == "0" {
				select {
				case <-first:
				case <-time.After(time.Second):
				}
			}
			if e == nil && seq == "1" {
				close(first)
			}
		}
		h.ServeHTTP(w, r)
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, e := dialXHTTP(ctx, strings.TrimPrefix(server.URL, "http://"), "", model.LocalTLS{XHTTP: x})
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	payload := bytes.Repeat([]byte("abcdef"), 3000)
	if n, e := c.Write(payload); e != nil || n != len(payload) {
		t.Fatalf("write %d: %v", n, e)
	}
	if e := c.(interface{ CloseWrite() error }).CloseWrite(); e != nil {
		t.Fatal(e)
	}
	got, e := io.ReadAll(c)
	if e != nil || string(got) != "done" {
		t.Fatalf("reply %q: %v", got, e)
	}
	select {
	case got := <-received:
		if !bytes.Equal(got, payload) {
			t.Fatal("reassembly changed payload")
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if peak.Load() < 2 {
		t.Fatal("requests were not concurrent")
	}
}

func TestXHTTPBufferedWindowDuplicateAndCancel(t *testing.T) {
	x := model.XHTTP{Path: "/buffer/", Mode: "packet-up", MaxBufferedPosts: 2}
	h := newXHTTPHandler(x.Path, func(net.Conn) {})
	h.settings = x
	h.timeout = time.Second
	app, wire := xhttpPair()
	defer app.Close()
	defer wire.Close()
	id, _ := newXHTTPSessionID()
	s := &xhttpSession{app: app, wire: wire}
	h.sessions[id] = s
	server := httptest.NewServer(h)
	defer server.Close()
	defer h.Close()
	post := func(ctx context.Context, seq int) int {
		req, _ := http.NewRequestWithContext(ctx, "POST", server.URL+x.Path+id+"/"+strconv.Itoa(seq), strings.NewReader("data"))
		_ = xhttpSetPadding(req, x)
		resp, e := server.Client().Do(req)
		if e != nil {
			return 0
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() { done <- post(ctx, 1) }()
	deadline := time.Now().Add(time.Second)
	for {
		s.mu.Lock()
		pending := s.buffer != nil && len(s.buffer.pending) > 0
		s.mu.Unlock()
		if pending {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("upload not queued")
		}
		time.Sleep(time.Millisecond)
	}
	if status := post(context.Background(), 1); status != 409 {
		t.Fatalf("duplicate %d", status)
	}
	if status := post(context.Background(), 3); status != 409 {
		t.Fatalf("window %d", status)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancel blocked")
	}
}

func TestXHTTPBufferConfiguration(t *testing.T) {
	for _, x := range []model.XHTTP{
		{MaxBufferedPosts: -1}, {MaxBufferedPosts: 33}, {MaxConcurrentPosts: 9}, {MaxBufferedPosts: 1, MaxConcurrentPosts: 3},
	} {
		if checkXHTTPBuffer(x, "packet-up") == nil {
			t.Fatalf("accepted %+v", x)
		}
	}
	if checkXHTTPBuffer(model.XHTTP{MaxBufferedPosts: 2}, "stream-up") == nil {
		t.Fatal("stream accepted")
	}
	if e := checkXHTTPBuffer(model.XHTTP{MaxBufferedPosts: 32, MaxConcurrentPosts: 8}, "packet-up"); e != nil {
		t.Fatal(e)
	}
}

func TestXHTTPConcurrentSlidingWindow(t *testing.T) {
	x := model.XHTTP{Path: "/window/", Mode: "packet-up", MaxEachPostBytes: 1024, MaxBufferedPosts: 2, MaxConcurrentPosts: 2}
	h := newXHTTPHandler(x.Path, func(c net.Conn) { defer c.Close(); _, _ = io.Copy(io.Discard, c) })
	h.settings, h.maxPost = x, 1024
	secondConsumed := make(chan struct{})
	thirdStarted := make(chan struct{})
	releaseSecond := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, seq, _ := xhttpGetMeta(r, x, x.Path, true)
		if r.Method == http.MethodPost && seq == "2" {
			close(thirdStarted)
		}
		h.ServeHTTP(w, r)
		if r.Method == http.MethodPost && seq == "0" {
			<-secondConsumed // Hold response 0 until request 1 has been consumed.
		}
		if r.Method == http.MethodPost && seq == "1" {
			close(secondConsumed)
			<-releaseSecond // Sliding window sends request 2 before response 1.
		}
	}))
	t.Cleanup(func() { h.Close(); server.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := dialXHTTP(ctx, strings.TrimPrefix(server.URL, "http://"), "", model.LocalTLS{XHTTP: x})
	if err != nil {
		close(releaseSecond)
		t.Fatal(err)
	}
	defer c.Close()
	done := make(chan error, 1)
	go func() { _, err := c.Write(bytes.Repeat([]byte("x"), 3072)); done <- err }()
	select {
	case <-thirdStarted:
	case <-time.After(time.Second):
		close(releaseSecond)
		t.Fatal("next POST waited for the entire previous batch")
	}
	close(releaseSecond)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestXHTTPPacketUploadMutableDeadline(t *testing.T) {
	for _, buffered := range []bool{false, true} {
		t.Run(strconv.FormatBool(buffered), func(t *testing.T) {
			x := model.XHTTP{Path: "/deadline/", Mode: "packet-up"}
			if buffered {
				x.MaxBufferedPosts, x.MaxConcurrentPosts = 2, 2
			}
			started := make(chan struct{})
			h := newXHTTPHandler(x.Path, func(c net.Conn) { defer c.Close(); _, _ = io.Copy(io.Discard, c) })
			h.settings = x
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost {
					_, _ = io.Copy(io.Discard, r.Body)
					close(started)
					<-r.Context().Done()
					return
				}
				h.ServeHTTP(w, r)
			}))
			t.Cleanup(func() { h.Close(); server.Close() })
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			c, err := dialXHTTP(ctx, strings.TrimPrefix(server.URL, "http://"), "", model.LocalTLS{XHTTP: x})
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			done := make(chan error, 1)
			go func() { _, err := c.Write([]byte("blocked")); done <- err }()
			<-started
			_ = c.SetWriteDeadline(time.Now().Add(time.Hour))
			_ = c.SetWriteDeadline(time.Now().Add(20 * time.Millisecond))
			select {
			case err := <-done:
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("write deadline: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("deadline change did not interrupt pending POST")
			}
		})
	}
}

func TestXHTTPPacketUploadRejectsUnacknowledgedWrite(t *testing.T) {
	for _, concurrent := range []int{1, 2} {
		t.Run(strconv.Itoa(concurrent), func(t *testing.T) {
			x := model.XHTTP{Path: "/failure/", Mode: "packet-up", MaxEachPostBytes: 1024, MaxBufferedPosts: concurrent, MaxConcurrentPosts: concurrent}
			h := newXHTTPHandler(x.Path, func(c net.Conn) { defer c.Close(); _, _ = io.Copy(io.Discard, c) })
			h.settings, h.maxPost = x, 1024
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, seq, _ := xhttpGetMeta(r, x, x.Path, true)
				if r.Method == http.MethodPost && seq == "1" {
					http.Error(w, "rejected", http.StatusConflict)
					return
				}
				h.ServeHTTP(w, r)
			}))
			t.Cleanup(func() { h.Close(); server.Close() })
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			c, err := dialXHTTP(ctx, strings.TrimPrefix(server.URL, "http://"), "", model.LocalTLS{XHTTP: x})
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			n, err := c.Write(bytes.Repeat([]byte("x"), 3072))
			if err == nil || n > 1024 {
				t.Fatalf("unacknowledged prefix reported as success: n=%d err=%v", n, err)
			}
		})
	}
}

func TestXHTTPPacketUploadClearedDeadline(t *testing.T) {
	x := model.XHTTP{Path: "/clear-deadline/", Mode: "packet-up"}
	started, release := make(chan struct{}), make(chan struct{})
	h := newXHTTPHandler(x.Path, func(c net.Conn) { defer c.Close(); _, _ = io.Copy(io.Discard, c) })
	h.settings = x
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r)
		if r.Method == http.MethodPost {
			close(started)
			select {
			case <-release:
			case <-r.Context().Done():
			}
		}
	}))
	t.Cleanup(func() { h.Close(); server.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := dialXHTTP(ctx, strings.TrimPrefix(server.URL, "http://"), "", model.LocalTLS{XHTTP: x})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	done := make(chan error, 1)
	go func() { _, err := c.Write([]byte("blocked")); done <- err }()
	<-started
	_ = c.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
	_ = c.SetWriteDeadline(time.Time{})
	select {
	case err := <-done:
		t.Fatalf("cleared deadline interrupted pending POST: %v", err)
	case <-time.After(150 * time.Millisecond):
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestXHTTPPacketUploadPacingDeadline(t *testing.T) {
	x := model.XHTTP{Path: "/pace-deadline/", Mode: "packet-up", MinPostsIntervalMs: 1000, MaxEachPostBytes: 1024}
	h := newXHTTPHandler(x.Path, func(c net.Conn) { defer c.Close(); _, _ = io.Copy(io.Discard, c) })
	h.settings, h.maxPost = x, 1024
	server := httptest.NewServer(h)
	t.Cleanup(func() { h.Close(); server.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := dialXHTTP(ctx, strings.TrimPrefix(server.URL, "http://"), "", model.LocalTLS{XHTTP: x})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("first")); err != nil {
		t.Fatal(err)
	}
	_ = c.SetWriteDeadline(time.Now().Add(20 * time.Millisecond))
	start := time.Now()
	n, err := c.Write([]byte("paced"))
	if n != 0 || !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 500*time.Millisecond {
		t.Fatalf("pacing ignored deadline: n=%d err=%v elapsed=%v", n, err, time.Since(start))
	}
}

func TestXHTTPDelayedResponsePerformance(t *testing.T) {
	if os.Getenv("VEILINK_PERF") != "1" {
		t.Skip("set VEILINK_PERF=1 for serial performance measurement")
	}
	for round := 1; round <= 3; round++ {
		x := model.XHTTP{Path: "/delayed-response/", Mode: "packet-up", MaxEachPostBytes: 16 * 1024, MaxBufferedPosts: 2, MaxConcurrentPosts: 2}
		h := newXHTTPHandler(x.Path, func(c net.Conn) { defer c.Close(); _, _ = io.Copy(io.Discard, c) })
		h.settings, h.maxPost = x, x.MaxEachPostBytes
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h.ServeHTTP(w, r)
			if r.Method == http.MethodPost {
				_, text, _ := xhttpGetMeta(r, x, x.Path, true)
				seq, _ := strconv.Atoi(text)
				delay := 5 * time.Millisecond
				if seq%4 == 1 || seq%4 == 2 {
					delay = 30 * time.Millisecond
				}
				select {
				case <-time.After(delay):
				case <-r.Context().Done():
				}
			}
		}))
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		c, err := dialXHTTP(ctx, strings.TrimPrefix(server.URL, "http://"), "", model.LocalTLS{XHTTP: x})
		if err != nil {
			cancel()
			h.Close()
			server.Close()
			t.Fatal(err)
		}
		payload := bytes.Repeat([]byte("x"), 1024*1024)
		start := time.Now()
		n, err := c.Write(payload)
		elapsed := time.Since(start)
		_ = c.Close()
		cancel()
		h.Close()
		server.Close()
		if n != len(payload) || err != nil {
			t.Fatalf("delayed upload: n=%d err=%v", n, err)
		}
		t.Logf("XHTTP_DELAY round=%d bytes=%d seconds=%.6f MiBps=%.3f", round, n, elapsed.Seconds(), float64(n)/(1024*1024)/elapsed.Seconds())
	}
}
