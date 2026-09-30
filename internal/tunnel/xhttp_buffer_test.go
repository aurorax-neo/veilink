package tunnel

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
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
