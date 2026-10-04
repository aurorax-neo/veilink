package tunnel

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"veilink/internal/model"
)

func TestXHTTPPacketUpPacingAndHalfClose(t *testing.T) {
	h := newXHTTPHandler("/packet/", func(c net.Conn) {
		defer c.Close()
		data, err := io.ReadAll(c)
		if err == nil {
			_, _ = c.Write(data)
		}
	})
	var mu sync.Mutex
	var posts []time.Time
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			mu.Lock()
			posts = append(posts, time.Now())
			mu.Unlock()
		}
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(func() { h.Close(); s.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	c, err := xhttpTestDial(t, ctx, s, false, model.XHTTP{Path: "/packet/", Mode: "packet-up", MaxEachPostBytes: 1024, MinPostsIntervalMs: 120})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	want := bytes.Repeat([]byte("p"), 3072)
	if _, err = c.Write(want); err != nil {
		t.Fatal(err)
	}
	if err = c.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(c)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("roundtrip %d bytes: %v", len(got), err)
	}
	mu.Lock()
	observed := append([]time.Time(nil), posts...)
	mu.Unlock()
	if len(observed) != 4 {
		t.Fatalf("three chunks plus EOF: %d", len(observed))
	}
	for i := 1; i < len(observed); i++ {
		if elapsed := observed[i].Sub(observed[i-1]); elapsed < 100*time.Millisecond {
			t.Fatalf("upload %d interval %v below configured 120ms", i, elapsed)
		}
	}
}

func TestXHTTPPacketUpPacingCancel(t *testing.T) {
	seen := make(chan struct{}, 2)
	h := newXHTTPHandler("/packet/", func(c net.Conn) { defer c.Close(); _, _ = io.Copy(io.Discard, c) })
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			seen <- struct{}{}
		}
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(func() { h.Close(); s.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c, err := xhttpTestDial(t, ctx, s, false, model.XHTTP{Path: "/packet/", Mode: "packet-up", MaxEachPostBytes: 1024, MinPostsIntervalMs: 900, MaxPostsIntervalMs: 1000})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err = c.Write([]byte("first")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-seen:
	case <-time.After(time.Second):
		t.Fatal("first upload not sent")
	}
	done := make(chan error, 1)
	go func() { _, err := c.Write([]byte("second")); done <- err }()
	time.Sleep(30 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled upload acknowledged")
		}
	case <-time.After(300 * time.Millisecond):
		t.Fatal("cancel did not interrupt pacing wait")
	}
	select {
	case <-seen:
		t.Fatal("cancelled upload still sent")
	default:
	}
}
