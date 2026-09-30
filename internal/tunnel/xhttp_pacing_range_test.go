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

func TestXHTTPPacketUpIntervalRangeRoundtrip(t *testing.T) {
	h := newXHTTPHandler("/packet/", func(c net.Conn) {
		defer c.Close()
		b, err := io.ReadAll(c)
		if err == nil {
			_, _ = c.Write(b)
		}
	})
	h.uplinkMethod = http.MethodPut
	var mu sync.Mutex
	var posts []time.Time
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			mu.Lock()
			posts = append(posts, time.Now())
			mu.Unlock()
		}
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(func() { h.Close(); s.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	c, err := xhttpTestDial(t, ctx, s, false, model.XHTTP{Path: "/packet/", Mode: "packet-up", UplinkHTTPMethod: "PUT", MaxEachPostBytes: 1024, MinPostsIntervalMs: 120, MaxPostsIntervalMs: 160})
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
		t.Fatalf("expected 3 chunks and EOF, got %d", len(observed))
	}
	for i := 1; i < len(observed); i++ {
		elapsed := observed[i].Sub(observed[i-1])
		if elapsed < 100*time.Millisecond || elapsed > 400*time.Millisecond {
			t.Fatalf("interval %d = %v outside bounded range (with scheduling tolerance)", i, elapsed)
		}
	}
}
