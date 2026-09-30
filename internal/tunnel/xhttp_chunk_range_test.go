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

func TestXHTTPPacketUpChunkRangeRoundtrip(t *testing.T) {
	h := newXHTTPHandler("/packet/", func(c net.Conn) {
		defer c.Close()
		b, err := io.ReadAll(c)
		if err == nil {
			_, _ = c.Write(b)
		}
	})
	h.maxPost = 2048
	var mu sync.Mutex
	var lengths []int64
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			mu.Lock()
			lengths = append(lengths, r.ContentLength)
			mu.Unlock()
		}
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(func() { h.Close(); s.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	c, err := xhttpTestDial(t, ctx, s, false, model.XHTTP{Path: "/packet/", Mode: "packet-up", MaxEachPostBytes: 1024, PostBytesMax: 2048})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	data := bytes.Repeat([]byte("x"), 16384)
	if _, err = c.Write(data); err != nil {
		t.Fatal(err)
	}
	if err = c.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(c)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("roundtrip %d bytes: %v", len(got), err)
	}
	mu.Lock()
	observed := append([]int64(nil), lengths...)
	mu.Unlock()
	if len(observed) < 9 || observed[len(observed)-1] != 0 {
		t.Fatalf("POST lengths: %v", observed)
	}
	var total int64
	var varied bool
	for i, n := range observed[:len(observed)-1] {
		if n < 1 || n > 2048 || (i < len(observed)-2 && n < 1024) {
			t.Fatalf("POST %d size %d", i, n)
		}
		if i < len(observed)-2 && n > 1024 {
			varied = true
		}
		total += n
	}
	if !varied {
		t.Fatalf("configured chunk range had no effect: %v", observed)
	}
	if total != int64(len(data)) {
		t.Fatalf("POST total = %d", total)
	}
}
