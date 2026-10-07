package tunnel

import (
	"context"
	"io"
	"net"
	"net/http/httptest"
	"testing"
	"time"
)

func TestXHTTPIdleSurvivesWriteTimeout(t *testing.T) {
	for _, mode := range []string{"packet-up", "stream-up", "stream-one"} {
		t.Run(mode, func(t *testing.T) {
			h := newXHTTPHandler("/packet/", func(c net.Conn) { defer c.Close(); _, _ = io.Copy(c, c) })
			h.mode, h.timeout = mode, 150*time.Millisecond
			s := httptest.NewUnstartedServer(h)
			s.EnableHTTP2 = true
			s.StartTLS()
			defer s.Close()
			defer h.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			c, err := streamTestDial(t, ctx, s, mode)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			for range 2 {
				time.Sleep(350 * time.Millisecond)
				_ = c.SetDeadline(time.Now().Add(time.Second))
				if _, err := c.Write([]byte("idle")); err != nil {
					t.Fatal(err)
				}
				p := make([]byte, 4)
				if _, err := io.ReadFull(c, p); err != nil || string(p) != "idle" {
					t.Fatalf("after idle: %q %v", p, err)
				}
			}
		})
	}
}
