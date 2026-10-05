package tunnel

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

func TestRealityListenerConcurrentClose(t *testing.T) {
	for iteration := 0; iteration < 40; iteration++ {
		inner, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		started := make(chan struct{})
		release := make(chan struct{})
		finished := make(chan struct{})
		l := newRealityListener(context.Background(), inner, func(_ context.Context, raw net.Conn) (net.Conn, error) {
			close(started)
			<-release
			defer close(finished)
			return raw, nil
		})
		peer, err := net.Dial("tcp", inner.Addr().String())
		if err != nil {
			_ = l.Close()
			t.Fatal(err)
		}
		select {
		case <-started:
		case <-time.After(3 * time.Second):
			t.Fatal("handshake did not start")
		}
		var wg sync.WaitGroup
		for i := 0; i < 4; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = l.Close()
			}()
		}
		close(release)
		wg.Wait()
		if conn, err := l.Accept(); conn != nil || !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Accept after close: %v, %v", conn, err)
		}
		select {
		case <-finished:
		case <-time.After(3 * time.Second):
			t.Fatal("handshake did not finish")
		}
		_ = peer.SetReadDeadline(time.Now().Add(3 * time.Second))
		if _, err := peer.Read(make([]byte, 1)); err == nil {
			t.Fatal("raw connection remained open")
		} else if e, ok := err.(net.Error); ok && e.Timeout() {
			t.Fatal("shutdown did not close raw connection")
		}
		_ = peer.Close()
	}
}

func TestRealityListenerCancelsPendingHandshake(t *testing.T) {
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started, finished := make(chan struct{}), make(chan struct{})
	l := newRealityListener(ctx, inner, func(_ context.Context, raw net.Conn) (net.Conn, error) {
		close(started)
		defer close(finished)
		_, err := raw.Read(make([]byte, 1))
		return nil, err
	})
	defer l.Close()
	peer, err := net.Dial("tcp", inner.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("handshake did not start")
	}
	cancel()
	select {
	case <-finished:
	case <-time.After(3 * time.Second):
		t.Fatal("pending handshake was not canceled")
	}
	if conn, err := l.Accept(); conn != nil || !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept after cancel: %v, %v", conn, err)
	}
}
