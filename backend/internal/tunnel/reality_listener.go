package tunnel

import (
	"context"
	"net"
	"sync"
	"time"
)

// Keep the connection channel open: in-flight handshakes may outlive Accept.
// Shutdown cancels their raw sockets instead of racing a send with channel close.
type realityListener struct {
	net.Listener
	ctx        context.Context
	cancel     context.CancelFunc
	ready      chan net.Conn
	done       chan struct{}
	err        error
	once       sync.Once
	handshakes sync.WaitGroup
	handshake  func(context.Context, net.Conn) (net.Conn, error)
}

func newRealityListener(parent context.Context, inner net.Listener, handshake func(context.Context, net.Conn) (net.Conn, error)) *realityListener {
	ctx, cancel := context.WithCancel(parent)
	l := &realityListener{Listener: inner, ctx: ctx, cancel: cancel, ready: make(chan net.Conn), done: make(chan struct{}), handshake: handshake}
	l.handshakes.Add(1)
	go l.serve()
	return l
}

func (l *realityListener) serve() {
	defer l.handshakes.Done()
	stop := context.AfterFunc(l.ctx, func() { _ = l.Listener.Close() })
	defer stop()
	defer close(l.done)
	defer l.cancel()
	slots := make(chan struct{}, 2*xhttpSessions)
	for {
		select {
		case slots <- struct{}{}:
		case <-l.ctx.Done():
			l.err = net.ErrClosed
			return
		}
		raw, err := l.Listener.Accept()
		if err != nil {
			<-slots
			l.err = err
			return
		}
		l.handshakes.Add(1)
		go func() {
			defer l.handshakes.Done()
			defer func() { <-slots }()
			stop := context.AfterFunc(l.ctx, func() { _ = raw.Close() })
			defer stop()
			_ = raw.SetDeadline(time.Now().Add(15 * time.Second))
			conn, err := l.handshake(l.ctx, raw)
			if err != nil {
				_ = raw.Close()
				return
			}
			_ = conn.SetDeadline(time.Time{})
			select {
			case l.ready <- conn:
			case <-l.ctx.Done():
				_ = conn.Close()
			}
		}()
	}
}

func (l *realityListener) drainReady() {
	for {
		select {
		case conn := <-l.ready:
			if conn != nil {
				_ = conn.Close()
			}
		default:
			return
		}
	}
}

func (l *realityListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.ready:
		if l.ctx.Err() != nil {
			_ = conn.Close()
			l.drainReady()
			return nil, net.ErrClosed
		}
		return conn, nil
	case <-l.ctx.Done():
		l.drainReady()
		return nil, net.ErrClosed
	case <-l.done:
		l.drainReady()
		return nil, l.err
	}
}

func (l *realityListener) Close() error {
	var err error
	l.once.Do(func() {
		l.cancel()
		err = l.Listener.Close()
		l.drainReady()
	})
	l.handshakes.Wait()
	return err
}
