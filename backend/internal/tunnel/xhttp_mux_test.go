package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"veilink/internal/model"
)

type muxTestTransport struct{ closed atomic.Int32 }

func (m *muxTestTransport) RoundTrip(*http.Request) (*http.Response, error) { return nil, nil }
func (m *muxTestTransport) CloseIdleConnections()                           {}
func (m *muxTestTransport) Close() error                                    { m.closed.Add(1); return nil }

func TestXHTTPMuxLifecycleAndLimits(t *testing.T) {
	p := &xhttpMuxPool{entries: make(map[[32]byte][]*xhttpMuxEntry)}
	var made atomic.Int32
	x := model.XHTTP{Xmux: model.XHTTPXmux{MaxConcurrency: 1, MaxConnections: 2, CMaxReuseTimes: 2, HMaxRequestTimes: 2, HMaxReusableSecs: 1}}
	key := [32]byte{1}
	create := func() (xhttpCloser, error) { made.Add(1); return &muxTestTransport{}, nil }
	a, err := p.acquire(context.Background(), key, x, create)
	if err != nil {
		t.Fatal(err)
	}
	b, err := p.acquire(context.Background(), key, x, create)
	if err != nil || made.Load() != 2 {
		t.Fatalf("second connection: %v made=%d", err, made.Load())
	}
	lease, err := p.acquire(context.Background(), key, x, create)
	if err != nil || made.Load() != 3 {
		t.Fatalf("concurrency did not expand the pool: %v made=%d", err, made.Load())
	}
	_ = a.Close()
	_ = b.Close()
	_ = lease.Close()
	time.Sleep(1100 * time.Millisecond)
	d, err := p.acquire(context.Background(), key, x, create)
	if err != nil {
		t.Fatal(err)
	}
	_ = d.Close()
	if made.Load() < 4 {
		t.Fatal("expired transport reused")
	}
}
func TestXHTTPMuxRejectsUnsafeRanges(t *testing.T) {
	cases := []model.XHTTP{{Xmux: model.XHTTPXmux{MaxConcurrency: -1}}, {Xmux: model.XHTTPXmux{MaxConnections: 129}}, {Xmux: model.XHTTPXmux{HMaxReusableSecs: 86401}}, {Xmux: model.XHTTPXmux{KeepAlivePeriod: 3601}}}
	for _, x := range cases {
		if checkXHTTPMux(x) == nil {
			t.Fatalf("accepted %+v", x)
		}
	}
}

func TestXHTTPMuxReleasesIdleKeysWithoutClosingActiveLeases(t *testing.T) {
	p := &xhttpMuxPool{entries: make(map[[32]byte][]*xhttpMuxEntry)}
	x := model.XHTTP{Xmux: model.XHTTPXmux{MaxConcurrency: 4}}
	for i := 0; i < 256; i++ {
		key := [32]byte{byte(i)}
		transport := &muxTestTransport{}
		create := func() (xhttpCloser, error) { return transport, nil }
		a, err := p.acquire(context.Background(), key, x, create)
		if err != nil {
			t.Fatal(err)
		}
		b, err := p.acquire(context.Background(), key, x, create)
		if err != nil || a.entry != b.entry {
			t.Fatalf("active leases did not share transport: %v", err)
		}
		_ = a.Close()
		_ = a.Close()
		if transport.closed.Load() != 0 || b.entry.running != 1 {
			t.Fatal("closing one lease interrupted another lease")
		}
		_ = b.Close()
		_ = b.Close()
		if transport.closed.Load() != 1 || len(p.entries) != 0 {
			t.Fatalf("idle transport leaked: closes=%d keys=%d", transport.closed.Load(), len(p.entries))
		}
	}
}

func TestXHTTPMuxConcurrentAcquireRelease(t *testing.T) {
	p := &xhttpMuxPool{entries: make(map[[32]byte][]*xhttpMuxEntry)}
	x := model.XHTTP{Xmux: model.XHTTPXmux{MaxConcurrency: 4}}
	var made, closed atomic.Int32
	create := func() (xhttpCloser, error) {
		made.Add(1)
		return &countedMuxTransport{closed: &closed}, nil
	}
	var wg sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				lease, err := p.acquire(context.Background(), [32]byte{byte(i % 3)}, x, create)
				if err != nil {
					t.Error(err)
					return
				}
				_ = lease.Close()
			}
		}()
	}
	wg.Wait()
	if len(p.entries) != 0 || made.Load() != closed.Load() {
		t.Fatalf("pool leaked: keys=%d made=%d closed=%d", len(p.entries), made.Load(), closed.Load())
	}
}

func TestXHTTPMuxRetiredLeaseDoesNotEvictReplacement(t *testing.T) {
	p := &xhttpMuxPool{entries: make(map[[32]byte][]*xhttpMuxEntry)}
	x := model.XHTTP{Xmux: model.XHTTPXmux{CMaxReuseTimes: 1}}
	key := [32]byte{42}
	oldTransport, newTransport := &muxTestTransport{}, &muxTestTransport{}
	old, err := p.acquire(context.Background(), key, x, func() (xhttpCloser, error) { return oldTransport, nil })
	if err != nil {
		t.Fatal(err)
	}
	replacement, err := p.acquire(context.Background(), key, x, func() (xhttpCloser, error) { return newTransport, nil })
	if err != nil {
		t.Fatal(err)
	}
	_ = old.Close()
	if oldTransport.closed.Load() != 1 || newTransport.closed.Load() != 0 || len(p.entries[key]) != 1 || p.entries[key][0] != replacement.entry {
		t.Fatal("retired lease evicted or closed the active replacement")
	}
	_ = replacement.Close()
	if newTransport.closed.Load() != 1 || len(p.entries) != 0 {
		t.Fatal("replacement leaked")
	}
}

func TestXHTTPMuxFailedCreateDoesNotRetainKeys(t *testing.T) {
	p := &xhttpMuxPool{entries: make(map[[32]byte][]*xhttpMuxEntry)}
	for i := 0; i < 256; i++ {
		_, err := p.acquire(context.Background(), [32]byte{byte(i)}, model.XHTTP{}, func() (xhttpCloser, error) {
			return nil, errors.New("transport unavailable")
		})
		if err == nil || len(p.entries) != 0 {
			t.Fatal("failed transport creation retained a key")
		}
	}
}

func TestXHTTPMuxCanceledAcquireDoesNotCreateTransport(t *testing.T) {
	p := &xhttpMuxPool{entries: make(map[[32]byte][]*xhttpMuxEntry)}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := p.acquire(ctx, [32]byte{1}, model.XHTTP{}, func() (xhttpCloser, error) {
		t.Fatal("canceled acquire created a transport")
		return nil, nil
	})
	if !errors.Is(err, context.Canceled) || len(p.entries) != 0 {
		t.Fatalf("canceled acquire retained resources: error=%v keys=%d", err, len(p.entries))
	}
}

func TestXHTTPMuxSlowCloseDoesNotBlockOtherKeys(t *testing.T) {
	p := &xhttpMuxPool{entries: make(map[[32]byte][]*xhttpMuxEntry)}
	closing := &blockingMuxTransport{started: make(chan struct{}), release: make(chan struct{})}
	lease, err := p.acquire(context.Background(), [32]byte{1}, model.XHTTP{}, func() (xhttpCloser, error) { return closing, nil })
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _ = lease.Close(); close(done) }()
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(closing.release) }); <-done }
	defer release()
	select {
	case <-closing.started:
	case <-time.After(time.Second):
		t.Fatal("transport close did not start")
	}
	acquired := make(chan error, 1)
	go func() {
		other, err := p.acquire(context.Background(), [32]byte{2}, model.XHTTP{}, func() (xhttpCloser, error) { return &muxTestTransport{}, nil })
		if other != nil {
			_ = other.Close()
		}
		acquired <- err
	}()
	select {
	case err := <-acquired:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		release()
		<-acquired
		t.Fatal("slow transport close blocked an unrelated key")
	}
}

type blockingMuxTransport struct{ started, release chan struct{} }

func (m *blockingMuxTransport) RoundTrip(*http.Request) (*http.Response, error) { return nil, nil }
func (m *blockingMuxTransport) CloseIdleConnections()                           {}
func (m *blockingMuxTransport) Close() error {
	close(m.started)
	<-m.release
	return nil
}

func TestXHTTPXmuxRuntimeCleanup(t *testing.T) {
	for _, version := range []string{"1.1", "2", "3"} {
		for round := 0; round < 3; round++ {
			t.Run(fmt.Sprintf("h%s/round%d", version, round), func(t *testing.T) {
				s, c := fixtures(t, echoServer(t))
				local := tlsFiles(t)
				local.ListenHost, local.ListenPort = "127.0.0.1", s.Node.Port
				if version == "3" {
					local.ListenPort = freeUDPPort(t)
					s.Node.Port = local.ListenPort
				}
				local.XHTTP = model.XHTTP{Path: "/xmux/", Mode: "packet-up", TLS: true, HTTPVersion: version, Xmux: model.XHTTPXmux{MaxConcurrency: 4, MaxConnections: 2, KeepAlivePeriod: 1}}
				s.Node.Tunnel = local
				public, err := PublicPeerTunnel(local, s.Node)
				if err != nil {
					t.Fatal(err)
				}
				c.Nodes[0] = s.Node
				c.Nodes[0].Tunnel = public
				sr := run(t, s, model.LocalTLS{})
				cr := run(t, c, model.LocalTLS{})
				awaitEcho(t, s.Mappings[0].ListenPort)
				if err := exchange(s.Mappings[0].ListenPort, []byte("xmux-runtime-cleanup"), true); err != nil {
					t.Fatal(err)
				}
				key := xhttpMuxKey(fmt.Sprintf("127.0.0.1:%d", local.ListenPort), "127.0.0.1", public)
				globalXHTTPMuxPool.mu.Lock()
				active := len(globalXHTTPMuxPool.entries[key])
				globalXHTTPMuxPool.mu.Unlock()
				if active == 0 {
					t.Fatal("runtime did not use xmux")
				}
				_ = cr.Close()
				_ = sr.Close()
				until := time.Now().Add(5 * time.Second)
				for {
					globalXHTTPMuxPool.mu.Lock()
					remaining := len(globalXHTTPMuxPool.entries[key])
					globalXHTTPMuxPool.mu.Unlock()
					if remaining == 0 {
						break
					}
					if time.Now().After(until) {
						t.Fatalf("stopped runtime retained %d transports", remaining)
					}
					time.Sleep(10 * time.Millisecond)
				}
			})
		}
	}
}

type countedMuxTransport struct{ closed *atomic.Int32 }

func (m *countedMuxTransport) RoundTrip(*http.Request) (*http.Response, error) { return nil, nil }
func (m *countedMuxTransport) CloseIdleConnections()                           {}
func (m *countedMuxTransport) Close() error                                    { m.closed.Add(1); return nil }
