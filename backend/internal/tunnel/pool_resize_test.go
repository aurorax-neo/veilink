package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	M "github.com/metacubex/sing/common/metadata"

	"veilink/internal/model"
)

type resizeTestClient struct{}

func (resizeTestClient) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, errResizeTestDial
}

var errResizeTestDial = errors.New("test lane selected")

func (resizeTestClient) Close() error { return nil }

type resizeAcquireContext struct {
	context.Context
	once    sync.Once
	entered chan struct{}
	resume  chan struct{}
}

func (c *resizeAcquireContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.entered) })
	<-c.resume
	return c.Context.Done()
}

func TestPoolResizeDuringTransportAcquisition(t *testing.T) {
	for _, size := range []int{0, 1} {
		t.Run(fmt.Sprintf("size=%d", size), func(t *testing.T) {
			testResizeDuringAcquisition(t, size)
		})
	}
}

func testResizeDuringAcquisition(t *testing.T, size int) {
	t.Helper()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	conn := &singReverseConn{Conn: a, done: make(chan struct{}), claimed: make(chan struct{})}
	lane := &singLane{client: resizeTestClient{}, conn: conn, active: 8}
	p := &singPool{ctx: context.Background(), queue: make(chan *singReverseConn, 32), limit: 2, lanes: []*singLane{lane}, reverse: map[*singReverseConn]bool{conn: true}}
	stale := &singReverseConn{done: make(chan struct{})}
	close(stale.done)
	p.queue <- stale
	parent, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ctx := &resizeAcquireContext{Context: parent, entered: make(chan struct{}), resume: make(chan struct{})}
	result := make(chan error, 1)
	go func() {
		_, err := p.DialContext(ctx, "tcp", M.ParseSocksaddr("127.0.0.1:443"))
		result <- err
	}()
	select {
	case <-ctx.entered:
	case <-parent.Done():
		close(ctx.resume)
		t.Fatal("transport acquisition did not start")
	}
	p.resize(size)
	close(ctx.resume)
	want := net.ErrClosed
	if size == 1 {
		want = errResizeTestDial
	}
	if err := <-result; !errors.Is(err, want) {
		t.Fatalf("incorrect lane admission after resize: got %v, want %v", err, want)
	}
	if lane.active != 8 {
		t.Fatal("retirement changed active stream count")
	}
}

func TestPoolResizePreservesActiveFlows(t *testing.T) {
	for _, kind := range []string{"", "smux", "yamux", "h2mux", "udp"} {
		t.Run(kind, func(t *testing.T) {
			local := tlsFiles(t)
			target := echoServer(t)
			if kind == "udp" {
				target = udpEchoServer(t)
			}
			s, c := fixtures(t, target)
			m := &s.Mappings[0]
			m.Pool = 4
			if kind == "udp" {
				m.Network, m.ListenPort = "udp", freeUDPPort(t)
			} else {
				m.Mux, m.MuxType = kind != "", kind
			}
			other := *m
			other.ID, other.Name, other.Pool = "other", "other", 1
			other.ListenPort = freePort(t)
			if kind == "udp" {
				other.ListenPort = freeUDPPort(t)
			}
			s.Mappings = append(s.Mappings, other)
			c.Mappings = append([]model.Mapping(nil), s.Mappings...)
			server, client := run(t, s, local), run(t, c, local)
			c = clone(*client.good)
			sc, cc := testBindingService(server.instance, "one"), testBindingService(client.instance, "one")
			awaitSessions(t, sc, "one", 4)
			listener := sc.mappingListeners[other.ID]
			var flows []net.Conn
			for i := range 36 {
				port := s.Mappings[i%2].ListenPort
				if kind == "udp" {
					awaitUDPEcho(t, port)
					conn, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", port))
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { conn.Close() })
					flows = append(flows, conn)
					assertPersistentEcho(t, conn)
				} else {
					awaitEcho(t, port)
					flows = append(flows, persistentEcho(t, port))
				}
			}
			for _, size := range []int{1, 4, 2, 1, 4, 1} {
				s.Revision++
				c.Revision++
				s.Mappings[0].Pool = size
				c.Mappings = append([]model.Mapping(nil), s.Mappings...)
				// Exercise independently delivered snapshots in both orders.
				if size%2 == 0 {
					if err := client.Apply(c); err != nil {
						t.Fatal(err)
					}
					if err := server.Apply(s); err != nil {
						t.Fatal(err)
					}
				} else {
					if err := server.Apply(s); err != nil {
						t.Fatal(err)
					}
					if err := client.Apply(c); err != nil {
						t.Fatal(err)
					}
				}
				if sc != testBindingService(server.instance, "one") || cc != testBindingService(client.instance, "one") || listener != sc.mappingListeners[other.ID] {
					t.Fatal("resize replaced binding or listener")
				}
				for _, conn := range flows {
					assertPersistentEcho(t, conn)
				}
				if kind == "udp" {
					awaitUDPEcho(t, other.ListenPort)
				} else {
					awaitEcho(t, other.ListenPort)
				}
			}
			for _, conn := range flows {
				conn.Close()
			}
			if kind != "udp" {
				awaitSessions(t, sc, "one", 1)
			}
			if kind != "" && kind != "udp" {
				pool := sc.singPools[singKey("one", kind)]
				until := time.Now().Add(3 * time.Second)
				for {
					pool.mu.Lock()
					count := pool.count
					lanes := len(pool.lanes)
					pool.mu.Unlock()
					if count <= 1 && lanes <= 1 {
						break
					}
					if time.Now().After(until) {
						t.Fatalf("retired mux transports leaked: count=%d lanes=%d", count, lanes)
					}
					time.Sleep(20 * time.Millisecond)
				}
			}
		})
	}
}

func TestPoolResizeFailureKeepsPolicy(t *testing.T) {
	local := tlsFiles(t)
	s, c := fixtures(t, echoServer(t))
	server := run(t, s, local)
	run(t, c, local)
	awaitEcho(t, s.Mappings[0].ListenPort)
	conn := persistentEcho(t, s.Mappings[0].ListenPort)
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	next := clone(s)
	next.Revision++
	next.Mappings[0].Pool = 4
	other := next.Mappings[0]
	other.ID, other.Name, other.ListenPort = "busy", "busy", busy.Addr().(*net.TCPAddr).Port
	next.Mappings = append(next.Mappings, other)
	if err := server.Apply(next); err == nil {
		t.Fatal("occupied port accepted")
	}
	child := testBindingService(server.instance, "one")
	if bindingPool(child.policy.Load().Mappings, "one") != 1 || server.Revision() != s.Revision {
		t.Fatal("failed resize published policy")
	}
	assertPersistentEcho(t, conn)
}

func TestMuxTransportFailureIsIsolated(t *testing.T) {
	for _, kind := range singKinds {
		t.Run(kind, func(t *testing.T) {
			local := tlsFiles(t)
			s, c := fixtures(t, echoServer(t))
			s.Mappings[0].Mux, s.Mappings[0].MuxType, s.Mappings[0].Pool = true, kind, 2
			c.Mappings = append([]model.Mapping(nil), s.Mappings...)
			server := run(t, s, local)
			run(t, c, local)
			awaitEcho(t, s.Mappings[0].ListenPort)
			var flows []net.Conn
			for range 16 {
				flows = append(flows, persistentEcho(t, s.Mappings[0].ListenPort))
			}
			p := testBindingService(server.instance, "one").singPools[singKey("one", kind)]
			p.mu.Lock()
			if len(p.lanes) != 2 {
				p.mu.Unlock()
				t.Fatal("pool did not use two transports")
			}
			broken, survivor := p.lanes[0].conn, p.lanes[1].conn
			p.mu.Unlock()
			broken.Close()
			for _, conn := range flows[8:] {
				assertPersistentEcho(t, conn)
			}
			if survivor.closed() {
				t.Fatal("unrelated mux transport closed")
			}
			awaitEcho(t, s.Mappings[0].ListenPort)
		})
	}
}

func TestPoolModeChangePreservesOtherMapping(t *testing.T) {
	for _, kind := range singKinds {
		t.Run(kind, func(t *testing.T) {
			local := tlsFiles(t)
			s, c := fixtures(t, echoServer(t))
			other := s.Mappings[0]
			other.ID, other.Name, other.ListenPort = "other", "other", freePort(t)
			other.Mux, other.MuxType = true, kind
			s.Mappings = append(s.Mappings, other)
			c.Mappings = append([]model.Mapping(nil), s.Mappings...)
			server, client := run(t, s, local), run(t, c, local)
			c = clone(*client.good)
			awaitEcho(t, other.ListenPort)
			conn := persistentEcho(t, other.ListenPort)
			for _, mode := range []string{kind, "", "yamux", "h2mux", "smux", ""} {
				s.Revision++
				c.Revision++
				s.Mappings[0].Mux, s.Mappings[0].MuxType = mode != "", mode
				c.Mappings = append([]model.Mapping(nil), s.Mappings...)
				if err := server.Apply(s); err != nil {
					t.Fatal(err)
				}
				if err := client.Apply(c); err != nil {
					t.Fatal(err)
				}
				assertPersistentEcho(t, conn)
				awaitEcho(t, s.Mappings[0].ListenPort)
			}
		})
	}
}
