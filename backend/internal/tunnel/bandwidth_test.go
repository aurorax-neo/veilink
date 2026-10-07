package tunnel

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"veilink/internal/model"
)

func TestBandwidthSharedAndCancellable(t *testing.T) {
	b := &bandwidthBucket{}
	b.update("80Kbps")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	started := time.Now()
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			if err := b.wait(ctx, 1250); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if elapsed := time.Since(started); elapsed < 400*time.Millisecond || elapsed > 2*time.Second {
		t.Fatalf("aggregate shaping: %v", elapsed)
	}
	canceled, stop := context.WithCancel(ctx)
	stop()
	if err := b.wait(canceled, 100000); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- b.wait(ctx, 100000) }()
	b.update("")
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("disable did not unblock")
	}
}

func TestShapedConnDeadlinePreservesDataAndCloseCancels(t *testing.T) {
	b := &bandwidthBucket{}
	b.update("1Kbps")
	b.bucket.TakeAvailable(1000)
	left, right := net.Pipe()
	c := shapeConn(context.Background(), left, b)
	defer c.Close()
	defer right.Close()
	c.SetReadDeadline(time.Now().Add(time.Millisecond))
	go func() { _, _ = right.Write([]byte("abcdef")) }()
	p := make([]byte, 6)
	if n, err := c.Read(p); n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("deadline: %d %v", n, err)
	}
	c.SetReadDeadline(time.Time{})
	b.update("")
	if _, err := io.ReadFull(c, p); err != nil || string(p) != "abcdef" {
		t.Fatalf("resume: %q %v", p, err)
	}
	b.update("1Kbps")
	b.bucket.TakeAvailable(1000)
	go func() { _, _ = right.Write([]byte("cancel")) }()
	done := make(chan error, 1)
	go func() { _, err := c.Read(p); done <- err }()
	c.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("close succeeded read")
		}
	case <-time.After(time.Second):
		t.Fatal("close left read blocked")
	}
}

func TestMappingIDBounds(t *testing.T) {
	for _, id := range []string{"mapping", string(bytes.Repeat([]byte("x"), 128))} {
		var wire bytes.Buffer
		if err := writeMappingID(&wire, id); err != nil {
			t.Fatal(err)
		}
		got, err := readMappingID(&wire)
		if err != nil || got != id {
			t.Fatalf("roundtrip: %q %v", got, err)
		}
	}
	for _, input := range [][]byte{{0}, {129}, {5, 'a'}} {
		if _, err := readMappingID(bytes.NewReader(input)); err == nil {
			t.Fatal("accepted malformed ID")
		}
	}
}

func TestMappingIDTimeoutClosesStalledStream(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	started := time.Now()
	if _, err := readMappingIDTimeout(left, 20*time.Millisecond); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal(err)
	}
	if time.Since(started) > time.Second {
		t.Fatal("stalled authorization header was not bounded")
	}
}

func TestBandwidthUpdateKeepsMappingConnections(t *testing.T) {
	for _, kind := range []string{"", "smux", "yamux", "h2mux"} {
		t.Run(kind, func(t *testing.T) {
			local := tlsFiles(t)
			s, c := fixtures(t, echoServer(t))
			s.Mappings[0].Mux, s.Mappings[0].MuxType = kind != "", kind
			s.Mappings[0].BandwidthLimit = "80Kbps"
			c.Mappings = append(c.Mappings[:0], s.Mappings...)
			server, client := run(t, s, local), run(t, c, local)
			awaitEcho(t, s.Mappings[0].ListenPort)
			conn := persistentEcho(t, s.Mappings[0].ListenPort)
			for _, rate := range []string{"160Kbps", ""} {
				s.Revision++
				s.Mappings[0].BandwidthLimit = rate
				updated := clone(*client.good)
				updated.Revision++
				updated.Mappings[0].BandwidthLimit = rate
				if err := server.Apply(s); err != nil {
					t.Fatal(err)
				}
				if err := client.Apply(updated); err != nil {
					t.Fatal(err)
				}
				assertPersistentEcho(t, conn)
			}
		})
	}
}

func TestMappingIDAuthorization(t *testing.T) {
	snap, _ := fixtures(t, 80)
	m := snap.Mappings[0]
	s := &service{snapshot: snap}
	if _, ok := s.mappingFor(m.ID, m.BindingID, m.TargetHost, m.TargetPort, "tcp", false, ""); !ok {
		t.Fatal("authorized mapping denied")
	}
	for _, tc := range []struct {
		id, binding, host, network, kind string
		port                             int
		mux                              bool
	}{
		{"other", m.BindingID, m.TargetHost, "tcp", "", 80, false},
		{m.ID, "other", m.TargetHost, "tcp", "", 80, false},
		{m.ID, m.BindingID, "example.org", "tcp", "", 80, false},
		{m.ID, m.BindingID, m.TargetHost, "tcp", "", 81, false},
		{m.ID, m.BindingID, m.TargetHost, "udp", "", 80, false},
		{m.ID, m.BindingID, m.TargetHost, "tcp", "smux", 80, true},
	} {
		if _, ok := s.mappingFor(tc.id, tc.binding, tc.host, tc.port, tc.network, tc.mux, tc.kind); ok {
			t.Fatal("unauthorized mapping accepted", tc)
		}
	}
	s.snapshot.Mappings[0].Enabled = false
	if _, ok := s.mappingFor(m.ID, m.BindingID, m.TargetHost, m.TargetPort, "tcp", false, ""); ok {
		t.Fatal("disabled mapping accepted")
	}
}

func TestMappingWithdrawalClosesOnlyItsTarget(t *testing.T) {
	for _, kind := range []string{"", "smux", "yamux", "h2mux"} {
		t.Run(kind, func(t *testing.T) {
			local := tlsFiles(t)
			s, c := fixtures(t, echoServer(t))
			s.Mappings[0].Mux, s.Mappings[0].MuxType = kind != "", kind
			other := s.Mappings[0]
			other.ID, other.Name, other.ListenPort = "other", "other", freePort(t)
			s.Mappings = append(s.Mappings, other)
			c.Mappings = append([]model.Mapping(nil), s.Mappings...)
			run(t, s, local)
			client := run(t, c, local)
			awaitEcho(t, other.ListenPort)
			first := persistentEcho(t, s.Mappings[0].ListenPort)
			second := persistentEcho(t, other.ListenPort)
			// Withdraw only on the target side; do not rely on closing the public listener.
			updated := clone(*client.good)
			updated.Revision++
			updated.Mappings[0].Enabled = false
			if err := client.Apply(updated); err != nil {
				t.Fatal(err)
			}
			first.SetReadDeadline(time.Now().Add(time.Second))
			if _, err := first.Read(make([]byte, 1)); err == nil {
				t.Fatal("withdrawn target stayed open")
			} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				t.Fatal("withdrawn target was not closed")
			}
			assertPersistentEcho(t, second)
		})
	}
}

func TestUDPBandwidthCancellationAndDisable(t *testing.T) {
	for _, disable := range []bool{false, true} {
		t.Run(map[bool]string{true: "disable", false: "close"}[disable], func(t *testing.T) {
			peer := newGatewayUDP(nil, &net.UDPAddr{}, "127.0.0.1", 80)
			peer.bucket = &bandwidthBucket{}
			peer.bucket.update("1Kbps")
			peer.bucket.bucket.TakeAvailable(1000)
			peer.ctx, peer.cancel = context.WithCancel(context.Background())
			defer peer.Close()
			payload := bytes.Repeat([]byte("x"), 100)
			peer.push(payload)
			done := make(chan error, 1)
			go func() {
				p := make([]byte, 1024)
				n, err := peer.Read(p)
				if err == nil {
					_, _, got, decodeErr := decodeXUDP(p[:n])
					if decodeErr != nil || !bytes.Equal(got, payload) {
						err = errors.New("UDP payload changed by shaping")
					}
				}
				done <- err
			}()
			if disable {
				peer.bucket.update("")
			} else {
				peer.Close()
			}
			select {
			case err := <-done:
				if disable && err != nil || !disable && err == nil {
					t.Fatalf("disable=%v: %v", disable, err)
				}
			case <-time.After(time.Second):
				t.Fatal("UDP limiter did not unblock")
			}
		})
	}
}
