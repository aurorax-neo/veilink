package tunnel

import (
	"bytes"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func TestOrdinaryTLSNeverHandsOff(t *testing.T) {
	c := &ownedTLSConn{gate: &recordBoundaryConn{ordinary: true}}
	if c.switchRead() == nil || c.switchWrite() == nil {
		t.Fatal("ordinary TLS permitted raw handoff")
	}
	if c.rd || c.wd || c.gate.rawWrite {
		t.Fatal("failed handoff changed state")
	}
}

func TestMuxWriteBufferConcurrent(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	_ = left.SetDeadline(time.Now().Add(5 * time.Second))
	_ = right.SetDeadline(time.Now().Add(5 * time.Second))
	s := &session{conn: left}
	var wg sync.WaitGroup
	for id := 1; id <= 8; id++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < 32; i++ {
				if err := s.writeFrame(frameData, uint32(id), bytes.Repeat([]byte{byte(id)}, 1024+i)); err != nil {
					t.Error(err)
					return
				}
			}
		}(id)
	}
	for i := 0; i < 8*32; i++ {
		kind, id, p, err := readFrame(right)
		if err != nil {
			t.Fatal(err)
		}
		if kind != frameData || id < 1 || id > 8 || !bytes.Equal(p, bytes.Repeat([]byte{byte(id)}, len(p))) {
			t.Fatal("concurrent frame buffer corruption")
		}
	}
	wg.Wait()
}

func TestOwnedTLSReadBufferPreservesPending(t *testing.T) {
	left, right, _ := visionOwnedPair(t, 4096)
	defer left.Close()
	defer right.Close()
	payload := bytes.Repeat([]byte("buffer-ownership"), 2048)
	done := make(chan error, 1)
	go func() { done <- writeAll(left, payload) }()
	got := make([]byte, len(payload))
	for i := range got {
		if _, err := io.ReadFull(right, got[i:i+1]); err != nil {
			t.Fatal(err)
		}
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("pending plaintext overwritten")
	}
}

func TestXUDPReadBufferOwnership(t *testing.T) {
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	c := newClientUDP(pc, "127.0.0.1", 9000)
	defer c.Close()
	sender, err := net.DialUDP("udp", nil, pc.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	if err := sender.SetWriteBuffer(128 << 10); err != nil {
		t.Fatal(err)
	}
	if err := c.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if n, err := c.Read(nil); n != 0 || err != nil {
		t.Fatalf("empty read: %d %v", n, err)
	}
	if _, err := sender.Write(make([]byte, maxDatagram+1)); err != nil {
		t.Fatal(err)
	}
	for round := 0; round < 3; round++ {
		payload := bytes.Repeat([]byte{byte(round + 1)}, 1200)
		want, err := encodeXUDP(round == 0, c.host, c.port, c.global, payload)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := sender.Write(payload); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(want))
		for i := range got {
			if _, err := io.ReadFull(c, got[i:i+1]); err != nil {
				t.Fatal(err)
			}
		}
		if !bytes.Equal(got, want) {
			t.Fatal("XUDP pending record overwritten")
		}
	}
	if err := c.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := c.Read(make([]byte, 1500)); done <- err }()
	c.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("read succeeded after close")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("close did not release read")
	}
}
