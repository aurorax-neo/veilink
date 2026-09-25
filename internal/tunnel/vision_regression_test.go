package tunnel

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"veilink/internal/model"
)

func TestVisionPoolOneBurstAndRestart(t *testing.T) {
	files := tlsFiles(t)
	files.Flow = flowVision
	server, client := fixtures(t, echoServer(t))
	sr := run(t, server, files)
	cr := run(t, client, files)
	awaitApplication(t, sr.instance, "one")
	// Hold every public socket open until all have exchanged data, so success
	// requires replenishment, not serial reuse of one application connection.
	const count = 12
	ready := make(chan error, count)
	release := make(chan struct{})
	defer close(release)
	for i := 0; i < count; i++ {
		go func() {
			c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", server.Mappings[0].ListenPort))
			if err != nil {
				ready <- err
				return
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(5 * time.Second))
			err = writeAll(c, []byte("burst"))
			b := make([]byte, 5)
			if err == nil {
				_, err = io.ReadFull(c, b)
			}
			if err == nil && string(b) != "burst" {
				err = fmt.Errorf("corrupt burst")
			}
			ready <- err
			<-release
		}()
	}
	for i := 0; i < count; i++ {
		if err := <-ready; err != nil {
			t.Fatal(err)
		}
	}
	awaitApplication(t, sr.instance, "one")
	cr.Close()
	// The old idle reader must detect EOF, not wait for its 45 second lease.
	deadline := time.Now().Add(2 * time.Second)
	for {
		sr.instance.mu.Lock()
		n := len(sr.instance.applications["one"])
		sr.instance.mu.Unlock()
		if n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("dead idle slot retained")
		}
		time.Sleep(time.Millisecond)
	}
	// Start the first request before the replacement client, proving it queues.
	result := make(chan error, 1)
	go func() { result <- exchange(server.Mappings[0].ListenPort, []byte("first-after-restart"), false) }()
	deadline = time.Now().Add(time.Second)
	for {
		sr.instance.mu.Lock()
		n := sr.instance.applicationWaiting["one"]
		sr.instance.mu.Unlock()
		if n > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("first request did not queue")
		}
		time.Sleep(time.Millisecond)
	}
	run(t, client, files)
	if err := <-result; err != nil {
		t.Fatal("first request lost", err)
	}
	awaitApplication(t, sr.instance, "one")
}

func TestVisionEncryptionHalfCloseResponse(t *testing.T) {
	for _, mode := range []string{"native", "xorpub", "random"} {
		t.Run(mode, func(t *testing.T) {
			files := tlsFiles(t)
			files.Flow = flowVision
			dec, enc, _, _, err := GenerateVLESSEnc()
			if err != nil {
				t.Fatal(err)
			}
			files.Decryption = strings.Replace(dec, ".native.", "."+mode+".", 1)
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			response := bytes.Repeat([]byte("response-after-EOF"), 16384)
			targetDone := make(chan error, 1)
			go func() {
				c, err := ln.Accept()
				if err != nil {
					targetDone <- err
					return
				}
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				got, err := io.ReadAll(c)
				if err == nil && string(got) != "request" {
					err = fmt.Errorf("bad request")
				}
				if err == nil {
					err = writeAll(c, response)
				}
				targetDone <- err
			}()
			server, client := fixtures(t, ln.Addr().(*net.TCPAddr).Port)
			sr := run(t, server, files)
			run(t, client, model.LocalTLS{TransportSecurity: "tls", CAPEM: files.CAPEM, Flow: flowVision, Encryption: strings.Replace(enc, ".native.", "."+mode+".", 1)})
			awaitApplication(t, sr.instance, "one")
			c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", server.Mappings[0].ListenPort))
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(5 * time.Second))
			if err = writeAll(c, []byte("request")); err != nil {
				t.Fatal(err)
			}
			if err = c.(*net.TCPConn).CloseWrite(); err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(c)
			if err != nil || !bytes.Equal(got, response) {
				t.Fatalf("truncated half-close response: %d %v", len(got), err)
			}
			if err = <-targetDone; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestVisionRecordBoundaryArbitraryWrites(t *testing.T) {
	for _, chunk := range []int{4093, 8192, 32768} {
		t.Run(fmt.Sprint(chunk), func(t *testing.T) {
			left, right, _ := visionOwnedPair(t, 127)
			id := [16]byte{3}
			lv, rv := newApplicationVision(left, id), newApplicationVision(right, id)
			transfer := func(from, to *visionConn, wire []byte) {
				t.Helper()
				done := make(chan error, 1)
				go func() {
					for p := wire; len(p) > 0; {
						n := min(chunk, len(p))
						if err := writeAll(from, p[:n]); err != nil {
							done <- err
							return
						}
						p = p[n:]
					}
					done <- nil
				}()
				got := make([]byte, len(wire))
				_, err := io.ReadFull(to, got)
				if err != nil {
					t.Fatal(err)
				}
				if err = <-done; err != nil || !bytes.Equal(got, wire) {
					t.Fatal("transfer", err)
				}
			}
			transfer(lv, rv, recognitionHello(1, structuralHello(1)))
			transfer(rv, lv, recognitionHello(2, structuralHello(2)))
			// Every caller chunk ends inside records; total size exceeds the budget.
			wire := bytes.Repeat(recognitionRecord(23, bytes.Repeat([]byte{7}, 16384)), 24)
			transfer(lv, rv, wire)
			transfer(rv, lv, wire)
			for _, c := range []*ownedTLSConn{left, right} {
				if c.readSwitches.Load() != 1 || c.writeSwitches.Load() != 1 || c.rawRead.Load() == 0 || c.rawWritten.Load() == 0 {
					t.Fatal("record boundaries missed")
				}
			}
		})
	}
}

func TestVisionCrossedFallbackAndDirect(t *testing.T) {
	left, right, _ := visionOwnedPair(t, 127)
	id := [16]byte{9}
	lv, rv := newApplicationVision(left, id), newApplicationVision(right, id)
	ch, sh := recognitionHello(1, structuralHello(1)), recognitionHello(2, structuralHello(2))
	// Seed the same previously exchanged hellos at both endpoints.
	lv.recognition.observe(1, ch)
	lv.recognition.observe(0, sh)
	rv.recognition.observe(0, ch)
	rv.recognition.observe(1, sh)
	// One direction exhausts its bounded recognition before the opposite's
	// already queued command 2 is received. Neither may invalidate the other.
	lv.recognition.dirs[1].budget = 128 << 10
	rv.recognition.dirs[0].budget = 128 << 10
	app := recognitionRecord(23, bytes.Repeat([]byte{1}, 32))
	if err := writeAll(rv, app); err != nil {
		t.Fatal(err)
	} // command 2 queued
	if err := writeAll(lv, app); err != nil {
		t.Fatal(err)
	} // command 1 crosses it
	for _, c := range []*visionConn{lv, rv} {
		got := make([]byte, len(app))
		if _, err := io.ReadFull(c, got); err != nil || !bytes.Equal(got, app) {
			t.Fatal("crossed commands", err)
		}
	}
	if left.readSwitches.Load() != 1 || left.writeSwitches.Load() != 0 || right.readSwitches.Load() != 0 || right.writeSwitches.Load() != 1 {
		t.Fatal("incorrect directional handoff")
	}
}

func TestVisionApplicationQueueBounds(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		s := &service{ctx: ctx, applications: map[string][]*applicationSlot{}, applicationWaiting: map[string]int{}, applicationChanged: make(chan struct{})}
		m := model.Mapping{BindingID: "one"}
		done := make(chan struct{}, applicationQueueLimit)
		for range applicationQueueLimit {
			a, b := net.Pipe()
			defer b.Close()
			go func() { s.openApplication(a, m); done <- struct{}{} }()
		}
		synctest.Wait()
		if s.applicationWaiting["one"] != applicationQueueLimit {
			t.Fatal("queue not bounded as expected")
		}
		a, b := net.Pipe()
		defer b.Close()
		rejected := make(chan struct{})
		go func() { s.openApplication(a, m); close(rejected) }()
		synctest.Wait()
		select {
		case <-rejected:
		default:
			t.Fatal("queue overflow waited")
		}
		// Fake time proves the acquisition timeout without a slow/flaky wall-clock test.
		time.Sleep(applicationWait)
		synctest.Wait()
		if s.applicationWaiting["one"] != 0 || len(done) != applicationQueueLimit {
			t.Fatal("queue did not expire")
		}
		a, b = net.Pipe()
		defer b.Close()
		cancelled := make(chan struct{})
		go func() { s.openApplication(a, m); close(cancelled) }()
		synctest.Wait()
		cancel()
		synctest.Wait()
		select {
		case <-cancelled:
		default:
			t.Fatal("queue ignored cancellation")
		}
	})
}
