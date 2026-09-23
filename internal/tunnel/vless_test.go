package tunnel

import (
	"io"
	"net"
	"testing"
	"time"
)

func TestVisionRoundTrip(t *testing.T) {
	left, right := net.Pipe()
	var id [16]byte
	id[0] = 7
	writer := newVision(left, id)
	reader := newVision(right, id)
	go func() {
		if err := writer.camouflage(); err != nil {
			t.Error(err)
		}
		if _, err := writer.Write([]byte("hello vision")); err != nil {
			t.Error(err)
		}
	}()
	buf := make([]byte, len("hello vision"))
	if _, err := io.ReadFull(reader, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "hello vision" {
		t.Fatalf("got %q", buf)
	}
}

func TestEncryptionRoundTrip(t *testing.T) {
	dec, enc, pqDec, pqEnc, err := GenerateVLESSEnc()
	if err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]string{{dec, enc}, {pqDec, pqEnc}} {
		server, err := mustSpec(t, pair[0], false).newServer()
		if err != nil {
			t.Fatal(err)
		}
		client, err := mustSpec(t, pair[1], true).newClient()
		if err != nil {
			t.Fatal(err)
		}
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		errc := make(chan error, 2)
		go func() {
			conn, err := ln.Accept()
			if err != nil {
				errc <- err
				return
			}
			defer conn.Close()
			conn, err = server.Handshake(conn)
			if err != nil {
				errc <- err
				return
			}
			buf := make([]byte, 4)
			_, err = io.ReadFull(conn, buf)
			if err == nil && string(buf) != "ping" {
				err = io.ErrUnexpectedEOF
			}
			if err == nil {
				_, err = conn.Write([]byte("pong"))
			}
			errc <- err
		}()
		go func() {
			conn, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				errc <- err
				return
			}
			defer conn.Close()
			conn, err = client.Handshake(conn)
			if err != nil {
				errc <- err
				return
			}
			_, err = conn.Write([]byte("ping"))
			if err != nil {
				errc <- err
				return
			}
			buf := make([]byte, 4)
			_, err = io.ReadFull(conn, buf)
			if err == nil && string(buf) != "pong" {
				err = io.ErrUnexpectedEOF
			}
			errc <- err
		}()
		for range 2 {
			if err := <-errc; err != nil {
				t.Fatal(pair, err)
			}
		}
		server.Close()
		_ = ln.Close()
	}
}

func TestFlowAndEncryption(t *testing.T) {
	files := tlsFiles(t)
	dec, enc, _, _, err := GenerateVLESSEnc()
	if err != nil {
		t.Fatal(err)
	}
	serverSnap, clientSnap := fixtures(t, echoServer(t))
	serverLocal, clientLocal := files, files
	serverLocal.Flow, clientLocal.Flow = flowVision, flowVision
	serverLocal.Decryption = dec
	clientLocal.Encryption = enc
	run(t, serverSnap, serverLocal)
	run(t, clientSnap, clientLocal)
	awaitEcho(t, serverSnap.Mappings[0].ListenPort)
}

func TestFlowMismatchBlocked(t *testing.T) {
	files := tlsFiles(t)
	serverSnap, clientSnap := fixtures(t, echoServer(t))
	serverLocal, clientLocal := files, files
	serverLocal.Flow = flowVision
	run(t, serverSnap, serverLocal)
	run(t, clientSnap, clientLocal)
	time.Sleep(400 * time.Millisecond)
	assertBlocked(t, serverSnap.Mappings[0].ListenPort)
}

func mustSpec(t *testing.T, raw string, client bool) *cryptSpec {
	t.Helper()
	var spec *cryptSpec
	var err error
	if client {
		spec, err = parseEncryption(raw)
	} else {
		spec, err = parseDecryption(raw)
	}
	if err != nil || spec == nil {
		t.Fatal(err)
	}
	return spec
}
