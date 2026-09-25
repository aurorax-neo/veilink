package tunnel

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"veilink/internal/model"
)

func awaitApplication(t *testing.T, s *service, binding string) {
	t.Helper()
	until := time.Now().Add(10 * time.Second)
	for time.Now().Before(until) {
		s.mu.Lock()
		n := len(s.applications[binding])
		s.mu.Unlock()
		if n > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("dedicated application pool did not replenish")
}

func applicationCounters(s *service) (reads, writes, rawReads, rawWrites uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for conn := range s.conns {
		if c, ok := conn.(*ownedTLSConn); ok {
			reads += c.readSwitches.Load()
			writes += c.writeSwitches.Load()
			rawReads += c.rawRead.Load()
			rawWrites += c.rawWritten.Load()
		}
	}
	return
}

func tlsApplicationTarget(t *testing.T, files model.LocalTLS, version uint16) int {
	t.Helper()
	cert, err := tls.X509KeyPair([]byte(files.CertPEM), []byte(files.KeyPEM))
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: version, MaxVersion: version})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); c.SetDeadline(time.Now().Add(15 * time.Second)); io.Copy(c, c) }()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// Exercises the actual reverse runtime, not an isolated padding round trip.
// Inner TLS bytes traverse dedicated authenticated sockets; mux remains present
// and its counters must never show a raw handoff.
func TestVisionApplicationRuntime(t *testing.T) {
	for _, tc := range []struct {
		name       string
		version    uint16
		encryption bool
		reality    bool
	}{
		{"tls13", tls.VersionTLS13, false, false}, {"tls12", tls.VersionTLS12, false, false},
		{"plain", 0, false, false}, {"encryption-fallback", tls.VersionTLS13, true, false},
		{"reality-tls13", tls.VersionTLS13, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			files := tlsFiles(t)
			target := 0
			if tc.version == 0 {
				target = echoServer(t)
			} else {
				target = tlsApplicationTarget(t, files, tc.version)
			}
			server, client := fixtures(t, target)
			serverLocal, clientLocal := files, model.LocalTLS{TransportSecurity: "tls", CAPEM: files.CAPEM, Flow: flowVision}
			serverLocal.Flow = flowVision
			if tc.encryption {
				dec, enc, _, _, err := GenerateVLESSEnc()
				if err != nil {
					t.Fatal(err)
				}
				serverLocal.Decryption, clientLocal.Encryption = dec, enc
			}
			if tc.reality {
				priv, pub, err := GenerateX25519()
				if err != nil {
					t.Fatal(err)
				}
				serverLocal = model.LocalTLS{Flow: flowVision, Reality: model.Reality{Dest: camouflage(t, files.CertPEM, files.KeyPEM), PrivateKey: priv, ShortIDs: "0123456789abcdef", ServerNames: "gateway.test"}}
				clientLocal = model.LocalTLS{Flow: flowVision, Reality: model.Reality{PublicKey: pub, ShortID: "0123456789abcdef"}}
			}
			sr := run(t, server, serverLocal)
			cr := run(t, client, clientLocal)
			awaitApplication(t, sr.instance, "one")
			raw, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", server.Mappings[0].ListenPort))
			if err != nil {
				t.Fatal(err)
			}
			defer raw.Close()
			raw.SetDeadline(time.Now().Add(10 * time.Second))
			var app net.Conn = raw
			if tc.version != 0 {
				pool, _ := roots(files.CAPEM)
				app = tls.Client(raw, &tls.Config{RootCAs: pool, ServerName: "gateway.test", MinVersion: tc.version, MaxVersion: tc.version})
				if err := app.(*tls.Conn).Handshake(); err != nil {
					t.Fatal(err)
				}
			}
			payload := bytes.Repeat([]byte("real application TLS data "), 8192)
			errC := make(chan error, 1)
			go func() { errC <- writeAll(app, payload) }()
			got := make([]byte, len(payload))
			if _, err := io.ReadFull(app, got); err != nil {
				t.Fatal(err)
			}
			if err := <-errC; err != nil || !bytes.Equal(payload, got) {
				t.Fatal("duplex corruption", err)
			}
			awaitApplication(t, sr.instance, "one") // replenishes while this flow remains open
			r, w, rr, rw := applicationCounters(sr.instance)
			if tc.version == tls.VersionTLS13 && !tc.encryption {
				if r != 1 || w != 1 || rr == 0 || rw == 0 {
					t.Fatalf("not actual duplex raw copy: switches=%d/%d bytes=%d/%d", r, w, rr, rw)
				}
			} else if r != 0 || w != 0 || rr != 0 || rw != 0 {
				t.Fatal("fallback bypassed encryption")
			}
			sr.instance.mu.Lock()
			for _, sess := range sr.instance.sessions["one"] {
				v, ok := sess.conn.(*visionConn)
				if !ok || v.direct != nil {
					t.Error("mux acquired direct-copy capability")
				}
			}
			sr.instance.mu.Unlock()
			// Revocation/cancellation must close active dedicated connections as
			// well as idle slots and the target sockets on the reverse client.
			cr.Close()
			app.SetReadDeadline(time.Now().Add(2 * time.Second))
			if _, err := app.Read(make([]byte, 1)); err == nil {
				t.Fatal("active flow survived cancellation")
			} else if e, ok := err.(net.Error); ok && e.Timeout() {
				t.Fatal("cancellation did not close active flow")
			}
		})
	}
}

// Fragment both outer ciphertext and inner TLS writes, including one-byte
// record headers. TCP is used so coalesced raw data can already be waiting when
// the reader finishes its final encrypted padding record.
type fragmentVisionConn struct {
	net.Conn
	size int
}

func (c *fragmentVisionConn) Read(p []byte) (int, error) { return c.Conn.Read(p[:min(len(p), c.size)]) }
func (c *fragmentVisionConn) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		n, err := c.Conn.Write(p[:min(len(p), c.size)])
		written += n
		p = p[n:]
		if err != nil {
			return written, err
		}
		if n == 0 {
			return written, io.ErrShortWrite
		}
	}
	return written, nil
}

func visionOwnedPair(t *testing.T, fragment int) (*ownedTLSConn, *ownedTLSConn, model.LocalTLS) {
	t.Helper()
	files := tlsFiles(t)
	cert, err := tls.X509KeyPair([]byte(files.CertPEM), []byte(files.KeyPEM))
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	left, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	right, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { left.Close(); right.Close() })
	left.SetDeadline(time.Now().Add(15 * time.Second))
	right.SetDeadline(time.Now().Add(15 * time.Second))
	lg := &recordBoundaryConn{Conn: &fragmentVisionConn{Conn: left, size: fragment}}
	rg := &recordBoundaryConn{Conn: &fragmentVisionConn{Conn: right, size: fragment}}
	pool, _ := roots(files.CAPEM)
	lc := tls.Client(lg, &tls.Config{RootCAs: pool, ServerName: "gateway.test", MinVersion: tls.VersionTLS13, SessionTicketsDisabled: true})
	rc := tls.Server(rg, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13, SessionTicketsDisabled: true})
	ec := make(chan error, 1)
	go func() { ec <- rc.Handshake() }()
	if err := lc.Handshake(); err != nil {
		t.Fatal(err)
	}
	if err := <-ec; err != nil {
		t.Fatal(err)
	}
	return ownTLS(lc, lg), ownTLS(rc, rg), files
}

func TestVisionFragmentedTLS13DirectCopy(t *testing.T) {
	left, right, files := visionOwnedPair(t, 7)
	id := [16]byte{1, 2, 3}
	lv, rv := newApplicationVision(left, id), newApplicationVision(right, id)
	cert, _ := tls.X509KeyPair([]byte(files.CertPEM), []byte(files.KeyPEM))
	pool, _ := roots(files.CAPEM)
	client := tls.Client(&fragmentVisionConn{Conn: lv, size: 1}, &tls.Config{RootCAs: pool, ServerName: "gateway.test", MinVersion: tls.VersionTLS13})
	server := tls.Server(&fragmentVisionConn{Conn: rv, size: 3}, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13})
	errC := make(chan error, 1)
	go func() {
		if err := server.Handshake(); err != nil {
			errC <- err
			return
		}
		_, err := io.Copy(server, server)
		errC <- err
	}()
	if err := client.Handshake(); err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("fragmented duplex"), 512)
	writeC := make(chan error, 1)
	go func() { writeC <- writeAll(client, payload) }()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(client, got); err != nil {
		t.Fatal(err)
	}
	if err := <-writeC; err != nil || !bytes.Equal(payload, got) {
		t.Fatal("fragmentation", err)
	}
	for _, c := range []*ownedTLSConn{left, right} {
		if c.readSwitches.Load() != 1 || c.writeSwitches.Load() != 1 || c.rawRead.Load() == 0 || c.rawWritten.Load() == 0 {
			t.Fatal("missing raw handoff", c.readSwitches.Load(), c.writeSwitches.Load())
		}
	}
	left.Close()
	right.Close()
	<-errC
}

func TestVisionPrematureAndIsolation(t *testing.T) {
	for _, mode := range []string{"dedicated", "mux", "encryption", "wrong-id"} {
		t.Run(mode, func(t *testing.T) {
			left, right, _ := visionOwnedPair(t, 128)
			id := [16]byte{1}
			var reader *visionConn
			switch mode {
			case "mux":
				reader = newVision(right, id)
			case "encryption":
				// Even an adapter exposing an owned TLS connection must not be
				// recursively unwrapped. recordConn uses the same explicit fallback.
				reader = newApplicationVision(&fragmentVisionConn{Conn: right, size: 128}, id)
			default:
				reader = newApplicationVision(right, id)
			}
			if mode == "wrong-id" {
				id[0] = 2
			}
			wire := append(append([]byte{}, id[:]...), 2, 0, 0, 0, 0)
			if err := writeAll(left, wire); err != nil {
				t.Fatal(err)
			}
			if _, err := reader.Read(make([]byte, 1)); err == nil {
				t.Fatal("accepted injected command 2")
			}
			if right.readSwitches.Load() != 0 {
				t.Fatal("injection switched transport")
			}
		})
	}
}

func TestVisionHandoffRejectsOwnedTrailingPlaintext(t *testing.T) {
	left, right, _ := visionOwnedPair(t, 128)
	if err := writeAll(left, []byte("authenticated trailing bytes")); err != nil {
		t.Fatal(err)
	}
	if _, err := right.Read(make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	if err := right.switchRead(); err == nil {
		t.Fatal("discarded pending outer plaintext")
	}
	if right.readSwitches.Load() != 0 {
		t.Fatal("unsafe read handoff")
	}
}

func TestVisionDedicatedAuthorizationAndUDPIsolation(t *testing.T) {
	files := tlsFiles(t)
	server, client := fixtures(t, echoServer(t))
	udp := server.Mappings[0]
	udp.ID, udp.Name, udp.Network = "udp", "udp", "udp"
	udp.ListenPort, udp.TargetPort = freeUDPPort(t), udpEchoServer(t)
	server.Mappings = append(server.Mappings, udp)
	client.Mappings = append(client.Mappings, udp)
	files.Flow = flowVision
	sr := run(t, server, files)
	// A valid reverse binding still cannot request a target absent from the
	// client's independently authorized snapshot.
	client.Mappings[0].TargetPort = freePort(t)
	cr := run(t, client, model.LocalTLS{TransportSecurity: "tls", CAPEM: files.CAPEM, Flow: flowVision})
	awaitApplication(t, sr.instance, "one")
	assertBlocked(t, server.Mappings[0].ListenPort)
	awaitApplication(t, sr.instance, "one")
	until := time.Now().Add(5 * time.Second)
	for {
		err := exchangeUDP(udp.ListenPort, []byte("UDP stays inside mux"))
		if err == nil {
			break
		}
		if time.Now().After(until) {
			t.Fatal(err)
		}
	}
	r, w, _, _ := applicationCounters(sr.instance)
	if r != 0 || w != 0 {
		t.Fatal("UDP or unauthorized target switched outer transport")
	}
	// A real configuration revocation closes idle dedicated slots too.
	client.Revision++
	client.Bindings, client.Mappings, client.Nodes = nil, nil, nil
	if err := cr.Apply(client); err != nil {
		t.Fatal(err)
	}
	assertBlocked(t, server.Mappings[0].ListenPort)
}

func TestVisionDedicatedRejectsBindingMismatch(t *testing.T) {
	files := tlsFiles(t)
	files.Flow = flowVision
	server, _ := fixtures(t, echoServer(t))
	sr := run(t, server, files)
	pool, _ := roots(files.CAPEM)
	for _, wrongID := range []bool{false, true} {
		c, err := tls.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", server.Node.Port), &tls.Config{RootCAs: pool, ServerName: "gateway.test"})
		if err != nil {
			t.Fatal(err)
		}
		c.SetDeadline(time.Now().Add(time.Second))
		id, _ := parseUUID(server.Bindings[0].UUID)
		host := "another.reverse.test"
		if wrongID {
			id[0] ^= 0xff
			host = server.Bindings[0].Domain
		}
		if err := writeVLESS(c, id, host, applicationPort, flowVision); err != nil {
			t.Fatal(err)
		}
		if err := readVLESSResponse(c); err == nil {
			t.Fatal("dedicated binding mismatch accepted")
		}
		c.Close()
	}
	sr.instance.mu.Lock()
	defer sr.instance.mu.Unlock()
	if len(sr.instance.applications["one"]) != 0 {
		t.Fatal("unauthorized pool insertion")
	}
}

func TestVisionCommand2DoesNotReleasePrematureContent(t *testing.T) {
	left, right, _ := visionOwnedPair(t, 128)
	id := [16]byte{1}
	reader := newApplicationVision(right, id)
	wire := append(append([]byte{}, id[:]...), 2, 0, 5, 0, 0)
	wire = append(wire, []byte("plain")...)
	if err := writeAll(left, wire); err != nil {
		t.Fatal(err)
	}
	if n, err := reader.Read(make([]byte, 32)); n != 0 || err == nil {
		t.Fatal("premature content escaped", n, err)
	}
}

func TestVisionOuterWriteGuard(t *testing.T) {
	left, _, _ := visionOwnedPair(t, 128)
	if err := left.switchWrite(); err != nil {
		t.Fatal(err)
	}
	if _, err := left.Conn.Write([]byte("late outer TLS alert")); err == nil {
		t.Fatal("outer TLS emitted after raw write handoff")
	}
}
