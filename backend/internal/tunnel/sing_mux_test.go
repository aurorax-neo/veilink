package tunnel

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	mux "github.com/metacubex/sing-mux"
	M "github.com/metacubex/sing/common/metadata"
	"veilink/internal/model"
)

func TestSingMuxProtocolAuthorization(t *testing.T) {
	for want := range singKinds {
		for got := range singKinds {
			a, b := net.Pipe()
			go func() {
				defer b.Close()
				wire := mux.EncodeRequest(mux.Request{Version: mux.Version0, Protocol: byte(got)}, nil)
				defer wire.Release()
				b.Write(wire.Bytes())
			}()
			checked, err := checkSingRequest(a, byte(want))
			if (err == nil) != (want == got) {
				t.Fatalf("want %d got %d: %v", want, got, err)
			}
			if err == nil {
				req, e := mux.ReadRequest(checked)
				if e != nil || req.Protocol != byte(got) {
					t.Fatal("request replay", e)
				}
			}
			a.Close()
		}
	}
}

func TestSingMuxTargetAuthorization(t *testing.T) {
	snap, _ := fixtures(t, 80)
	m := &snap.Mappings[0]
	m.Mux = true
	m.MuxType = model.MuxTypeSMux
	s := &service{snapshot: snap}
	if !s.singTargetAllowed(m.BindingID, model.MuxTypeSMux, m.TargetHost, 80) {
		t.Fatal("authorized target denied")
	}
	for _, tc := range []struct {
		binding, kind, host string
		port                int
	}{
		{"foreign", model.MuxTypeSMux, m.TargetHost, 80},
		{m.BindingID, model.MuxTypeYAMux, m.TargetHost, 80},
		{m.BindingID, model.MuxTypeSMux, "example.org", 80},
		{m.BindingID, model.MuxTypeSMux, m.TargetHost, 81},
	} {
		if s.singTargetAllowed(tc.binding, tc.kind, tc.host, tc.port) {
			t.Fatal("unauthorized target accepted", tc)
		}
	}
	s.snapshot.Mappings[0].Network = "udp"
	if s.singTargetAllowed(m.BindingID, model.MuxTypeSMux, m.TargetHost, 80) {
		t.Fatal("UDP mapping authorized TCP")
	}
}

func TestSingMuxRejectWireTargetsAndUDP(t *testing.T) {
	for _, kind := range singKinds {
		t.Run(kind, func(t *testing.T) {
			local := tlsFiles(t)
			s, c := fixtures(t, echoServer(t))
			s.Mappings[0].Mux = true
			s.Mappings[0].MuxType = kind
			c.Mappings = append([]model.Mapping(nil), s.Mappings...)
			server := run(t, s, local)
			run(t, c, local)
			awaitEcho(t, s.Mappings[0].ListenPort)
			pool := testBindingService(server.instance, s.Bindings[0].ID).singPools[singKey(s.Bindings[0].ID, kind)]
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			stream, err := pool.client.DialContext(ctx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", 1))
			if err == nil {
				defer stream.Close()
				stream.Write(nil)
				done := make(chan error, 1)
				go func() { var b [1]byte; _, e := stream.Read(b[:]); done <- e }()
				select {
				case e := <-done:
					if e == nil {
						t.Fatal("unauthorized target accepted")
					}
				case <-ctx.Done():
					t.Fatal("rejection hung")
				}
			}
			if kind == model.MuxTypeH2Mux {
				if _, e := pool.client.DialContext(ctx, "udp", M.ParseSocksaddrHostPort(s.Mappings[0].TargetHost, uint16(s.Mappings[0].TargetPort))); e == nil {
					t.Fatal("UDP accepted")
				}
				return
			}
			if _, e := pool.ListenPacket(ctx, M.ParseSocksaddrHostPort(s.Mappings[0].TargetHost, uint16(s.Mappings[0].TargetPort))); e == nil {
				t.Fatal("UDP accepted")
			}
			// Also exercise the upstream wire request, bypassing the public
			// scheduler's TCP-only guard. The receiving handler must reject it.
			pool.mu.Lock()
			upstream := pool.lanes[0].client.(*mux.Client)
			pool.mu.Unlock()
			packet, err := upstream.ListenPacket(ctx, M.ParseSocksaddrHostPort(s.Mappings[0].TargetHost, uint16(s.Mappings[0].TargetPort)))
			if err != nil {
				t.Fatal(err)
			}
			defer packet.Close()
			packet.SetDeadline(time.Now().Add(time.Second))
			packet.WriteTo([]byte("denied"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: s.Mappings[0].TargetPort})
			var b [32]byte
			if _, _, e := packet.ReadFrom(b[:]); e == nil {
				t.Fatal("wire UDP accepted")
			}
		})
	}
}

func TestSingMuxHalfCloseDelayedResponse(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			go func() {
				defer c.Close()
				data, e := io.ReadAll(c)
				if e == nil {
					c.Write(data)
				}
			}()
		}
	}()
	for _, kind := range singKinds {
		t.Run(kind, func(t *testing.T) {
			local := tlsFiles(t)
			s, c := fixtures(t, ln.Addr().(*net.TCPAddr).Port)
			s.Mappings[0].Mux = true
			s.Mappings[0].MuxType = kind
			c.Mappings = append([]model.Mapping(nil), s.Mappings...)
			run(t, s, local)
			run(t, c, local)
			if err := exchange(s.Mappings[0].ListenPort, bytes.Repeat([]byte("half-close"), 100000), true); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSingMuxDisconnectRebuildAndCancel(t *testing.T) {
	for _, kind := range singKinds {
		t.Run(kind, func(t *testing.T) {
			local := tlsFiles(t)
			s, c := fixtures(t, echoServer(t))
			s.Mappings[0].Mux = true
			s.Mappings[0].MuxType = kind
			c.Mappings = append([]model.Mapping(nil), s.Mappings...)
			server := run(t, s, local)
			client := run(t, c, local)
			c.Nodes = clone(*client.good).Nodes
			awaitEcho(t, s.Mappings[0].ListenPort)
			old := testBindingService(client.instance, s.Bindings[0].ID)
			old.mu.Lock()
			conns := make([]net.Conn, 0, len(old.conns))
			for conn := range old.conns {
				conns = append(conns, conn)
			}
			old.mu.Unlock()
			for _, conn := range conns {
				conn.Close()
			}
			awaitEcho(t, s.Mappings[0].ListenPort)
			c.Revision++
			c.Mappings[0].Pool = 2
			if e := client.Apply(c); e != nil {
				t.Fatal(e)
			}
			if old.ctx.Err() != nil {
				t.Fatal("pool resize canceled service")
			}
			awaitEcho(t, s.Mappings[0].ListenPort)
			done := make(chan struct{})
			go func() { client.Close(); server.Close(); close(done) }()
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("close blocked")
			}
		})
	}
}
