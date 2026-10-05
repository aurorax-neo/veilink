package tunnel

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"veilink/internal/model"
)

func TestRealityHandshakeBoundedAndCanceled(t *testing.T) {
	for _, cancelEarly := range []bool{false, true} {
		t.Run(fmt.Sprintf("cancel=%v", cancelEarly), func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			_, public, err := GenerateX25519()
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := make(chan error, 1)
			started := time.Now()
			go func() {
				conn, err := dialReality(ctx, ln.Addr().String(), "gateway.test", model.Reality{PublicKey: public, ShortID: "aa"})
				if conn != nil {
					conn.Close()
				}
				result <- err
			}()
			peer, err := ln.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer peer.Close()
			// Consume the hello, but never send a server handshake.
			peer.SetReadDeadline(time.Now().Add(time.Second))
			var hello [5]byte
			if _, err := io.ReadFull(peer, hello[:]); err != nil {
				t.Fatal(err)
			}
			want := context.DeadlineExceeded
			limit := 17 * time.Second
			if cancelEarly {
				cancel()
				want = context.Canceled
				limit = time.Second
			}
			select {
			case err := <-result:
				if !errors.Is(err, want) {
					t.Fatalf("handshake error = %v, want %v", err, want)
				}
				if !cancelEarly && time.Since(started) < 14*time.Second {
					t.Fatal("handshake expired before its configured timeout")
				}
			case <-time.After(limit):
				t.Fatal("unresponsive REALITY endpoint blocked recovery")
			}
		})
	}
}

func TestRealityConcurrentShortConnections(t *testing.T) {
	for _, vision := range []bool{false, true} {
		for _, mldsa := range []bool{false, true} {
			t.Run(fmt.Sprintf("vision=%v/mldsa=%v", vision, mldsa), func(t *testing.T) {
				files := tlsFiles(t)
				private, _, err := GenerateX25519()
				if err != nil {
					t.Fatal(err)
				}
				local := model.LocalTLS{Reality: model.Reality{PrivateKey: private, Dest: camouflage(t, files.CertPEM, files.KeyPEM, mldsa), ServerNames: "gateway.test", ShortIDs: "aa"}}
				if vision {
					local.Flow = flowVision
				}
				if mldsa {
					local.Reality.Mldsa65Seed, local.Reality.Mldsa65Verify, err = GenerateMldsa65()
					if err != nil {
						t.Fatal(err)
					}
				}
				s, c := fixtures(t, tlsApplicationTarget(t, files, tls.VersionTLS13))
				s.Mappings[0].Pool = 4
				other := s.Mappings[0]
				other.ID, other.Name, other.ListenPort = "other", "other", freePort(t)
				s.Mappings = append(s.Mappings, other)
				c.Mappings = append([]model.Mapping(nil), s.Mappings...)
				server, client := run(t, s, local), run(t, c, local)
				targets := []int{s.Mappings[0].TargetPort, tlsApplicationTarget(t, files, tls.VersionTLS13)}
				roots, err := roots(files.CAPEM)
				if err != nil {
					t.Fatal(err)
				}
				connect := func(port int) (*tls.Conn, error) {
					raw, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
					if err != nil {
						return nil, err
					}
					conn := tls.Client(raw, &tls.Config{RootCAs: roots, ServerName: "gateway.test", MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13})
					conn.SetDeadline(time.Now().Add(10 * time.Second))
					if err := conn.Handshake(); err != nil {
						conn.Close()
						return nil, err
					}
					return conn, nil
				}
				persistent, err := connect(other.ListenPort)
				if err != nil {
					t.Fatal(err)
				}
				defer persistent.Close()
				assertPersistentEcho(t, persistent)
				c = clone(*client.good)
				for round := 0; round < 4; round++ {
					var wg sync.WaitGroup
					for worker := 0; worker < 16; worker++ {
						wg.Add(1)
						go func() {
							defer wg.Done()
							conn, err := connect(s.Mappings[0].ListenPort)
							if err != nil {
								t.Error(err)
								return
							}
							defer conn.Close()
							payload := bytes.Repeat([]byte("short-connection"), 4096)
							got := make([]byte, len(payload))
							writeResult := make(chan error, 1)
							go func() { writeResult <- writeAll(conn, payload) }()
							_, readErr := io.ReadFull(conn, got)
							if err := <-writeResult; err != nil || readErr != nil || !bytes.Equal(got, payload) {
								t.Errorf("short flow corrupted: write=%v read=%v", err, readErr)
							}
						}()
					}
					wg.Wait()
					assertPersistentEcho(t, persistent)
					// Target edits must preserve the other mapping's live flow.
					s.Revision++
					c.Revision++
					s.Mappings[0].Name = fmt.Sprintf("round-%d", round)
					s.Mappings[0].TargetPort = targets[(round+1)%len(targets)]
					c.Mappings = append([]model.Mapping(nil), s.Mappings...)
					if err := server.Apply(s); err != nil {
						t.Fatal(err)
					}
					if err := client.Apply(c); err != nil {
						t.Fatal(err)
					}
					assertPersistentEcho(t, persistent)
				}
			})
		}
	}
}

func TestRealityHandshakeTimeoutAllowsEndpointFailover(t *testing.T) {
	files := tlsFiles(t)
	private, _, err := GenerateX25519()
	if err != nil {
		t.Fatal(err)
	}
	local := model.LocalTLS{Reality: model.Reality{PrivateKey: private, Dest: camouflage(t, files.CertPEM, files.KeyPEM), ServerNames: "gateway.test", ShortIDs: "aa"}}
	s, _ := fixtures(t, echoServer(t))
	server := run(t, s, local)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			accepted <- conn
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 18*time.Second)
	defer cancel()
	public := model.DeriveClientTunnel(local, s.Node)
	gateway := s.Node
	gateway.ConnectEndpoints = []model.ConnectEndpoint{
		{ID: "stalled", Host: "127.0.0.1", Port: ln.Addr().(*net.TCPAddr).Port, Enabled: true},
		{ID: "working", Host: "127.0.0.1", Port: s.Node.Port, Enabled: true},
	}
	peer, err := newClientGateway(model.LocalTLS{}, model.Node{Tunnel: public})
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		conn, err := (&service{ctx: ctx}).dialGateway(gateway, peer)
		if conn != nil {
			conn.Close()
		}
		result <- err
	}()
	select {
	case conn := <-accepted:
		defer conn.Close()
	case <-ctx.Done():
		t.Fatal("stalled endpoint was not dialed")
	}
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("working backup endpoint not reached: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("handshake blocked endpoint failover")
	}
	if server.instance.ctx.Err() != nil {
		t.Fatal("server stopped during failover")
	}
}

func TestBindingOwnerIndexWithdrawalAndReplacement(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	old := &service{ctx: ctx, byUser: map[string]model.Binding{"user": {ID: "old"}}}
	s := &service{}
	s.publishChildren(bindingServices{"old": old})
	if owner, _, ok := s.bindingOwner("user"); !ok || owner != old {
		t.Fatal("active owner not found")
	}
	cancel()
	if _, _, ok := s.bindingOwner("user"); ok {
		t.Fatal("stopped owner admitted authentication")
	}
	next := &service{ctx: context.Background(), byUser: map[string]model.Binding{"replacement": {ID: "new"}}}
	s.publishChildren(bindingServices{"new": next})
	if _, _, ok := s.bindingOwner("user"); ok {
		t.Fatal("withdrawn user remains authorized")
	}
	if owner, binding, ok := s.bindingOwner("replacement"); !ok || owner != next || binding.ID != "new" {
		t.Fatal("replacement not published")
	}
	s.publishChildren(bindingServices{})
	if _, _, ok := s.bindingOwner("replacement"); ok {
		t.Fatal("empty index admitted withdrawn user")
	}
}

func TestBindingOwnerIndexConcurrentPublication(t *testing.T) {
	first := &service{ctx: context.Background(), byUser: map[string]model.Binding{"first": {ID: "first"}}}
	second := &service{ctx: context.Background(), byUser: map[string]model.Binding{"second": {ID: "second"}}}
	s := &service{}
	s.publishChildren(bindingServices{"first": first})
	var readers sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 8; i++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			<-start
			for j := 0; j < 2000; j++ {
				for user, expected := range map[string]*service{"first": first, "second": second} {
					owner, binding, ok := s.bindingOwner(user)
					if ok && (owner != expected || binding.ID != user) {
						t.Errorf("authentication resolved to a foreign binding: %q", user)
						return
					}
				}
				if _, _, ok := s.bindingOwner("unknown"); ok {
					t.Error("unknown user admitted during publication")
					return
				}
			}
		}()
	}
	close(start)
	for i := 0; i < 2000; i++ {
		s.publishChildren(bindingServices{"second": second})
		s.publishChildren(bindingServices{})
		s.publishChildren(bindingServices{"first": first})
	}
	readers.Wait()
}

func BenchmarkBindingOwner(b *testing.B) {
	for _, count := range []int{1, 32, 1024} {
		b.Run(fmt.Sprintf("bindings=%d", count), func(b *testing.B) {
			children := bindingServices{}
			for i := 0; i < count; i++ {
				user := fmt.Sprintf("user-%d", i)
				children[user] = &service{ctx: context.Background(), byUser: map[string]model.Binding{user: {ID: user}}}
			}
			s := &service{}
			s.publishChildren(children)
			user := fmt.Sprintf("user-%d", count-1)
			b.Run("indexed", func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					if _, _, ok := s.bindingOwner(user); !ok {
						b.Fatal("authorized binding not found")
					}
				}
			})
			b.Run("previous-linear", func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					found := false
					for _, child := range *s.children.Load() {
						if _, ok := child.byUser[user]; ok && child.ctx.Err() == nil {
							found = true
							break
						}
					}
					if !found {
						b.Fatal("authorized binding not found")
					}
				}
			})
		})
	}
}
