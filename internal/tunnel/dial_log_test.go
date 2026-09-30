package tunnel

import (
	"context"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"veilink/internal/logring"
	"veilink/internal/model"
)

func TestDialDiagnosticsThrottleRecoveryAndRedaction(t *testing.T) {
	ring := logring.New(20)
	log := newDialDiagnostics(slog.New(logring.NewHandler(ring, "node", slog.NewTextHandler(io.Discard, nil))))
	b := model.Binding{ID: "binding-1", UUID: "private-credential", Domain: "private.domain"}
	gateway := model.Node{ID: "server-1", Address: "private.address"}
	var wg sync.WaitGroup
	for range 40 {
		wg.Go(func() { log.report(context.Background(), b, gateway, io.EOF) })
	}
	wg.Wait()
	if got := ring.Query("", "", "", 20); len(got) != 1 {
		t.Fatalf("failure log count %d", len(got))
	}
	log.report(context.Background(), b, gateway, nil)
	log.report(context.Background(), b, gateway, nil)
	log.report(context.Background(), b, gateway, io.EOF)
	entries := ring.Query("", "", "", 20)
	if len(entries) != 3 {
		t.Fatalf("transition count %d", len(entries))
	}
	for _, e := range entries {
		if strings.Contains(e.Message, b.UUID) || strings.Contains(e.Message, b.Domain) || strings.Contains(e.Message, gateway.Address) {
			t.Fatal("sensitive value logged")
		}
	}
	log.report(context.Background(), b, gateway, nil)
	log.mu.Lock()
	log.state[b.ID] = dialStatus{failing: true, last: time.Now().Add(-time.Minute)}
	log.mu.Unlock()
	log.report(context.Background(), b, gateway, io.EOF)
	if got := len(ring.Query("", "", "", 20)); got != 5 {
		t.Fatalf("throttle interval count %d", got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	log.report(ctx, b, gateway, io.EOF)
	if got := len(ring.Query("", "", "", 20)); got != 5 {
		t.Fatalf("canceled dial logged: %d", got)
	}
}

func TestMappingLabelDoesNotChangeRuntimeConfiguration(t *testing.T) {
	s, _ := fixtures(t, 8080)
	next := clone(s)
	next.Mappings[0].Name = "new label"
	if !sameConfiguration(s, next) {
		t.Fatal("mapping label rebuilt runtime")
	}
	next.Mappings[0].TargetPort++
	if sameConfiguration(s, next) {
		t.Fatal("target change ignored")
	}
	if s.Mappings[0].Name != "echo" {
		t.Fatal("canonical comparison mutated caller")
	}
}

func TestClientFailedDialReachesNodeLog(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	ring := logring.New(10)
	r := New(model.LocalTLS{})
	r.SetDialLogger(slog.New(logring.NewHandler(ring, "node", slog.NewTextHandler(io.Discard, nil))))
	defer r.Close()
	b := model.Binding{ID: "binding-1", ServerID: "server-1", ClientID: "client-1", Domain: "reverse.test", UUID: "e2587f5e-b746-4e68-a131-184984fa56a0"}
	gateway := model.Node{ID: b.ServerID, Role: "server", Address: "127.0.0.1", Port: port, Tunnel: model.LocalTLS{TransportSecurity: "tls", ListenPort: port}}
	client := model.Snapshot{Revision: 1, Node: model.Node{ID: b.ClientID, Role: "client"}, Nodes: []model.Node{gateway}, Bindings: []model.Binding{b}}
	if err := r.Apply(client); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if entries := ring.Query("node", "", "WARN", 10); len(entries) > 0 {
			if !strings.Contains(entries[0].Message, "connection_refused") || strings.Contains(entries[0].Message, strconv.Itoa(port)) || strings.Contains(entries[0].Message, b.UUID) {
				t.Fatalf("unsafe or missing diagnostic: %+v", entries)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("client dial failure was not logged")
}
