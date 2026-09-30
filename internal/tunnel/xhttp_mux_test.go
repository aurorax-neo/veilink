package tunnel

import (
	"context"
	"net/http"
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
