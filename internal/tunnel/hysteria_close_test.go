package tunnel

import (
	"context"
	"testing"
	"time"
)

func TestHysteriaGracefulCleanupBounded(t *testing.T) {
	for _, mode := range []string{"peer", "runtime", "timeout"} {
		t.Run(mode, func(t *testing.T) {
			runtime, cancelRuntime := context.WithCancel(context.Background())
			defer cancelRuntime()
			peer, cancelPeer := context.WithCancel(context.Background())
			defer cancelPeer()
			done := make(chan struct{})
			timeout := time.Hour
			if mode == "timeout" {
				timeout = 20 * time.Millisecond
			}
			go finishQUIC(runtime, peer, timeout, func() { close(done) })
			if mode != "timeout" {
				select {
				case <-done:
					t.Fatal("closed before peer consumed FIN or cancellation")
				case <-time.After(10 * time.Millisecond):
				}
			}
			switch mode {
			case "peer":
				cancelPeer()
			case "runtime":
				cancelRuntime()
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("cleanup did not finish")
			}
		})
	}
}
