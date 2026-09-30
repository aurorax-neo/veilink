package tunnel

import (
	"context"
	"crypto/x509"
	"errors"
	"log/slog"
	"net"
	"sync"
	"syscall"
	"time"

	"veilink/internal/model"
)

// dialDiagnostics deliberately excludes raw errors, endpoint addresses and
// credentials: node logs are forwarded to the Master through heartbeats.
type dialDiagnostics struct {
	mu     sync.Mutex
	logger *slog.Logger
	state  map[string]dialStatus
}
type dialStatus struct {
	failing bool
	last    time.Time
}

func newDialDiagnostics(logger *slog.Logger) *dialDiagnostics {
	if logger == nil {
		return nil
	}
	return &dialDiagnostics{logger: logger, state: make(map[string]dialStatus)}
}

func (d *dialDiagnostics) report(ctx context.Context, b model.Binding, gateway model.Node, dialErr error) {
	failed := dialErr != nil
	if d == nil || ctx.Err() != nil {
		return
	}
	d.mu.Lock()
	previous := d.state[b.ID]
	now := time.Now()
	if failed {
		if previous.failing && now.Sub(previous.last) < 30*time.Second {
			d.mu.Unlock()
			return
		}
		d.state[b.ID] = dialStatus{failing: true, last: now}
	} else {
		if !previous.failing {
			d.mu.Unlock()
			return
		}
		d.state[b.ID] = dialStatus{}
	}
	d.mu.Unlock()
	if failed {
		d.logger.Warn("client tunnel connection failed ("+dialFailureReason(dialErr)+"); retrying", "role", "client", "id", b.ID, "node_id", gateway.ID)
	} else {
		d.logger.Info("client tunnel connection restored", "role", "client", "id", b.ID, "node_id", gateway.ID)
	}
}

func dialFailureReason(err error) string {
	var certificate x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalid x509.CertificateInvalidError
	var network net.Error
	switch {
	case errors.As(err, &certificate), errors.As(err, &hostname), errors.As(err, &invalid):
		return "certificate"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "connection_refused"
	case errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EHOSTUNREACH):
		return "network_unreachable"
	case errors.As(err, &network) && network.Timeout():
		return "timeout"
	default:
		return "transport_or_authentication"
	}
}
