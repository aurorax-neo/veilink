package tunnel

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"

	"veilink/internal/model"
)

// dialDiagnostics records operational dial state. Credentials, binding domains
// and raw errors stay out of the text because entries are forwarded to Master.
// The configured connect host and port are included so a NAT mapping can be
// checked from the node log.
type dialDiagnostics struct {
	mu       sync.Mutex
	logger   *slog.Logger
	state    map[string]dialStatus
	attempts map[string]int
}
type dialStatus struct {
	failing bool
	last    time.Time
}

func newDialDiagnostics(logger *slog.Logger) *dialDiagnostics {
	if logger == nil {
		return nil
	}
	return &dialDiagnostics{logger: logger, state: make(map[string]dialStatus), attempts: make(map[string]int)}
}

func (d *dialDiagnostics) noteAttempt(id string, attempt int) {
	if d == nil {
		return
	}
	d.mu.Lock()
	d.attempts[id] = attempt
	d.mu.Unlock()
}

func (d *dialDiagnostics) warnLimited(key, message string, args ...any) {
	if d == nil || d.logger == nil {
		return
	}
	d.mu.Lock()
	previous := d.state[key]
	now := time.Now()
	if previous.failing && now.Sub(previous.last) < 30*time.Second {
		d.mu.Unlock()
		return
	}
	d.state[key] = dialStatus{failing: true, last: now}
	d.mu.Unlock()
	d.logger.Warn(message, args...)
}

func (d *dialDiagnostics) report(ctx context.Context, b model.Binding, gateway model.Node, dialErr error) {
	failed := dialErr != nil
	if d == nil || ctx.Err() != nil {
		return
	}
	d.mu.Lock()
	previous := d.state[b.ID]
	attempt := d.attempts[b.ID]
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
	if attempt < 1 {
		attempt = 1
	}
	host, port := dialTarget(gateway)
	args := []any{"role", "client", "id", b.ID, "node_id", gateway.ID, "attempt", attempt}
	if host != "" && port > 0 {
		args = append(args, "addr", host, "port", port)
	}
	if failed {
		d.logger.Warn("client tunnel connection failed ("+dialFailureReason(dialErr)+"); backing off", args...)
	} else {
		d.logger.Info("client tunnel connected", args...)
	}
}

func dialTarget(gateway model.Node) (string, int) {
	endpoints := enabledEndpoints(gateway)
	if len(endpoints) == 1 {
		return endpoints[0].Host, endpoints[0].Port
	}
	if gateway.Address != "" && gateway.Port > 0 {
		return gateway.Address, gateway.Port
	}
	if len(endpoints) > 0 {
		return endpoints[0].Host, endpoints[0].Port
	}
	return "", 0
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
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return "peer_closed"
	default:
		message := err.Error()
		if strings.HasPrefix(message, "xhttp GET status ") {
			code := strings.TrimPrefix(message, "xhttp GET status ")
			if code != "" && len(code) <= 3 {
				return "xhttp_status_" + code
			}
		}
		return "transport_or_authentication"
	}
}

func retryWait(ctx context.Context, attempt int) bool {
	if attempt < 1 {
		attempt = 1
	}
	if attempt > 5 {
		attempt = 5
	}
	base := time.Second << (attempt - 1)
	return sleep(ctx, base)
}
