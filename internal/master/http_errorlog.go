package master

import (
	"log"
	"log/slog"
	"strings"
)

// newHTTPErrorLog avoids the standard log -> slog INFO bridge. Only explicit
// remote certificate-rejection alerts are quieted; other server errors remain
// visible, including local certificate failures and handler panic stack traces.
func newHTTPErrorLog(logger *slog.Logger) *log.Logger {
	return log.New(httpErrorWriter{logger: logger}, "", 0)
}

type httpErrorWriter struct {
	logger *slog.Logger
}

func (w httpErrorWriter) Write(p []byte) (int, error) {
	message := strings.TrimSuffix(string(p), "\n")
	if strings.HasPrefix(message, "http: TLS handshake error from ") && !strings.ContainsAny(message, "\r\n") {
		for _, alert := range []string{"unknown certificate", "bad certificate", "certificate unknown"} {
			if strings.HasSuffix(message, ": remote error: tls: "+alert) {
				return len(p), nil
			}
		}
	}
	w.logger.Warn(message)
	return len(p), nil
}
