package master

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"veilink/internal/logring"
)

func TestHTTPErrorLogFiltering(t *testing.T) {
	const prefix = "http: TLS handshake error from 127.0.0.1:12345: "
	for _, tc := range []struct {
		name    string
		message string
		quiet   bool
	}{
		{"unknown certificate", prefix + "remote error: tls: unknown certificate", true},
		{"bad certificate", prefix + "remote error: tls: bad certificate", true},
		{"certificate unknown", prefix + "remote error: tls: certificate unknown", true},
		{"local certificate error", prefix + "tls: bad certificate", false},
		{"other remote alert", prefix + "remote error: tls: internal error", false},
		{"EOF", prefix + "EOF", false},
		{"not TLS handshake", "http: panic serving client: remote error: tls: bad certificate", false},
		{"suffix not exact", prefix + "remote error: tls: bad certificate: additional failure", false},
		{"multiline", prefix + "failure\n: remote error: tls: bad certificate", false},
		{"panic stack", "http: panic serving client: broken\ngoroutine 1 [running]:\nstack", false},
		{"accept failure", "http: Accept error: too many open files; retrying", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ring := logring.New(10)
			logger := slog.New(logring.NewHandler(ring, "master", slog.NewTextHandler(io.Discard, nil)))
			newHTTPErrorLog(logger).Print(tc.message)
			entries := ring.Query("", "", "", 10)
			if tc.quiet {
				if len(entries) != 0 {
					t.Fatalf("refused certificate entered console: %+v", entries)
				}
				return
			}
			if len(entries) != 1 || entries[0].Level != "WARN" || entries[0].Source != "master" || entries[0].Message != tc.message {
				t.Fatalf("expected intact Master WARN, got %+v", entries)
			}
		})
	}
}

func TestHTTPErrorLogUntrustedTLS(t *testing.T) {
	ring := logring.New(10)
	logger := slog.New(logring.NewHandler(ring, "master", slog.NewTextHandler(io.Discard, nil)))
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	server.Config.ErrorLog = newHTTPErrorLog(logger)
	server.StartTLS()
	defer server.Close()

	// An empty trust store must reject the test server's self-signed certificate.
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: x509.NewCertPool()}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	resp, err := client.Get(server.URL)
	if err == nil {
		resp.Body.Close()
		t.Fatal("untrusted certificate unexpectedly accepted")
	}
	// The trusted client still works; filtering does not relax TLS verification.
	resp, err = server.Client().Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("trusted request status: %d", resp.StatusCode)
	}
	server.Close() // Wait for handshake handlers before checking the log ring.
	if entries := ring.Query("", "", "", 10); len(entries) != 0 {
		t.Fatalf("untrusted handshake entered console: %+v", entries)
	}
}
