package store

import (
	"errors"
	"strings"
	"testing"

	"veilink/internal/model"
)

func TestCAPEMRejectsSkippedMalformedPrefixes(t *testing.T) {
	s, _, _ := testStore(t)
	n := testNode(t, s, "server", "gateway")
	cert, private := testPEM(t)
	second, _ := testPEM(t)
	// Generated certificate bundles, including CRLF and whitespace separators,
	// remain valid and are distributed unchanged.
	for _, chain := range []string{cert + second, " \n" + strings.ReplaceAll(cert, "\n", "\r\n") + "\n\t" + second + "\n"} {
		n.Tunnel.CAPEM = chain
		n.ClientTunnel = nil
		saved, err := s.SaveNode(n)
		if err != nil || saved.ClientTunnel == nil || saved.ClientTunnel.CAPEM != chain {
			t.Fatal("valid generated chain rejected", err)
		}
		n = saved
	}
	var before string
	if err := s.db.QueryRow("SELECT data FROM config WHERE id=1").Scan(&before); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		"-----BEGIN CERTIFICATE-----\nprivate deployment secret!\n" + cert,
		"-----BEGIN CERTIFICATE-----\n" + private + cert,
		"-----BEGIN CERTIFICATE-----\nnot base64!\n-----END CERTIFICATE-----\n" + cert,
		cert + "-----BEGIN CERTIFICATE-----\nprivate deployment secret!\n" + second,
	} {
		for _, clientTemplate := range []bool{false, true} {
			candidate := n
			candidate.ClientTunnel = nil
			if clientTemplate {
				candidate.ClientTunnel = &model.LocalTLS{TransportSecurity: "tls", CAPEM: bad}
			} else {
				candidate.Tunnel.CAPEM = bad
			}
			if _, err := s.SaveNode(candidate); !errors.Is(err, ErrInvalid) {
				t.Fatalf("malformed CA accepted (client=%t): %v", clientTemplate, err)
			}
			var after string
			if err := s.db.QueryRow("SELECT data FROM config WHERE id=1").Scan(&after); err != nil || before != after {
				t.Fatal("invalid CA changed database", err)
			}
		}
	}
}
