package store

import (
	"strings"
	"testing"
	"veilink/internal/model"
)

func TestPEMFieldSizeLimit(t *testing.T) {
	cert, key := testPEM(t)
	if err := validateTunnel("client", model.LocalTLS{CAPEM: cert}); err != nil {
		t.Fatal(err)
	}
	oversizedCA := strings.Repeat(cert, (64<<10)/len(cert)+1)
	if err := validateTunnel("client", model.LocalTLS{CAPEM: oversizedCA}); err == nil {
		t.Fatal("oversized valid CA bundle accepted")
	}
	for _, local := range []model.LocalTLS{
		{TransportSecurity: "tls", CertPEM: strings.Repeat(cert, (64<<10)/len(cert)+1), KeyPEM: key},
		{TransportSecurity: "tls", CertPEM: cert, KeyPEM: key + strings.Repeat("\n", 64<<10)},
	} {
		if err := validateTunnel("server", local); err == nil {
			t.Fatal("oversized PEM accepted")
		}
	}
}
