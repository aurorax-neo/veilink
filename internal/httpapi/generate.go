package httpapi

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"strings"
	"time"

	"veilink/internal/tunnel"
)

type generationRequest struct {
	Role           string `json:"role"`
	Kind           string `json:"kind"`
	Host           string `json:"host,omitempty"`
	Mode           string `json:"mode,omitempty"`
	Authentication string `json:"authentication,omitempty"`
	TTLDays        *int   `json:"ttl_days,omitempty"`
}

// generate is reached only after the administrator session and CSRF checks.
// Generated material is returned once, never logged or saved to the store.
func generate(w http.ResponseWriter, r *http.Request) {
	var in generationRequest
	if !decode(w, r, &in) {
		return
	}
	if in.Role != "server" ||
		(in.Kind != "vless" && (in.Mode != "" || in.Authentication != "")) ||
		(in.Kind != "certificate" && (in.Host != "" || in.TTLDays != nil)) {
		failure(w, http.StatusBadRequest)
		return
	}
	var result map[string]string
	var err error
	switch in.Kind {
	case "reality":
		var private, public, shortID string
		private, public, err = tunnel.GenerateX25519()
		if err == nil {
			shortID, err = generateShortID()
		}
		result = map[string]string{"private_key": private, "public_key": public, "short_id": shortID}
	case "short_id":
		var shortID string
		shortID, err = generateShortID()
		result = map[string]string{"short_id": shortID}
	case "mldsa65":
		var private, public string
		private, public, err = tunnel.GenerateMldsa65()
		result = map[string]string{"private_key": private, "public_key": public}
	case "spider_x":
		var spiderX string
		spiderX, err = tunnel.GenerateSpiderX()
		result = map[string]string{"spider_x": spiderX}
	case "vless":
		if in.Mode == "" {
			in.Mode = "native"
		}
		if in.Authentication == "" {
			in.Authentication = "x25519"
		}
		if (in.Mode != "native" && in.Mode != "xorpub" && in.Mode != "random") ||
			(in.Authentication != "x25519" && in.Authentication != "mlkem768") {
			failure(w, http.StatusBadRequest)
			return
		}
		var dec, enc, pqDec, pqEnc string
		dec, enc, pqDec, pqEnc, err = tunnel.GenerateVLESSEnc()
		if err == nil {
			if in.Authentication == "mlkem768" {
				dec, enc = pqDec, pqEnc
			}
			dec, err = generationVLESSMode(dec, in.Mode)
			if err == nil {
				enc, err = generationVLESSMode(enc, in.Mode)
			}
		}
		result = map[string]string{"decryption": dec, "encryption": enc}
	case "hysteria2":
		var password [32]byte
		_, err = rand.Read(password[:])
		result = map[string]string{"password": base64.RawURLEncoding.EncodeToString(password[:])}
	case "certificate":
		days := 30
		if in.TTLDays != nil {
			days = *in.TTLDays
		}
		if days < 1 || days > 365 || !validGenerationHost(in.Host) {
			failure(w, http.StatusBadRequest)
			return
		}
		result, err = generateCertificate(in.Host, days)
	default:
		failure(w, http.StatusBadRequest)
		return
	}
	if err != nil {
		failure(w, http.StatusInternalServerError)
		return
	}
	output(w, http.StatusOK, result)
}

func generateShortID() (string, error) {
	var id [8]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(id[:]), nil
}

// Change only the mode component, retaining the helper's scheme, ticket and key.
func generationVLESSMode(value, mode string) (string, error) {
	parts := strings.Split(value, ".")
	if len(parts) != 4 || parts[0] != "mlkem768x25519plus" || parts[1] != "native" ||
		(mode != "native" && mode != "xorpub" && mode != "random") {
		return "", errors.New("unexpected VLESS generation grammar")
	}
	parts[1] = mode
	return strings.Join(parts, "."), nil
}

func validGenerationHost(name string) bool {
	if net.ParseIP(name) != nil {
		return true
	}
	if len(name) == 0 || len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// This is local issuance, NOT a publicly trusted certificate. Clients must trust
// the returned ca_pem explicitly. The separate CA signing key is not returned.
func generateCertificate(name string, days int) (map[string]string, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial := func() (*big.Int, error) {
		n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		if err != nil {
			return nil, err
		}
		return n.Add(n, big.NewInt(1)), nil
	}
	caSerial, err := serial()
	if err != nil {
		return nil, err
	}
	leafSerial, err := serial()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC().Truncate(time.Second)
	expires := now.Add(time.Duration(days) * 24 * time.Hour)
	ca := &x509.Certificate{
		SerialNumber: caSerial,
		Subject:      pkix.Name{CommonName: "Veilink local generated CA"},
		NotBefore:    now.Add(-5 * time.Minute), NotAfter: expires,
		IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	ca, err = x509.ParseCertificate(caDER)
	if err != nil {
		return nil, err
	}
	leaf := &x509.Certificate{
		SerialNumber: leafSerial, Subject: pkix.Name{CommonName: name},
		NotBefore: now.Add(-5 * time.Minute), NotAfter: expires,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(name); ip != nil {
		leaf.IPAddresses = []net.IP{ip}
	} else {
		leaf.DNSNames = []string{name}
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		return nil, err
	}
	return map[string]string{
		"cert_pem":   string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})),
		"key_pem":    string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})),
		"ca_pem":     string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})),
		"expires_at": expires.Format(time.RFC3339),
	}, nil
}
