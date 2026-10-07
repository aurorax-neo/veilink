package model

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"golang.org/x/crypto/sha3"
)

// ParseMldsa65Private preserves packed keys generated before seed-based storage.
func ParseMldsa65Private(value string) (*mldsa65.PrivateKey, error) {
	s := strings.TrimSpace(value)
	enc := base64.RawURLEncoding
	if strings.ContainsAny(s, "+/=") {
		enc = base64.StdEncoding
	}
	b, err := enc.DecodeString(s)
	if err != nil {
		return nil, errors.New("invalid ML-DSA-65 private key encoding")
	}
	if len(b) == mldsa65.SeedSize {
		_, private := mldsa65.NewKeyFromSeed((*[mldsa65.SeedSize]byte)(b))
		return private, nil
	}
	if len(b) != mldsa65.PrivateKeySize {
		return nil, errors.New("ML-DSA-65 requires a 32-byte seed or a legacy 4032-byte private key")
	}
	// FIPS 204: rho || K || tr || s1 || s2 || t0; eta=4, L=5, K=6.
	for _, v := range b[128 : 128+11*128] {
		if v&15 > 8 || v>>4 > 8 {
			return nil, errors.New("invalid legacy ML-DSA-65 secret coefficients")
		}
	}
	private := new(mldsa65.PrivateKey)
	if err := private.UnmarshalBinary(b); err != nil {
		return nil, err
	}
	public := private.Public().(*mldsa65.PublicKey)
	var tr [64]byte
	sha3.ShakeSum256(tr[:], public.Bytes())
	if !bytes.Equal(b[64:128], tr[:]) || !bytes.Equal(b, private.Bytes()) {
		return nil, errors.New("invalid legacy ML-DSA-65 public key digest")
	}
	if err := checkLegacyMldsa65Signature(private, public); err != nil {
		return nil, err
	}
	return private, nil
}

func checkLegacyMldsa65Signature(private *mldsa65.PrivateKey, public *mldsa65.PublicKey) (err error) {
	defer func() {
		if recover() != nil {
			err = errors.New("invalid legacy ML-DSA-65 signing key")
		}
	}()
	message := []byte("veilink legacy ML-DSA-65 key validation")
	signature := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(private, message, nil, false, signature); err != nil {
		return err
	}
	if !mldsa65.Verify(public, message, nil, signature) {
		return errors.New("invalid legacy ML-DSA-65 signing key")
	}
	return nil
}
