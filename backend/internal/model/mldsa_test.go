package model

import (
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

func TestLegacyMldsa65Private(t *testing.T) {
	public, private, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	packed := private.Bytes()
	encoded := base64.RawURLEncoding.EncodeToString(packed)
	if DeriveMldsa65Verify(encoded) != base64.RawURLEncoding.EncodeToString(public.Bytes()) {
		t.Fatal("legacy signing identity changed")
	}
	for _, offset := range []int{0, 64, 128, 1536} {
		bad := append([]byte(nil), packed...)
		if offset == 1536 {
			clear(bad[offset:])
		} else {
			bad[offset] ^= 0xff
		}
		if _, err := ParseMldsa65Private(base64.RawURLEncoding.EncodeToString(bad)); err == nil {
			t.Fatalf("accepted corrupted key at %d", offset)
		}
	}
}
