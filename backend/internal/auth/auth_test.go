package auth

import (
	"bytes"
	"testing"
)

func TestSecrets(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	b, e := Seal(key, "secret")
	if e != nil {
		t.Fatal(e)
	}
	v, e := Open(key, b)
	if e != nil || v != "secret" {
		t.Fatal("roundtrip")
	}
	b[len(b)-1] ^= 1
	if _, e = Open(key, b); e == nil {
		t.Fatal("tampered ciphertext accepted")
	}
	h, e := Password("long test password")
	if e != nil || !Check(h, "long test password") || Check(h, "wrong") {
		t.Fatal("password validation")
	}
	if _, e = Password("short"); e == nil {
		t.Fatal("weak password accepted")
	}
	if Hash(Token()) == Hash(Token()) {
		t.Fatal("token collision")
	}
}
