package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"golang.org/x/crypto/bcrypt"
)

func Token() string {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func Hash(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
func Password(s string) (string, error) {
	if len(s) < 12 || len(s) > 72 {
		return "", errors.New("password must contain 12 to 72 bytes")
	}
	b, e := bcrypt.GenerateFromPassword([]byte(s), bcrypt.DefaultCost)
	return string(b), e
}
func Check(hash, s string) bool { return bcrypt.CompareHashAndPassword([]byte(hash), []byte(s)) == nil }
func Seal(key []byte, s string) ([]byte, error) {
	b, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	a, e := cipher.NewGCM(b)
	if e != nil {
		return nil, e
	}
	n := make([]byte, a.NonceSize())
	if _, e = rand.Read(n); e != nil {
		return nil, e
	}
	return a.Seal(n, n, []byte(s), nil), nil
}
func Open(key, b []byte) (string, error) {
	c, e := aes.NewCipher(key)
	if e != nil {
		return "", e
	}
	a, e := cipher.NewGCM(c)
	if e != nil {
		return "", e
	}
	if len(b) < a.NonceSize() {
		return "", errors.New("invalid ciphertext")
	}
	p, e := a.Open(nil, b[:a.NonceSize()], b[a.NonceSize():], nil)
	return string(p), e
}
