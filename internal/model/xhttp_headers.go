package model

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// XHTTPHeaders is a comparable, canonical JSON object. An object, not a quoted
// JSON string, is used on the wire; this preserves LocalTLS equality checks.
type XHTTPHeaders string

func (h XHTTPHeaders) MarshalJSON() ([]byte, error) {
	if h == "" {
		return []byte("{}"), nil
	}
	return []byte(h), nil
}

func (h *XHTTPHeaders) UnmarshalJSON(data []byte) error {
	if len(data) > 2048 {
		return errors.New("xhttp headers exceed 2048 bytes")
	}
	if !utf8.Valid(data) || !validXHTTPJSONSurrogates(data) {
		return errors.New("xhttp headers contain invalid Unicode")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	token, err := dec.Token()
	if err != nil || token != json.Delim('{') {
		return errors.New("xhttp headers must be an object")
	}
	entries := map[string]string{}
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return err
		}
		name, ok := key.(string)
		if !ok || !safeXHTTPHeaderName(name) {
			return fmt.Errorf("unsafe xhttp header name %q", name)
		}
		name = http.CanonicalHeaderKey(name)
		if _, exists := entries[name]; exists {
			return fmt.Errorf("duplicate xhttp header %q", name)
		}
		var value string
		if err := dec.Decode(&value); err != nil {
			return errors.New("xhttp header values must be strings")
		}
		if len(value) == 0 || len(value) > 256 || !utf8.ValidString(value) || strings.TrimSpace(value) != value || strings.ContainsFunc(value, unicode.IsControl) {
			return fmt.Errorf("invalid xhttp header value for %q", name)
		}
		entries[name] = value
		if len(entries) > 8 {
			return errors.New("too many xhttp headers")
		}
	}
	if token, err = dec.Token(); err != nil || token != json.Delim('}') {
		return errors.New("invalid xhttp headers object")
	}
	if _, err = dec.Token(); err != io.EOF {
		return errors.New("trailing xhttp headers data")
	}
	if len(entries) == 0 {
		return errors.New("empty xhttp headers object must be omitted")
	}
	canonical, err := json.Marshal(entries)
	if err != nil {
		return err
	}
	if len(canonical) > 2048 {
		return errors.New("xhttp headers exceed 2048 bytes after normalization")
	}
	*h = XHTTPHeaders(canonical)
	return nil
}

// encoding/json replaces unpaired UTF-16 surrogates with U+FFFD; reject them
// before decoding instead of silently changing a configured header value.
func validXHTTPJSONSurrogates(data []byte) bool {
	for i := 0; i < len(data); i++ {
		if data[i] != '\\' || i+1 >= len(data) {
			continue
		}
		if data[i+1] != 'u' {
			i++ // An escaped backslash is not a Unicode escape.
			continue
		}
		if i+6 > len(data) {
			return false
		}
		code, err := strconv.ParseUint(string(data[i+2:i+6]), 16, 16)
		if err != nil {
			return false
		}
		i += 5
		if code >= 0xdc00 && code <= 0xdfff {
			return false
		}
		if code >= 0xd800 && code <= 0xdbff {
			if i+7 > len(data) || data[i+1] != '\\' || data[i+2] != 'u' {
				return false
			}
			next, err := strconv.ParseUint(string(data[i+3:i+7]), 16, 16)
			if err != nil || next < 0xdc00 || next > 0xdfff {
				return false
			}
			i += 6
		}
	}
	return true
}
func safeXHTTPHeaderName(name string) bool {
	if len(name) < 1 || len(name) > 64 {
		return false
	}
	lower := strings.ToLower(name)
	if lower == "user-agent" || lower == "accept-language" {
		return true
	}
	if !strings.HasPrefix(lower, "x-custom-") || len(lower) <= len("x-custom-") {
		return false
	}
	for _, c := range name[len("X-Custom-"):] {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// Entries rechecks values constructed directly in Go as well as JSON-decoded
// configuration. Callers must reject errors rather than accepting no-op input.
func (h XHTTPHeaders) Entries() (http.Header, error) {
	if h == "" {
		return http.Header{}, nil
	}
	var checked XHTTPHeaders
	if err := checked.UnmarshalJSON([]byte(h)); err != nil {
		return nil, err
	}
	if h != checked {
		return nil, errors.New("xhttp headers must use canonical JSON")
	}
	var entries map[string]string
	if err := json.Unmarshal([]byte(checked), &entries); err != nil {
		return nil, err
	}
	result := http.Header{}
	for key, value := range entries {
		result.Set(key, value)
	}
	return result, nil
}
