package tunnel

import (
	"crypto/rand"
	"errors"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"veilink/internal/model"
)

func xhttpMetaPlacement(value string) string {
	if value == "" {
		return "path"
	}
	return value
}

func xhttpMetaKey(key, fallback string) string {
	if key != "" {
		return key
	}
	return fallback
}

func xhttpSessionTable(x model.XHTTP) string {
	switch x.SessionIDTable {
	case "base62":
		return "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	case "hex":
		return "0123456789abcdef"
	default:
		return x.SessionIDTable
	}
}

func safeXHTTPMetaQueryKey(key string) bool {
	if len(key) == 0 || len(key) > 40 || key == "x_padding" {
		return false
	}
	for i := 0; i < len(key); i++ {
		c := key[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

func safeXHTTPMetaCookieKey(key string) bool {
	return strings.HasPrefix(key, "x_") && safeXHTTPMetaQueryKey(key)
}

func safeXHTTPMetaHeaderKey(key string) bool {
	if len(key) <= len("X-Veilink-") || len(key) > 48 || !strings.HasPrefix(key, "X-Veilink-") {
		return false
	}
	for i := len("X-Veilink-"); i < len(key); i++ {
		c := key[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	for _, reserved := range []string{"X-Veilink-EOF", "X-Veilink-Upload-Complete"} {
		if strings.EqualFold(key, reserved) {
			return false
		}
	}
	return true
}

func xhttpSessionKey(x model.XHTTP) string {
	if xhttpMetaPlacement(x.SessionIDPlacement) == "header" {
		return xhttpMetaKey(x.SessionIDKey, "X-Veilink-Session")
	}
	return xhttpMetaKey(x.SessionIDKey, "x_session")
}
func xhttpSequenceKey(x model.XHTTP) string {
	if xhttpMetaPlacement(x.SeqPlacement) == "header" {
		return xhttpMetaKey(x.SeqKey, "X-Veilink-Seq")
	}
	return xhttpMetaKey(x.SeqKey, "x_seq")
}

func checkXHTTPMeta(x model.XHTTP, mode string) error {
	for _, field := range []struct{ placement, key string }{{x.SessionIDPlacement, x.SessionIDKey}, {x.SeqPlacement, x.SeqKey}} {
		placement := xhttpMetaPlacement(field.placement)
		switch placement {
		case "path":
			if field.key != "" {
				return errors.New("xhttp path metadata cannot have a key")
			}
		case "query":
			if field.key != "" && !safeXHTTPMetaQueryKey(field.key) {
				return errors.New("invalid xhttp query metadata key")
			}
		case "cookie":
			if field.key != "" && !safeXHTTPMetaCookieKey(field.key) {
				return errors.New("xhttp metadata cookies must use a private x_ key")
			}
		case "header":
			if field.key != "" && !safeXHTTPMetaHeaderKey(field.key) {
				return errors.New("invalid xhttp metadata header key")
			}
		default:
			return errors.New("xhttp metadata placement must be path, query, header or cookie")
		}
	}
	if mode != "packet-up" && (x.SeqPlacement != "" || x.SeqKey != "") {
		return errors.New("xhttp sequence metadata requires packet-up")
	}
	if x.Mode == "stream-one" && (x.SessionIDPlacement != "" || x.SessionIDKey != "" || x.SessionIDTable != "" || x.SessionIDLength != 0) {
		return errors.New("xhttp stream-one has no session ID metadata")
	}
	if xhttpMetaPlacement(x.SessionIDPlacement) == xhttpMetaPlacement(x.SeqPlacement) && xhttpMetaPlacement(x.SessionIDPlacement) != "path" {
		if strings.EqualFold(xhttpSessionKey(x), xhttpSequenceKey(x)) {
			return errors.New("xhttp metadata keys must differ")
		}
	}
	if x.SessionIDTable == "" && x.SessionIDLength == 0 {
		return nil
	}
	if x.SessionIDTable == "" || x.SessionIDLength < 24 || x.SessionIDLength > 64 {
		return errors.New("xhttp custom session ID requires table and length 24-64")
	}
	table := xhttpSessionTable(x)
	if len(table) < 16 || len(table) > 64 || float64(x.SessionIDLength)*math.Log2(float64(len(table))) < 128 {
		return errors.New("xhttp session ID must retain at least 128 bits of entropy")
	}
	var seen [256]bool
	for i := 0; i < len(table); i++ {
		c := table[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') || seen[c] {
			return errors.New("xhttp session table must contain unique URL-safe ASCII characters")
		}
		seen[c] = true
	}
	return nil
}

func newXHTTPSessionIDFor(x model.XHTTP) (string, error) {
	if x.SessionIDTable == "" {
		return newXHTTPSessionID()
	}
	table := xhttpSessionTable(x)
	id := make([]byte, x.SessionIDLength)
	ceiling := 256 - 256%len(table)
	for i := range id {
		for {
			var b [1]byte
			if _, err := rand.Read(b[:]); err != nil {
				return "", err
			}
			if int(b[0]) < ceiling {
				id[i] = table[int(b[0])%len(table)]
				break
			}
		}
	}
	return string(id), nil
}

func validXHTTPSessionIDFor(id string, x model.XHTTP) bool {
	if x.SessionIDTable == "" {
		return validXHTTPSessionID(id)
	}
	if len(id) != x.SessionIDLength {
		return false
	}
	table := xhttpSessionTable(x)
	for i := 0; i < len(id); i++ {
		if !strings.ContainsRune(table, rune(id[i])) {
			return false
		}
	}
	return true
}

func xhttpMetaPath(base string, x model.XHTTP, id, seq string) string {
	if id != "" && xhttpMetaPlacement(x.SessionIDPlacement) == "path" {
		base += id
	}
	if seq != "" && xhttpMetaPlacement(x.SeqPlacement) == "path" {
		if !strings.HasSuffix(base, "/") {
			base += "/"
		}
		base += seq
	}
	return base
}

func xhttpSetMeta(req *http.Request, x model.XHTTP, id, seq string) {
	for _, field := range []struct{ placement, key, value string }{{x.SessionIDPlacement, xhttpSessionKey(x), id}, {x.SeqPlacement, xhttpSequenceKey(x), seq}} {
		if field.value == "" {
			continue
		}
		switch xhttpMetaPlacement(field.placement) {
		case "query":
			q := req.URL.Query()
			q.Set(field.key, field.value)
			req.URL.RawQuery = q.Encode()
		case "header":
			req.Header.Set(field.key, field.value)
		case "cookie":
			req.AddCookie(&http.Cookie{Name: field.key, Value: field.value})
		}
	}
}

// xhttpGetMeta consumes exactly the configured locations; no extra path,
// query, or reserved metadata headers may create an alternative identity.
func xhttpGetMeta(req *http.Request, x model.XHTTP, path string, withSequence bool) (string, string, error) {
	if req.URL.RawPath != "" || !strings.HasPrefix(req.URL.Path, path) {
		return "", "", errors.New("invalid xhttp path")
	}
	var parts []string
	if tail := strings.TrimPrefix(req.URL.Path, path); tail != "" {
		parts = strings.Split(tail, "/")
	}
	query, err := url.ParseQuery(req.URL.RawQuery)
	if err != nil {
		return "", "", errors.New("invalid xhttp query")
	}
	cookies := req.Cookies()
	if values := req.Header.Values("Cookie"); len(values) > 0 {
		if len(values) != 1 || len(cookies) != len(strings.Split(values[0], ";")) {
			return "", "", errors.New("invalid xhttp cookies")
		}
	}
	index := 0
	usedQuery := make(map[string]bool, 2)
	usedHeader := make(map[string]bool, 2)
	usedCookie := make(map[string]bool, 2)
	// Padding was validated independently before metadata extraction. Account for
	// precisely its configured location without accepting other query or cookies.
	if x.PaddingObfsMode && xhttpPaddingPlacement(x) == "query" {
		usedQuery[xhttpPaddingKey(x)] = true
	}
	if x.PaddingObfsMode && xhttpPaddingPlacement(x) == "cookie" {
		usedCookie[xhttpPaddingKey(x)] = true
	}
	if xhttpDataPlacement(x) == "cookie" {
		for _, c := range req.Cookies() {
			for i := 0; i < xhttpMaxDataChunks; i++ {
				if c.Name == xhttpDataCookieKey(x, i) {
					usedCookie[c.Name] = true
					break
				}
			}
		}
	}
	extract := func(placement, key string) (string, error) {
		switch xhttpMetaPlacement(placement) {
		case "path":
			if index >= len(parts) || parts[index] == "" {
				return "", errors.New("missing xhttp path metadata")
			}
			v := parts[index]
			index++
			return v, nil
		case "query":
			vs := query[key]
			if len(vs) != 1 || vs[0] == "" {
				return "", errors.New("invalid xhttp query metadata")
			}
			usedQuery[key] = true
			return vs[0], nil
		case "header":
			vs := req.Header.Values(key)
			if len(vs) != 1 || vs[0] == "" {
				return "", errors.New("invalid xhttp header metadata")
			}
			usedHeader[http.CanonicalHeaderKey(key)] = true
			return vs[0], nil
		case "cookie":
			var value string
			for _, cookie := range cookies {
				if cookie.Name == key {
					if value != "" || cookie.Value == "" {
						return "", errors.New("duplicate xhttp cookie")
					}
					value = cookie.Value
				}
			}
			if value == "" {
				return "", errors.New("missing xhttp cookie")
			}
			usedCookie[key] = true
			return value, nil
		}
		return "", errors.New("invalid xhttp metadata placement")
	}
	id, err := extract(x.SessionIDPlacement, xhttpSessionKey(x))
	if err != nil {
		return "", "", err
	}
	var seq string
	if withSequence {
		seq, err = extract(x.SeqPlacement, xhttpSequenceKey(x))
		if err != nil {
			return "", "", err
		}
	}
	if index != len(parts) || len(query) != len(usedQuery) || len(cookies) != len(usedCookie) {
		return "", "", errors.New("unexpected xhttp metadata")
	}
	for _, key := range []string{"X-Veilink-Session", "X-Veilink-Seq", xhttpSessionKey(x), xhttpSequenceKey(x)} {
		if !strings.HasPrefix(key, "X-Veilink-") {
			continue
		}
		if len(req.Header.Values(key)) > 0 && !usedHeader[http.CanonicalHeaderKey(key)] {
			return "", "", errors.New("unexpected xhttp metadata header")
		}
	}
	if !validXHTTPSessionIDFor(id, x) {
		return "", "", errors.New("invalid xhttp session")
	}
	if withSequence {
		n, err := strconv.ParseUint(seq, 10, 64)
		if err != nil || strconv.FormatUint(n, 10) != seq {
			return "", "", errors.New("invalid xhttp sequence")
		}
	}
	return id, seq, nil
}
