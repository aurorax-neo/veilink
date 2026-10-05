package tunnel

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"veilink/internal/model"
)

const xhttpMaxDataChunks = 32

var xhttpDataHeaderName = regexp.MustCompile(`^X-Veilink-[A-Za-z0-9-]{1,48}$`)
var xhttpDataCookieName = regexp.MustCompile(`^x_[a-z0-9_]{1,48}$`)

func xhttpDataPlacement(x model.XHTTP) string {
	if x.UplinkDataPlacement == "" {
		return "body"
	}
	return x.UplinkDataPlacement
}
func xhttpDataKey(x model.XHTTP) string {
	if x.UplinkDataKey != "" {
		return x.UplinkDataKey
	}
	if xhttpDataPlacement(x) == "header" {
		return "X-Veilink-Data"
	}
	return "x_data"
}
func xhttpDataChunkSize(x model.XHTTP) int {
	if x.UplinkChunkSize > 0 {
		return x.UplinkChunkSize
	}
	if xhttpDataPlacement(x) == "header" {
		return 4096
	}
	if xhttpDataPlacement(x) == "cookie" {
		return 3072
	}
	return xhttpPostMaximum(x)
}
func checkXHTTPData(x model.XHTTP, mode string) error {
	p, key := xhttpDataPlacement(x), x.UplinkDataKey
	if x.UplinkDataPlacement != "" && p != "body" && p != "header" && p != "cookie" {
		return errors.New("xhttp uplink_data_placement must be body, header or cookie")
	}
	if (x.UplinkDataPlacement != "" || key != "" || x.UplinkChunkSize != 0) && mode != "packet-up" {
		return errors.New("xhttp uplink data settings require packet-up")
	}
	if p == "header" {
		if key == "" {
			key = "X-Veilink-Data"
		}
		if !xhttpDataHeaderName.MatchString(key) || strings.EqualFold(key, "X-Veilink-EOF") {
			return errors.New("xhttp header uplink data key must be a private X-Veilink header")
		}
	}
	if p == "cookie" {
		if key == "" {
			key = "x_data"
		}
		if !xhttpDataCookieName.MatchString(key) {
			return errors.New("xhttp cookie uplink data key must use private x_ name")
		}
	}
	if x.UplinkChunkSize != 0 && (x.UplinkChunkSize < 64 || x.UplinkChunkSize > 8192) {
		return errors.New("xhttp uplink_chunk_size must be 64-8192")
	}
	if p == "body" && (key != "" || x.UplinkChunkSize != 0) {
		return errors.New("xhttp body placement cannot configure a data key or chunk size")
	}
	if p == "header" || p == "cookie" {
		prefix := xhttpDataKey(x) + "_"
		if p == "header" {
			prefix = strings.ToLower(xhttpDataKey(x) + "-")
		}
		for _, field := range []struct{ placement, key string }{
			{xhttpMetaPlacement(x.SessionIDPlacement), xhttpSessionKey(x)},
			{xhttpMetaPlacement(x.SeqPlacement), xhttpSequenceKey(x)},
			{"header", "X-Veilink-EOF"}, {"header", "X-Veilink-Upload-Complete"},
		} {
			name := field.key
			if p == "header" {
				name = strings.ToLower(name)
			}
			if field.placement == p && strings.HasPrefix(name, prefix) {
				return errors.New("xhttp data chunk keys collide with metadata")
			}
		}
		if p == "cookie" && x.PaddingObfsMode && xhttpPaddingPlacement(x) == "cookie" && strings.HasPrefix(xhttpPaddingKey(x), prefix) {
			return errors.New("xhttp data chunk keys collide with padding")
		}
	}
	if p != "body" && xhttpUploadLimit(x) == 0 {
		return errors.New("xhttp uplink data has no room within the request header budget")
	}
	return nil
}

// Reserve space for the URL, session/sequence metadata, padding and HTTP/2
// field overhead. Bound each POST by both the header budget and chunk count.
func xhttpUploadLimit(x model.XHTTP) int {
	if xhttpDataPlacement(x) == "body" {
		return xhttpPostMaximum(x)
	}
	budget := xhttpServerHeaderLimit(x) - 2048 - xhttpPaddingMaximum(x)
	headers, _ := x.Headers.Entries()
	for key, values := range headers {
		for _, value := range values {
			budget -= len(key) + len(value) + 36
		}
	}
	size := xhttpDataChunkSize(x)
	if size <= 0 || budget <= 0 {
		return 0
	}
	low, high := 0, xhttpPostMaximum(x)
	for low < high {
		n := low + (high-low+1)/2
		encoded := base64.RawURLEncoding.EncodedLen(n)
		chunks := (encoded + size - 1) / size
		cost := encoded + chunks*(len(xhttpDataKey(x))+40)
		if chunks <= xhttpMaxDataChunks && cost <= budget {
			low = n
		} else {
			high = n - 1
		}
	}
	return low
}

func xhttpReadData(req *http.Request, x model.XHTTP, max int) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(req.Body, int64(max)+1))
	if err != nil || xhttpDataPlacement(x) == "body" {
		return body, err
	}
	if len(body) != 0 || req.ContentLength > 0 {
		return nil, errors.New("xhttp data body must be empty")
	}
	return xhttpDecodeData(req, x, max)
}
func xhttpDataHeaderKey(x model.XHTTP, n int) string { return xhttpDataKey(x) + "-" + strconv.Itoa(n) }
func xhttpDataCookieKey(x model.XHTTP, n int) string { return xhttpDataKey(x) + "_" + strconv.Itoa(n) }
func xhttpEncodeData(req *http.Request, data []byte, x model.XHTTP) error {
	if xhttpDataPlacement(x) == "body" {
		return nil
	}
	enc := base64.RawURLEncoding.EncodeToString(data)
	size := xhttpDataChunkSize(x)
	if size <= 0 {
		return errors.New("invalid xhttp data chunk size")
	}
	if len(enc) == 0 {
		return nil
	}
	chunks := (len(enc) + size - 1) / size
	if chunks > xhttpMaxDataChunks {
		return errors.New("xhttp uplink data has too many chunks")
	}
	for i := 0; i < chunks; i++ {
		end := (i + 1) * size
		if end > len(enc) {
			end = len(enc)
		}
		part := enc[i*size : end]
		if xhttpDataPlacement(x) == "header" {
			req.Header.Set(xhttpDataHeaderKey(x, i), part)
		} else {
			req.AddCookie(&http.Cookie{Name: xhttpDataCookieKey(x, i), Value: part})
		}
	}
	req.Body = http.NoBody
	req.ContentLength = 0
	return nil
}
func xhttpDecodeData(req *http.Request, x model.XHTTP, max int) ([]byte, error) {
	if xhttpDataPlacement(x) == "body" {
		return nil, nil
	}
	chunks := make(map[int]string)
	add := func(index, value string) error {
		n, err := strconv.Atoi(index)
		if err != nil || n < 0 || n >= xhttpMaxDataChunks || strconv.Itoa(n) != index {
			return errors.New("invalid xhttp data chunk index")
		}
		if _, exists := chunks[n]; exists || value == "" || len(value) > xhttpDataChunkSize(x) {
			return errors.New("duplicate, empty or oversized xhttp data chunk")
		}
		chunks[n] = value
		return nil
	}
	if xhttpDataPlacement(x) == "header" {
		prefix := strings.ToLower(xhttpDataKey(x) + "-")
		for key, values := range req.Header {
			if strings.HasPrefix(strings.ToLower(key), prefix) {
				for _, value := range values {
					if err := add(key[len(prefix):], value); err != nil {
						return nil, err
					}
				}
			}
		}
	} else {
		prefix := xhttpDataKey(x) + "_"
		for _, cookie := range req.Cookies() {
			if strings.HasPrefix(cookie.Name, prefix) {
				if err := add(cookie.Name[len(prefix):], cookie.Value); err != nil {
					return nil, err
				}
			}
		}
	}
	parts := make([]string, len(chunks))
	for n := range parts {
		var exists bool
		parts[n], exists = chunks[n]
		if !exists {
			return nil, errors.New("non-contiguous xhttp data chunks")
		}
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.Join(parts, ""))
	if err != nil {
		return nil, errors.New("invalid xhttp uplink data encoding")
	}
	if len(raw) > max {
		return nil, fmt.Errorf("xhttp uplink data exceeds %d bytes", max)
	}
	return raw, nil
}
