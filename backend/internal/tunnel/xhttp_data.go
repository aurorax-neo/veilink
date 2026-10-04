package tunnel

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"veilink/internal/model"
)

const xhttpMaxDataChunks = 32

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
		if !strings.HasPrefix(key, "X-Veilink-") || strings.ContainsAny(key, " \t\r\n") || strings.EqualFold(key, "X-Veilink-EOF") {
			return errors.New("xhttp header uplink data key must be a private X-Veilink header")
		}
	}
	if p == "cookie" {
		if key == "" {
			key = "x_data"
		}
		if !strings.HasPrefix(key, "x_") || strings.ContainsAny(key, " \t\r\n;=") {
			return errors.New("xhttp cookie uplink data key must use private x_ name")
		}
	}
	if x.UplinkChunkSize != 0 && (x.UplinkChunkSize < 64 || x.UplinkChunkSize > 8192) {
		return errors.New("xhttp uplink_chunk_size must be 64-8192")
	}
	return nil
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
	var parts []string
	for i := 0; i < xhttpMaxDataChunks; i++ {
		var v string
		if xhttpDataPlacement(x) == "header" {
			vs := req.Header.Values(xhttpDataHeaderKey(x, i))
			if len(vs) > 1 {
				return nil, errors.New("duplicate xhttp data header")
			}
			if len(vs) == 1 {
				v = vs[0]
			}
		} else {
			for _, c := range req.Cookies() {
				if c.Name == xhttpDataCookieKey(x, i) {
					if v != "" {
						return nil, errors.New("duplicate xhttp data cookie")
					}
					v = c.Value
				}
			}
		}
		if v == "" {
			break
		}
		parts = append(parts, v)
	}
	if len(parts) == 0 {
		if xhttpDataPlacement(x) == "header" {
			for i := 1; i < xhttpMaxDataChunks; i++ {
				if len(req.Header.Values(xhttpDataHeaderKey(x, i))) > 0 {
					return nil, errors.New("non-contiguous xhttp data headers")
				}
			}
		} else {
			for _, c := range req.Cookies() {
				if strings.HasPrefix(c.Name, xhttpDataKey(x)+"_") {
					return nil, errors.New("non-contiguous xhttp data cookies")
				}
			}
		}
		return nil, nil
	}
	if len(parts) == xhttpMaxDataChunks {
		return nil, errors.New("too many xhttp data chunks")
	}
	if xhttpDataPlacement(x) == "header" {
		for i := len(parts); i < xhttpMaxDataChunks; i++ {
			if len(req.Header.Values(xhttpDataHeaderKey(x, i))) > 0 {
				return nil, errors.New("non-contiguous xhttp data headers")
			}
		}
	} else {
		for _, c := range req.Cookies() {
			if strings.HasPrefix(c.Name, xhttpDataKey(x)+"_") {
				n, err := strconv.Atoi(strings.TrimPrefix(c.Name, xhttpDataKey(x)+"_"))
				if err != nil || n < 0 || n >= len(parts) {
					return nil, errors.New("non-contiguous xhttp data cookies")
				}
			}
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
