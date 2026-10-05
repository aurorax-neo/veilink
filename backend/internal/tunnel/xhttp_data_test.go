package tunnel

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"veilink/internal/model"
)

func TestXHTTPDataPlacementRoundtripAndBounds(t *testing.T) {
	for _, placement := range []string{"header", "cookie"} {
		t.Run(placement, func(t *testing.T) {
			x := model.XHTTP{Mode: "packet-up", UplinkDataPlacement: placement, UplinkChunkSize: 64}
			req := httptest.NewRequest(http.MethodPost, "https://edge.test/cdn/", bytes.NewReader(nil))
			payload := bytes.Repeat([]byte("data-"), 80)
			if err := xhttpEncodeData(req, payload, x); err != nil {
				t.Fatal(err)
			}
			if req.ContentLength != 0 {
				t.Fatal("encoded placement retained body")
			}
			got, err := xhttpDecodeData(req, x, 4096)
			if err != nil || !bytes.Equal(got, payload) {
				t.Fatalf("decode %s: %v", placement, err)
			}
		})
	}
	if err := checkXHTTPData(model.XHTTP{Mode: "stream-up", UplinkDataPlacement: "header"}, "stream-up"); err == nil {
		t.Fatal("stream accepted")
	}
	for _, x := range []model.XHTTP{{Mode: "packet-up", UplinkDataPlacement: "query"}, {Mode: "packet-up", UplinkDataPlacement: "header", UplinkDataKey: "Cookie"}, {Mode: "packet-up", UplinkDataPlacement: "cookie", UplinkDataKey: "data"}, {Mode: "packet-up", UplinkChunkSize: 63}, {Mode: "packet-up", UplinkChunkSize: 8193}} {
		if checkXHTTPData(x, "packet-up") == nil {
			t.Fatalf("invalid accepted: %+v", x)
		}
	}
}

func TestXHTTPDataChunkBoundaryAndSmuggling(t *testing.T) {
	for _, placement := range []string{"header", "cookie"} {
		t.Run(placement, func(t *testing.T) {
			x := model.XHTTP{Mode: "packet-up", UplinkDataPlacement: placement, UplinkChunkSize: 64}
			data := bytes.Repeat([]byte{255}, 1536) // exactly 32 encoded chunks
			request := func() *http.Request {
				r := httptest.NewRequest(http.MethodPost, "https://edge.test/x/", nil)
				if err := xhttpEncodeData(r, data, x); err != nil {
					t.Fatal(err)
				}
				return r
			}
			got, err := xhttpDecodeData(request(), x, len(data))
			if err != nil || !bytes.Equal(got, data) {
				t.Fatalf("32 chunks: %v", err)
			}
			for _, index := range []string{"32", "01", "-1", "bad"} {
				r := request()
				if placement == "header" {
					r.Header.Add(xhttpDataKey(x)+"-"+index, "AA")
				} else {
					r.AddCookie(&http.Cookie{Name: xhttpDataKey(x) + "_" + index, Value: "AA"})
				}
				if _, err := xhttpDecodeData(r, x, 4096); err == nil {
					t.Fatalf("invalid index %s accepted", index)
				}
			}
			r := request()
			r.ContentLength = -1
			r.Body = io.NopCloser(bytes.NewBufferString("hidden chunked body"))
			if _, err := xhttpReadData(r, x, 4096); err == nil {
				t.Fatal("chunked mixed body accepted")
			}
			for _, index := range []int{0, 31} {
				r = request()
				if placement == "header" {
					r.Header.Add(xhttpDataHeaderKey(x, index), "")
				} else {
					r.AddCookie(&http.Cookie{Name: xhttpDataCookieKey(x, index), Value: ""})
				}
				if _, err := xhttpDecodeData(r, x, 4096); err == nil {
					t.Fatal("empty duplicate accepted")
				}
			}
		})
	}
}

func TestXHTTPDataRejectsMalformedChunks(t *testing.T) {
	x := model.XHTTP{Mode: "packet-up", UplinkDataPlacement: "header", UplinkChunkSize: 64}
	req := httptest.NewRequest(http.MethodPost, "https://edge.test/cdn/", nil)
	req.Header.Set("X-Veilink-Data-0", "not_base64!")
	if _, err := xhttpDecodeData(req, x, 100); err == nil {
		t.Fatal("bad encoding accepted")
	}
	req = httptest.NewRequest(http.MethodPost, "https://edge.test/cdn/", nil)
	req.Header.Set("X-Veilink-Data-1", "AA")
	if _, err := xhttpDecodeData(req, x, 100); err == nil {
		t.Fatal("gap accepted")
	}
	req = httptest.NewRequest(http.MethodPost, "https://edge.test/cdn/", nil)
	req.Header.Add("X-Veilink-Data-0", "AA")
	req.Header.Add("X-Veilink-Data-0", "AA")
	if _, err := xhttpDecodeData(req, x, 100); err == nil {
		t.Fatal("duplicate accepted")
	}
}

func TestXHTTPDataRejectsMetadataAndPaddingCollisions(t *testing.T) {
	for _, placement := range []string{"header", "cookie"} {
		x := model.XHTTP{UplinkDataPlacement: placement}
		key := xhttpDataKey(x) + "_0"
		if placement == "header" {
			key = "X-Veilink-DATA-0"
		}
		for _, field := range []string{"session", "sequence", "padding"} {
			t.Run(placement+"/"+field, func(t *testing.T) {
				v := x
				switch field {
				case "session":
					v.SessionIDPlacement, v.SessionIDKey = placement, key
				case "sequence":
					v.SeqPlacement, v.SeqKey = placement, key
				case "padding":
					if placement != "cookie" {
						return // Padding headers are restricted to a disjoint namespace.
					}
					v.PaddingObfsMode, v.PaddingPlacement, v.PaddingKey = true, placement, key
				}
				if err := checkXHTTPData(v, "packet-up"); err == nil {
					t.Fatal("colliding configuration accepted")
				}
			})
		}
		if err := checkXHTTPData(x, "packet-up"); err != nil {
			t.Fatal("default keys rejected", err)
		}
	}
}
