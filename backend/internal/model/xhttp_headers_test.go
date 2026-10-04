package model

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestXHTTPHeadersStrictObject(t *testing.T) {
	var x XHTTP
	good := `{"path":"/x/","mode":"packet-up","headers":{"x-custom-route":"east","User-Agent":"veilink-test"}}`
	if err := json.Unmarshal([]byte(good), &x); err != nil {
		t.Fatal(err)
	}
	if x.Headers == "" || !strings.Contains(string(x.Headers), `"X-Custom-Route":"east"`) {
		t.Fatalf("not canonical: %s", x.Headers)
	}
	wire, err := json.Marshal(x)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(wire), `"headers":{"User-Agent":"veilink-test","X-Custom-Route":"east"}`) {
		t.Fatalf("wrong JSON shape: %s", wire)
	}
	var restored XHTTP
	if err := json.Unmarshal(wire, &restored); err != nil || restored != x {
		t.Fatalf("roundtrip: %v %+v", err, restored)
	}
	for name, raw := range map[string]string{
		"duplicate_case":  `{"X-Custom-Key":"a","x-custom-key":"b"}`,
		"duplicate_exact": `{"X-Custom-Key":"a","X-Custom-Key":"b"}`,
		"host":            `{"Host":"evil.example"}`,
		"csrf":            `{"X-CSRF-Token":"bad"}`,
		"cookie":          `{"Cookie":"session=bad"}`,
		"forwarded":       `{"X-Forwarded-For":"127.0.0.1"}`,
		"referer":         `{"Referer":"bad"}`,
		"empty":           `{}`,
		"null":            `null`,
		"value_number":    `{"X-Custom-Key":42}`,
		"control":         `{"X-Custom-Key":"line\r\nsecond"}`,
		"c1_control":      `{"X-Custom-Key":"\u0085"}`,
		"unpaired_high":   `{"X-Custom-Key":"\ud800"}`,
		"unpaired_low":    `{"X-Custom-Key":"\udc00"}`,
		"wrong_pair":      `{"X-Custom-Key":"\ud800\ud800"}`,
		"invalid_utf8":    string([]byte{'{', '"', 'X', '-', 'C', 'u', 's', 't', 'o', 'm', '-', 'K', 'e', 'y', '"', ':', '"', 0xff, '"', '}'}),
		"too_many":        `{"X-Custom-1":"1","X-Custom-2":"2","X-Custom-3":"3","X-Custom-4":"4","X-Custom-5":"5","X-Custom-6":"6","X-Custom-7":"7","X-Custom-8":"8","X-Custom-9":"9"}`,
		"too_long":        `{"X-Custom-Key":"` + strings.Repeat("x", 257) + `"}`,
		"oversize":        `{"X-Custom-Key":"` + strings.Repeat("x", 2050) + `"}`,
	} {
		t.Run(name, func(t *testing.T) {
			var h XHTTPHeaders
			if err := json.Unmarshal([]byte(raw), &h); err == nil {
				t.Fatalf("accepted %s", raw)
			}
		})
	}
	var paired XHTTPHeaders
	if err := json.Unmarshal([]byte(`{"X-Custom-Key":"\ud83d\ude00"}`), &paired); err != nil {
		t.Fatalf("valid surrogate pair rejected: %v", err)
	}
	var escaped XHTTPHeaders
	if err := json.Unmarshal([]byte(`{"X-Custom-Key":"\\ud800"}`), &escaped); err != nil {
		t.Fatalf("escaped backslash rejected: %v", err)
	}
	var expanded XHTTPHeaders
	var longObject strings.Builder
	longObject.WriteByte('{')
	for i := 0; i < 8; i++ {
		if i > 0 {
			longObject.WriteByte(',')
		}
		longObject.WriteString(`"X-Custom-` + string(rune('A'+i)) + `":"` + strings.Repeat("<", 220) + `"`)
	}
	longObject.WriteByte('}')
	if len(longObject.String()) > 2048 {
		t.Fatal("fixture too large before normalization")
	}
	if err := json.Unmarshal([]byte(longObject.String()), &expanded); err == nil {
		t.Fatal("expanded canonical headers exceeded budget")
	}
	if _, err := (XHTTPHeaders(`{"x-custom-key":"ok"}`)).Entries(); err == nil {
		t.Fatal("direct noncanonical construction accepted")
	}
}
