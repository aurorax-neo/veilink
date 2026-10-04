package tunnel

import "testing"

func TestDecodeFlowRejectsOverflowingLengths(t *testing.T) {
	for _, raw := range [][]byte{
		{0x0a, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01},
		{0x0a, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02},
		{0x0a, 0x80},
		{0x0a, 0x02, 'x'},
	} {
		if _, err := decodeFlow(raw); err == nil {
			t.Fatalf("malformed flow accepted: %x", raw)
		}
	}
	if got, err := decodeFlow(encodeFlow(flowVision)); err != nil || got != flowVision {
		t.Fatalf("valid flow rejected: %q %v", got, err)
	}
}

func FuzzDecodeFlow(f *testing.F) {
	f.Add(encodeFlow(flowVision))
	f.Add([]byte{0x0a, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01})
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) <= 255 {
			_, _ = decodeFlow(raw)
		}
	})
}
