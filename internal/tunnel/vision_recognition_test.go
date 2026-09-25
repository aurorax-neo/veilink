package tunnel

import (
	"bytes"
	"testing"
)

func structuralHello(kind byte) []byte {
	p := append([]byte{3, 3}, make([]byte, 32)...)
	p = append(p, 0) // empty session ID
	if kind == 1 {
		p = append(p, 0, 2, 0x13, 1, 1, 0, 0, 7, 0, 43, 0, 3, 2, 3, 4)
	} else {
		p = append(p, 0x13, 1, 0, 0, 6, 0, 43, 0, 2, 3, 4)
	}
	return p
}

func recognitionRecord(kind byte, p []byte) []byte {
	return append([]byte{kind, 3, 3, byte(len(p) >> 8), byte(len(p))}, p...)
}
func recognitionHello(kind byte, p []byte) []byte {
	return recognitionRecord(22, append([]byte{kind, 0, byte(len(p) >> 8), byte(len(p))}, p...))
}

func TestVisionStructuralRecognition(t *testing.T) {
	ch, sh := structuralHello(1), structuralHello(2)
	if parseVisionHello(1, ch) == nil || parseVisionHello(2, sh) == nil {
		t.Fatal("valid structural hellos rejected")
	}
	for _, kind := range []byte{1, 2} {
		valid := structuralHello(kind)
		for n := 0; n < len(valid); n++ {
			if parseVisionHello(kind, valid[:n]) != nil {
				t.Fatalf("truncated hello accepted at %d", n)
			}
		}
		// A TLS1.3-looking pattern inside random is not a supported_versions extension.
		bad := append([]byte{}, valid...)
		copy(bad[2:], []byte{0, 43, 0, 2, 3, 4})
		bad[len(bad)-1] = 3
		if parseVisionHello(kind, bad) != nil {
			t.Fatal("random-field version injection")
		}
		bad = append(append([]byte{}, valid...), 0)
		if parseVisionHello(kind, bad) != nil {
			t.Fatal("trailing hello byte accepted")
		}
	}
	r := &tlsRecognition{}
	for dir, wire := range [][]byte{recognitionHello(1, ch), recognitionHello(2, sh)} {
		for _, b := range wire {
			r.observe(dir, []byte{b})
		}
	}
	if r.eligible(0) || r.eligible(1) {
		t.Fatal("hello alone permitted direct-copy")
	}
	app := recognitionRecord(23, bytes.Repeat([]byte{0xab}, 32))
	r.observe(0, app[:len(app)-1])
	if r.eligible(0) {
		t.Fatal("partial inner record permitted direct-copy")
	}
	r.observe(0, app[len(app)-1:])
	if !r.eligible(0) || r.eligible(1) {
		t.Fatal("directional recognition lost")
	}
	r.observe(1, app)
	if !r.eligible(1) {
		t.Fatal("duplex recognition lost")
	}
	r = &tlsRecognition{}
	r.observe(0, recognitionHello(1, ch))
	r.observe(0, recognitionHello(2, sh))
	if !r.fallback(0) {
		t.Fatal("same direction supplied both hellos")
	}
	r = &tlsRecognition{}
	r.observe(0, make([]byte, 129<<10))
	if !r.fallback(0) {
		t.Fatal("recognition budget unbounded")
	}
}
