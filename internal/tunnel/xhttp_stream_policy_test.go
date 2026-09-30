package tunnel

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"veilink/internal/model"
)

func TestXHTTPStreamPolicyRanges(t *testing.T) {
	for i := 0; i < 100; i++ {
		d := xhttpStreamPolicyInterval(model.XHTTP{})
		if d < 20*time.Second || d > 80*time.Second {
			t.Fatal(d)
		}
	}
	if d := xhttpStreamPolicyInterval(model.XHTTP{StreamUpServerSecs: 3}); d != 3*time.Second {
		t.Fatal(d)
	}
	for _, x := range []model.XHTTP{{StreamUpServerSecs: -1}, {StreamUpServerSecs: 301}, {StreamUpServerMaxSecs: 1}, {StreamUpServerSecs: 2, StreamUpServerMaxSecs: 1}, {StreamUpServerSecs: 1, StreamUpServerMaxSecs: 301}} {
		if checkXHTTPStreamPolicy(x, "stream-up") == nil {
			t.Fatal("invalid accepted", x)
		}
	}
	for _, mode := range []string{"packet-up", "auto", "stream-one"} {
		if checkXHTTPStreamPolicy(model.XHTTP{StreamUpServerSecs: 1}, mode) == nil {
			t.Fatal(mode)
		}
	}
}

func TestXHTTPStreamPolicyResponseAndCancellation(t *testing.T) {
	for _, cancelUpload := range []bool{false, true} {
		t.Run(map[bool]string{false: "EOF", true: "cancel"}[cancelUpload], func(t *testing.T) {
			app, wire := xhttpPair()
			defer app.Close()
			defer wire.Close()
			h := newXHTTPHandler("/", nil)
			h.settings = model.XHTTP{StreamUpServerSecs: 1, PaddingBytes: 100}
			finished := make(chan bool, 1)
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { finished <- h.streamUploadResponse(w, r, wire) }))
			server.EnableHTTP2 = true
			server.StartTLS()
			defer server.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			reader, writer := io.Pipe()
			defer writer.Close()
			request, _ := http.NewRequestWithContext(ctx, "POST", server.URL, reader)
			response, err := server.Client().Do(request)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if response.ProtoMajor != 2 {
				t.Fatal(response.Proto)
			}
			padding := make([]byte, 100)
			if _, err = io.ReadFull(response.Body, padding); err != nil || !bytes.Equal(padding, bytes.Repeat([]byte("X"), 100)) {
				t.Fatal("first padding", err)
			}
			start := time.Now()
			if _, err = io.ReadFull(response.Body, padding); err != nil || time.Since(start) < 800*time.Millisecond {
				t.Fatal("period padding", time.Since(start), err)
			}
			consumed := make(chan []byte, 1)
			go func() { data, _ := io.ReadAll(app); consumed <- data }()
			if _, err = writer.Write([]byte("business")); err != nil {
				t.Fatal(err)
			}
			if cancelUpload {
				cancel()
				_ = writer.CloseWithError(context.Canceled)
				_ = response.Body.Close()
			} else {
				_ = writer.Close()
				if _, err = io.ReadAll(response.Body); err != nil || response.Trailer.Get("X-Veilink-Upload-Complete") != "1" {
					t.Fatal("completion", err, response.Trailer)
				}
			}
			select {
			case clean := <-finished:
				if clean == cancelUpload {
					t.Fatal("wrong completion", clean)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("handler leaked")
			}
			if !cancelUpload {
				select {
				case data := <-consumed:
					if !bytes.Equal(data, []byte("business")) {
						t.Fatal("payload mixed with padding", string(data))
					}
				case <-time.After(time.Second):
					t.Fatal("reader leaked")
				}
			}
		})
	}
}
