package tunnel

import (
	"crypto/rand"
	"errors"
	"io"
	"math/big"
	"net/http"
	"time"

	"veilink/internal/model"
)

func checkXHTTPStreamPolicy(x model.XHTTP, mode string) error {
	min, max := x.StreamUpServerSecs, x.StreamUpServerMaxSecs
	if min == 0 && max == 0 {
		return nil
	}
	if mode != "stream-up" || min < 1 || min > 300 || max < 0 || max > 300 || (max != 0 && max < min) {
		return errors.New("xhttp stream-up server interval requires stream-up and 1-300 seconds with ordered bounds")
	}
	return nil
}

func xhttpStreamPolicyInterval(x model.XHTTP) time.Duration {
	min, max := x.StreamUpServerSecs, x.StreamUpServerMaxSecs
	if min == 0 {
		min, max = 20, 80
	} else if max == 0 {
		max = min
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max-min+1)))
	if err != nil {
		return time.Duration(max) * time.Second
	}
	return time.Duration(min+int(n.Int64())) * time.Second
}

// Only this goroutine writes the response. The upload worker is joined before
// return so cancellation cannot leave a reader using a finished request.
func (h *xhttpHandler) streamUploadResponse(w http.ResponseWriter, r *http.Request, wire *xhttpStream) bool {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Set("Trailer", "X-Veilink-Upload-Complete")
	controller := http.NewResponseController(w)
	w.WriteHeader(http.StatusOK)
	if controller.Flush() != nil {
		_ = wire.Close()
		return false
	}
	done := make(chan bool, 1)
	go func() { done <- h.consumeStreamUpload(controller, r, wire) }()
	defer func() { _ = controller.SetReadDeadline(time.Time{}); _ = controller.SetWriteDeadline(time.Time{}) }()
	abort := func() bool {
		_ = wire.Close()
		_ = controller.SetReadDeadline(time.Now())
		_ = r.Body.Close()
		<-done
		return false
	}
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case clean := <-done:
			if clean {
				w.Header().Set("X-Veilink-Upload-Complete", "1")
			} else {
				_ = wire.Close()
			}
			return clean
		case <-r.Context().Done():
			return abort()
		case <-timer.C:
			padding, err := xhttpPaddingValue(h.settingsWithPadding())
			if err != nil || controller.SetWriteDeadline(time.Now().Add(h.timeout)) != nil {
				return abort()
			}
			if _, err = io.WriteString(w, padding); err != nil || controller.Flush() != nil {
				return abort()
			}
			timer.Reset(xhttpStreamPolicyInterval(h.settings))
		}
	}
}

func (h *xhttpHandler) consumeStreamUpload(controller *http.ResponseController, r *http.Request, wire *xhttpStream) bool {
	buf := make([]byte, xhttpChunk)
	for {
		if controller.SetReadDeadline(time.Now().Add(90*time.Second)) != nil {
			return false
		}
		n, err := r.Body.Read(buf)
		if n > 0 {
			_ = wire.SetWriteDeadline(time.Now().Add(h.timeout))
			if _, e := wire.Write(buf[:n]); e != nil {
				return false
			}
		}
		if err == io.EOF {
			_ = wire.CloseWrite()
			return true
		}
		if err != nil {
			return false
		}
	}
}
