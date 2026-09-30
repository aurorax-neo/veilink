package tunnel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"veilink/internal/model"
)

// HTTP/2 request and response bodies are independent streams. A pipe keeps
// writes bounded by transport backpressure; neither direction is buffered in
// full. This is native Veilink framing, not an Xray compatibility promise.
type xhttpStreamingConn struct {
	*xhttpStream
	cancel     context.CancelFunc
	transport  xhttpCloser
	once       sync.Once
	uploadDone <-chan error // stream-up: server consumed the upload, not just the local pipe
	timeout    time.Duration
}

func (c *xhttpStreamingConn) Close() error {
	var err error
	c.once.Do(func() {
		c.cancel()
		err = c.xhttpStream.Close()
		closeXHTTPTransport(c.transport)
	})
	return err
}
func (c *xhttpStreamingConn) CloseWrite() error {
	if err := c.xhttpStream.CloseWrite(); err != nil {
		return err
	}
	if c.uploadDone == nil {
		return nil
	}
	timer := time.NewTimer(c.timeout)
	defer timer.Stop()
	select {
	case err := <-c.uploadDone:
		return err
	case <-timer.C:
		_ = c.Close()
		return errors.New("xhttp upload confirmation timed out")
	}
}

func (h *xhttpHandler) validStreamContentType(r *http.Request) bool {
	values := r.Header.Values("Content-Type")
	if h.noGRPCHeader {
		return len(values) == 0
	}
	return len(values) == 1 && values[0] == "application/grpc"
}

func (h *xhttpHandler) streamOne(w http.ResponseWriter, r *http.Request) {
	if r.ProtoMajor != h.streamHTTPMajor() || r.Method != h.uplinkMethod || r.URL.Path != h.path || r.ContentLength == 0 || !h.validStreamContentType(r) {
		http.Error(w, "invalid streaming request", http.StatusBadRequest)
		return
	}
	h.mu.Lock()
	if h.closed || len(h.sessions)+len(h.streams) >= xhttpSessions {
		h.mu.Unlock()
		http.Error(w, "session limit", http.StatusServiceUnavailable)
		return
	}
	app, wire := xhttpPair()
	h.streams[wire] = struct{}{}
	h.mu.Unlock()
	defer func() { _ = wire.Close(); _ = app.Close(); h.mu.Lock(); delete(h.streams, wire); h.mu.Unlock() }()
	h.streamResponse(w, r, app, wire)
}

func (h *xhttpHandler) streamUpload(w http.ResponseWriter, r *http.Request, id string) {
	if r.ProtoMajor != h.streamHTTPMajor() || r.ContentLength == 0 || !h.validStreamContentType(r) {
		http.Error(w, "invalid streaming upload", http.StatusBadRequest)
		return
	}
	h.mu.Lock()
	s := h.sessions[id]
	h.mu.Unlock()
	if s == nil {
		http.Error(w, "unknown session", http.StatusNotFound)
		return
	}
	s.mu.Lock()
	if s.uploading || s.eof {
		s.mu.Unlock()
		http.Error(w, "duplicate upload", http.StatusConflict)
		return
	}
	s.uploading = true
	s.mu.Unlock()
	clean := h.streamUploadResponse(w, r, s.wire)
	s.mu.Lock()
	s.uploading = false
	if clean {
		s.eof = true
	}
	s.mu.Unlock()
}

func (h *xhttpHandler) streamResponse(w http.ResponseWriter, r *http.Request, app, wire *xhttpStream) {
	stop := context.AfterFunc(r.Context(), func() { _ = wire.Close(); _ = app.Close() })
	defer stop()
	go h.accept(app)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	if !h.noSSEHeader {
		w.Header().Set("Content-Type", "text/event-stream")
	} else {
		w.Header()["Content-Type"] = nil // suppress net/http's content sniffing
	}
	controller := http.NewResponseController(w)
	w.WriteHeader(http.StatusOK)
	if controller.Flush() != nil {
		return
	}
	var uploadDone chan struct{}
	if h.mode == "stream-one" {
		uploadDone = make(chan struct{})
		go func() {
			defer close(uploadDone)
			// A response EOF must not end the HTTP request while upload is pending.
			if _, err := io.Copy(wire, r.Body); err == nil {
				_ = wire.CloseWrite()
			} else {
				_ = wire.Close()
			}
		}()
	}
	buf := make([]byte, xhttpChunk)
	for {
		_ = wire.SetReadDeadline(time.Now().Add(90 * time.Second))
		n, err := wire.Read(buf)
		if n > 0 {
			if controller.SetWriteDeadline(time.Now().Add(h.timeout)) != nil {
				return
			}
			if _, e := w.Write(buf[:n]); e != nil || controller.Flush() != nil {
				return
			}
		}
		if err != nil {
			if err == io.EOF && uploadDone != nil {
				timer := time.NewTimer(90 * time.Second)
				defer timer.Stop()
				select {
				case <-uploadDone:
				case <-r.Context().Done():
				case <-timer.C:
					_ = wire.Close()
				}
			}
			return
		}
	}
}

func dialXHTTPStream(parent context.Context, client *http.Client, transport xhttpCloser, base string, settings model.XHTTP, headers http.Header, cancel context.CancelFunc) (net.Conn, error) {
	ctx, stop := context.WithTimeout(parent, xhttpRequestTimeout(settings))
	defer stop()
	setupTimer := time.AfterFunc(xhttpRequestTimeout(settings), cancel)
	defer setupTimer.Stop()
	id, err := newXHTTPSessionIDFor(settings)
	if err != nil {
		cancel()
		return nil, err
	}
	url := base
	if settings.Mode == "stream-up" {
		url = xhttpMetaPath(base, settings, id, "")
	}
	// Keep request contexts alive after setup; the setup deadline cancels the
	// parent only on failure, rather than terminating active response streams.
	var down *http.Response
	if settings.Mode == "stream-up" {
		var get *http.Request
		get, err = http.NewRequestWithContext(parent, http.MethodGet, url, nil)
		if err == nil {
			if settings.Host != "" {
				get.Host = settings.Host
			}
			xhttpApplyHeaders(get, headers)
			xhttpSetMeta(get, settings, id, "")
			if err = xhttpSetPadding(get, settings); err == nil {
				down, err = client.Do(get)
			}
		}
		if err == nil && (down.StatusCode != http.StatusOK || !xhttpCheckResponsePadding(down, settings) || down.ProtoMajor != xhttpExpectedStreamMajor(settings)) {
			err = fmt.Errorf("xhttp download status %d or unexpected HTTP version", down.StatusCode)
		}
		if err != nil || ctx.Err() != nil {
			if down != nil {
				_ = down.Body.Close()
			}
			cancel()
			closeXHTTPTransport(transport)
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, err
		}
	}
	app, wire := xhttpPair()
	bodyReader, bodyWriter := io.Pipe()
	conn := &xhttpStreamingConn{xhttpStream: app, cancel: cancel, transport: transport, timeout: xhttpRequestTimeout(settings)}
	// Closing the request body on cancellation unblocks a pending HTTP/2 upload.
	context.AfterFunc(parent, func() {
		_ = bodyReader.Close()
		_ = bodyWriter.Close()
		_ = wire.Close()
		_ = app.Close()
	})
	if down != nil {
		response := down
		context.AfterFunc(parent, func() { _ = response.Body.Close() })
	}
	go func() {
		defer bodyWriter.Close()
		_, copyErr := io.Copy(bodyWriter, wire)
		if copyErr != nil {
			_ = conn.Close()
		}
	}()
	post, postErr := http.NewRequestWithContext(parent, xhttpUplinkMethod(settings), url, bodyReader)
	if postErr != nil {
		_ = conn.Close()
		return nil, postErr
	}
	if settings.Host != "" {
		post.Host = settings.Host
	}
	xhttpApplyHeaders(post, headers)
	if settings.Mode == "stream-up" {
		xhttpSetMeta(post, settings, id, "")
	}
	if !settings.NoGRPCHeader {
		post.Header.Set("Content-Type", "application/grpc")
	}
	if err = xhttpSetPadding(post, settings); err != nil {
		_ = conn.Close()
		return nil, err
	}
	type postResult struct {
		response *http.Response
		err      error
	}
	result := make(chan postResult)
	go func() {
		response, e := client.Do(post)
		select {
		case result <- postResult{response, e}:
		case <-ctx.Done():
			if response != nil {
				_ = response.Body.Close()
			}
		}
	}()
	select {
	case outcome := <-result:
		if outcome.err != nil {
			err = outcome.err
		} else if outcome.response.StatusCode != http.StatusOK || !xhttpCheckResponsePadding(outcome.response, settings) || outcome.response.ProtoMajor != xhttpExpectedStreamMajor(settings) {
			err = fmt.Errorf("xhttp upload status %d or unexpected HTTP version", outcome.response.StatusCode)
		}
		if err != nil || ctx.Err() != nil {
			if outcome.response != nil {
				_ = outcome.response.Body.Close()
			}
			_ = conn.Close()
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, err
		}
		if settings.Mode == "stream-one" {
			down = outcome.response
			response := down
			context.AfterFunc(parent, func() { _ = response.Body.Close() })
		} else {
			response := outcome.response
			completed := make(chan error, 1)
			conn.uploadDone = completed
			go func() {
				defer response.Body.Close()
				_, err := io.Copy(io.Discard, response.Body)
				if err == nil && response.Trailer.Get("X-Veilink-Upload-Complete") != "1" {
					err = errors.New("xhttp upload incomplete")
				}
				completed <- err
			}()
		}
	case <-ctx.Done():
		_ = conn.Close()
		return nil, ctx.Err()
	}
	if down == nil {
		_ = conn.Close()
		return nil, errors.New("xhttp download unavailable")
	}
	go func() {
		defer down.Body.Close()
		_, copyErr := io.Copy(wire, down.Body)
		if copyErr != nil {
			_ = conn.Close()
		} else {
			_ = wire.CloseWrite()
		}
	}()
	if err := ctx.Err(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if !setupTimer.Stop() {
		_ = conn.Close()
		return nil, context.DeadlineExceeded
	}
	return conn, nil
}
