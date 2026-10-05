package tunnel

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	mux "github.com/metacubex/sing-mux"
	"github.com/metacubex/sing/common/buf"
	M "github.com/metacubex/sing/common/metadata"
	"golang.org/x/net/http2"
)

// sing-mux v0.3.10's h2 client constructs a nil Request.Header, rejected by
// current x/net. This independently implemented CONNECT adapter uses upstream
// sing-mux codecs and Service; it neither copies nor patches dependency code.
type singH2Client struct {
	pool     *singPool
	dial     func(context.Context, string, M.Socksaddr) (net.Conn, error)
	mu       sync.Mutex
	sessions []*http2.ClientConn
	closed   bool
}

func (c *singH2Client) session(ctx context.Context) (*http2.ClientConn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, net.ErrClosed
	}
	live := c.sessions[:0]
	for _, s := range c.sessions {
		if !s.State().Closed && !s.State().Closing {
			live = append(live, s)
		} else {
			s.Close()
		}
	}
	c.sessions = live
	var best *http2.ClientConn
	for _, s := range live {
		if s.CanTakeNewRequest() && (best == nil || s.State().StreamsActive < best.State().StreamsActive) {
			best = s
		}
	}
	if best != nil {
		return best, nil
	}
	if len(live) >= 1 {
		return nil, errors.New("h2mux connection limit")
	}
	conn, err := c.dial(ctx, "tcp", mux.Destination)
	if err != nil {
		return nil, err
	}
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	header := mux.EncodeRequest(mux.Request{Version: mux.Version0, Protocol: mux.ProtocolH2Mux}, nil)
	err = writeAll(conn, header.Bytes())
	header.Release()
	if err != nil {
		conn.Close()
		return nil, err
	}
	tr := &http2.Transport{ReadIdleTimeout: 30 * time.Second, MaxReadFrameSize: 32 << 10}
	s, err := tr.NewClientConn(conn)
	conn.SetWriteDeadline(time.Time{})
	if err != nil {
		conn.Close()
		return nil, err
	}
	c.sessions = append(c.sessions, s)
	return s, nil
}
func (c *singH2Client) DialContext(ctx context.Context, network string, dst M.Socksaddr) (net.Conn, error) {
	if network != "tcp" {
		return nil, errors.New("TCP mux only")
	}
	session, err := c.session(ctx)
	if err != nil {
		return nil, err
	}
	// The request header is emitted by a bounded reader, avoiding a goroutine
	// blocked writing the stream request before HTTP response headers arrive.
	header := buf.NewSize(512)
	err = mux.EncodeStreamRequest(mux.StreamRequest{Network: "tcp", Destination: dst}, header)
	wire := append([]byte(nil), header.Bytes()...)
	header.Release()
	if err != nil {
		return nil, err
	}
	reader, writer := io.Pipe()
	life, cancel := context.WithCancel(c.pool.ctx)
	request := (&http.Request{Method: http.MethodConnect, URL: &url.URL{Scheme: "https", Host: "localhost"}, Header: make(http.Header), Body: &singH2Body{Reader: io.MultiReader(bytes.NewReader(wire), reader), closer: reader}}).WithContext(life)
	result := make(chan singH2Result, 1)
	go func() { r, e := session.RoundTrip(request); result <- singH2Result{r, e} }()
	select {
	case r := <-result:
		if r.err != nil || r.response.StatusCode != http.StatusOK {
			cancel()
			reader.Close()
			writer.Close()
			if r.response != nil {
				r.response.Body.Close()
			}
			return nil, errors.New("h2mux CONNECT rejected")
		}
		return &singH2Stream{reader: r.response.Body, writer: writer, cancel: cancel}, nil
	case <-ctx.Done():
		cancel()
		reader.Close()
		writer.Close()
		go func() {
			r := <-result
			if r.response != nil {
				r.response.Body.Close()
			}
		}()
		return nil, ctx.Err()
	}
}

type singH2Result struct {
	response *http.Response
	err      error
}
type singH2Body struct {
	io.Reader
	closer io.Closer
}

func (b *singH2Body) Close() error { return b.closer.Close() }
func (c *singH2Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	for _, s := range c.sessions {
		s.Close()
	}
	c.sessions = nil
	return nil
}

type singH2Stream struct {
	reader   io.ReadCloser
	writer   *io.PipeWriter
	cancel   context.CancelFunc
	response bool
}

func (s *singH2Stream) Read(b []byte) (int, error) {
	if !s.response {
		r, e := mux.ReadStreamResponse(s.reader)
		if e != nil {
			return 0, e
		}
		if r.Status != 0 {
			return 0, errors.New("mux stream rejected")
		}
		s.response = true
	}
	return s.reader.Read(b)
}
func (s *singH2Stream) Write(b []byte) (int, error) { return s.writer.Write(b) }
func (s *singH2Stream) Close() error                { s.cancel(); s.writer.Close(); return s.reader.Close() }
func (s *singH2Stream) LocalAddr() net.Addr         { return M.Socksaddr{} }
func (s *singH2Stream) RemoteAddr() net.Addr        { return M.Socksaddr{} }
func (s *singH2Stream) SetDeadline(time.Time) error {
	return errors.New("h2mux stream deadlines unsupported")
}
func (s *singH2Stream) SetReadDeadline(time.Time) error {
	return errors.New("h2mux stream deadlines unsupported")
}
func (s *singH2Stream) SetWriteDeadline(time.Time) error {
	return errors.New("h2mux stream deadlines unsupported")
}
