package master

import (
	"context"
	"crypto/tls"
	"errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"log/slog"
	"net"
	"net/http"
	"time"
	pb "veilink/api/control/v1"
	"veilink/internal/config"
	"veilink/internal/control"
	"veilink/internal/httpapi"
	"veilink/internal/store"
	"veilink/web"
)

func Run(ctx context.Context, c config.Config) error {
	if e := c.Validate("master"); e != nil {
		return e
	}
	cert, e := tls.LoadX509KeyPair(c.ControlCert, c.ControlKey)
	if e != nil {
		return e
	}
	s, e := store.Open(c.Database, c.DeploymentKey)
	if e != nil {
		return e
	}
	defer s.Close()
	listener, e := net.Listen("tcp", c.ControlAddr)
	if e != nil {
		return e
	}
	defer listener.Close()
	g := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}})), grpc.MaxRecvMsgSize(64<<10), grpc.MaxSendMsgSize(4<<20), grpc.MaxConcurrentStreams(16), grpc.KeepaliveParams(keepalive.ServerParameters{MaxConnectionIdle: 5 * time.Minute, Time: time.Minute, Timeout: 10 * time.Second}))
	pb.RegisterControlServer(g, &control.Service{Store: s})
	h := &http.Server{Addr: c.HTTPAddr, Handler: httpapi.New(s, c.InsecureLoopbackHTTP && c.HTTPCert == "" && !c.TrustedProxy, web.Handler()), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: time.Minute, MaxHeaderBytes: 16 << 10, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	errs := make(chan error, 2)
	go func() { errs <- g.Serve(listener) }()
	go func() {
		if c.HTTPCert != "" {
			errs <- h.ListenAndServeTLS(c.HTTPCert, c.HTTPKey)
		} else {
			errs <- h.ListenAndServe()
		}
	}()
	slog.Info("master started", "http", c.HTTPAddr, "control", c.ControlAddr)
	select {
	case <-ctx.Done():
		e = nil
	case e = <-errs:
	}
	stop, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	h.Shutdown(stop)
	g.Stop()
	if errors.Is(e, http.ErrServerClosed) {
		return nil
	}
	return e
}
