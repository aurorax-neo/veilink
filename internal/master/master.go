package master

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"

	pb "veilink/api/control/v1"
	"veilink/internal/config"
	"veilink/internal/console"
	"veilink/internal/control"
	"veilink/internal/httpapi"
	"veilink/internal/logring"
	"veilink/internal/store"
)

func Run(ctx context.Context, c config.Config) error {
	if e := c.Validate("master"); e != nil {
		return e
	}

	ring := logring.New(2000)
	slog.SetDefault(slog.New(logring.NewHandler(ring, "master", slog.NewTextHandler(os.Stderr, nil))))

	mode := c.EffectiveTLSMode()

	var cert tls.Certificate
	var tlsConfig *tls.Config
	if mode == "https" {
		var e error
		cert, e = tls.LoadX509KeyPair(c.ControlCert, c.ControlKey)
		if e != nil {
			return e
		}
		tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2", "http/1.1"}}
	}

	s, e := store.Open(c.Database, c.DeploymentKey)
	if e != nil {
		return e
	}
	defer s.Close()
	initPass := os.Getenv("VEILINK_INIT_ADMIN_PASSWORD")
	if initPass == "" {
		initPass = os.Getenv("VEILINK_ADMIN_PASSWORD")
	}
	if initPass != "" {
		hasAdmin, err := s.HasAdmin()
		if err != nil {
			return err
		}
		if !hasAdmin {
			initUser := os.Getenv("VEILINK_INIT_ADMIN_USERNAME")
			if initUser == "" {
				initUser = "admin"
			}
			if err := s.InitAdmin(initUser, initPass); err != nil {
				return fmt.Errorf("auto-init admin failed: %w", err)
			}
			slog.Info("initial administrator initialized from environment", "username", initUser)
		}
	}
	listener, e := net.Listen("tcp", c.BindAddr)
	if e != nil {
		return e
	}
	g := grpc.NewServer(grpc.MaxRecvMsgSize(64<<10), grpc.MaxSendMsgSize(4<<20), grpc.MaxConcurrentStreams(16), grpc.KeepaliveParams(keepalive.ServerParameters{MaxConnectionIdle: 5 * time.Minute, Time: time.Minute, Timeout: 10 * time.Second}))
	pb.RegisterControlServer(g, &control.Service{Store: s, NodeRing: logring.NewNodeRing(ring)})

	insecure := mode == "http"
	panel := httpapi.New(s, insecure, console.Handler(console.Locate(c.HTMLDir)), ring)

	mux := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor == 2 && strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc") {
			g.ServeHTTP(w, r)
			return
		}
		panel.ServeHTTP(w, r)
	})

	var handler http.Handler
	if mode == "http" {
		handler = h2c.NewHandler(mux, &http2.Server{})
	} else {
		handler = mux
	}

	h := &http.Server{
		Handler:           handler,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       5 * time.Minute,
		MaxHeaderBytes:    16 << 10,
	}
	errc := make(chan error, 2)
	if mode == "https" {
		go func() { errc <- h.Serve(tls.NewListener(listener, tlsConfig)) }()
	} else {
		go func() { errc <- h.Serve(listener) }()
	}
	slog.Info("master started", "addr", c.BindAddr, "tls", mode)
	embeddedDone := make(chan struct{})
	if c.EmbeddedServer.Enabled {
		go func() {
			defer close(embeddedDone)
			if err := runEmbeddedServer(ctx, c, s); err != nil && ctx.Err() == nil {
				slog.Error("embedded server failed", "error", err)
				errc <- err
			}
		}()
	} else {
		close(embeddedDone)
	}
	select {
	case <-ctx.Done():
		e = nil
	case e = <-errc:
	}
	stop, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = h.Shutdown(stop)
	g.Stop()
	<-embeddedDone
	if errors.Is(e, http.ErrServerClosed) {
		return nil
	}
	return e
}
