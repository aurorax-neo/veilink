package tunnel

import (
	"context"
	"net"
	"time"
)

var tunnelKeepAlive = net.KeepAliveConfig{Enable: true, Idle: 60 * time.Second, Interval: 60 * time.Second, Count: 3}

func tunnelDialer() *net.Dialer {
	return &net.Dialer{Timeout: 5 * time.Second, KeepAliveConfig: tunnelKeepAlive}
}

func listenTCP(ctx context.Context, addr string) (net.Listener, error) {
	lc := net.ListenConfig{KeepAliveConfig: tunnelKeepAlive}
	return lc.Listen(ctx, "tcp", addr)
}
