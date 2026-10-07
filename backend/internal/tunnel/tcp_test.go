//go:build darwin || linux

package tunnel

import (
	"context"
	"net"
	"testing"

	"golang.org/x/sys/unix"
)

func TestTunnelTCPKeepAlive(t *testing.T) {
	ln, err := listenTCP(context.Background(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	dialed, err := tunnelDialer().DialContext(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer dialed.Close()
	accepted, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer accepted.Close()
	for _, conn := range []net.Conn{dialed, accepted} {
		raw, err := conn.(*net.TCPConn).SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		err = raw.Control(func(fd uintptr) {
			check := func(level, option, want int) {
				got, err := unix.GetsockoptInt(int(fd), level, option)
				if err != nil || got != want {
					t.Errorf("socket option %d: got %d, want %d: %v", option, got, want, err)
				}
			}
			if enabled, err := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_KEEPALIVE); err != nil || enabled == 0 {
				t.Errorf("keepalive disabled: %d %v", enabled, err)
			}
			check(unix.IPPROTO_TCP, tcpKeepAliveIdleOption, 60)
			check(unix.IPPROTO_TCP, unix.TCP_KEEPINTVL, 60)
			check(unix.IPPROTO_TCP, unix.TCP_KEEPCNT, 3)
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}
