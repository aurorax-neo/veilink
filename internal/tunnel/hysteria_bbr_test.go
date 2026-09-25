package tunnel

import (
	"net"
	"reflect"
	"testing"

	"github.com/apernet/quic-go/congestion"
	"github.com/xtls/xray-core/transport/internet/hysteria/congestion/bbr"
)

type congestionCapture struct {
	size       congestion.ByteCount
	addr       net.Addr
	controller congestion.CongestionControl
	calls      int
}

func (c *congestionCapture) InitialPacketSize() congestion.ByteCount { return c.size }
func (c *congestionCapture) RemoteAddr() net.Addr                    { return c.addr }
func (c *congestionCapture) SetCongestionControl(cc congestion.CongestionControl) {
	c.controller = cc
	c.calls++
}

func TestHysteriaBBRController(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "::1"} {
		for _, size := range []congestion.ByteCount{0, 1200, 1252, 1452} {
			c := &congestionCapture{size: size, addr: &net.UDPAddr{IP: net.ParseIP(ip), Port: 443}}
			enableHysteriaBBR(c)
			if c.calls != 1 || c.controller == nil {
				t.Fatal("BBR was not installed exactly once")
			}
			packetSize := bbr.GetInitialPacketSize(c.addr)
			if size > 0 {
				packetSize = min(size, packetSize)
			}
			want := bbr.NewBbrSender(bbr.DefaultClock{}, packetSize, bbr.ProfileStandard)
			if reflect.TypeOf(c.controller) != reflect.TypeOf(want) {
				t.Fatalf("not Xray BBR: %T", c.controller)
			}
			// Inspect the controller passed to QUIC, not a separate configuration flag.
			profile := reflect.ValueOf(c.controller).Elem().FieldByName("profile").String()
			if profile != "standard" {
				t.Fatalf("profile = %q", profile)
			}
			if got := c.controller.GetCongestionWindow(); got != want.GetCongestionWindow() {
				t.Fatalf("initial window = %d, want %d", got, want.GetCongestionWindow())
			}
			// A first MTU probe between the configured and address-guessed sizes
			// must not panic due to an apparent controller MTU decrease.
			c.controller.SetMaxDatagramSize(packetSize + 1)
		}
	}
}
