package tunnel

import (
	"context"
	"net"
	"testing"
	"veilink/internal/model"
)

func TestXHTTPDownloadEndpointRequiresAuthorizedGatewayEndpoint(t *testing.T) {
	gateway := model.Node{ID: "server", Role: "server", ConnectEndpoints: []model.ConnectEndpoint{{ID: "up", Host: "up.example", Port: 443, Enabled: true}}}
	if _, err := bindingGateway(gateway, model.Binding{ServerID: "server", ConnectEndpointID: "down"}); err == nil {
		t.Fatal("unknown endpoint accepted")
	}
	gateway.ConnectEndpoints = append(gateway.ConnectEndpoints, model.ConnectEndpoint{ID: "down", Host: "down.example", Port: 443, Enabled: false})
	if _, err := bindingGateway(gateway, model.Binding{ServerID: "server", ConnectEndpointID: "down"}); err == nil {
		t.Fatal("disabled endpoint accepted")
	}
}

func TestXHTTPDownloadEndpointPreservedWithExplicitUploadBinding(t *testing.T) {
	gateway := model.Node{
		ID: "server", Role: "server",
		ConnectEndpoints: []model.ConnectEndpoint{
			{ID: "up", Host: "up.example", Port: 443, Enabled: true},
			{ID: "down", Host: "down.example", Port: 8443, Enabled: true},
		},
		Tunnel: model.LocalTLS{XHTTP: model.XHTTP{Mode: "packet-up", DownloadEndpointID: "down"}},
	}
	selected, err := bindingGateway(gateway, model.Binding{ServerID: "server", ConnectEndpointID: "up"})
	if err != nil {
		t.Fatal(err)
	}
	if len(selected.ConnectEndpoints) != 2 || selected.ConnectEndpoints[0].ID != "up" || selected.ConnectEndpoints[1].ID != "down" {
		t.Fatalf("authorized upload/downlink endpoints were not preserved: %#v", selected.ConnectEndpoints)
	}
}
func TestXHTTPDownloadEndpointRuntimeFailsClosed(t *testing.T) {
	x := model.LocalTLS{CAPEM: "", XHTTP: model.XHTTP{Path: "/x/", Mode: "packet-up", DownloadEndpointID: "down"}}
	if _, err := dialXHTTPWithDownDialer(context.Background(), "127.0.0.1:1", "127.0.0.1", x, func(context.Context) (net.Conn, error) { return nil, nil }, nil, ""); err == nil {
		t.Fatal("missing downlink dialer accepted")
	}
}
