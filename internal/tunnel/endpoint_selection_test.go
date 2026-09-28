package tunnel

import (
	"testing"

	"veilink/internal/model"
)

func TestBindingGatewayEndpointSelectionNoFallback(t *testing.T) {
	gateway := model.Node{ID: "server", Role: "server", Address: "fallback.invalid", Port: 6553, ConnectEndpoints: []model.ConnectEndpoint{
		{ID: "first", Name: "First", Host: "first.example", Port: 443, Enabled: true},
		{ID: "second", Name: "Second", Host: "second.example", Port: 8443, Enabled: true},
	}}
	selected, err := bindingGateway(gateway, model.Binding{ServerID: "server", ConnectEndpointID: "second"})
	if err != nil {
		t.Fatal(err)
	}
	if len(selected.ConnectEndpoints) != 1 || selected.ConnectEndpoints[0].ID != "second" {
		t.Fatalf("selected endpoint was not isolated: %#v", selected.ConnectEndpoints)
	}
	gateway.ConnectEndpoints[1].Enabled = false
	if _, err := bindingGateway(gateway, model.Binding{ServerID: "server", ConnectEndpointID: "second"}); err == nil {
		t.Fatal("disabled selected endpoint fell back")
	}
	gateway.ConnectEndpoints[1].Enabled = true
	automatic, err := bindingGateway(gateway, model.Binding{ServerID: "server"})
	if err != nil {
		t.Fatal(err)
	}
	if len(automatic.ConnectEndpoints) != 2 {
		t.Fatalf("empty selection changed auto semantics: %#v", automatic.ConnectEndpoints)
	}
}
