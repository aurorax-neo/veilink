package tunnel

import (
	"errors"

	"veilink/internal/model"
)

// checkTransportSecurity allows empty client settings to inherit their gateway.
// Server settings and resolved TCP gateways must specify tls or plain.
func checkTransportSecurity(local model.LocalTLS) error {
	switch local.TransportSecurity {
	case "", "tls", "plain":
	default:
		return errors.New("transport_security must be tls or plain")
	}
	if local.TransportSecurity == "plain" && (local.Reality.Enabled() || local.Hysteria2.Enabled()) {
		return errors.New("plain transport_security cannot be combined with REALITY or Hysteria2")
	}
	return nil
}

func requireTransportSecurity(local model.LocalTLS) error {
	if err := checkTransportSecurity(local); err != nil {
		return err
	}
	if local.TransportSecurity == "" && !local.Reality.Enabled() && !local.Hysteria2.Enabled() {
		return errors.New("transport_security is required: tls or plain")
	}
	return nil
}
