package tunnel

import (
	"errors"
	"path"
	"regexp"
	"strings"

	"veilink/internal/model"
)

var xhttpPath = regexp.MustCompile(`^/[A-Za-z0-9/_-]*$`)

// checkTransportSecurity allows empty client settings to inherit their gateway.
func checkTransportSecurity(local model.LocalTLS) error {
	switch local.TransportSecurity {
	case "", "tls", "plain":
	default:
		return errors.New("transport_security must be tls or plain")
	}
	if local.TransportSecurity == "plain" && (local.Reality.Enabled() || local.Hysteria2.Enabled()) {
		return errors.New("plain transport_security cannot be combined with REALITY or Hysteria2")
	}
	if x := local.XHTTP; x.Enabled() {
		if x.Mode != "packet-up" {
			return errors.New("xhttp mode must be packet-up")
		}
		if len(x.Path) > 256 || !xhttpPath.MatchString(x.Path) || strings.Contains(x.Path, "//") || !strings.HasSuffix(x.Path, "/") || (x.Path != "/" && path.Clean(x.Path)+"/" != x.Path) {
			return errors.New("xhttp path must be canonical, begin and end with /, and contain only letters, digits, /, _ or - (maximum 256 bytes)")
		}
		if local.Reality.Enabled() || local.Hysteria2.Enabled() || (local.Flow != "" && local.Flow != "none") {
			return errors.New("xhttp cannot be combined with REALITY, Hysteria2 or Vision")
		}
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
