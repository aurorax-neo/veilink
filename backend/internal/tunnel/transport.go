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
	if err := checkProtocol(local); err != nil {
		return err
	}
	switch local.TransportSecurity {
	case "", "tls", "plain":
	default:
		return errors.New("transport_security must be tls or plain")
	}
	if local.TransportSecurity == "plain" && (local.Reality.Enabled() || local.Hysteria2.Enabled()) {
		return errors.New("plain transport_security cannot be combined with REALITY or Hysteria2")
	}
	if x := local.XHTTP; x.Enabled() {
		if x.Mode != "packet-up" && x.Mode != "stream-up" && x.Mode != "stream-one" && x.Mode != "auto" {
			return errors.New("xhttp mode must be packet-up, stream-up, stream-one or auto")
		}
		mode := xhttpEffectiveMode(x, local.Reality.Enabled())
		if err := checkXHTTPMeta(x, mode); err != nil {
			return err
		}
		if err := checkXHTTPPadding(x); err != nil {
			return err
		}
		if err := checkXHTTPBuffer(x, mode); err != nil {
			return err
		}
		if err := checkXHTTPData(x, mode); err != nil {
			return err
		}
		if err := checkXHTTPMux(x); err != nil {
			return err
		}
		if x.DownloadEndpointID != "" && mode != "packet-up" {
			return errors.New("xhttp download_endpoint_id requires packet-up or auto")
		}
		if err := checkXHTTPStreamPolicy(x, mode); err != nil {
			return err
		}
		if x.Host != "" && (!hostOK(x.Host) || !strings.Contains(x.Host, ".") || strings.ContainsAny(x.Host, ":[]")) {
			return errors.New("xhttp host must be a lowercase DNS name or IPv4 address without a port")
		}
		if _, err := x.Headers.Entries(); err != nil {
			return err
		}
		if x.UplinkHTTPMethod != "" && x.UplinkHTTPMethod != "POST" && x.UplinkHTTPMethod != "PUT" {
			return errors.New("xhttp uplink_http_method must be POST or PUT")
		}
		if x.HTTPVersion != "" && x.HTTPVersion != "1.1" && x.HTTPVersion != "2" && x.HTTPVersion != "3" {
			return errors.New("xhttp http_version must be 1.1, 2 or 3")
		}
		if x.HTTPVersion == "3" && (!x.TLS || local.Reality.Enabled() || local.TransportSecurity != "tls") {
			return errors.New("xhttp HTTP/3 requires direct HTTPS and TLS origin")
		}
		if mode != "packet-up" && x.HTTPVersion == "1.1" {
			return errors.New("xhttp streaming requires HTTP/2 or HTTP/3")
		}
		if x.HTTPVersion == "2" && !x.TLS && (mode != "packet-up" || local.Reality.Enabled() || local.TransportSecurity != "plain") {
			return errors.New("xhttp h2c requires packet-up, direct HTTP and plain origin with VLESS encryption")
		}
		if mode != "packet-up" && !local.Reality.Enabled() && (!x.TLS || local.TransportSecurity != "tls") {
			return errors.New("xhttp streaming modes require direct HTTPS with HTTP/2 or HTTP/3 and TLS origin (or REALITY)")
		}
		if mode == "packet-up" && x.NoGRPCHeader {
			return errors.New("xhttp no_grpc_header applies only to streaming modes")
		}
		if mode != "packet-up" && x.MaxEachPostBytes != 0 {
			return errors.New("xhttp max_each_post_bytes applies only to packet-up")
		}
		if x.MaxEachPostBytes != 0 && (x.MaxEachPostBytes < 1024 || x.MaxEachPostBytes > 32768) {
			return errors.New("xhttp max_each_post_bytes must be 1024-32768")
		}
		if x.PostBytesMax != 0 && (mode != "packet-up" || x.MaxEachPostBytes == 0 || x.PostBytesMax < x.MaxEachPostBytes || x.PostBytesMax > 32768) {
			return errors.New("xhttp post_bytes_max requires packet-up and max_each_post_bytes <= post_bytes_max <= 32768")
		}
		if x.MinPostsIntervalMs != 0 && (mode != "packet-up" || x.MinPostsIntervalMs < 1 || x.MinPostsIntervalMs > 1000) {
			return errors.New("xhttp min_posts_interval_ms requires packet-up and 1-1000 ms")
		}
		if x.MaxPostsIntervalMs != 0 && (mode != "packet-up" || x.MinPostsIntervalMs == 0 || x.MaxPostsIntervalMs < x.MinPostsIntervalMs || x.MaxPostsIntervalMs > 1000) {
			return errors.New("xhttp max_posts_interval_ms requires packet-up and min_posts_interval_ms <= max_posts_interval_ms <= 1000")
		}
		if x.RequestTimeoutSeconds != 0 && (x.RequestTimeoutSeconds < 5 || x.RequestTimeoutSeconds > 60) {
			return errors.New("xhttp request_timeout_seconds must be 5-60")
		}
		if x.PaddingBytes != 0 && (x.PaddingBytes < 1 || x.PaddingBytes > 1000) {
			return errors.New("xhttp padding_bytes must be 1-1000")
		}
		if x.PaddingMaxBytes != 0 && (x.PaddingMaxBytes < 1 || x.PaddingMaxBytes > 1000 || x.PaddingMaxBytes < xhttpPaddingMinimum(x)) {
			return errors.New("xhttp padding_max_bytes must be between padding_bytes (default 100) and 1000")
		}
		if x.ServerMaxHeaderBytes != 0 && (x.ServerMaxHeaderBytes < 8<<10 || x.ServerMaxHeaderBytes > 32<<10) {
			return errors.New("xhttp server_max_header_bytes must be 8192-32768")
		}
		if len(x.Path) > 256 || !xhttpPath.MatchString(x.Path) || strings.Contains(x.Path, "//") || !strings.HasSuffix(x.Path, "/") || (x.Path != "/" && path.Clean(x.Path)+"/" != x.Path) {
			return errors.New("xhttp path must be canonical, begin and end with /, and contain only letters, digits, /, _ or - (maximum 256 bytes)")
		}
		if local.Flow != "" && local.Flow != "none" {
			return errors.New("xhttp cannot be combined with Vision")
		}
		if local.Reality.Enabled() && x.TLS {
			return errors.New("xhttp with REALITY must disable xhttp TLS")
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
