package caddy_smallshield

import (
	"net"
)

// extractIP returns the host part of a "host:port" or "[host]:port" address.
// IPv4-mapped IPv6 addresses (e.g. ::ffff:1.2.3.4) are converted to plain IPv4.
// If the address has no port, it is returned as-is.
func extractIP(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// No port present; return the raw value.
		return addr
	}
	// Convert IPv4-mapped IPv6 (::ffff:x.x.x.x) to plain IPv4.
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			return ip4.String()
		}
	}
	return host
}
