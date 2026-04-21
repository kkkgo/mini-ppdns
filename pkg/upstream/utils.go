package upstream

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// socketOpts bundles the SO_* options applied to outbound sockets.
// Platform-specific code in sockopt_*.go turns these into setsockopt
// calls; on platforms that don't support a given option, the field is
// silently ignored (zero-valued).
type socketOpts struct {
	so_mark        int
	bind_to_device string
}

// parseDialAddr resolves the final dial target. dialAddr, if set,
// overrides the URL-level host. Returns a tuple of (host, port) where
// port falls back to defaultPort when the address carries none.
func parseDialAddr(urlHost, dialAddr string, defaultPort uint16) (string, uint16, error) {
	src := urlHost
	if dialAddr != "" {
		src = dialAddr
	}
	host, port, err := trySplitHostPort(src)
	if err != nil {
		return "", 0, err
	}
	if port == 0 {
		port = defaultPort
	}
	return host, port, nil
}

// joinPort is net.JoinHostPort with the port as a uint16 — saves every
// caller a strconv.Itoa.
func joinPort(host string, port uint16) string {
	return net.JoinHostPort(host, strconv.Itoa(int(port)))
}

// tryRemovePort strips a trailing :port (or ]:port for bracketed IPv6)
// from s. If s doesn't parse as host:port, it's returned unchanged.
func tryRemovePort(s string) string {
	host, _, err := net.SplitHostPort(s)
	if err != nil {
		return s
	}
	return host
}

// trySplitHostPort is a permissive net.SplitHostPort: if s has no port,
// it returns (s, 0, nil) instead of erroring. The port, when present,
// must fit in uint16.
func trySplitHostPort(s string) (string, uint16, error) {
	host, portS, err := net.SplitHostPort(s)
	if err != nil {
		// No port recognizable — hand back the whole string as host.
		return s, 0, nil
	}
	n, err := strconv.ParseUint(portS, 10, 16)
	if err != nil {
		return "", 0, fmt.Errorf("invalid port, %w", err)
	}
	return host, uint16(n), nil
}

// tryTrimIpv6Brackets peels a matching [...] wrapping off s (as used by
// IPv6 literals in URLs). If s isn't bracketed, it's returned as-is.
func tryTrimIpv6Brackets(s string) string {
	if len(s) >= 2 && strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		return s[1 : len(s)-1]
	}
	return s
}

// dnsFlagTC is the mask for the TC bit inside the third byte of a DNS
// header (byte offset 2). TC flags that the response was truncated and
// the client should retry over TCP.
const dnsFlagTC byte = 1 << 1

// msgTruncated reports whether the DNS frame's TC flag is set. Frames
// shorter than the 3 header bytes needed to inspect the flag byte are
// treated as not-truncated (there's nothing to fall back to anyway).
func msgTruncated(b []byte) bool {
	if len(b) < 3 {
		return false
	}
	return b[2]&dnsFlagTC != 0
}
