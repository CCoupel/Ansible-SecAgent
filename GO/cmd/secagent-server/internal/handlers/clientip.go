package handlers

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
)

// EnvTrustedProxyCIDRs lists, comma separated, the CIDRs of the reverse proxies allowed to state
// the client address through X-Forwarded-For. Empty (default) = X-Forwarded-For is ignored and
// only the TCP peer address counts (#177).
const EnvTrustedProxyCIDRs = "TRUSTED_PROXY_CIDRS"

// trustedProxies is the parsed list; nil/empty = no proxy is trusted.
var trustedProxies atomic.Pointer[[]*net.IPNet]

// ParseTrustedProxyCIDRs parses a comma-separated CIDR list ("" → none). A single invalid entry is
// an error: the server must refuse to start rather than silently trust a wrong range. A range with
// prefix length 0 (0.0.0.0/0, ::/0, or an IPv4-mapped equivalent) trusts every peer, so any client
// could forge X-Forwarded-For and defeat allowed_ips: it is refused too (fail closed).
func ParseTrustedProxyCIDRs(list string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, part := range strings.Split(list, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		_, n, err := net.ParseCIDR(part)
		if err != nil {
			return nil, fmt.Errorf("%s: invalid CIDR %q: %w", EnvTrustedProxyCIDRs, part, err)
		}
		if ones, bits := n.Mask.Size(); ones == 0 || (bits == 128 && n.IP.To4() != nil && ones <= 96) {
			return nil, fmt.Errorf("%s: entry #%d trusts every address (prefix length 0), refused", EnvTrustedProxyCIDRs, len(out)+1)
		}
		out = append(out, n)
	}
	return out, nil
}

// SetTrustedProxies installs the trusted proxy ranges (nil clears them).
func SetTrustedProxies(nets []*net.IPNet) {
	trustedProxies.Store(&nets)
}

func isTrustedProxy(ip net.IP) bool {
	p := trustedProxies.Load()
	if p == nil || ip == nil {
		return false
	}
	for _, n := range *p {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// clientAddr returns the client IP used for every address-based decision (plugin token
// allowed_ips, last_used_ip, audit logs) and the TCP peer IP.
//
// X-Forwarded-For (and X-Real-IP / Forwarded, never read) is consulted ONLY when the TCP peer is a
// trusted proxy. The list is then walked from the right (the entries appended by trusted hops)
// and the first address that is not itself a trusted proxy is the client: the leftmost entries are
// chosen by the caller and must never be believed. An unparsable entry stops the walk and the peer
// address is kept (fail safe: the allowed_ips check then sees the proxy, not an invented client).
func clientAddr(r *http.Request) (client, peer string) {
	peer = stripPort(r.RemoteAddr)
	peerIP := net.ParseIP(peer)
	if peerIP != nil {
		peer = peerIP.String()
	}
	if !isTrustedProxy(peerIP) {
		return peer, peer
	}
	var entries []string
	for _, h := range r.Header.Values("X-Forwarded-For") {
		for _, e := range strings.Split(h, ",") {
			entries = append(entries, strings.TrimSpace(e))
		}
	}
	for i := len(entries) - 1; i >= 0; i-- {
		ip := net.ParseIP(stripPort(entries[i]))
		if ip == nil {
			return peer, peer
		}
		if !isTrustedProxy(ip) {
			return ip.String(), peer
		}
	}
	return peer, peer
}
