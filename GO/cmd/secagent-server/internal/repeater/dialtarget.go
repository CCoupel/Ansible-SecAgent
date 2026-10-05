package repeater

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"secagent-server/internal/endpoints"
)

// ErrForbiddenTarget wraps the refusal of an internal dial target (SSRF guard, #165).
var ErrForbiddenTarget = errors.New("forbidden dial target")

// resolveTimeout bounds the DNS resolution done when a target is validated.
const resolveTimeout = 3 * time.Second

var allowInternal atomic.Bool

// UnsafeAllowInternalDialTargets disables the SSRF guard (loopback, link-local, metadata...). It
// exists ONLY for the test harness (loopback children); nothing in the server calls it and no
// environment variable reaches it. #151 replaces it with the controlled dev/CI opt-in.
func UnsafeAllowInternalDialTargets(allow bool) { allowInternal.Store(allow) }

// SetResolverForTests replaces the DNS resolver used by the target validation and by the dial
// guard, and returns the function that restores the previous one. TEST SEAM: nothing in the server
// calls it, and no environment variable reaches it.
func SetResolverForTests(fn func(ctx context.Context, host string) ([]net.IP, error)) (restore func()) {
	prev := lookupIP
	lookupIP = fn
	return func() { lookupIP = prev }
}

// lookupIP is the resolver (replaced in tests).
var lookupIP = func(ctx context.Context, host string) ([]net.IP, error) {
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	out := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, a.IP)
	}
	return out, nil
}

// internalReason returns why ip is an internal or non routable destination, "" when it is fine.
// RFC 1918 (and the IPv6 unique-local range) stay ALLOWED: relays live on private networks.
func internalReason(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	switch {
	case ip.IsLoopback():
		return "loopback"
	case ip.IsUnspecified():
		return "unspecified"
	case ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast():
		return "link-local"
	case ip.IsMulticast():
		return "multicast"
	}
	if v4 := ip.To4(); v4 != nil {
		if v4[0] == 0 {
			return "non routable (0.0.0.0/8)"
		}
		for _, m := range metadataV4 {
			if v4.Equal(m) {
				return "cloud metadata"
			}
		}
		return ""
	}
	if ip.Equal(metadataV6) {
		return "cloud metadata"
	}
	// an IPv4 address embedded in a NAT64 (64:ff9b::/96) or 6to4 (2002::/16) address is judged as
	// that IPv4 address: 64:ff9b::a9fe:a9fe is 169.254.169.254 behind a translator
	if len(ip) == net.IPv6len {
		var emb net.IP
		switch {
		case ip[0] == 0x00 && ip[1] == 0x64 && ip[2] == 0xff && ip[3] == 0x9b && allZero(ip[4:12]):
			emb = net.IP(ip[12:16])
		case ip[0] == 0x20 && ip[1] == 0x02:
			emb = net.IP(ip[2:6])
		}
		if emb != nil {
			if why := internalReason(emb); why != "" {
				return why + " (embedded in " + "an IPv6 transition address)"
			}
		}
	}
	return ""
}

func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

// Cloud metadata endpoints beyond 169.254.169.254 (already link-local): Alibaba 100.100.100.200
// (inside the CGNAT range, which is NOT blocked as a whole: Tailscale and carrier-grade NAT are
// legitimate), the Azure wire server 168.63.129.16, the IETF DS-Lite/metadata address 192.0.0.192
// (Oracle/IBM style), and AWS IPv6 fd00:ec2::254 (inside unique-local, which stays allowed).
var (
	metadataV4 = []net.IP{net.ParseIP("100.100.100.200").To4(), net.ParseIP("168.63.129.16").To4(), net.ParseIP("192.0.0.192").To4()}
	metadataV6 = net.ParseIP("fd00:ec2::254")
)

// nonCanonicalNumericHost reports a host that is made only of numeric labels (decimal, octal like
// 0177, hex like 0x7f) but is not a canonical IP: inet_aton / getaddrinfo read "2130706433",
// "0x7f000001", "0177.0.0.1" or "127.1" as 127.0.0.1, which Go's ParseIP does not. Such a host is
// refused whatever it designates.
func nonCanonicalNumericHost(h string) bool {
	if net.ParseIP(strings.Trim(h, "[]")) != nil {
		return false
	}
	labels := strings.Split(h, ".")
	for _, l := range labels {
		if l == "" || (!isDigits(l) && !isHexLiteral(l)) {
			return false
		}
	}
	return true
}

func isDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return s != ""
}

func isHexLiteral(s string) bool {
	if len(s) < 3 || s[0] != '0' || (s[1] != 'x' && s[1] != 'X') {
		return false
	}
	for _, r := range s[2:] {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') && (r < 'A' || r > 'F') {
			return false
		}
	}
	return true
}

// checkTargetHost refuses an internal host: a literal IP, "localhost", a non canonical numeric
// host, or a name that resolves to an internal IP (any of them). Registration-time check only: the
// connection itself is guarded on the IP actually contacted (guardedDial), which is what stops DNS
// rebinding.
// checkTargetHostStrict is checkTargetHost; with strict a name that cannot be resolved is refused
// too ("cannot resolve the target host"): used when an operator REGISTERS a target (feedback and no
// unverifiable name in the table). At boot (Start) the lenient form keeps a dialer alive while the
// DNS is down; the guard at dial time is the guarantee in every case.
func checkTargetHostStrict(host string, strict bool) error {
	h := strings.TrimSuffix(strings.ToLower(host), ".")
	if nonCanonicalNumericHost(h) {
		return fmt.Errorf("%w: numeric host that is not a canonical IP address", ErrForbiddenTarget)
	}
	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return fmt.Errorf("%w: localhost", ErrForbiddenTarget)
	}
	if ip := net.ParseIP(strings.Trim(h, "[]")); ip != nil {
		if why := internalReason(ip); why != "" {
			return fmt.Errorf("%w: %s address", ErrForbiddenTarget, why)
		}
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), resolveTimeout)
	defer cancel()
	ips, err := lookupIP(ctx, h)
	if err != nil {
		if strict {
			return fmt.Errorf("%w: cannot resolve the target host", ErrForbiddenTarget)
		}
		return nil
	}
	for _, ip := range ips {
		if why := internalReason(ip); why != "" {
			return fmt.Errorf("%w: the name resolves to a %s address", ErrForbiddenTarget, why)
		}
	}
	return nil
}

// ParseTargetURLs parses a push target's address list: wss only, no userinfo, no duplicates, and
// NONE of them internal. The errors never contain a URL, a userinfo or a token.
func ParseTargetURLs(urls []string) ([]*url.URL, error) { return parseTargetURLs(urls, false) }

func parseTargetURLs(urls []string, strict bool) ([]*url.URL, error) {
	if len(urls) == 0 {
		return nil, errors.New("invalid url")
	}
	parsed, err := endpoints.ParseSchemes(strings.Join(urls, ","), "wss")
	if err != nil {
		switch {
		case errors.Is(err, endpoints.ErrUserinfo):
			return nil, errors.New("url must not contain userinfo")
		case errors.Is(err, endpoints.ErrScheme):
			return nil, errors.New("url must use the wss:// scheme (TLS required)")
		default:
			return nil, fmt.Errorf("invalid url: %s", strings.TrimPrefix(err.Error(), "endpoints: "))
		}
	}
	if allowInternal.Load() {
		return parsed, nil
	}
	for i, u := range parsed {
		if err := checkTargetHostStrict(u.Hostname(), strict); err != nil {
			return nil, fmt.Errorf("url #%d: %w", i+1, err)
		}
	}
	return parsed, nil
}
