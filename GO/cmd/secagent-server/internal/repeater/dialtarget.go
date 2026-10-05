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
		return ""
	}
	if ip.Equal(net.ParseIP("fd00:ec2::254")) {
		return "cloud metadata"
	}
	return ""
}

// checkTargetHost refuses an internal host: a literal IP, "localhost", or a name that resolves to
// an internal IP (any of them). A name that does not resolve now is accepted (the anti-rebinding
// check at dial time is #151): refusing would stop a dialer at boot whenever the DNS is down.
func checkTargetHost(host string) error {
	h := strings.TrimSuffix(strings.ToLower(host), ".")
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
func ParseTargetURLs(urls []string) ([]*url.URL, error) {
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
		if err := checkTargetHost(u.Hostname()); err != nil {
			return nil, fmt.Errorf("url #%d: %w", i+1, err)
		}
	}
	return parsed, nil
}
