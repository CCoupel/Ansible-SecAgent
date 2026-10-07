package repeater

import (
	"context"
	"fmt"
	"net"
	"strings"
	"syscall"
)

// guardedDial opens the TCP connection of an outgoing relay link and applies the SSRF guard to the
// IP ADDRESSES ACTUALLY CONTACTED, not to the name that was validated earlier: a name that
// resolved to a public address when the target was registered may resolve to 127.0.0.1,
// 169.254.169.254 or 100.100.100.200 when the connection is made (DNS rebinding), and again at
// every reconnection. For each attempt:
//
//   - a literal IP is checked as is, a name is resolved NOW (lookupIP) and every resolved address is
//     checked; only the allowed ones are dialed, one after the other, so a name that mixes a
//     public and an internal address still reaches the public one and never the internal one;
//   - net.Dialer.Control re-checks the address of the socket right before connect(2): a second,
//     independent barrier on what the kernel really connects to;
//   - a refusal is a *net.OpError "dial" wrapping ErrForbiddenTarget: for endpoints.DialFirst it is a
//     failure BEFORE send (the next address is tried, nothing was sent).
//
// The host name stays in the TLS configuration (SNI and certificate verification are those of the
// name, see dialWS): only the TCP destination is an IP. UnsafeAllowInternalDialTargets (test
// harness) turns the checks off but still dials through the same resolver.
func guardedDial(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, dialErr(addr, err)
	}
	h := strings.Trim(strings.ToLower(host), "[]")
	allow := allowInternal.Load()

	var ips []net.IP
	if ip := net.ParseIP(h); ip != nil {
		ips = []net.IP{ip}
	} else {
		if !allow && !currentPolicy().AllowsLoopback() && (h == "localhost" || strings.HasSuffix(strings.TrimSuffix(h, "."), ".localhost")) {
			return nil, dialErr(addr, fmt.Errorf("%w: localhost (category=%s)", ErrForbiddenTarget, CategoryLoopback))
		}
		if !allow && nonCanonicalNumericHost(h) {
			return nil, dialErr(addr, fmt.Errorf("%w: numeric host that is not a canonical IP address", ErrForbiddenTarget))
		}
		rctx, cancel := context.WithTimeout(ctx, resolveTimeout)
		ips, err = lookupIP(rctx, h)
		cancel()
		if err != nil {
			return nil, dialErr(addr, fmt.Errorf("resolve: %w", err))
		}
		if len(ips) == 0 {
			return nil, dialErr(addr, fmt.Errorf("resolve: no address"))
		}
	}

	d := &net.Dialer{}
	if !allow {
		d.Control = func(_, address string, _ syscall.RawConn) error { return rejectInternalSocket(address) }
	}
	var lastErr error
	for _, ip := range ips {
		if !allow {
			if cat, why := currentPolicy().refusal(ip); cat != "" {
				lastErr = fmt.Errorf("%w: the name resolves to a %s address (category=%s)", ErrForbiddenTarget, why, cat)
				continue
			}
		}
		conn, derr := d.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if derr == nil {
			return conn, nil
		}
		lastErr = derr
		if ctx.Err() != nil {
			break
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("%w: no usable address", ErrForbiddenTarget)
	}
	return nil, dialErr(addr, lastErr)
}

// rejectInternalSocket is the check of net.Dialer.Control: the address the socket is about to
// connect to (ip:port, as the kernel sees it) must be a parseable, non internal IP.
func rejectInternalSocket(address string) error {
	ipStr, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("%w: unreadable socket address", ErrForbiddenTarget)
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return fmt.Errorf("%w: unreadable socket address", ErrForbiddenTarget)
	}
	if cat := currentPolicy().Category(ip); cat != "" {
		return fmt.Errorf("%w: the connection would reach a forbidden address (category=%s)", ErrForbiddenTarget, cat)
	}
	return nil
}

// dialErr is what the standard dialer returns: a *net.OpError "dial", which endpoints.IsBeforeSend
// recognises. The message never contains a URL or a token (only host:port).
func dialErr(_ string, err error) error {
	return &net.OpError{Op: "dial", Net: "tcp", Err: err}
}
