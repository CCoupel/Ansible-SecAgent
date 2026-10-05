// Package endpoints is the shared multi-address helper used by every Go client
// of the relay (minion, repeater, CLI, inventory).
//
// In active/passive mode a relay is reachable at N addresses of which only one
// answers: the master (the standby opens no port). The package provides three
// building blocks:
//
//   - [Parse] turns a comma separated list into validated URLs;
//   - [Rotor] orders the attempts (last good address first) and computes the
//     exponential backoff applied after a full round without success;
//   - [DialFirst] tries the addresses in that order, with a per-address
//     timeout, and distinguishes failures BEFORE the request is sent (next
//     address is tried) from failures AFTER (returned as-is, never replayed).
//
// Typical client loop:
//
//	urls, err := endpoints.Parse(cfg.RelayURLs)               // or ParseSchemes(v, "wss")
//	rotor, err := endpoints.NewRotor(urls, endpoints.Backoff{Min: time.Second, Max: time.Minute})
//	for {
//	    conn, u, err := endpoints.DialFirst(ctx, rotor, 5*time.Second, dial)
//	    if err == nil { serve(conn); continue }
//	    if errors.Is(err, endpoints.ErrAfterSend) { /* caller decides: replay only if idempotent */ }
//	    if werr := rotor.Wait(ctx); werr != nil { return werr }
//	}
//
// # TLS
//
// Each address must present a certificate valid for its own host name, using
// the TLS configuration of the caller (system CAs, or a custom CA). The helper
// never sets InsecureSkipVerify.
//
// # DNS without code
//
// A single DNS name with several A records already works without this package:
// net.Dialer (used by websocket.Dialer and http.Transport) tries every
// resolved IP in order, so the standby refusing TCP makes the dialer move to
// the next IP. Limits: DNS cache and TTL, order not controlled, the dial
// timeout is shared between IPs when a host is down, and the certificate must
// cover the common name.
//
// # Secrets
//
// Userinfo is forbidden in addresses, and neither errors nor logs ever echo a
// URL: addresses are referred to by their position and host only.
package endpoints

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// Sentinel errors returned (wrapped) by Parse and ParseSchemes. Messages carry
// the 1-based position of the offending address, never its content.
var (
	ErrEmpty     = errors.New("endpoints: empty address list")
	ErrInvalid   = errors.New("endpoints: invalid address")
	ErrUserinfo  = errors.New("endpoints: userinfo not allowed in address")
	ErrDuplicate = errors.New("endpoints: duplicate address")
	ErrScheme    = errors.New("endpoints: unsupported scheme")
)

// Parse splits a comma separated list of absolute URLs (spaces around items are
// ignored) and validates it. A single value is a valid list of one. Any scheme
// is accepted; use ParseSchemes to restrict it.
//
// Errors: empty list or empty item (ErrEmpty/ErrInvalid), unparsable URL or
// missing scheme/host (ErrInvalid), userinfo (ErrUserinfo), duplicate
// (ErrDuplicate). The offending URL is never included in the error.
func Parse(value string) ([]*url.URL, error) {
	return ParseSchemes(value)
}

// ParseSchemes is Parse with the scheme restricted to the given set
// (case-insensitive), e.g. ParseSchemes(v, "wss") for the repeater. An empty
// set accepts any scheme.
func ParseSchemes(value string, schemes ...string) ([]*url.URL, error) {
	if strings.TrimSpace(value) == "" {
		return nil, ErrEmpty
	}
	allowed := make(map[string]bool, len(schemes))
	for _, s := range schemes {
		allowed[strings.ToLower(s)] = true
	}
	items := strings.Split(value, ",")
	out := make([]*url.URL, 0, len(items))
	seen := make(map[string]int, len(items))
	for i, raw := range items {
		pos := i + 1
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return nil, fmt.Errorf("%w: address #%d is empty", ErrInvalid, pos)
		}
		u, err := url.Parse(raw)
		if err != nil {
			// url.Error embeds the raw URL: do not wrap it.
			return nil, fmt.Errorf("%w: address #%d is not a valid URL", ErrInvalid, pos)
		}
		if u.User != nil || strings.Contains(u.Host, "@") {
			return nil, fmt.Errorf("%w: address #%d", ErrUserinfo, pos)
		}
		if u.Scheme == "" || u.Hostname() == "" {
			return nil, fmt.Errorf("%w: address #%d needs a scheme and a host", ErrInvalid, pos)
		}
		u.Scheme = strings.ToLower(u.Scheme)
		u.Host = strings.ToLower(u.Host)
		if len(allowed) > 0 && !allowed[u.Scheme] {
			return nil, fmt.Errorf("%w: address #%d", ErrScheme, pos)
		}
		key := u.Scheme + "://" + dedupHost(u) + strings.TrimRight(u.EscapedPath(), "/") + "?" + u.RawQuery
		if first, dup := seen[key]; dup {
			return nil, fmt.Errorf("%w: address #%d repeats #%d", ErrDuplicate, pos, first)
		}
		seen[key] = pos
		out = append(out, u)
	}
	return out, nil
}

// dedupHost returns the lowercase host[:port] with the scheme's default port
// removed, so https://a and https://a:443 are the same address.
func dedupHost(u *url.URL) string {
	def := map[string]string{"http": "80", "ws": "80", "https": "443", "wss": "443"}[u.Scheme]
	if def != "" && u.Port() == def {
		h := u.Hostname()
		if strings.Contains(h, ":") {
			return "[" + h + "]"
		}
		return h
	}
	return u.Host
}
