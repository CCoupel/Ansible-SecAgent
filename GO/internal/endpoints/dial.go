package endpoints

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http/httptrace"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

// DefaultAttemptTimeout bounds one address when DialFirst gets timeout <= 0.
const DefaultAttemptTimeout = 5 * time.Second

// ErrAfterSend marks (via errors.Is) a failure that happened after the
// connection was established / the request possibly sent. DialFirst returns it
// without trying another address: only the caller knows whether the operation
// is idempotent (an inventory GET may be replayed, an exec must not).
var ErrAfterSend = errors.New("endpoints: failure after send, no other address tried")

// ErrAllFailed marks (via errors.Is) a round where every address failed
// BEFORE sending anything. Safe to retry after rotor.Wait.
var ErrAllFailed = errors.New("endpoints: all addresses failed before send")

type sentKey struct{}

// MarkSent records, on a ctx received by a dial function, that request bytes
// are about to leave (or have left). From then on a timeout is an after-send
// failure and DialFirst will not try another address. A dial function that
// writes a request itself (raw conn, WebSocket upgrade, ...) must call it
// right before the first write; net/http requests are tracked automatically
// (httptrace) when made with the received ctx. No-op on a foreign ctx.
func MarkSent(ctx context.Context) {
	if f, ok := ctx.Value(sentKey{}).(*atomic.Bool); ok {
		f.Store(true)
	}
}

// isTimeout reports a timeout-like error: deadline/context expiry, net
// timeout, or the net/http TLS handshake timeout.
func isTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	// Includes net/http's "TLS handshake timeout" (a net.Error with Timeout()).
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

type beforeSendError struct{ err error }

func (e *beforeSendError) Error() string { return e.err.Error() }
func (e *beforeSendError) Unwrap() error { return e.err }

// MarkBeforeSend flags err as a failure that occurred before anything was sent
// (e.g. an HTTP 503 handshake status from a node known to be inactive), so
// DialFirst moves to the next address. nil stays nil. Use sparingly: unmarked
// errors that are not recognised as connection-phase errors are treated as
// after-send (fail safe).
func MarkBeforeSend(err error) error {
	if err == nil {
		return nil
	}
	return &beforeSendError{err: err}
}

// IsBeforeSend reports whether err is a failure that occurred before the
// request was sent: explicitly marked by MarkBeforeSend, or a recognised
// connection-phase error (DNS failure, TCP dial error incl. refusal/timeout,
// TLS handshake or certificate verification failure).
func IsBeforeSend(err error) bool {
	if err == nil {
		return false
	}
	var marked *beforeSendError
	if errors.As(err, &marked) {
		return true
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return true
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Op == "dial" {
		return true
	}
	return isTLS(err)
}

// afterSendError is returned when a failure occurs after send.
type afterSendError struct {
	index int
	err   error
}

func (e *afterSendError) Error() string {
	return fmt.Sprintf("address #%d: failure after send, not retried: %s", e.index+1, redact(e.err))
}
func (e *afterSendError) Unwrap() []error { return []error{ErrAfterSend, e.err} }

// AfterSendIndex returns the index of the address on which DialFirst stopped with an after-send
// failure (errors.Is(err, ErrAfterSend)), so the caller can Rotor.Rotate it away.
func AfterSendIndex(err error) (int, bool) {
	var ae *afterSendError
	if errors.As(err, &ae) {
		return ae.index, true
	}
	return 0, false
}

// allFailedError aggregates the per-address failures of a round.
type allFailedError struct{ msgs []string }

func (e *allFailedError) Error() string {
	return "all addresses failed before send: " + strings.Join(e.msgs, "; ")
}
func (e *allFailedError) Is(target error) bool { return target == ErrAllFailed }

// redact returns the error text without any URL: *url.Error (which embeds the
// full URL, possibly with a token in the query) is reduced to its cause.
func redact(err error) string {
	msg := err.Error()
	var ue *url.Error
	if errors.As(err, &ue) {
		msg = strings.ReplaceAll(msg, ue.Error(), ue.Err.Error())
	}
	return msg
}

// DialFirst tries dial on the addresses of rotor in rotor.Order() until one
// succeeds, and returns its result with the address used.
//
// Each attempt gets a context bounded by timeout (DefaultAttemptTimeout if <=
// 0) so a silent host cannot block the rest of the list. That context is only
// valid during dial and is cancelled when dial returns: dial must use it to
// establish the connection (e.g. websocket Dialer.DialContext, or a request
// fully read before returning) and must not keep it.
//
// Outcome per attempt:
//   - success: rotor.Success(i), result returned;
//   - failure BEFORE send (IsBeforeSend): rotor.Failure(i), logged (address
//     index and host only), next address;
//   - any other failure (AFTER send): returned at once wrapped with ErrAfterSend,
//     NO other address is tried and the rotor is untouched. Callers replaying
//     idempotent requests may call DialFirst again; others must not.
//
// A timeout (per-address timeout, net timeout, "TLS handshake timeout") is
// also treated as before-send when no request byte has left: net/http
// requests made with the received ctx are tracked automatically; a dial
// function that writes the request itself must call MarkSent(ctx) before the
// first write. A dial that wraps the whole exchange and does neither would see
// its after-send timeouts replayed: do not rely on DialFirst for that without
// MarkSent. Every case not explicitly recognised stays after-send (fail safe).
// A frozen WebSocket handshake is after-send only once the Upgrade request left.
//
// If every address failed before send, the error satisfies
// errors.Is(err, ErrAllFailed); call rotor.Wait(ctx) before the next round.
// If ctx is done, ctx.Err() is returned.
func DialFirst[T any](ctx context.Context, r *Rotor, timeout time.Duration,
	dial func(ctx context.Context, u *url.URL) (T, error)) (T, *url.URL, error) {

	var zero T
	if r == nil {
		return zero, nil, errNilRotor
	}
	if timeout <= 0 {
		timeout = DefaultAttemptTimeout
	}
	var msgs []string
	for _, i := range r.Order() {
		if err := ctx.Err(); err != nil {
			return zero, nil, err
		}
		u := r.URL(i)
		res, sent, err := attempt(ctx, timeout, u, dial)
		if err == nil {
			r.Success(i)
			return res, u, nil
		}
		if cerr := ctx.Err(); cerr != nil {
			return zero, nil, cerr
		}
		// Timeouts (frozen master: TCP accepted, TLS/handshake never answered)
		// are before-send as long as no request byte left.
		if !IsBeforeSend(err) && (sent || !isTimeout(err)) {
			return zero, nil, &afterSendError{index: i, err: err}
		}
		r.Failure(i)
		slog.Warn("endpoints: address failed before send",
			"address", i+1, "host", u.Host, "tls_error", isTLS(err), "error", redact(err))
		msgs = append(msgs, fmt.Sprintf("#%d: %s", i+1, redact(err)))
	}
	return zero, nil, &allFailedError{msgs: msgs}
}

// attempt runs one dial with its own timeout; cancel is deferred so the
// attempt context is released even if dial panics. sent reports whether a
// request byte left (httptrace or MarkSent).
func attempt[T any](ctx context.Context, timeout time.Duration, u *url.URL,
	dial func(context.Context, *url.URL) (T, error)) (res T, sent bool, err error) {
	var flag atomic.Bool
	actx, cancel := context.WithTimeout(context.WithValue(ctx, sentKey{}, &flag), timeout)
	defer cancel()
	actx = httptrace.WithClientTrace(actx, &httptrace.ClientTrace{
		WroteHeaderField: func(string, []string) { flag.Store(true) },
	})
	res, err = dial(actx, u)
	return res, flag.Load(), err
}

func isTLS(err error) bool {
	var certVerif *tls.CertificateVerificationError
	var hostErr x509.HostnameError
	var unknownAuth x509.UnknownAuthorityError
	var certInvalid x509.CertificateInvalidError
	var recHdr tls.RecordHeaderError
	var alert tls.AlertError
	return errors.As(err, &certVerif) || errors.As(err, &hostErr) ||
		errors.As(err, &unknownAuth) || errors.As(err, &certInvalid) ||
		errors.As(err, &recHdr) || errors.As(err, &alert)
}
