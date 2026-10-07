package repeater

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"time"
)

// ErrPermanentRefusal wraps the reason when the peer refused the link for good (close 4010).
var ErrPermanentRefusal = errors.New("link refused permanently")

// runLoop calls session until ctx is cancelled, reconnecting with exponential backoff
// (min → max). A session that reached steady state restarts the sequence.
// Refusals (#148): a PERMANENT one (close 4010: revoked/unauthorized identity, loop, identity
// mismatch) stops the loop and is returned (wrapping ErrPermanentRefusal): the peer must not be
// hammered and an operator must act. A CORRECTABLE one (close 4012) is retried with the normal
// exponential backoff.
//
// onTerminal (optional) is called with the terminal error BEFORE the status flips to
// refused_permanent, so that "Status() permanent ⇒ Terminal() != nil" always holds.
func runLoop(ctx context.Context, peer string, minBackoff, maxBackoff time.Duration, tr *linkTracker,
	onTerminal func(error), session func(context.Context) (established bool, err error)) error {
	return runLoopAfter(ctx, peer, minBackoff, maxBackoff, tr, onTerminal, session, nil)
}

// runLoopAfter is runLoop with the wait between two attempts injected (nil = time.After): tests
// record the computed delays instead of measuring wall-clock gaps, which are dominated by TLS
// handshakes and scheduling noise on a loaded machine.
func runLoopAfter(ctx context.Context, peer string, minBackoff, maxBackoff time.Duration, tr *linkTracker,
	onTerminal func(error), session func(context.Context) (established bool, err error),
	after func(time.Duration) <-chan time.Time) error {
	if after == nil {
		after = time.After
	}
	backoff := minBackoff
	for ctx.Err() == nil {
		established, err := session(ctx)
		if ctx.Err() != nil {
			tr.set(LinkRetrying, "stopped") // cancellation is not a refusal
			return nil
		}
		var ref *refusedError
		wait := backoff
		switch {
		case errors.As(err, &ref) && ref.permanent:
			log.Printf("[REPEATER] ERROR %s refused link (permanent), giving up — operator action required: %s", peer, sanitizeText(errText(err)))
			terr := fmt.Errorf("%w: %s: %s", ErrPermanentRefusal, peer, ref.reason)
			if onTerminal != nil {
				onTerminal(terr)
			}
			tr.set(LinkRefusedPermanent, ref.reason)
			return terr
		case errors.As(err, &ref):
			log.Printf("[REPEATER] %s refused link (correctable), retrying: %s", peer, sanitizeText(errText(err)))
			tr.set(LinkRetrying, ref.reason)
			backoff = min(backoff*2, maxBackoff)
		case established:
			log.Printf("[REPEATER] link to %s lost: %s", peer, sanitizeText(errText(err)))
			tr.set(LinkRetrying, "link lost: "+errText(err))
			backoff = minBackoff
			wait = backoff
		default:
			log.Printf("[REPEATER] connect to %s failed: %s", peer, sanitizeText(errText(err)))
			tr.set(LinkRetrying, "connect failed: "+errText(err))
			backoff = min(backoff*2, maxBackoff)
		}
		select {
		case <-ctx.Done():
			tr.set(LinkRetrying, "stopped") // same observable as the cancellation inside a session
			return nil
		case <-after(wait):
		}
	}
	tr.set(LinkRetrying, "stopped") // the context ended between two attempts: same observable
	return nil
}

// tlsOrDefault returns cfg, or the default client TLS configuration (system roots, TLS ≥ 1.2).
// This is the single extension point for a custom CA (#147, REPEATER_UPSTREAM_*-style variable):
// build the *tls.Config there and pass it via Options.TLSConfig / DialerOptions.TLSConfig.
// InsecureSkipVerify must never be set outside tests.
func tlsOrDefault(cfg *tls.Config) *tls.Config {
	if cfg != nil {
		return cfg
	}
	return &tls.Config{MinVersion: tls.VersionTLS12}
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
