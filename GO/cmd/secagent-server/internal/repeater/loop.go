package repeater

import (
	"context"
	"crypto/tls"
	"errors"
	"log"
	"time"
)

// runLoop calls session until ctx is cancelled, reconnecting with exponential backoff
// (min → max). A session that reached steady state restarts the sequence; a refusal
// (loop, identity mismatch, close 4010) waits the maximum delay: it is structural and
// the peer must not be hammered. The 4010 distinction (#148) hooks in the refusedError case.
func runLoop(ctx context.Context, peer string, minBackoff, maxBackoff time.Duration,
	session func(context.Context) (established bool, err error)) {
	backoff := minBackoff
	for ctx.Err() == nil {
		established, err := session(ctx)
		if ctx.Err() != nil {
			return
		}
		var ref *refusedError
		wait := backoff
		switch {
		case errors.As(err, &ref):
			log.Printf("[REPEATER] %s refused link: %v", peer, err)
			wait = maxBackoff
			backoff = maxBackoff
		case established:
			log.Printf("[REPEATER] link to %s lost: %v", peer, err)
			backoff = minBackoff
			wait = backoff
		default:
			log.Printf("[REPEATER] connect to %s failed: %v", peer, err)
			backoff = min(backoff*2, maxBackoff)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
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
