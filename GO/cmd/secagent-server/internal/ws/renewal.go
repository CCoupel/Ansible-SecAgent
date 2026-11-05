// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

package ws

import (
	"context"
	"errors"
	"log"
	"math/rand"
	"sync/atomic"
	"time"
)

// Periodic renewal of the JWT of a connected agent (#217).
//
// The JWT of an agent is checked at the /ws/agent handshake only. Without renewal it expires one
// TTL after enrollment and every agent whose connection drops later (relay restarted, failover)
// would be refused with 401 and have to re-enroll with a token it no longer has: a fleet-wide stop.
// The relay therefore sends each connected agent a fresh JWT in the existing "rekey" frame before
// the current one expires.
//
// There is no global sweep: every connection owns one timer, due when the remaining validity drops
// to TTL - interval, with a +/-10 % jitter, so a fleet of thousands of agents renews spread over
// the period (one state write per agent and per period).

// ErrRenewStop is returned by the renewal function when the agent must not be renewed any more
// (revoked or unknown): the loop of that connection ends.
var ErrRenewStop = errors.New("agent jwt renewal stopped")

// RenewFunc sends the agent a fresh JWT and returns its expiry.
type RenewFunc func(hostname string) (time.Time, error)

type renewalParams struct {
	ttl      time.Duration
	interval time.Duration
	fn       RenewFunc
}

var renewal atomic.Pointer[renewalParams]

// SetRenewal enables the periodic renewal: ttl is the lifetime of the agent JWTs, interval the
// renewal period (ttl/3 by default, chosen by the caller). A zero interval or a nil fn disables it.
func SetRenewal(ttl, interval time.Duration, fn RenewFunc) {
	if interval <= 0 || fn == nil {
		renewal.Store(nil)
		return
	}
	renewal.Store(&renewalParams{ttl: ttl, interval: interval, fn: fn})
}

// renewalSlots caps the renewals in flight at once (each is an RSA-OAEP encryption plus one state
// write with fsync): even if a whole fleet became due together, the relay emits a bounded number at a time.
var renewalSlots = make(chan struct{}, 16)

// jitterFraction is the +/- share of the interval added to every delay.
const jitterFraction = 0.1

// nextRenewalDelay returns the wait before the next renewal of a JWT with the given remaining
// validity. j is a random number in [-1, 1].
func nextRenewalDelay(p *renewalParams, remaining time.Duration, j float64) time.Duration {
	base := remaining - (p.ttl - p.interval) // renew once one interval has passed since the issue
	if base < 0 {
		base = 0
	}
	if base > p.interval {
		base = p.interval
	}
	d := base + time.Duration(j*jitterFraction*float64(p.interval))
	if d < 0 {
		d = -d // an expiring token: spread over [0, 10 % of the interval] instead of a burst at 0
	}
	return d
}

// firstSpread is the extra random wait of the FIRST renewal of a connection: agents that connected
// together (a failover, a restart) would otherwise all fall due at the same instant. It is uniform on
// [0, interval) but never pushes the renewal closer than interval/4 to the expiry of the JWT.
func firstSpread(p *renewalParams, remaining, base time.Duration, u float64) time.Duration {
	room := remaining - p.interval/4 - base
	if room > p.interval {
		room = p.interval
	}
	if room <= 0 {
		return 0
	}
	return time.Duration(u * float64(room))
}

// retryDelay is the wait after a renewal that could not be sent (read-only state, ...).
func retryDelay(p *renewalParams, j float64) time.Duration {
	d := p.interval / 10
	if d < 100*time.Millisecond {
		d = 100 * time.Millisecond
	}
	return d + time.Duration((j+1)/2*float64(d)/2)
}

// runRenewal renews the JWT of hostname until ctx is done or the agent is revoked/unknown. exp is
// the expiry of the JWT the agent connected with.
func runRenewal(ctx context.Context, hostname string, exp time.Time) {
	p := renewal.Load()
	if p == nil {
		return
	}
	retry, first := false, true
	for {
		var d time.Duration
		if retry {
			d = retryDelay(p, rand.Float64()*2-1)
		} else {
			remaining := time.Until(exp)
			d = nextRenewalDelay(p, remaining, rand.Float64()*2-1)
			if first {
				d += firstSpread(p, remaining, d, rand.Float64())
			}
		}
		first = false
		t := time.NewTimer(d)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		select {
		case renewalSlots <- struct{}{}:
		case <-ctx.Done():
			return
		}
		newExp, err := p.fn(hostname)
		<-renewalSlots
		switch {
		case err == nil:
			exp, retry = newExp, false
		case errors.Is(err, ErrRenewStop):
			log.Printf("agent JWT renewal ended: hostname=%q", hostname)
			return
		default:
			retry = true
		}
	}
}
