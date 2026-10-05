package endpoints

import (
	"context"
	"errors"
	"net/url"
	"sync"
	"time"
)

// Backoff bounds the delay applied after a full round of failures. Zero values
// default to Min=1s, Max=60s. Min is clamped to Max.
type Backoff struct {
	Min time.Duration
	Max time.Duration
}

// Rotor orders connection attempts over a fixed address list and tracks
// failures. Safe for concurrent use.
//
// Order: the last address that answered first (initially the first of the
// list), then the others in list order. After a full round with no success
// (consecutive failures >= number of addresses) Backoff returns an
// exponentially growing delay Min, 2*Min, 4*Min... capped at Max; the first
// Success resets everything.
type Rotor struct {
	urls []*url.URL
	bo   Backoff

	mu    sync.Mutex
	last  int
	fails int // consecutive failures since last success
}

// NewRotor builds a Rotor over urls (not modified, not copied by element: URLs
// must be treated as read-only). Returns ErrEmpty if urls is empty.
func NewRotor(urls []*url.URL, bo Backoff) (*Rotor, error) {
	if len(urls) == 0 {
		return nil, ErrEmpty
	}
	if bo.Min <= 0 {
		bo.Min = time.Second
	}
	if bo.Max <= 0 {
		bo.Max = time.Minute
	}
	if bo.Min > bo.Max {
		bo.Min = bo.Max
	}
	return &Rotor{urls: append([]*url.URL(nil), urls...), bo: bo}, nil
}

// Len returns the number of addresses.
func (r *Rotor) Len() int { return len(r.urls) }

// URL returns the address at index i (nil if out of range).
func (r *Rotor) URL(i int) *url.URL {
	if i < 0 || i >= len(r.urls) {
		return nil
	}
	return r.urls[i]
}

// Order returns the indices to try: last good address first, then the rest in
// list order.
func (r *Rotor) Order() []int {
	r.mu.Lock()
	last := r.last
	r.mu.Unlock()
	out := make([]int, 0, len(r.urls))
	out = append(out, last)
	for i := range r.urls {
		if i != last {
			out = append(out, i)
		}
	}
	return out
}

// Success records that address i answered: it becomes the first choice and the
// backoff is reset. Out-of-range indices are ignored.
func (r *Rotor) Success(i int) {
	if i < 0 || i >= len(r.urls) {
		return
	}
	r.mu.Lock()
	r.last = i
	r.fails = 0
	r.mu.Unlock()
}

// Failure records that address i failed. Out-of-range indices are ignored.
func (r *Rotor) Failure(i int) {
	if i < 0 || i >= len(r.urls) {
		return
	}
	r.mu.Lock()
	r.fails++
	r.mu.Unlock()
}

// Backoff returns the delay to wait before the next round: 0 while the current
// round is incomplete, then Min doubling per additional full round, capped at Max.
func (r *Rotor) Backoff() time.Duration {
	r.mu.Lock()
	fails := r.fails
	r.mu.Unlock()
	rounds := fails / len(r.urls)
	if rounds == 0 {
		return 0
	}
	d := r.bo.Min
	for i := 1; i < rounds; i++ {
		if d >= r.bo.Max/2 {
			return r.bo.Max
		}
		d *= 2
	}
	if d > r.bo.Max {
		d = r.bo.Max
	}
	return d
}

// Wait sleeps for Backoff() (returns at once if 0) or until ctx is done, in
// which case it returns ctx.Err().
func (r *Rotor) Wait(ctx context.Context) error {
	d := r.Backoff()
	if d == 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

var errNilRotor = errors.New("endpoints: nil rotor")
