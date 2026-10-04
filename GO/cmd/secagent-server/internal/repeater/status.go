package repeater

import (
	"strings"
	"sync"
	"time"
)

// LinkState is the observable state of a parent/child link (#154).
type LinkState string

const (
	// LinkConnected: the handshake succeeded and the link is being served.
	LinkConnected LinkState = "connected"
	// LinkRetrying: not linked; reconnecting with backoff (initial attempts, lost link,
	// correctable refusal 4012, context cancelled). NOT a terminal state.
	LinkRetrying LinkState = "retrying"
	// LinkRefusedPermanent: the peer refused for good (close 4010, identity mismatch, loop):
	// the client/dialer gave up, an operator must act.
	LinkRefusedPermanent LinkState = "refused_permanent"
)

// maxReasonLen bounds the free-text reason exposed in the status.
const maxReasonLen = 200

// LinkStatus is a snapshot of a link. Reason never contains a secret: it is built from the
// refusal text / transport error (peer ids, close text, host) — never from tokens or headers.
type LinkStatus struct {
	State  LinkState `json:"state"`
	Reason string    `json:"reason,omitempty"`
	Since  time.Time `json:"since"`
}

// linkTracker records the current LinkStatus of one link.
type linkTracker struct {
	mu sync.Mutex
	st LinkStatus
}

func newLinkTracker() *linkTracker {
	return &linkTracker{st: LinkStatus{State: LinkRetrying, Reason: "starting", Since: time.Now().UTC()}}
}

func (t *linkTracker) set(state LinkState, reason string) {
	if t == nil {
		return
	}
	reason = strings.TrimSpace(reason)
	if len(reason) > maxReasonLen {
		reason = reason[:maxReasonLen] + "…"
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.st.State == state && t.st.Reason == reason {
		return // same condition: keep the original timestamp
	}
	t.st = LinkStatus{State: state, Reason: reason, Since: time.Now().UTC()}
}

func (t *linkTracker) get() LinkStatus {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.st
}

// NamedStatus is the status of one push child link.
type NamedStatus struct {
	RelayID string `json:"relay_id"`
	LinkStatus
}

// UpstreamStatus is the link to this node's parent.
type UpstreamStatus struct {
	Mode string `json:"mode"` // "pull" (we dial the parent) | "push" (the parent dialed us)
	Peer string `json:"peer,omitempty"`
	LinkStatus
}

// LinksStatus groups every observable link of the node (#154).
type LinksStatus struct {
	Upstream *UpstreamStatus `json:"upstream,omitempty"`
	Push     []NamedStatus   `json:"push_children,omitempty"`
	Degraded bool            `json:"degraded"` // at least one link was refused permanently
}

// Empty reports whether the node has no link to report (a plain root without push children).
func (l LinksStatus) Empty() bool { return l.Upstream == nil && len(l.Push) == 0 }

// NewLinksStatus builds the summary and computes Degraded.
func NewLinksStatus(up *UpstreamStatus, push []NamedStatus) LinksStatus {
	l := LinksStatus{Upstream: up, Push: push}
	if up != nil && up.State == LinkRefusedPermanent {
		l.Degraded = true
	}
	for _, p := range push {
		if p.State == LinkRefusedPermanent {
			l.Degraded = true
		}
	}
	return l
}
