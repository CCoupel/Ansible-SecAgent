package server

import (
	"context"
	"time"

	"secagent-server/cmd/secagent-server/internal/repeater"
	"secagent-server/cmd/secagent-server/internal/state"
	"secagent-server/cmd/secagent-server/internal/storage"
)

// trustStore persists the link trust of a non-root relay in the state (link_trust, schema v2).
type trustStore struct{ s *storage.Store }

func (t trustStore) LoadLinkTrust() (repeater.TrustRecord, error) {
	lt := t.s.LinkTrust()
	return repeater.TrustRecord{RootID: lt.RootID, CurrentPub: lt.CurrentPub, CurrentKID: lt.CurrentKID,
		PreviousPub: lt.PreviousPub, PreviousKID: lt.PreviousKID, Seq: lt.Seq}, nil
}

func (t trustStore) SaveLinkTrust(r repeater.TrustRecord) error {
	return t.s.SetLinkTrust(context.Background(), state.LinkTrust{RootID: r.RootID, CurrentPub: r.CurrentPub, CurrentKID: r.CurrentKID,
		PreviousPub: r.PreviousPub, PreviousKID: r.PreviousKID, Seq: r.Seq})
}

// linkBlacklist is the blacklist of the link-token JTI revoked by the root.
type linkBlacklist struct{ s *storage.Store }

func (b linkBlacklist) BlacklistLinkJTI(jti string, exp time.Time) error {
	reason := "link token revoked by the root"
	return b.s.AddToBlacklist(context.Background(), jti, "", exp.UTC().Format(time.RFC3339), &reason)
}

func (b linkBlacklist) IsLinkJTIBlacklisted(jti string) bool {
	bad, err := b.s.IsJTIBlacklisted(context.Background(), jti)
	return bad || err != nil // fail closed
}
