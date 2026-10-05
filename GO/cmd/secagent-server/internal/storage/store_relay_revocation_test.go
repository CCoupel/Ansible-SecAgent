package storage

import (
	"context"
	"testing"
	"time"
)

func TestRelayRevocation_TokenInfoRoundTrip(t *testing.T) {
	s := newRelayTestStore(t)
	seedNodes(t, s, "legacy")
	// a relay declared without token info: no JTI, not revoked
	info, err := s.GetRelayTokenInfo("legacy")
	if err != nil || info.JTI != "" || info.Revoked || info.Exp != 0 {
		t.Fatalf("info of a relay without token = %+v %v", info, err)
	}
	if err := s.SetRelayTokenInfo("legacy", "jti-9", 123456); err != nil {
		t.Fatal(err)
	}
	if info, _ := s.GetRelayTokenInfo("legacy"); info.JTI != "jti-9" || info.Exp != 123456 {
		t.Errorf("info = %+v", info)
	}
	if err := s.SetRelayTokenInfo("nobody", "x", 1); err == nil {
		t.Error("unknown relay must be an error")
	}
	if info, err := s.GetRelayTokenInfo("nobody"); err != nil || info != (RelayTokenInfo{}) {
		t.Errorf("unknown relay info = %+v %v", info, err)
	}
}

func TestRelayRevocation_RevokeBlacklistsAndFlags(t *testing.T) {
	s := newRelayTestStore(t)
	ctx := context.Background()
	seedNodes(t, s, "dmz1", "dmz2")
	exp := time.Now().Add(24 * time.Hour).Unix()
	if err := s.SetRelayTokenInfo("dmz1", "jti-dmz1", exp); err != nil {
		t.Fatal(err)
	}
	info, found, err := s.RevokeRelayNode(ctx, "dmz1", "admin revoke")
	if err != nil || !found || info.JTI != "jti-dmz1" {
		t.Fatalf("revoke = %+v %v %v", info, found, err)
	}
	if bl, _ := s.IsJTIBlacklisted(ctx, "jti-dmz1"); !bl {
		t.Error("JTI must be blacklisted")
	}
	if got, _ := s.GetRelayTokenInfo("dmz1"); !got.Revoked {
		t.Error("relay must be flagged revoked")
	}
	// other relays untouched
	if other, _ := s.GetRelayTokenInfo("dmz2"); other.Revoked {
		t.Error("dmz2 must not be affected")
	}
	// idempotent
	if _, found, err := s.RevokeRelayNode(ctx, "dmz1", "again"); err != nil || !found {
		t.Errorf("second revoke: %v %v", found, err)
	}
	// fresh token re-enables the relay
	if err := s.SetRelayTokenInfo("dmz1", "jti-new", exp); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetRelayTokenInfo("dmz1"); got.Revoked || got.JTI != "jti-new" {
		t.Errorf("after re-issue: %+v", got)
	}
	if bl, _ := s.IsJTIBlacklisted(ctx, "jti-dmz1"); !bl {
		t.Error("the old JTI must stay blacklisted")
	}
}

// A relay that never had a token JTI is still flagged revoked (the flag alone makes /ws/relay refuse
// it). The state engine requires every revoked relay to be blacklisted, so the revocation gives it a
// synthetic JTI, flagged and blacklisted in the SAME mutation.
func TestRelayRevocation_RelayWithoutJTIIsFlaggedAndSyntheticallyBlacklisted(t *testing.T) {
	s := newRelayTestStore(t)
	seedNodes(t, s, "legacy")
	info, found, err := s.RevokeRelayNode(context.Background(), "legacy", "r")
	if err != nil || !found || info.JTI != "" {
		t.Fatalf("revoke = %+v %v %v", info, found, err)
	}
	if got, _ := s.GetRelayTokenInfo("legacy"); !got.Revoked {
		t.Error("a relay without JTI must still be flagged revoked (the flag alone makes /ws/relay refuse it)")
	}
	if bl, _ := s.IsJTIBlacklisted(context.Background(), "no-token:legacy"); !bl {
		t.Error("the synthetic JTI must be blacklisted together with the flag")
	}
	if _, found, _ := s.RevokeRelayNode(context.Background(), "ghost", "r"); found {
		t.Error("unknown relay: found must be false")
	}
}
