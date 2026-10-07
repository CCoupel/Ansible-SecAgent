package storage

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"secagent-server/cmd/secagent-server/internal/state"
)

func sampleParentToken(id, jti string) RelayParentToken {
	now := time.Now().UTC().Truncate(time.Second)
	return RelayParentToken{ID: id, JTI: jti, ParentID: "central", Description: "link to central",
		CreatedAt: now, ExpiresAt: now.Add(90 * 24 * time.Hour)}
}

func TestRelayParentToken_CreateListGet(t *testing.T) {
	s := newRelayTestStore(t)
	ctx := context.Background()
	tok := sampleParentToken("id-1", "jti-1")
	if err := s.CreateRelayParentToken(ctx, tok); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateRelayParentToken(ctx, sampleParentToken("id-2", "jti-1")); err == nil {
		t.Error("a JTI must be unique")
	}
	list, err := s.ListRelayParentTokens(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("list = %v %v", list, err)
	}
	got := list[0]
	if got.ID != "id-1" || got.JTI != "jti-1" || got.ParentID != "central" || got.Revoked() ||
		!got.ExpiresAt.Equal(tok.ExpiresAt) || got.Description != "link to central" {
		t.Errorf("got %+v", got)
	}
	one, err := s.GetRelayParentToken(ctx, "id-1")
	if err != nil || one == nil || one.JTI != "jti-1" {
		t.Errorf("Get = %+v %v", one, err)
	}
	if none, err := s.GetRelayParentToken(ctx, "nope"); err != nil || none != nil {
		t.Errorf("unknown id: %+v %v", none, err)
	}
}

func TestRelayParentToken_RevokeBlacklistsJTIAtomically(t *testing.T) {
	s := newRelayTestStore(t)
	ctx := context.Background()
	if err := s.CreateRelayParentToken(ctx, sampleParentToken("id-1", "jti-1")); err != nil {
		t.Fatal(err)
	}
	if bl, _ := s.IsJTIBlacklisted(ctx, "jti-1"); bl {
		t.Fatal("must not be blacklisted before revocation")
	}
	tok, found, err := s.RevokeRelayParentToken(ctx, "id-1")
	if err != nil || !found || tok == nil || !tok.Revoked() || tok.JTI != "jti-1" {
		t.Fatalf("revoke = %+v %v %v", tok, found, err)
	}
	if bl, err := s.IsJTIBlacklisted(ctx, "jti-1"); err != nil || !bl {
		t.Errorf("JTI not blacklisted after revoke: %v %v", bl, err)
	}
	// idempotent
	if _, found, err := s.RevokeRelayParentToken(ctx, "id-1"); err != nil || !found {
		t.Errorf("second revoke: %v %v", found, err)
	}
	// unknown id
	if tok, found, err := s.RevokeRelayParentToken(ctx, "nope"); err != nil || found || tok != nil {
		t.Errorf("unknown id: %+v %v %v", tok, found, err)
	}
	list, _ := s.ListRelayParentTokens(ctx)
	if len(list) != 1 || !list[0].Revoked() {
		t.Errorf("list after revoke = %+v", list)
	}
}

// The record must hold metadata only: a JWT-looking value can never end up in it (neither in the
// store type nor in the state entity written to the file).
func TestRelayParentToken_RecordHasNoTokenField(t *testing.T) {
	for _, typ := range []reflect.Type{reflect.TypeOf(RelayParentToken{}), reflect.TypeOf(state.RelayParentToken{})} {
		for i := 0; i < typ.NumField(); i++ {
			name := strings.ToLower(typ.Field(i).Name)
			if strings.Contains(name, "token") || strings.Contains(name, "jwt") {
				t.Errorf("%s.%s could hold the token", typ, typ.Field(i).Name)
			}
		}
	}
}
