// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

package state

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

// agentV305 is the Agent of a v3.0.5 binary: no first_seen_at. Its decoder is strict (DisallowUnknownFields,
// state/file.go), which is why a v3.0.6 state that carries the mark is REFUSED by v3.0.5 (rollback rule of
// STATE_SPEC: restore the backup taken before the upgrade) while a state without it is read as before.
type agentV305 struct {
	Hostname     string         `json:"hostname"`
	PublicKeyPEM string         `json:"public_key_pem"`
	TokenJTI     string         `json:"token_jti,omitempty"`
	PrevTokenJTI string         `json:"prev_token_jti,omitempty"`
	EnrolledAt   time.Time      `json:"enrolled_at"`
	Suspended    bool           `json:"suspended,omitempty"`
	Revoked      bool           `json:"revoked,omitempty"`
	Vars         map[string]any `json:"vars,omitempty"`
	LastSeen     *time.Time     `json:"last_seen,omitempty"`
}

func TestFirstSeenAt_IsRefusedByAStrictV305DecoderOnlyWhenSet(t *testing.T) {
	now := time.Now().UTC()
	with, _ := json.Marshal(Agent{Hostname: "h", PublicKeyPEM: "p", EnrolledAt: now, FirstSeenAt: &now})
	without, _ := json.Marshal(Agent{Hostname: "h", PublicKeyPEM: "p", EnrolledAt: now})
	decode := func(raw []byte) error {
		var a agentV305
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		return dec.Decode(&a)
	}
	if err := decode(with); err == nil {
		t.Error("a v3.0.5 strict decoder must refuse a state that carries first_seen_at (documented rollback blocker)")
	}
	if err := decode(without); err != nil {
		t.Errorf("a state without the mark must stay readable by v3.0.5: %v", err)
	}
	// and the current decoder round-trips both, deep-copying the pointer
	var a Agent
	if err := json.Unmarshal(with, &a); err != nil || a.FirstSeenAt == nil || !a.FirstSeenAt.Equal(now) {
		t.Errorf("round trip: %v %+v", err, a)
	}
	c := a.clone()
	*c.FirstSeenAt = c.FirstSeenAt.Add(time.Hour)
	if a.FirstSeenAt.Equal(*c.FirstSeenAt) {
		t.Error("clone must not share the FirstSeenAt pointer")
	}
}
