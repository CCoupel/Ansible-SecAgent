// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

// #217 (v3.0.5, D1) — invariants of the agent JWT renewal (maquette agent_jwt/renouvellement_217),
// unit level. The renewal reuses the existing control frame {"type":"rekey","token_encrypted":…}:
// these tests drive sendRekeyToAgent, the issuing primitive both the key rotation and the periodic
// renewal go through (the dev may move it behind a renewal service; the tests keep the contract
// "revoked ⇒ nothing, state refused ⇒ nothing, no secret in the logs").
//
//	I1 a revoked agent never receives a renewal rekey
//	I4 read-only state ⇒ no emission, explicit journal, no panic
//	I5 no JWT / token in the logs (jti truncated only)
//	I7 two rekeys in a row ⇒ the last JTI wins

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"log"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"secagent-server/cmd/secagent-server/internal/storage"
)

type renewalRig struct {
	host string
	priv *rsa.PrivateKey
	sent []map[string]interface{}
	logs *bytes.Buffer
}

// newRenewalRig enrolls host in the shared store, plugs the store as admin store and captures both
// the control frames and the logs.
func newRenewalRig(t *testing.T, host string) *renewalRig {
	t.Helper()
	if server == nil || server.PrivateKey == nil {
		t.Skip("server state not initialized")
	}
	priv, pub := genRSAPubPEM(t, 4096)
	preAuthorize(t, host, pub)
	if _, err := registerStore.RegisterAgent(context.Background(), host, pub, "jti-initial-"+host); err != nil {
		t.Fatal(err)
	}
	prev := adminStore
	adminStore = registerStore
	t.Cleanup(func() { adminStore = prev })

	r := &renewalRig{host: host, priv: priv, logs: &bytes.Buffer{}}
	prevSend := sendToAgentFn
	sendToAgentFn = func(h string, m map[string]interface{}) error {
		if h == host {
			r.sent = append(r.sent, m)
		}
		return nil
	}
	t.Cleanup(func() { sendToAgentFn = prevSend })
	log.SetOutput(r.logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	return r
}

// open decrypts the token_encrypted of a rekey frame with the agent's key.
func (r *renewalRig) open(t *testing.T, frame map[string]interface{}) (rawJWT string, claims jwt.MapClaims) {
	t.Helper()
	if frame["type"] != "rekey" {
		t.Fatalf("frame type %v, want rekey", frame["type"])
	}
	enc, _ := frame["token_encrypted"].(string)
	ct, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		t.Fatalf("token_encrypted is not base64: %v", err)
	}
	plain, err := rsa.DecryptOAEP(sha256.New(), nil, r.priv, ct, nil)
	if err != nil {
		t.Fatalf("token_encrypted must be RSA-OAEP(SHA-256) of the agent's public key: %v", err)
	}
	claims = jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(string(plain), claims); err != nil {
		t.Fatalf("the rekey carries a JWT: %v", err)
	}
	return string(plain), claims
}

// I1 (critical): a revoked agent gets nothing — no frame, JTI untouched, [SECURITY WARNING] journal.
func TestSpec217_I1_ARevokedAgentNeverReceivesAWrittenRenewal(t *testing.T) {
	r := newRenewalRig(t, "renew-revoked-host")
	ctx := context.Background()
	if found, err := registerStore.RevokeAgent(ctx, r.host, "jti-initial-"+r.host, "test", time.Now().Add(time.Hour)); err != nil || !found {
		t.Fatalf("revoke: found=%v err=%v", found, err)
	}
	secret, _, _ := GetServerJWTSecrets()
	for i := 0; i < 3; i++ { // the periodic loop would try again and again: never any frame
		if sendRekeyToAgent(ctx, r.host, secret, time.Hour) {
			t.Fatalf("attempt %d: a revoked agent must not be issued a token", i+1)
		}
	}
	if len(r.sent) != 0 {
		t.Fatalf("a revoked agent received %d frame(s)", len(r.sent))
	}
	a, _ := registerStore.GetAgent(ctx, r.host)
	if a == nil || a.TokenJTI != "jti-initial-"+r.host {
		t.Errorf("the stored JTI of a revoked agent must not move: %+v", a)
	}
	if !strings.Contains(r.logs.String(), "SECURITY WARNING") {
		t.Errorf("the refusal must be journalized as a [SECURITY WARNING]:\n%s", r.logs.String())
	}
}

// I4: the state refuses writes (read-only secondary, lost lock) ⇒ nothing sent, an explicit line
// names the host and says the frame was not sent, the stored JTI is unchanged, no panic.
func TestSpec217_I4_ReadOnlyStateEmitsNothingAndSaysSo(t *testing.T) {
	r := newRenewalRig(t, "renew-readonly-host")
	secret, _, _ := GetServerJWTSecrets()
	registerStore.SetWriteGuard(func() error { return storage.ErrReadOnly })
	defer registerStore.SetWriteGuard(func() error { return nil })

	if sendRekeyToAgent(context.Background(), r.host, secret, time.Hour) || len(r.sent) != 0 {
		t.Fatalf("read-only state: nothing may be sent (sent=%d)", len(r.sent))
	}
	logs := strings.ToLower(r.logs.String())
	if !strings.Contains(logs, r.host) || (!strings.Contains(logs, "not sent") && !strings.Contains(logs, "read-only") && !strings.Contains(logs, "read only")) {
		t.Errorf("the refusal must be explicit (host + not sent / read-only):\n%s", r.logs.String())
	}
	a, _ := registerStore.GetAgent(context.Background(), r.host)
	if a == nil || a.TokenJTI != "jti-initial-"+r.host {
		t.Errorf("the stored JTI must be untouched: %+v", a)
	}
}

// I5: the logs of an emission never contain the JWT, the encrypted token nor a full JTI (the JTI is
// truncated in the journal), while the frame itself carries a valid token.
func TestSpec217_I5_NoJWTNorFullJTIInTheLogs(t *testing.T) {
	r := newRenewalRig(t, "renew-logs-host")
	secret, _, _ := GetServerJWTSecrets()
	if !sendRekeyToAgent(context.Background(), r.host, secret, time.Hour) || len(r.sent) != 1 {
		t.Fatalf("emission failed (sent=%d)\n%s", len(r.sent), r.logs.String())
	}
	raw, claims := r.open(t, r.sent[0])
	jti, _ := claims["jti"].(string)
	if len(jti) < 16 || len(raw) < 40 {
		t.Fatalf("fixture: jti %q jwt len %d", jti, len(raw))
	}
	logs := r.logs.String()
	enc, _ := r.sent[0]["token_encrypted"].(string)
	for name, needle := range map[string]string{
		"the raw JWT":            raw,
		"its signature":          raw[strings.LastIndex(raw, ".")+1:],
		"its payload":            strings.Split(raw, ".")[1],
		"the encrypted token":    enc,
		"the full JTI (#217 I5)": jti,
	} {
		if strings.Contains(logs, needle) {
			t.Errorf("the logs contain %s", name)
		}
	}
}

// I7: two rekeys in a row (key rotation then renewal, or two renewals): the LAST token's JTI is the
// current one, the previous JTIs are not; every frame is a valid, distinct, agent-role JWT.
func TestSpec217_I7_TwoRekeysInARowTheLastJTIWins(t *testing.T) {
	r := newRenewalRig(t, "renew-twice-host")
	ctx := context.Background()
	secret, _, _ := GetServerJWTSecrets()
	for i := 0; i < 3; i++ {
		if !sendRekeyToAgent(ctx, r.host, secret, time.Hour) {
			t.Fatalf("emission %d failed\n%s", i+1, r.logs.String())
		}
	}
	if len(r.sent) != 3 {
		t.Fatalf("%d frames, want 3", len(r.sent))
	}
	seen := map[string]bool{}
	var lastJTI string
	for i, f := range r.sent {
		_, c := r.open(t, f)
		jti, _ := c["jti"].(string)
		if jti == "" || seen[jti] {
			t.Fatalf("frame %d: JTI %q empty or reused", i+1, jti)
		}
		seen[jti] = true
		if c["role"] != "agent" || c["sub"] != r.host {
			t.Errorf("frame %d: claims %v", i+1, c)
		}
		if exp, _ := c["exp"].(float64); int64(exp) <= time.Now().Unix() {
			t.Errorf("frame %d: already expired", i+1)
		}
		lastJTI = jti
	}
	a, _ := registerStore.GetAgent(ctx, r.host)
	if a == nil || a.TokenJTI != lastJTI {
		t.Fatalf("the current JTI must be the last emitted (%q), stored %+v", lastJTI, a)
	}
}

// The TTL given to the issuing primitive is honoured: a renewal with a short TTL (the 6 s of the
// integration tests) carries exp ≈ now + TTL, never the historical 1 h.
func TestSpec217_TheConfiguredTTLIsHonouredByTheIssuedToken(t *testing.T) {
	r := newRenewalRig(t, "renew-ttl-host")
	secret, _, _ := GetServerJWTSecrets()
	if !sendRekeyToAgent(context.Background(), r.host, secret, 6*time.Second) {
		t.Fatalf("emission failed\n%s", r.logs.String())
	}
	_, c := r.open(t, r.sent[0])
	exp, _ := c["exp"].(float64)
	iat, _ := c["iat"].(float64)
	if d := int64(exp) - int64(iat); d < 5 || d > 7 {
		t.Errorf("exp-iat = %ds, want ≈ 6 s", d)
	}
}
