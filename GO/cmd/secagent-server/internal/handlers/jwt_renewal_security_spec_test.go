package handlers

// #217 — exigences de la revue sécurité en amont (_work/reports/security-reviewer-lot1-amont-v305.md).
//
//	H1 course renouvellement ↔ révocation : le contrôle `revoked` est atomique avec l'écriture du JTI
//	H2 échec d'envoi après UpdateTokenJTI : jamais traité comme un succès, journalisé, renouvelable
//
// À lancer avec -race.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"secagent-server/cmd/secagent-server/internal/ws"
)

// H1 (HAUT): a renewal that raced a revocation must not write a new JTI once the agent is revoked.
// GetAgent(revoked=false) then UpdateTokenJTI are two operations: a revocation committed between them
// let a fresh, non-blacklisted JWT be issued to a revoked host. The write guard runs under the
// writer lock before every state write: it records the JTI the agent holds the first time it sees the
// agent revoked; a later change of that JTI is a token issued after the revocation.
func TestSecH1_ARenewalRacingARevocationNeverIssuesAJTIAfterTheRevocation(t *testing.T) {
	r := newRenewalRig(t, "race-seed")
	_ = r
	_, pub := genRSAPubPEM(t, 4096)
	secret, _, _ := GetServerJWTSecrets()
	ctx := context.Background()
	prevSend := sendToAgentFn
	sendToAgentFn = func(string, map[string]interface{}) error { return nil }
	defer func() { sendToAgentFn = prevSend }()
	defer registerStore.SetWriteGuard(func() error { return nil })

	const rounds = 300
	violations, renewedBeforeRevocation, writeAfterRevoke := 0, 0, 0
	for i := 0; i < rounds; i++ {
		host := fmt.Sprintf("race-host-%03d", i)
		preAuthorize(t, host, pub)
		if _, err := registerStore.RegisterAgent(ctx, host, pub, "jti-init"); err != nil {
			t.Fatal(err)
		}
		var seen atomic.Bool
		var jtiWhenRevoked atomic.Value
		registerStore.SetWriteGuard(func() error {
			if a, _ := registerStore.GetAgent(ctx, host); a != nil && a.Revoked && !seen.Swap(true) {
				jtiWhenRevoked.Store(a.TokenJTI)
			}
			return nil
		})

		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			sendRekeyToAgent(ctx, host, secret, time.Hour)
		}()
		go func() {
			defer wg.Done()
			<-start
			for spin := time.Now(); time.Since(spin) < time.Duration(i%100)*80*time.Microsecond; { // sweep the offset between the two
			}
			if _, err := registerStore.RevokeAgent(ctx, host, "jti-init", "race", time.Now().Add(time.Hour)); err != nil {
				t.Errorf("revoke: %v", err)
			}
		}()
		close(start)
		wg.Wait()

		a, _ := registerStore.GetAgent(ctx, host)
		if a == nil || !a.Revoked {
			t.Fatalf("round %d: the agent must end up revoked: %+v", i, a)
		}
		if a.TokenJTI != "jti-init" {
			renewedBeforeRevocation++
		}
		if seen.Load() {
			writeAfterRevoke++
		}
		if seen.Load() && a.TokenJTI != jtiWhenRevoked.Load().(string) {
			violations++
		}
	}
	registerStore.SetWriteGuard(func() error { return nil })
	if violations != 0 {
		t.Fatalf("H1: %d/%d rounds issued a new JTI AFTER the revocation committed (revoked check must be atomic with the JTI write)", violations, rounds)
	}
	t.Logf("%d/%d rounds renewed before the revocation (legitimate order), %d/%d had a write attempted after it (the raced window)", renewedBeforeRevocation, rounds, writeAfterRevoke, rounds)
}

// H1, deterministic half: nothing is issued once the agent is revoked, through every entry point
// (rotation primitive and the renewal function injected into the WebSocket loop), and the loop is told
// to stop.
func TestSecH1_RevokedAgentGetsNothingAndTheLoopIsToldToStop(t *testing.T) {
	r := newRenewalRig(t, "revoked-stop-host")
	ctx := context.Background()
	if _, err := registerStore.RevokeAgent(ctx, r.host, "jti-initial-"+r.host, "test", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	exp, err := RenewAgentJWT(r.host)
	if !errors.Is(err, ws.ErrRenewStop) || !exp.IsZero() {
		t.Fatalf("RenewAgentJWT on a revoked agent = (%v, %v), want ws.ErrRenewStop and no expiry", exp, err)
	}
	if len(r.sent) != 0 {
		t.Fatalf("a revoked agent received %d frame(s)", len(r.sent))
	}
	a, _ := registerStore.GetAgent(ctx, r.host)
	if a.TokenJTI != "jti-initial-"+r.host {
		t.Errorf("the stored JTI moved: %q", a.TokenJTI)
	}
}

// H2 (HAUT): the send fails after the JTI was persisted (WebSocket gone). It is never reported as a
// success, never as a stop (the agent is not revoked: the caller may retry), exactly one send was
// attempted, and the journal says so explicitly without the token.
func TestSecH2_ASendFailureAfterTheJTIWriteIsNeverASuccess(t *testing.T) {
	r := newRenewalRig(t, "send-fails-host")
	attempts := 0
	sendToAgentFn = func(string, map[string]interface{}) error { attempts++; return errors.New("no connection for host") }
	secret, _, _ := GetServerJWTSecrets()

	if sendRekeyToAgent(context.Background(), r.host, secret, time.Hour) {
		t.Fatal("a failed send must not be reported as a success")
	}
	exp, err := RenewAgentJWT(r.host)
	if err == nil || errors.Is(err, ws.ErrRenewStop) || !exp.IsZero() {
		t.Fatalf("RenewAgentJWT after a failed send = (%v, %v): want a retryable error (not nil, not ErrRenewStop) and no expiry", exp, err)
	}
	if attempts != 2 {
		t.Errorf("each issuance must attempt the send exactly once (2 calls, %d sends)", attempts)
	}
	logs := strings.ToLower(r.logs.String())
	if !strings.Contains(logs, r.host) || !(strings.Contains(logs, "sendtoagent") || strings.Contains(logs, "not sent") || strings.Contains(logs, "failed")) {
		t.Errorf("the failure must be journalized with the host:\n%s", r.logs.String())
	}
	if strings.Contains(r.logs.String(), "eyJ") {
		t.Error("a JWT is in the logs")
	}
}

// H2: after a failed send, the next successful renewal leaves the agent holding the CURRENT JTI (what
// was delivered is what the state accepts), so a retry heals the situation; the stored JTI is either
// still the previous one (rolled back) or the new one, never a JTI that no later frame can deliver.
func TestSecH2_TheRetryAfterAFailedSendDeliversTheCurrentJTI(t *testing.T) {
	r := newRenewalRig(t, "retry-host")
	ctx := context.Background()
	fail := true
	var delivered []map[string]interface{}
	sendToAgentFn = func(_ string, m map[string]interface{}) error {
		if fail {
			return errors.New("connection reset")
		}
		delivered = append(delivered, m)
		return nil
	}
	secret, _, _ := GetServerJWTSecrets()
	if sendRekeyToAgent(ctx, r.host, secret, time.Hour) {
		t.Fatal("first attempt must fail")
	}
	fail = false
	if _, err := RenewAgentJWT(r.host); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if len(delivered) != 1 {
		t.Fatalf("%d frame(s) delivered by the retry, want 1", len(delivered))
	}
	_, claims := r.open(t, delivered[0])
	a, _ := registerStore.GetAgent(ctx, r.host)
	if a == nil || a.TokenJTI != claims["jti"] {
		t.Fatalf("the delivered JTI %v must be the current one, stored %+v", claims["jti"], a)
	}
}

// B6: a non-positive lifetime is an explicit error, never a silent fallback to 24 h (a configuration bug
// would otherwise issue tokens of a lifetime nobody chose).
func TestSecB6_SignAgentJWTRefusesANonPositiveLifetime(t *testing.T) {
	for _, ttl := range []time.Duration{0, -time.Second, -24 * time.Hour} {
		if raw, jti, err := signAgentJWT("b6-host", "secret", ttl); err == nil || raw != "" || jti != "" {
			t.Errorf("ttl %s: got (%q, %q, %v), want an error and no token", ttl, raw, jti, err)
		}
	}
	if raw, jti, err := signAgentJWT("b6-host", "secret", time.Minute); err != nil || raw == "" || jti == "" {
		t.Errorf("a positive lifetime must work: %v", err)
	}
}

// B6 end to end: the issuing path writes nothing and sends nothing when the lifetime is invalid.
func TestSecB6_NothingIsIssuedNorWrittenWithANonPositiveLifetime(t *testing.T) {
	r := newRenewalRig(t, "b6-issue-host")
	secret, _, _ := GetServerJWTSecrets()
	if sendRekeyToAgent(context.Background(), r.host, secret, 0) || sendRekeyToAgent(context.Background(), r.host, secret, -time.Hour) {
		t.Fatal("a non-positive lifetime must not issue a token")
	}
	if len(r.sent) != 0 {
		t.Errorf("%d frame(s) sent", len(r.sent))
	}
	if a, _ := registerStore.GetAgent(context.Background(), r.host); a == nil || a.TokenJTI != "jti-initial-"+r.host {
		t.Errorf("the stored JTI must be untouched: %+v", a)
	}
}
