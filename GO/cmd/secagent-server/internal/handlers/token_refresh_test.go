package handlers

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"secagent-server/cmd/secagent-server/internal/storage"
)

var (
	refreshKeyOnce sync.Once
	refreshKey     *rsa.PrivateKey
	refreshKeyPEM  string
)

// agentKey is one 4096-bit key shared by the tests (a JWT does not fit a smaller OAEP block).
func agentKey(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	refreshKeyOnce.Do(func() { refreshKey, refreshKeyPEM = genRSAPubPEM(t, 4096) })
	return refreshKey, refreshKeyPEM
}

var refreshSeq int

// refreshFixture registers a fresh agent and returns its hostname and a valid current token.
func refreshFixture(t *testing.T) (hostname, token, jti string) {
	t.Helper()
	if server == nil || server.PrivateKey == nil {
		t.Skip("server state not initialized")
	}
	refreshSeq++
	hostname = fmt.Sprintf("refresh-agent-%d-%d", time.Now().UnixNano(), refreshSeq)
	_, pubPEM := agentKey(t)
	preAuthorize(t, hostname, pubPEM)
	current, _, _ := GetServerJWTSecrets()
	token, jti, err := signAgentJWT(hostname, current, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registerStore.RegisterAgent(context.Background(), hostname, pubPEM, jti); err != nil {
		t.Fatal(err)
	}
	// the limiters are process-wide: a fresh budget per test
	refreshIPLimiter = newWindowLimiter(refreshPerIP, refreshWindow)
	refreshHostLimiter = newWindowLimiter(refreshPerHost, refreshWindow)
	return hostname, token, jti
}

func tokenWith(t *testing.T, secret string, method jwt.SigningMethod, claims jwt.MapClaims) string {
	t.Helper()
	tok, err := jwt.NewWithClaims(method, claims).SignedString([]byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func doRefresh(bearer, body, remote string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "/api/token/refresh", strings.NewReader(body))
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	if remote != "" {
		r.RemoteAddr = remote
	}
	w := httptest.NewRecorder()
	TokenRefresh(w, r)
	return w
}

func currentJTIOf(t *testing.T, hostname string) string {
	t.Helper()
	a, err := registerStore.GetAgent(context.Background(), hostname)
	if err != nil || a == nil {
		t.Fatalf("agent %s: %v %v", hostname, a, err)
	}
	return a.TokenJTI
}

func assertRefused(t *testing.T, w *httptest.ResponseRecorder, want int, hostname, wantJTI string) {
	t.Helper()
	if w.Code != want {
		t.Fatalf("status %d (%s), want %d", w.Code, w.Body.String(), want)
	}
	if strings.Contains(w.Body.String(), "token_encrypted") {
		t.Fatal("a refused refresh must not carry a token")
	}
	if hostname != "" && currentJTIOf(t, hostname) != wantJTI {
		t.Fatal("a refused refresh must not touch the agent's JTI")
	}
}

func TestTokenRefresh_WithoutAValidBearerIs401AndChangesNothing(t *testing.T) {
	hostname, token, jti := refreshFixture(t)
	current, _, _ := GetServerJWTSecrets()
	now := time.Now()
	mk := func(secret string, m jwt.SigningMethod, c jwt.MapClaims) string { return tokenWith(t, secret, m, c) }
	base := func() jwt.MapClaims {
		return jwt.MapClaims{"sub": hostname, "role": "agent", "jti": jti, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()}
	}
	cases := map[string]string{
		"no Authorization":     "",
		"garbage":              "not-a-jwt",
		"wrong secret":         mk("another-secret", jwt.SigningMethodHS256, base()),
		"HS512 instead of 256": mk(current, jwt.SigningMethodHS512, base()),
		"alg none": func() string {
			s, _ := jwt.NewWithClaims(jwt.SigningMethodNone, base()).SignedString(jwt.UnsafeAllowNoneSignatureType)
			return s
		}(),
		"not an agent":         mk(current, jwt.SigningMethodHS256, func() jwt.MapClaims { c := base(); c["role"] = "plugin"; return c }()),
		"relay role":           mk(current, jwt.SigningMethodHS256, func() jwt.MapClaims { c := base(); c["role"] = "relay"; return c }()),
		"no subject":           mk(current, jwt.SigningMethodHS256, func() jwt.MapClaims { c := base(); delete(c, "sub"); return c }()),
		"no jti":               mk(current, jwt.SigningMethodHS256, func() jwt.MapClaims { c := base(); delete(c, "jti"); return c }()),
		"no exp":               mk(current, jwt.SigningMethodHS256, func() jwt.MapClaims { c := base(); delete(c, "exp"); return c }()),
		"issued in the future": mk(current, jwt.SigningMethodHS256, func() jwt.MapClaims { c := base(); c["iat"] = now.Add(time.Hour).Unix(); return c }()),
	}
	for name, bearer := range cases {
		t.Run(name, func(t *testing.T) {
			// the challenge of the OLD protocol is irrelevant: it proves nothing
			w := doRefresh(bearer, `{"hostname":"`+hostname+`","challenge_encrypted":"AAAA"}`, "")
			assertRefused(t, w, http.StatusUnauthorized, hostname, jti)
		})
	}
	_ = token
}

func TestTokenRefresh_RevokedTokenCannotComeBack(t *testing.T) {
	hostname, token, jti := refreshFixture(t)
	reason := "admin_revoke"
	if err := registerStore.AddToBlacklist(context.Background(), jti, hostname, time.Now().Add(25*time.Hour).Format(time.RFC3339), &reason); err != nil {
		t.Fatal(err)
	}
	assertRefused(t, doRefresh(token, "", ""), http.StatusUnauthorized, hostname, jti)
}

func TestTokenRefresh_ReplacedTokenIsRefused(t *testing.T) {
	hostname, token, _ := refreshFixture(t)
	if _, err := registerStore.UpdateTokenJTI(context.Background(), hostname, "a-newer-jti"); err != nil {
		t.Fatal(err)
	}
	assertRefused(t, doRefresh(token, "", ""), http.StatusUnauthorized, hostname, "a-newer-jti")
}

func TestTokenRefresh_AnotherHostnameIsRefused(t *testing.T) {
	hostA, tokenA, jtiA := refreshFixture(t)
	hostB, _, jtiB := refreshFixture(t)
	// A's token, asking for B: refused, and B's JTI is untouched
	assertRefused(t, doRefresh(tokenA, `{"hostname":"`+hostB+`"}`, ""), http.StatusUnauthorized, hostB, jtiB)
	if currentJTIOf(t, hostA) != jtiA {
		t.Error("A's JTI changed")
	}
	// an agent that does not exist
	current, _, _ := GetServerJWTSecrets()
	ghost := tokenWith(t, current, jwt.SigningMethodHS256, jwt.MapClaims{"sub": "ghost-host", "role": "agent", "jti": "g1", "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix()})
	if w := doRefresh(ghost, "", ""); w.Code != http.StatusUnauthorized {
		t.Errorf("a token of an unknown agent: %d", w.Code)
	}
}

func TestTokenRefresh_SuspendedAgentIsRefused(t *testing.T) {
	hostname, token, jti := refreshFixture(t)
	if _, err := registerStore.SetSuspended(context.Background(), hostname, true); err != nil {
		t.Fatal(err)
	}
	assertRefused(t, doRefresh(token, "", ""), http.StatusForbidden, hostname, jti)
}

func TestTokenRefresh_ExpiryToleranceIsBounded(t *testing.T) {
	hostname, _, jti := refreshFixture(t)
	current, _, _ := GetServerJWTSecrets()
	at := func(exp time.Time) string {
		return tokenWith(t, current, jwt.SigningMethodHS256, jwt.MapClaims{"sub": hostname, "role": "agent", "jti": jti, "iat": exp.Add(-time.Hour).Unix(), "exp": exp.Unix()})
	}
	// beyond the grace: refused
	assertRefused(t, doRefresh(at(time.Now().Add(-TokenRefreshGrace-time.Minute)), "", ""), http.StatusUnauthorized, hostname, jti)
	// expired for a while but inside the grace (the documented "token expired -> refresh" flow): accepted
	if w := doRefresh(at(time.Now().Add(-2*time.Hour)), "", ""); w.Code != http.StatusOK {
		t.Fatalf("an expired token inside the grace must refresh: %d %s", w.Code, w.Body.String())
	}
}

func TestTokenRefresh_LegitimateRefreshRotatesAndTheOldTokenIsDead(t *testing.T) {
	hostname, token, jti := refreshFixture(t)
	priv, _ := agentKey(t)

	w := doRefresh(token, `{"hostname":"`+hostname+`","challenge_encrypted":"ignored"}`, "")
	if w.Code != http.StatusOK {
		t.Fatalf("legitimate refresh: %d %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	mustUnmarshal(t, w.Body.Bytes(), &resp)
	if resp["token_encrypted"] == "" || resp["server_public_key_pem"] == "" || resp["token"] != "" {
		t.Fatalf("response = %v", resp)
	}
	ct, err := base64.StdEncoding.DecodeString(resp["token_encrypted"])
	if err != nil {
		t.Fatal(err)
	}
	plain, err := rsa.DecryptOAEP(sha256.New(), nil, priv, ct, nil)
	if err != nil {
		t.Fatalf("only the agent key can read the new token: %v", err)
	}
	newToken := string(plain)
	claims, _, err := verifyRefreshToken(newToken)
	if err != nil || claims["sub"] != hostname || claims["role"] != "agent" {
		t.Fatalf("new token: %v %v", claims, err)
	}
	newJTI, _ := claims["jti"].(string)
	if newJTI == jti || currentJTIOf(t, hostname) != newJTI {
		t.Fatal("the stored JTI must be the new one")
	}
	if bl, _ := registerStore.IsJTIBlacklisted(context.Background(), jti); !bl {
		t.Error("the old JTI must be blacklisted")
	}
	// the OLD token can never be used again, on refresh ...
	assertRefused(t, doRefresh(token, "", ""), http.StatusUnauthorized, hostname, newJTI)
	// ... while the NEW one refreshes again
	if w := doRefresh(newToken, "", ""); w.Code != http.StatusOK {
		t.Fatalf("the new token must refresh: %d %s", w.Code, w.Body.String())
	}
}

func TestTokenRefresh_BodyAndMethod(t *testing.T) {
	hostname, token, jti := refreshFixture(t)
	if w := doRefresh(token, "{not json", ""); w.Code != http.StatusBadRequest {
		t.Errorf("invalid JSON with a valid token: %d", w.Code)
	}
	if w := doRefresh(token, strings.Repeat("x", refreshBodyLimit+10), ""); w.Code != http.StatusBadRequest {
		t.Errorf("oversized body: %d", w.Code)
	}
	if currentJTIOf(t, hostname) != jti {
		t.Error("a malformed request changed the JTI")
	}
	r := httptest.NewRequest("GET", "/api/token/refresh", nil)
	w := httptest.NewRecorder()
	TokenRefresh(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET: %d", w.Code)
	}
}

// A refused write (read-only / lost lock) refuses the refresh: no token is issued and nothing changes.
func TestTokenRefresh_WriteFailureIssuesNoToken(t *testing.T) {
	hostname, token, jti := refreshFixture(t)
	registerStore.SetWriteGuard(func() error { return storage.ErrReadOnly })
	w := doRefresh(token, "", "")
	registerStore.SetWriteGuard(func() error { return nil })
	if w.Code != http.StatusInternalServerError || strings.Contains(w.Body.String(), "token_encrypted") {
		t.Fatalf("a refused write must refuse the refresh without a token: %d %s", w.Code, w.Body.String())
	}
	if currentJTIOf(t, hostname) != jti {
		t.Error("the JTI changed although the write was refused")
	}
	if bl, _ := registerStore.IsJTIBlacklisted(context.Background(), jti); bl {
		t.Error("the old JTI was blacklisted although the write was refused")
	}
	if w := doRefresh(token, "", ""); w.Code != http.StatusOK {
		t.Fatalf("the same token still works once writes are back: %d", w.Code)
	}
}

func TestTokenRefresh_RateLimits(t *testing.T) {
	hostname, token, _ := refreshFixture(t)
	// per hostname: the legitimate rhythm is one refresh per hour
	codes := map[int]int{}
	cur := token
	for i := 0; i < refreshPerHost+3; i++ {
		w := doRefresh(cur, "", fmt.Sprintf("10.0.%d.1:5555", i)) // distinct addresses: only the hostname limit applies
		codes[w.Code]++
		if w.Code == http.StatusOK { // follow the rotation
			var resp map[string]string
			mustUnmarshal(t, w.Body.Bytes(), &resp)
			priv, _ := agentKey(t)
			ct, _ := base64.StdEncoding.DecodeString(resp["token_encrypted"])
			plain, _ := rsa.DecryptOAEP(sha256.New(), nil, priv, ct, nil)
			cur = string(plain)
		}
	}
	if codes[http.StatusOK] != refreshPerHost || codes[http.StatusTooManyRequests] != 3 {
		t.Fatalf("per-hostname limit: %v, want %d x 200 then 429", codes, refreshPerHost)
	}
	_ = hostname

	// per address: a flood from one address is cut, whatever the tokens
	refreshIPLimiter = newWindowLimiter(refreshPerIP, refreshWindow)
	got429 := false
	for i := 0; i < refreshPerIP+5; i++ {
		if w := doRefresh("junk", "", "192.0.2.9:4444"); w.Code == http.StatusTooManyRequests {
			got429 = true
			if w.Header().Get("Retry-After") == "" {
				t.Error("429 without Retry-After")
			}
		}
	}
	if !got429 {
		t.Error("an address flooding the endpoint must be rate limited")
	}
}

// An attacker who only knows a hostname cannot burn the victim's budget (nor rotate its JTI):
// unauthenticated requests never reach the per-hostname counter.
func TestTokenRefresh_AnAttackerCannotExhaustTheVictimsBudget(t *testing.T) {
	hostname, token, jti := refreshFixture(t)
	for i := 0; i < 3*refreshPerHost; i++ {
		w := doRefresh("forged-"+fmt.Sprint(i), `{"hostname":"`+hostname+`"}`, fmt.Sprintf("198.51.100.%d:1", i%250))
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("forged request: %d", w.Code)
		}
	}
	if currentJTIOf(t, hostname) != jti {
		t.Fatal("forged requests rotated the victim's JTI")
	}
	if w := doRefresh(token, "", ""); w.Code != http.StatusOK {
		t.Fatalf("the victim's legitimate refresh must still work: %d %s", w.Code, w.Body.String())
	}
}

func TestTokenRefresh_ResponseNeverEchoesTheToken(t *testing.T) {
	_, token, _ := refreshFixture(t)
	w := doRefresh("bad."+token, "", "")
	if strings.Contains(w.Body.String(), token) {
		t.Error("the response echoes a token")
	}
}

// The per-address limiter counts FAILURES: an address (or a NAT) that floods forged requests gets cheap
// 429s for its failures, but a VALID token coming from the same address is never blocked.
func TestTokenRefresh_AFloodOfFailuresFromTheSameAddressDoesNotBlockAValidToken(t *testing.T) {
	_, token, _ := refreshFixture(t)
	const addr = "203.0.113.77:4000"
	var limited int
	for i := 0; i < 3*refreshPerIP; i++ {
		if w := doRefresh("forged", "", addr); w.Code == http.StatusTooManyRequests {
			limited++
		}
	}
	if limited == 0 {
		t.Fatal("the flood of failures must be rate limited")
	}
	if w := doRefresh(token, "", addr); w.Code != http.StatusOK {
		t.Fatalf("a valid token from the flooding address must still be served: %d %s", w.Code, w.Body.String())
	}
}
