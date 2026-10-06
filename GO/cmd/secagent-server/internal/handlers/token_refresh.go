package handlers

// POST /api/token/refresh (#192): renews the JWT of an agent that PROVES it holds the current one.
//
// Contract:
//   - Authorization: Bearer <the agent's current JWT> is REQUIRED. It is verified (HS256, current or,
//     during a rotation, previous secret), must carry role "agent", a subject equal to the optional
//     body hostname, and a jti that is not blacklisted, is the agent's current one (or, for a token of
//     the previous secret, merely not blacklisted), of an agent that exists and is not suspended.
//   - Expiry: the token may be EXPIRED by at most TokenRefreshGrace (24 h). The documented flow is
//     "token expired -> refresh" (ARCHITECTURE §22: the server closes /ws/agent with 4002), so the
//     presented token is normally already past its exp (default TTL 1 h); the signature and the
//     jti checks keep proving possession, and the grace bounds how long a leaked old token stays useful.
//   - The old JTI is replaced and blacklisted in ONE state write (storage.RotateAgentJTI); a write
//     failure refuses the refresh and no new token is issued.
//   - The new JWT is returned encrypted with the agent's RSA public key (only the key holder reads it).
//   - Rate limited per client address and per hostname (429).
//   - Every authentication failure is the same 401 {"error":"unauthorized"} (no oracle); the reason is
//     logged as a [SECURITY WARNING] with the hostname quoted, never the token.
//
// The Go minion does not call this route (it re-enrolls); the contract is for any client that does.

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"secagent-server/cmd/secagent-server/internal/storage"
)

// TokenRefreshGrace is how long after its exp a token can still be refreshed.
var TokenRefreshGrace = 24 * time.Hour

const (
	refreshBodyLimit = 4 << 10
	// iat is refused when it lies this far in the future (clock skew tolerance)
	refreshIATSkew = 5 * time.Minute
	// the legitimate rhythm is one refresh per TTL: these are generous ceilings
	refreshPerIP   = 30
	refreshPerHost = 6
	refreshWindow  = time.Minute
	refreshMaxKeys = 20000
)

// windowLimiter is a fixed-window counter per key (memory only, bounded).
type windowLimiter struct {
	mu     sync.Mutex
	window time.Duration
	limit  int
	m      map[string]*winCount
}

type winCount struct {
	start time.Time
	n     int
}

func newWindowLimiter(limit int, window time.Duration) *windowLimiter {
	return &windowLimiter{window: window, limit: limit, m: map[string]*winCount{}}
}

// allow counts one hit for key and reports whether it is within the limit.
func (l *windowLimiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.m) >= refreshMaxKeys { // bound the memory: drop the expired windows, then refuse new keys
		for k, w := range l.m {
			if now.Sub(w.start) >= l.window {
				delete(l.m, k)
			}
		}
		if _, ok := l.m[key]; !ok && len(l.m) >= refreshMaxKeys {
			return false
		}
	}
	w, ok := l.m[key]
	if !ok || now.Sub(w.start) >= l.window {
		l.m[key] = &winCount{start: now, n: 1}
		return true
	}
	w.n++
	return w.n <= l.limit
}

var (
	refreshIPLimiter   = newWindowLimiter(refreshPerIP, refreshWindow)
	refreshHostLimiter = newWindowLimiter(refreshPerHost, refreshWindow)
	// refreshNow is the clock (tests)
	refreshNow = time.Now
)

func refuseRefresh(w http.ResponseWriter, hostname, why string) {
	log.Printf("[SECURITY WARNING] token refresh refused: hostname=%q reason=%s", hostname, why)
	writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
}

// verifyRefreshToken checks the signature of tokenStr with the current secret, then (during a rotation)
// the previous one, WITHOUT the exp check (done by the caller with the grace) and returns the claims.
func verifyRefreshToken(tokenStr string) (claims jwt.MapClaims, usedPrevious bool, err error) {
	current, previous, deadline := GetServerJWTSecrets()
	if current == "" {
		return nil, false, errors.New("jwt secret not configured")
	}
	parse := func(secret string) (jwt.MapClaims, error) {
		tok, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, errors.New("unexpected signing method")
			}
			return []byte(secret), nil
		}, jwt.WithValidMethods([]string{"HS256"}), jwt.WithoutClaimsValidation())
		if err != nil {
			return nil, err
		}
		c, ok := tok.Claims.(jwt.MapClaims)
		if !ok || !tok.Valid {
			return nil, errors.New("invalid claims")
		}
		return c, nil
	}
	if c, err := parse(current); err == nil {
		return c, false, nil
	}
	if previous != "" && !deadline.IsZero() && refreshNow().Before(deadline) {
		if c, err := parse(previous); err == nil {
			return c, true, nil
		}
	}
	return nil, false, errors.New("bad signature")
}

func numericDate(c jwt.MapClaims, key string) (time.Time, bool) {
	switch v := c[key].(type) {
	case float64:
		return time.Unix(int64(v), 0), true
	case json.Number:
		if f, err := v.Float64(); err == nil {
			return time.Unix(int64(f), 0), true
		}
	}
	return time.Time{}, false
}

// TokenRefresh renews an agent JWT (see the contract at the top of this file).
func TokenRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	defer func() { _ = r.Body.Close() }()
	now := refreshNow()

	client, _ := clientAddr(r)
	if !refreshIPLimiter.allow(client, now) {
		w.Header().Set("Retry-After", "60")
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate_limited"})
		return
	}

	// 1. authentication BEFORE anything else
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") || len(auth) <= len("Bearer ") {
		refuseRefresh(w, "", "missing bearer token")
		return
	}
	claims, usedPrevious, err := verifyRefreshToken(strings.TrimSpace(auth[len("Bearer "):]))
	if err != nil {
		refuseRefresh(w, "", "invalid token signature")
		return
	}
	hostname, _ := claims["sub"].(string)
	jti, _ := claims["jti"].(string)
	if role, _ := claims["role"].(string); role != "agent" || hostname == "" || jti == "" {
		refuseRefresh(w, hostname, "not an agent token")
		return
	}
	exp, ok := numericDate(claims, "exp")
	if !ok {
		refuseRefresh(w, hostname, "no expiry")
		return
	}
	if now.After(exp.Add(TokenRefreshGrace)) {
		refuseRefresh(w, hostname, "token expired beyond the refresh grace")
		return
	}
	if iat, ok := numericDate(claims, "iat"); ok && iat.After(now.Add(refreshIATSkew)) {
		refuseRefresh(w, hostname, "token issued in the future")
		return
	}

	// 2. the optional body must agree with the token (never the other way round)
	var req TokenRefreshRequest
	if body, err := io.ReadAll(io.LimitReader(r.Body, refreshBodyLimit+1)); err != nil || len(body) > refreshBodyLimit {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	} else if len(strings.TrimSpace(string(body))) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
			return
		}
	}
	if req.Hostname != "" && req.Hostname != hostname {
		refuseRefresh(w, hostname, "body hostname differs from the token subject")
		return
	}

	// 3. per-hostname limit, counted only for an authenticated caller (an attacker cannot burn the
	// budget of a victim by guessing its name)
	if !refreshHostLimiter.allow(hostname, now) {
		w.Header().Set("Retry-After", "60")
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate_limited"})
		return
	}

	if registerStore == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "store_not_initialized"})
		return
	}
	agent, err := registerStore.GetAgent(r.Context(), hostname)
	if err != nil {
		log.Printf("TokenRefresh GetAgent: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_error"})
		return
	}
	if agent == nil {
		refuseRefresh(w, hostname, "unknown agent")
		return
	}

	// 4. build the new token and its encrypted envelope BEFORE the state write ...
	server.mu.RLock()
	jwtTTL := server.JWTttl
	pubPEM := server.PublicPEM
	server.mu.RUnlock()
	current, _, _ := GetServerJWTSecrets()
	rawJWT, newJTI, err := signAgentJWT(hostname, current, jwtTTL)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "jwt_generation_failed"})
		return
	}
	tokenEncrypted, err := encryptWithPublicKey(rawJWT, agent.PublicKeyPEM)
	if err != nil {
		log.Printf("TokenRefresh encrypt: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "encryption_failed"})
		return
	}

	// 5. ... and only hand it out once the rotation is durable (old JTI blacklisted, new one stored,
	// revocation / suspension / replacement re-checked in the SAME write)
	blacklistUntil := exp.Add(TokenRefreshGrace + time.Hour)
	if min := now.Add(time.Hour); blacklistUntil.Before(min) {
		blacklistUntil = min
	}
	if err := registerStore.RotateAgentJTI(r.Context(), hostname, jti, newJTI, !usedPrevious, blacklistUntil); err != nil {
		switch {
		case errors.Is(err, storage.ErrRefreshRevoked):
			refuseRefresh(w, hostname, "token revoked")
		case errors.Is(err, storage.ErrRefreshReplaced):
			refuseRefresh(w, hostname, "token replaced")
		case errors.Is(err, storage.ErrRefreshUnknownAgent):
			refuseRefresh(w, hostname, "unknown agent")
		case errors.Is(err, storage.ErrRefreshSuspended):
			log.Printf("[SECURITY WARNING] token refresh refused: hostname=%q reason=agent suspended", hostname)
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "agent_suspended"})
		default:
			log.Printf("TokenRefresh RotateAgentJTI: %v", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_error"})
		}
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"token_encrypted":       tokenEncrypted,
		"server_public_key_pem": pubPEM,
	})
}
