package handlers

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"relay-server/cmd/server/internal/storage"
)

// ========================================================================
// Plugin token authentication — SECURITY.md §6
// ========================================================================

// PluginAuthResult holds the validated plugin token after successful auth.
type PluginAuthResult struct {
	Token    *storage.PluginToken
	ClientIP string
}

// requirePluginAuth validates the plugin bearer token on the request.
//
// Validation sequence (SECURITY.md §6):
//  1. Extract Bearer token from Authorization header
//  2. SHA-256(token) → lookup in plugin_tokens
//  3. revoked == 0 ?
//  4. expires_at IS NULL OR expires_at > now() ?
//  5. allowed_ips IS NOT NULL → client IP in at least one CIDR ?
//  6. allowed_hostname_pattern IS NOT NULL → regexp.Match(pattern, X-Relay-Client-Host) ?
//  7. UPDATE last_used_at, last_used_ip (audit)
//
// Returns (result, true) on success, writes 401/403 and returns (nil, false) on failure.
func requirePluginAuth(w http.ResponseWriter, r *http.Request) (*PluginAuthResult, bool) {
	// 1. Extract Bearer token
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing_authorization"})
		return nil, false
	}
	tokenPlain := authHeader[7:]
	if tokenPlain == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing_authorization"})
		return nil, false
	}

	if adminStore == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "store_not_initialized"})
		return nil, false
	}

	// 2. SHA-256(token) → DB lookup
	h := sha256.Sum256([]byte(tokenPlain))
	tokenHash := fmt.Sprintf("%x", h)

	ctx := r.Context()
	tok, err := adminStore.GetPluginTokenByHash(ctx, tokenHash)
	if err != nil {
		log.Printf("requirePluginAuth GetPluginTokenByHash: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_error"})
		return nil, false
	}
	if tok == nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "token_not_found"})
		return nil, false
	}

	// 3. Revocation check
	if tok.Revoked {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "token_revoked"})
		return nil, false
	}

	// 4. Expiry check
	if tok.ExpiresAt != nil && time.Now().UTC().After(*tok.ExpiresAt) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "token_expired"})
		return nil, false
	}

	// 5. IP validation
	clientIP := extractClientIP(r)
	if tok.AllowedIPs != "" {
		allowed, err := storage.PluginTokenCheckIP(tok.AllowedIPs, clientIP)
		if err != nil {
			log.Printf("requirePluginAuth CIDR check error: %v", err)
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "ip_validation_error"})
			return nil, false
		}
		if !allowed {
			log.Printf("requirePluginAuth IP rejected: ip=%s allowed_ips=%s token_id=%s", clientIP, tok.AllowedIPs, tok.ID)
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "ip_not_allowed"})
			return nil, false
		}
	}

	// 6. Hostname pattern validation
	clientHostname := r.Header.Get("X-Relay-Client-Host")
	if tok.AllowedHostnamePattern != "" {
		matched, err := storage.PluginTokenCheckHostname(tok.AllowedHostnamePattern, clientHostname)
		if err != nil {
			log.Printf("requirePluginAuth hostname regexp error: %v", err)
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "hostname_validation_error"})
			return nil, false
		}
		if !matched {
			log.Printf("requirePluginAuth hostname rejected: hostname=%q pattern=%q token_id=%s",
				clientHostname, tok.AllowedHostnamePattern, tok.ID)
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "hostname_not_allowed"})
			return nil, false
		}
	}

	// 7. Audit: update last_used_at + last_used_ip (non-fatal)
	if err := adminStore.TouchPluginToken(context.Background(), tok.ID, clientIP); err != nil {
		log.Printf("requirePluginAuth TouchPluginToken: %v (non-fatal)", err)
	}

	return &PluginAuthResult{Token: tok, ClientIP: clientIP}, true
}

// extractClientIP returns the client IP address from the request.
// Priority: X-Forwarded-For (first non-empty entry) → r.RemoteAddr.
// Strips the port if present.
func extractClientIP(r *http.Request) string {
	// Check X-Forwarded-For (set by reverse proxies)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// May contain multiple IPs: "client, proxy1, proxy2"
		parts := strings.Split(xff, ",")
		ip := strings.TrimSpace(parts[0])
		if ip != "" {
			return stripPort(ip)
		}
	}

	return stripPort(r.RemoteAddr)
}

// stripPort removes the port from a "host:port" or "[ipv6]:port" address.
func stripPort(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// No port, or IPv6 without port — return as-is
		return addr
	}
	return host
}
