//go:build testhelpers

package server

import "time"

// Test seam: a binary built with `-tags testhelpers` accepts a short agent JWT lifetime (integration
// tests run real processes with AGENT_JWT_TTL=6s). Never compiled into a release binary.
func init() {
	minAgentJWTTTL = 2 * time.Second
	minAgentJWTInterval = 500 * time.Millisecond
}
