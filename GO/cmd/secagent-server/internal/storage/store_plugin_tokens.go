package storage

import (
	"context"
	"fmt"
	"log"
	"net"
	"regexp"
	"sort"
	"strings"
	"time"

	"secagent-server/cmd/secagent-server/internal/state"
)

// PluginToken represents a stored plugin/admin API token (SECURITY.md §6).
type PluginToken struct {
	ID                     string
	TokenHash              string // SHA-256(token) — never the token in clear
	Description            string
	Role                   string // "plugin"
	AllowedIPs             string // comma-separated CIDRs, empty = no restriction
	AllowedHostnamePattern string // Go regexp anchored ^...$, empty = no restriction
	CreatedAt              time.Time
	ExpiresAt              *time.Time // nil = no expiry
	// LastUsedAt / LastUsedIP are APPROXIMATE: kept in memory and persisted only when the state
	// file is written for another reason, so they may lag by minutes and a token used just before
	// a crash can read "never used".
	LastUsedAt *time.Time // nil = never used
	LastUsedIP string
	Revoked    bool
}

func (s *Store) pluginFromState(t state.PluginToken) *PluginToken {
	out := &PluginToken{ID: t.ID, TokenHash: t.TokenHash, Description: t.Description, Role: t.Role, AllowedIPs: t.AllowedIPs,
		AllowedHostnamePattern: t.AllowedHostnamePattern, CreatedAt: t.CreatedAt, ExpiresAt: t.ExpiresAt,
		LastUsedAt: t.LastUsedAt, LastUsedIP: t.LastUsedIP, Revoked: t.Revoked}
	s.mu.RLock()
	if v, ok := s.pluginVol[t.ID]; ok && (out.LastUsedAt == nil || v.at.After(*out.LastUsedAt)) {
		at := v.at
		out.LastUsedAt, out.LastUsedIP = &at, v.ip
	}
	s.mu.RUnlock()
	return out
}

// CreatePluginToken inserts a new plugin token.
func (s *Store) CreatePluginToken(ctx context.Context, t PluginToken) error {
	role := t.Role
	if role == "" {
		role = "plugin"
	}
	err := s.mutate(func(tx *state.Tx) error {
		if _, exists := tx.PluginToken(t.ID); exists {
			return fmt.Errorf("%w: plugin token id %q", state.ErrDuplicate, t.ID)
		}
		return tx.PutPluginToken(state.PluginToken{ID: t.ID, TokenHash: t.TokenHash, Description: t.Description, Role: role,
			AllowedIPs: t.AllowedIPs, AllowedHostnamePattern: t.AllowedHostnamePattern,
			CreatedAt: t.CreatedAt.UTC().Truncate(time.Second), ExpiresAt: secondsUTC(t.ExpiresAt)})
	})
	if err != nil {
		return fmt.Errorf("CreatePluginToken: %w", err)
	}
	log.Printf("Plugin token created: id=%q description=%q role=%q", t.ID, t.Description, role)
	return nil
}

// GetPluginTokenByHash returns the token with this hash, or (nil, nil).
func (s *Store) GetPluginTokenByHash(ctx context.Context, tokenHash string) (*PluginToken, error) {
	t, ok := s.snap().PluginTokenByHash(tokenHash)
	if !ok {
		return nil, nil
	}
	return s.pluginFromState(t), nil
}

// GetPluginTokenByID returns the token with this id, or (nil, nil).
func (s *Store) GetPluginTokenByID(ctx context.Context, id string) (*PluginToken, error) {
	t, ok := s.snap().PluginToken(id)
	if !ok {
		return nil, nil
	}
	return s.pluginFromState(t), nil
}

// ListPluginTokens returns all plugin tokens, newest first.
func (s *Store) ListPluginTokens(ctx context.Context) ([]PluginToken, error) {
	var out []PluginToken
	for _, t := range s.snap().PluginTokens() {
		out = append(out, *s.pluginFromState(t))
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

// RevokePluginToken marks a token revoked; reports whether it existed.
func (s *Store) RevokePluginToken(ctx context.Context, id string) (bool, error) {
	found := false
	err := s.mutate(func(tx *state.Tx) error {
		t, ok := tx.PluginToken(id)
		if !ok {
			return nil
		}
		found = true
		t.Revoked = true
		return tx.PutPluginToken(t)
	})
	if err != nil {
		return false, fmt.Errorf("RevokePluginToken: %w", err)
	}
	if found {
		log.Printf("Plugin token revoked: id=%q", id)
	}
	return found, nil
}

// DeletePluginToken removes a token; reports whether it existed.
func (s *Store) DeletePluginToken(ctx context.Context, id string) (bool, error) {
	deleted := false
	if err := s.mutate(func(tx *state.Tx) error { deleted = tx.DeletePluginToken(id); return nil }); err != nil {
		return false, fmt.Errorf("DeletePluginToken: %w", err)
	}
	if deleted {
		s.mu.Lock()
		delete(s.pluginVol, id)
		s.mu.Unlock()
		log.Printf("Plugin token deleted: id=%q", id)
	}
	return deleted, nil
}

// TouchPluginToken records the use of a token. MEMORY ONLY: a plugin request never writes to the
// disk (the value is persisted with the next write of the file).
func (s *Store) TouchPluginToken(ctx context.Context, id, remoteIP string) error {
	if _, ok := s.snap().PluginToken(id); !ok {
		return fmt.Errorf("TouchPluginToken: token not found id=%s", id)
	}
	s.mu.Lock()
	s.pluginVol[id] = pluginVolatile{at: time.Now().UTC().Truncate(time.Second), ip: remoteIP}
	s.mu.Unlock()
	return nil
}

// PluginTokenCheckIP reports whether remoteAddr is inside one of the comma-separated CIDRs
// of allowedIPs. An empty allowedIPs means "no restriction".
func PluginTokenCheckIP(allowedIPs, remoteAddr string) (bool, error) {
	if allowedIPs == "" {
		return true, nil
	}

	host := remoteAddr
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = h
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return false, fmt.Errorf("invalid remote IP: %q", host)
	}

	for _, cidr := range strings.Split(allowedIPs, ",") {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			return false, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
		}
		if network.Contains(ip) {
			return true, nil
		}
	}
	return false, nil
}

// PluginTokenCheckHostname reports whether hostname matches the anchored pattern. An empty pattern
// means "no restriction".
func PluginTokenCheckHostname(pattern, hostname string) (bool, error) {
	if pattern == "" {
		return true, nil
	}

	if _, err := regexp.Compile(pattern); err != nil {
		return false, fmt.Errorf("invalid hostname pattern %q: %w", pattern, err)
	}

	anchored := "^(?:" + pattern + ")$"
	matched, err := regexp.MatchString(anchored, hostname)
	if err != nil {
		return false, fmt.Errorf("invalid hostname pattern %q: %w", pattern, err)
	}
	return matched, nil
}
