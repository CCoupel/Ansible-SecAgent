// Package storage is the relay's data store: the permanent data lives in the single-file state
// engine (internal/state, #159/#160), read from memory through indexes and written by atomic
// mutations; the volatile data (agent status and last_seen, plugin token last_used, relay status,
// routing, relay chains) is kept in memory only and reaches the file only when it is written for
// another reason (piggyback).
package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"sync"
	"time"

	"secagent-server/cmd/secagent-server/internal/state"
)

// AgentRecord represents stored agent data
type AgentRecord struct {
	Hostname     string
	PublicKeyPEM string
	TokenJTI     string
	EnrolledAt   time.Time
	LastSeen     time.Time
	Status       string // "connected", "disconnected"
	Suspended    bool
	Vars         string // JSON object, e.g. {"key": "value"}
}

// AuthorizedKeyRecord represents a pre-authorized public key
type AuthorizedKeyRecord struct {
	Hostname     string
	PublicKeyPEM string
	ApprovedAt   time.Time
	ApprovedBy   string
}

// BlacklistEntry represents a revoked JWT identifier
type BlacklistEntry struct {
	JTI       string
	Hostname  string
	RevokedAt time.Time
	ExpiresAt time.Time
	Reason    string
}

// ErrReadOnly is returned by every write while no write guard is connected: the instance is not
// (yet) the confirmed master and must not write the shared state (#163 connects the guard).
var ErrReadOnly = state.ErrNoWriteGuard

// Store provides the relay data access on top of the state engine.
type Store struct {
	eng     *state.Engine
	cleanup func()

	mu        sync.RWMutex // volatile data below
	agentVol  map[string]agentVolatile
	pluginVol map[string]pluginVolatile
	relayVol  map[string]relayVolatile
	routes    map[string]RelayRoute
}

type agentVolatile struct {
	status   string
	lastSeen time.Time
}

type pluginVolatile struct {
	at time.Time
	ip string
}

type relayVolatile struct {
	status   string
	lastSeen *int64
	chain    []string
}

// Open loads the state of opts.Dir (see state.Open: a missing state is a *state.NotFoundError,
// never created here). The store installs the piggyback that persists the volatile last_seen /
// last_used data whenever the file is written for another reason.
func Open(opts state.Options) (*Store, error) {
	s := newStore()
	userPiggy := opts.Piggyback
	opts.Piggyback = func(p *state.Payload) {
		s.piggyback(p)
		if userPiggy != nil {
			userPiggy(p)
		}
	}
	eng, err := state.Open(opts)
	if err != nil {
		return nil, err
	}
	s.eng = eng
	log.Printf("AgentStore initialized: state_dir=%s", opts.Dir)
	return s, nil
}

func newStore() *Store {
	return &Store{
		agentVol:  map[string]agentVolatile{},
		pluginVol: map[string]pluginVolatile{},
		relayVol:  map[string]relayVolatile{},
		routes:    map[string]RelayRoute{},
	}
}

// SetWriteGuard connects the write guard (the lock identity check of #163). Without it every write
// fails with ErrReadOnly.
func (s *Store) SetWriteGuard(fn func() error) { s.eng.SetBeforeWrite(fn) }

// Engine exposes the state engine (reload on promotion, write counters).
func (s *Store) Engine() *state.Engine { return s.eng }

// Close releases what the store owns (a temporary directory for OpenTemp).
func (s *Store) Close() error {
	if s.cleanup != nil {
		s.cleanup()
		s.cleanup = nil
	}
	return nil
}

// piggyback merges the volatile last_seen / last_used data into the payload about to be written.
func (s *Store) piggyback(p *state.Payload) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for host, v := range s.agentVol {
		if a, ok := p.Agents[host]; ok {
			t := v.lastSeen
			a.LastSeen = &t
			p.Agents[host] = a
		}
	}
	for id, v := range s.pluginVol {
		if t, ok := p.PluginTokens[id]; ok {
			at := v.at
			t.LastUsedAt, t.LastUsedIP = &at, v.ip
			p.PluginTokens[id] = t
		}
	}
}

func (s *Store) mutate(fn func(*state.Tx) error) error { return s.eng.Mutate(fn) }

func (s *Store) snap() state.Snapshot { return s.eng.Snapshot() }

func nowUTC() time.Time { return time.Now().UTC().Truncate(time.Second) }

// ========================================================================
// authorized_keys — pre-enrollment (called by CI/CD pipeline)
// ========================================================================

// AddAuthorizedKey pre-authorizes a public key for a hostname before agent boots
// Called via POST /api/admin/authorize (CI/CD pipeline)
func (s *Store) AddAuthorizedKey(ctx context.Context, hostname, publicKeyPEM, approvedBy string) error {
	err := s.mutate(func(tx *state.Tx) error {
		return tx.PutAuthorizedKey(state.AuthorizedKey{Hostname: hostname, PublicKeyPEM: publicKeyPEM, ApprovedAt: nowUTC(), ApprovedBy: approvedBy})
	})
	if err != nil {
		return fmt.Errorf("failed to add authorized key: %w", err)
	}
	log.Printf("Key authorized: hostname=%q approved_by=%q", hostname, approvedBy)
	return nil
}

// GetAuthorizedKey fetches the authorized key entry for a hostname
// Used during enrollment to verify agent's public key
func (s *Store) GetAuthorizedKey(ctx context.Context, hostname string) (*AuthorizedKeyRecord, error) {
	k, ok := s.snap().AuthorizedKey(hostname)
	if !ok {
		return nil, nil
	}
	return &AuthorizedKeyRecord{Hostname: k.Hostname, PublicKeyPEM: k.PublicKeyPEM, ApprovedAt: k.ApprovedAt, ApprovedBy: k.ApprovedBy}, nil
}

// RevokeKey removes the authorized key for a hostname; reports whether one existed.
func (s *Store) RevokeKey(ctx context.Context, hostname string) (bool, error) {
	deleted := false
	if err := s.mutate(func(tx *state.Tx) error { deleted = tx.DeleteAuthorizedKey(hostname); return nil }); err != nil {
		return false, fmt.Errorf("failed to revoke key: %w", err)
	}
	if deleted {
		log.Printf("Authorized key revoked: hostname=%q", hostname)
	}
	return deleted, nil
}

// ========================================================================
// agents
// ========================================================================

func (s *Store) agentRecord(a state.Agent) AgentRecord {
	rec := AgentRecord{Hostname: a.Hostname, PublicKeyPEM: a.PublicKeyPEM, TokenJTI: a.TokenJTI, EnrolledAt: a.EnrolledAt,
		LastSeen: a.EnrolledAt, Status: "disconnected", Suspended: a.Suspended, Vars: varsJSON(a.Vars)}
	if a.LastSeen != nil {
		rec.LastSeen = *a.LastSeen
	}
	s.mu.RLock()
	if v, ok := s.agentVol[a.Hostname]; ok {
		rec.Status = v.status
		if v.lastSeen.After(rec.LastSeen) {
			rec.LastSeen = v.lastSeen
		}
	}
	s.mu.RUnlock()
	return rec
}

func varsJSON(m map[string]any) string {
	if len(m) == 0 {
		return "{}"
	}
	b, err := json.Marshal(m)
	if err != nil {
		return "{}"
	}
	return string(b)
}

// RegisterAgent registers (or re-registers) an agent. Re-registration refreshes the key, the JTI and
// the enrollment time and keeps the suspension flag and the vars.
func (s *Store) RegisterAgent(ctx context.Context, hostname, publicKeyPEM, tokenJTI string) (string, error) {
	now := nowUTC()
	err := s.mutate(func(tx *state.Tx) error { return putEnrolledAgent(tx, hostname, publicKeyPEM, tokenJTI, now) })
	if err != nil {
		return "", fmt.Errorf("failed to register agent: %w", err)
	}
	s.touchAgent(hostname, "disconnected", now, false)
	log.Printf("Agent registered: hostname=%q jti=%q", hostname, tokenJTI)
	return hostname, nil
}

func putEnrolledAgent(tx *state.Tx, hostname, publicKeyPEM, tokenJTI string, now time.Time) error {
	a, _ := tx.Agent(hostname)
	a.Hostname, a.PublicKeyPEM, a.TokenJTI, a.EnrolledAt = hostname, publicKeyPEM, tokenJTI, now
	a.LastSeen = &now
	return tx.PutAgent(a)
}

// EnrollAgent performs a whole enrollment in ONE mutation (one rename): the enrollment token is
// consumed, the public key is authorized and the agent is registered, or nothing happens at all
// (#160: a failure between the steps leaves neither a consumed token without agent nor an agent
// without key). tokenID may be empty for the legacy flow without enrollment token.
func (s *Store) EnrollAgent(ctx context.Context, tokenID, hostname, publicKeyPEM, tokenJTI, approvedBy string) error {
	now := nowUTC()
	err := s.mutate(func(tx *state.Tx) error {
		if tokenID != "" {
			tok, ok := tx.EnrollmentToken(tokenID)
			if !ok {
				return fmt.Errorf("token not found id=%s", tokenID)
			}
			tok.UseCount++
			tok.LastUsedAt = &now
			if err := tx.PutEnrollmentToken(tok); err != nil {
				return err
			}
		}
		if err := tx.PutAuthorizedKey(state.AuthorizedKey{Hostname: hostname, PublicKeyPEM: publicKeyPEM, ApprovedAt: now, ApprovedBy: approvedBy}); err != nil {
			return err
		}
		return putEnrolledAgent(tx, hostname, publicKeyPEM, tokenJTI, now)
	})
	if err != nil {
		return fmt.Errorf("EnrollAgent: %w", err)
	}
	s.touchAgent(hostname, "disconnected", now, false)
	log.Printf("Agent enrolled: hostname=%q token_id=%q jti=%q", hostname, tokenID, tokenJTI)
	return nil
}

// UpsertAgent is an alias for RegisterAgent
func (s *Store) UpsertAgent(ctx context.Context, hostname, publicKeyPEM, tokenJTI string) error {
	_, err := s.RegisterAgent(ctx, hostname, publicKeyPEM, tokenJTI)
	return err
}

// GetAgent retrieves a registered agent by hostname
func (s *Store) GetAgent(ctx context.Context, hostname string) (*AgentRecord, error) {
	a, ok := s.snap().Agent(hostname)
	if !ok {
		return nil, nil
	}
	rec := s.agentRecord(a)
	return &rec, nil
}

// ListAgents returns all agents, optionally filtered to connected ones
func (s *Store) ListAgents(ctx context.Context, onlyConnected bool) ([]AgentRecord, error) {
	var agents []AgentRecord
	for _, a := range s.snap().Agents() {
		rec := s.agentRecord(a)
		if onlyConnected && rec.Status != "connected" {
			continue
		}
		agents = append(agents, rec)
	}
	return agents, nil
}

// DeleteAgent removes an agent and its authorized key.
func (s *Store) DeleteAgent(ctx context.Context, hostname string) (bool, error) {
	deleted := false
	err := s.mutate(func(tx *state.Tx) error {
		deleted = tx.DeleteAgent(hostname)
		if deleted {
			tx.DeleteAuthorizedKey(hostname)
		}
		return nil
	})
	if err != nil {
		return false, fmt.Errorf("DeleteAgent: %w", err)
	}
	if deleted {
		s.mu.Lock()
		delete(s.agentVol, hostname)
		s.mu.Unlock()
		log.Printf("Agent deleted: hostname=%q", hostname)
	}
	return deleted, nil
}

func (s *Store) touchAgent(hostname, status string, at time.Time, bumpOnlyIfNewer bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cur, ok := s.agentVol[hostname]; ok && bumpOnlyIfNewer && cur.lastSeen.After(at) {
		at = cur.lastSeen
	}
	s.agentVol[hostname] = agentVolatile{status: status, lastSeen: at}
}

// UpdateLastSeen marks the agent connected now. Memory only: no disk write (the value is persisted
// with the next write of the file).
func (s *Store) UpdateLastSeen(ctx context.Context, hostname string) (bool, error) {
	if _, ok := s.snap().Agent(hostname); !ok {
		return false, nil
	}
	s.touchAgent(hostname, "connected", time.Now().UTC(), false)
	return true, nil
}

// UpdateAgentStatus records the connection status (memory only).
func (s *Store) UpdateAgentStatus(ctx context.Context, hostname, status, lastSeen string) error {
	at := time.Now().UTC()
	if lastSeen != "" {
		if t, err := time.Parse(time.RFC3339, lastSeen); err == nil {
			at = t.UTC()
		}
	}
	if _, ok := s.snap().Agent(hostname); !ok {
		return nil
	}
	s.touchAgent(hostname, status, at, false)
	return nil
}

// UpdateTokenJTI replaces the current JTI of an agent (refresh, rekey).
func (s *Store) UpdateTokenJTI(ctx context.Context, hostname, tokenJTI string) (bool, error) {
	found := false
	err := s.mutate(func(tx *state.Tx) error {
		a, ok := tx.Agent(hostname)
		if !ok {
			return nil
		}
		found = true
		a.TokenJTI = tokenJTI
		return tx.PutAgent(a)
	})
	if err != nil {
		return false, fmt.Errorf("failed to update token JTI: %w", err)
	}
	return found, nil
}

// ========================================================================
// JWT blacklist
// ========================================================================

// AddToBlacklist records a revoked JTI (an existing entry is kept).
func (s *Store) AddToBlacklist(ctx context.Context, jti, hostname, expiresAt string, reason *string) error {
	exp, err := time.Parse(time.RFC3339, expiresAt)
	if err != nil {
		return fmt.Errorf("failed to add to blacklist: invalid expires_at %q: %w", expiresAt, err)
	}
	reasonStr := ""
	if reason != nil {
		reasonStr = *reason
	}
	err = s.mutate(func(tx *state.Tx) error { return putBlacklist(tx, jti, hostname, reasonStr, nowUTC(), exp.UTC()) })
	if err != nil {
		return fmt.Errorf("failed to add to blacklist: %w", err)
	}
	log.Printf("JTI blacklisted: jti=%q hostname=%q reason=%q", jti, hostname, reasonStr)
	return nil
}

// putBlacklist adds the entry unless the JTI is already blacklisted (ON CONFLICT DO NOTHING).
func putBlacklist(tx *state.Tx, jti, hostname, reason string, revokedAt, expiresAt time.Time) error {
	if tx.Blacklisted(jti) {
		return nil
	}
	return tx.PutBlacklist(state.BlacklistEntry{JTI: jti, Hostname: hostname, RevokedAt: revokedAt, Reason: reason, ExpiresAt: expiresAt})
}

// IsJTIBlacklisted checks whether a JWT identifier is in the revocation blacklist (memory lookup).
func (s *Store) IsJTIBlacklisted(ctx context.Context, jti string) (bool, error) {
	return s.snap().Blacklisted(jti), nil
}

// PurgeExpiredBlacklist drops the entries whose expiry has passed. Nothing is written when there is
// nothing to purge. The periodic task of the server calls it (the write guard applies).
func (s *Store) PurgeExpiredBlacklist(ctx context.Context) (int64, error) {
	return s.purgeBlacklist(time.Now().UTC())
}

func (s *Store) purgeBlacklist(now time.Time) (int64, error) {
	expired := false
	for _, e := range s.snap().BlacklistEntries() {
		if !e.ExpiresAt.After(now) {
			expired = true
			break
		}
	}
	if !expired {
		return 0, nil
	}
	n := 0
	if err := s.mutate(func(tx *state.Tx) error { n = tx.PurgeExpiredBlacklist(now); return nil }); err != nil {
		return 0, fmt.Errorf("failed to purge blacklist: %w", err)
	}
	if n > 0 {
		log.Printf("Blacklist entries purged: count=%d", n)
	}
	return int64(n), nil
}

// PurgeBlacklistAt is PurgeExpiredBlacklist with an explicit clock (tests).
func (s *Store) PurgeBlacklistAt(now time.Time) (int64, error) { return s.purgeBlacklist(now) }

// CleanupExpiredBlacklist is an alias for PurgeExpiredBlacklist
func (s *Store) CleanupExpiredBlacklist(ctx context.Context) (int64, error) {
	return s.PurgeExpiredBlacklist(ctx)
}

// ListBlacklistEntries returns the blacklist, most recent revocation first.
func (s *Store) ListBlacklistEntries(ctx context.Context) ([]BlacklistEntry, error) {
	var out []BlacklistEntry
	for _, e := range s.snap().BlacklistEntries() {
		out = append(out, BlacklistEntry{JTI: e.JTI, Hostname: e.Hostname, RevokedAt: e.RevokedAt, ExpiresAt: e.ExpiresAt, Reason: e.Reason})
	}
	sortBlacklistRecentFirst(out)
	return out, nil
}

// ========================================================================
// agents — suspend / resume / vars
// ========================================================================

// SetSuspended sets the suspended flag for an agent.
// When suspended=true, exec requests for this agent will return 503.
func (s *Store) SetSuspended(ctx context.Context, hostname string, suspended bool) (bool, error) {
	found := false
	err := s.mutate(func(tx *state.Tx) error {
		a, ok := tx.Agent(hostname)
		if !ok {
			return nil
		}
		found = true
		a.Suspended = suspended
		return tx.PutAgent(a)
	})
	if err != nil {
		return false, fmt.Errorf("failed to set suspended: %w", err)
	}
	if found {
		action := "suspended"
		if !suspended {
			action = "resumed"
		}
		log.Printf("Agent %s: hostname=%q", action, hostname)
	}
	return found, nil
}

// IsAgentSuspended returns true if the agent exists and is suspended.
func (s *Store) IsAgentSuspended(ctx context.Context, hostname string) (bool, error) {
	a, ok := s.snap().Agent(hostname)
	return ok && a.Suspended, nil
}

// GetAgentVars returns the vars JSON string for an agent ("" when the agent does not exist).
func (s *Store) GetAgentVars(ctx context.Context, hostname string) (string, error) {
	a, ok := s.snap().Agent(hostname)
	if !ok {
		return "", nil
	}
	return varsJSON(a.Vars), nil
}

// SetAgentVar sets one var on an agent.
func (s *Store) SetAgentVar(ctx context.Context, hostname, key string, value interface{}) error {
	err := s.mutate(func(tx *state.Tx) error {
		a, ok := tx.Agent(hostname)
		if !ok {
			return fmt.Errorf("agent_not_found")
		}
		if a.Vars == nil {
			a.Vars = map[string]any{}
		}
		// normalise the value through JSON, as the previous JSON column did
		raw, err := json.Marshal(value)
		if err != nil {
			return fmt.Errorf("failed to marshal vars: %w", err)
		}
		var v any
		if err := json.Unmarshal(raw, &v); err != nil {
			return fmt.Errorf("failed to marshal vars: %w", err)
		}
		a.Vars[key] = v
		return tx.PutAgent(a)
	})
	if err != nil {
		if err.Error() == "agent_not_found" {
			return err
		}
		return fmt.Errorf("failed to update vars: %w", err)
	}
	log.Printf("Agent var set: hostname=%q key=%q", hostname, key)
	return nil
}

// DeleteAgentVar removes one var from an agent (false when the key did not exist).
func (s *Store) DeleteAgentVar(ctx context.Context, hostname, key string) (bool, error) {
	existed := false
	err := s.mutate(func(tx *state.Tx) error {
		a, ok := tx.Agent(hostname)
		if !ok {
			return fmt.Errorf("agent_not_found")
		}
		if _, ok := a.Vars[key]; !ok {
			return nil
		}
		existed = true
		delete(a.Vars, key)
		return tx.PutAgent(a)
	})
	if err != nil {
		if err.Error() == "agent_not_found" {
			return false, err
		}
		return false, fmt.Errorf("failed to update vars: %w", err)
	}
	if existed {
		log.Printf("Agent var deleted: hostname=%q key=%q", hostname, key)
	}
	return existed, nil
}

// ========================================================================
// server_config
// ========================================================================

// ConfigGet returns a server_config value ("" when absent).
func (s *Store) ConfigGet(ctx context.Context, key string) (string, error) {
	v, _ := s.snap().Config(key)
	return v, nil
}

// ConfigSet stores a server_config value. A secret key is only accepted encrypted (see state).
func (s *Store) ConfigSet(ctx context.Context, key, value string) error {
	if err := s.mutate(func(tx *state.Tx) error { return tx.SetConfig(key, value) }); err != nil {
		return fmt.Errorf("ConfigSet %q: %w", key, err)
	}
	return nil
}

// ConfigDelete removes a server_config value.
func (s *Store) ConfigDelete(ctx context.Context, key string) error {
	if err := s.mutate(func(tx *state.Tx) error { tx.DeleteConfig(key); return nil }); err != nil {
		return fmt.Errorf("ConfigDelete %q: %w", key, err)
	}
	return nil
}

func sortBlacklistRecentFirst(e []BlacklistEntry) {
	sort.SliceStable(e, func(i, j int) bool {
		if !e[i].RevokedAt.Equal(e[j].RevokedAt) {
			return e[i].RevokedAt.After(e[j].RevokedAt)
		}
		return e[i].JTI < e[j].JTI
	})
}

func sortParentTokens(t []RelayParentToken) {
	sort.SliceStable(t, func(i, j int) bool {
		if !t[i].CreatedAt.Equal(t[j].CreatedAt) {
			return t[i].CreatedAt.After(t[j].CreatedAt)
		}
		return t[i].ID < t[j].ID
	})
}
