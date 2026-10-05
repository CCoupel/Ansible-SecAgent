// store_relay.go — relay nodes (persistent configuration) and their volatile status.
package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"secagent-server/cmd/secagent-server/internal/state"
)

// RelayNode represents a downstream relay registered on a proxy.
// Mode "pull": the relay connects to the proxy via /ws/relay.
// Mode "push": the proxy dials the relay's URL.
//
// TokenHash (pull: SHA-256 of the relay JWT) and TokenSecret (push: the token the proxy presents,
// ALWAYS "enc:"-sealed, bound to the relay id) are distinct fields. Status and LastSeen are
// volatile (rebuilt by the topology snapshots), CreatedAt and the rest are persistent.
type RelayNode struct {
	ID          string   // UUID (internal primary key)
	RelayID     string   // human-readable unique ID, e.g. "dmz1"
	URLs        []string // wss:// addresses of the child's instances — push mode only (tried in order), empty for pull
	Description string
	TokenHash   string // pull mode: SHA-256 of the relay token
	TokenSecret string // push mode: sealed token ("enc:…"), see state.SealSecret
	Mode        string // "pull" | "push"
	IsProxy     bool   // true if the downstream relay is itself a proxy
	CreatedAt   int64  // Unix timestamp
	LastSeen    *int64 // nil if never connected (volatile)
	Status      string // "connected" | "disconnected" | "pending" (volatile)
}

func (s *Store) relayFromState(n state.RelayNode) RelayNode {
	out := RelayNode{ID: n.ID, RelayID: n.RelayID, Description: n.Description, TokenHash: n.TokenHash, TokenSecret: n.TokenSecret,
		Mode: n.Mode, IsProxy: n.IsProxy, CreatedAt: n.CreatedAt.Unix(), Status: "pending"}
	out.URLs = append([]string(nil), n.URLs...)
	s.mu.RLock()
	if v, ok := s.relayVol[n.RelayID]; ok {
		if v.status != "" {
			out.Status = v.status
		}
		if v.lastSeen != nil {
			ls := *v.lastSeen
			out.LastSeen = &ls
		}
	}
	s.mu.RUnlock()
	return out
}

// UpsertRelayNode inserts or updates a relay node keyed on relay_id. On update the identity, the
// creation time, the token info (jti, expiry, revoked flag) and the group vars are kept.
func (s *Store) UpsertRelayNode(node RelayNode) error {
	if err := checkRelayID(node.RelayID); err != nil { // last line of defence for every entry point
		return fmt.Errorf("UpsertRelayNode: %w", err)
	}
	if node.CreatedAt == 0 {
		node.CreatedAt = time.Now().UTC().Unix()
	}
	if node.Status == "" {
		node.Status = "pending"
	}
	if node.Mode == "" {
		node.Mode = "pull"
	}
	err := s.mutate(func(tx *state.Tx) error {
		n, exists := tx.RelayNode(node.RelayID)
		if !exists {
			n = state.RelayNode{ID: node.ID, RelayID: node.RelayID, CreatedAt: time.Unix(node.CreatedAt, 0).UTC()}
		}
		n.URLs = append([]string(nil), node.URLs...)
		n.Description, n.TokenHash, n.TokenSecret, n.Mode, n.IsProxy = node.Description, node.TokenHash, node.TokenSecret, node.Mode, node.IsProxy
		return tx.PutRelayNode(n)
	})
	if err != nil {
		return fmt.Errorf("UpsertRelayNode %q: %w", node.RelayID, err)
	}
	s.mu.Lock()
	v := s.relayVol[node.RelayID]
	v.status, v.lastSeen = node.Status, node.LastSeen
	s.relayVol[node.RelayID] = v
	s.mu.Unlock()
	log.Printf("RelayNode upserted: relay_id=%q mode=%s status=%s", node.RelayID, node.Mode, node.Status)
	return nil
}

// GetRelayNode returns the relay node with this relay_id, or (nil, nil).
func (s *Store) GetRelayNode(relayID string) (*RelayNode, error) {
	n, ok := s.snap().RelayNode(relayID)
	if !ok {
		return nil, nil
	}
	out := s.relayFromState(n)
	return &out, nil
}

// GetRelayNodeByID returns the relay node with this internal id, or (nil, nil).
func (s *Store) GetRelayNodeByID(id string) (*RelayNode, error) {
	n, ok := s.snap().RelayNodeByID(id)
	if !ok {
		return nil, nil
	}
	out := s.relayFromState(n)
	return &out, nil
}

// ListRelayNodes returns all relay nodes ordered by relay_id.
func (s *Store) ListRelayNodes() ([]RelayNode, error) {
	var out []RelayNode
	for _, n := range s.snap().RelayNodes() {
		out = append(out, s.relayFromState(n))
	}
	return out, nil
}

// DeleteRelayNode removes a relay node by its internal id, with its routes and volatile data.
func (s *Store) DeleteRelayNode(id string) error {
	var relayID string
	err := s.mutate(func(tx *state.Tx) error {
		n, ok := tx.RelayNodeByID(id)
		if !ok {
			return nil
		}
		relayID = n.RelayID
		tx.DeleteRelayNode(n.RelayID)
		return nil
	})
	if err != nil {
		return fmt.Errorf("DeleteRelayNode: %w", err)
	}
	if relayID != "" {
		s.mu.Lock()
		delete(s.relayVol, relayID)
		for h, r := range s.routes { // ON DELETE CASCADE
			if r.RelayID == relayID {
				delete(s.routes, h)
			}
		}
		s.mu.Unlock()
		log.Printf("RelayNode deleted: id=%q", id)
	}
	return nil
}

// SetRelayIsProxy updates the is_proxy flag of a relay (no error when it is unknown).
func (s *Store) SetRelayIsProxy(relayID string, isProxy bool) error {
	err := s.mutate(func(tx *state.Tx) error {
		n, ok := tx.RelayNode(relayID)
		if !ok || n.IsProxy == isProxy {
			return nil
		}
		n.IsProxy = isProxy
		return tx.PutRelayNode(n)
	})
	if err != nil {
		return fmt.Errorf("SetRelayIsProxy %q: %w", relayID, err)
	}
	return nil
}

// UpdateRelayStatus records the connection status and last_seen of a relay (memory only).
func (s *Store) UpdateRelayStatus(relayID, status string, lastSeen int64) error {
	s.mu.Lock()
	v := s.relayVol[relayID]
	ls := lastSeen
	v.status, v.lastSeen = status, &ls
	s.relayVol[relayID] = v
	s.mu.Unlock()
	return nil
}

// SetRelayChain records the top-down path to a deep relay (memory only). found=false when the relay
// is unknown.
func (s *Store) SetRelayChain(relayID string, chain []string) (bool, error) {
	if _, ok := s.snap().RelayNode(relayID); !ok {
		return false, nil
	}
	s.mu.Lock()
	v := s.relayVol[relayID]
	v.chain = append([]string(nil), chain...)
	s.relayVol[relayID] = v
	s.mu.Unlock()
	return true, nil
}

// ListRelayChains returns the recorded chains, by relay_id.
func (s *Store) ListRelayChains() (map[string][]string, error) {
	out := map[string][]string{}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for id, v := range s.relayVol {
		if len(v.chain) > 0 {
			out[id] = append([]string(nil), v.chain...)
		}
	}
	return out, nil
}

// SetRelayGroupVars stores the Ansible group vars (a JSON object) of a relay; "" clears them.
func (s *Store) SetRelayGroupVars(relayID, groupVarsJSON string) (bool, error) {
	var gv map[string]any
	if groupVarsJSON != "" {
		if err := json.Unmarshal([]byte(groupVarsJSON), &gv); err != nil {
			return false, fmt.Errorf("SetRelayGroupVars %q: group vars are not a JSON object: %w", relayID, err)
		}
	}
	found := false
	err := s.mutate(func(tx *state.Tx) error {
		n, ok := tx.RelayNode(relayID)
		if !ok {
			return nil
		}
		found = true
		n.GroupVars = gv
		return tx.PutRelayNode(n)
	})
	if err != nil {
		return false, fmt.Errorf("SetRelayGroupVars %q: %w", relayID, err)
	}
	return found, nil
}

// ListRelayGroupVars returns the group vars (JSON) of the relays that have some.
func (s *Store) ListRelayGroupVars() (map[string]string, error) {
	out := map[string]string{}
	for _, n := range s.snap().RelayNodes() {
		if len(n.GroupVars) == 0 {
			continue
		}
		b, err := json.Marshal(n.GroupVars)
		if err != nil {
			continue
		}
		out[n.RelayID] = string(b)
	}
	return out, nil
}

// ── relay-parent tokens ──────────────────────────────────────────────────────

// RelayParentToken is the metadata of a relay-parent token minted on a child relay (#150): never the JWT.
type RelayParentToken struct {
	ID          string // internal id used by `tokens revoke`
	JTI         string // JWT identifier (blacklist key)
	ParentID    string // jwt.sub: the parent this token was minted for
	Description string
	CreatedAt   time.Time
	ExpiresAt   time.Time
	RevokedAt   *time.Time
}

// Revoked reports whether the token was revoked.
func (t RelayParentToken) Revoked() bool { return t.RevokedAt != nil }

func parentFromState(t state.RelayParentToken) RelayParentToken {
	return RelayParentToken{ID: t.ID, JTI: t.JTI, ParentID: t.ParentID, Description: t.Description, CreatedAt: t.CreatedAt, ExpiresAt: t.ExpiresAt, RevokedAt: t.RevokedAt}
}

// CreateRelayParentToken records a token's metadata.
func (s *Store) CreateRelayParentToken(ctx context.Context, t RelayParentToken) error {
	err := s.mutate(func(tx *state.Tx) error {
		if _, exists := tx.RelayParentToken(t.ID); exists {
			return fmt.Errorf("%w: relay-parent token id %q", state.ErrDuplicate, t.ID)
		}
		return tx.PutRelayParentToken(state.RelayParentToken{ID: t.ID, JTI: t.JTI, ParentID: t.ParentID, Description: t.Description,
			CreatedAt: t.CreatedAt.UTC().Truncate(time.Second), ExpiresAt: t.ExpiresAt.UTC().Truncate(time.Second)})
	})
	if err != nil {
		return fmt.Errorf("CreateRelayParentToken: %w", err)
	}
	log.Printf("Relay-parent token created: id=%q parent=%q", t.ID, t.ParentID)
	return nil
}

// ListRelayParentTokens returns the tokens, newest first.
func (s *Store) ListRelayParentTokens(ctx context.Context) ([]RelayParentToken, error) {
	var out []RelayParentToken
	for _, t := range s.snap().RelayParentTokens() {
		out = append(out, parentFromState(t))
	}
	sortParentTokens(out)
	return out, nil
}

// GetRelayParentToken returns one token, or (nil, nil).
func (s *Store) GetRelayParentToken(ctx context.Context, id string) (*RelayParentToken, error) {
	t, ok := s.snap().RelayParentToken(id)
	if !ok {
		return nil, nil
	}
	out := parentFromState(t)
	return &out, nil
}

// RevokeRelayParentToken marks the token revoked AND blacklists its JTI in ONE mutation. Idempotent.
// found=false when the token does not exist.
func (s *Store) RevokeRelayParentToken(ctx context.Context, id string) (*RelayParentToken, bool, error) {
	var out RelayParentToken
	found := false
	err := s.mutate(func(tx *state.Tx) error {
		t, ok := tx.RelayParentToken(id)
		if !ok {
			return nil
		}
		found = true
		now := time.Now().UTC().Truncate(time.Second)
		if t.RevokedAt == nil {
			t.RevokedAt = &now
			if err := tx.PutRelayParentToken(t); err != nil {
				return err
			}
		}
		if err := putBlacklist(tx, t.JTI, t.ParentID, "relay-parent token revoked", now, t.ExpiresAt.UTC()); err != nil {
			return err
		}
		out = parentFromState(t)
		return nil
	})
	if err != nil {
		return nil, false, fmt.Errorf("RevokeRelayParentToken: %w", err)
	}
	if !found {
		return nil, false, nil
	}
	log.Printf("Relay-parent token revoked: id=%q parent=%q", out.ID, out.ParentID)
	return &out, true, nil
}

// ── relay token info and revocation ──────────────────────────────────────────

// RelayTokenInfo is the JWT identity of a relay's registration token.
type RelayTokenInfo struct {
	JTI     string // "" when unknown
	Exp     int64  // unix seconds, 0 when unknown
	Revoked bool
}

// SetRelayTokenInfo records the JTI and expiry of the token issued at registration, and clears the
// revoked flag (a re-registration issues a new token).
func (s *Store) SetRelayTokenInfo(relayID, jti string, exp int64) error {
	err := s.mutate(func(tx *state.Tx) error {
		n, ok := tx.RelayNode(relayID)
		if !ok {
			return fmt.Errorf("unknown relay")
		}
		n.JTI, n.TokenExp, n.Revoked = jti, exp, false
		return tx.PutRelayNode(n)
	})
	if err != nil {
		return fmt.Errorf("SetRelayTokenInfo %q: %w", relayID, err)
	}
	return nil
}

// GetRelayTokenInfo returns the token info of a relay (zero value when unknown).
func (s *Store) GetRelayTokenInfo(relayID string) (RelayTokenInfo, error) {
	n, ok := s.snap().RelayNode(relayID)
	if !ok {
		return RelayTokenInfo{}, nil
	}
	return RelayTokenInfo{JTI: n.JTI, Exp: n.TokenExp, Revoked: n.Revoked}, nil
}

// RevokeRelayNode flags relayID revoked and blacklists its JTI in ONE mutation (the state engine
// refuses a revoked relay whose token is not blacklisted, so a crash can never leave one without
// the other). It returns the token info as it was. Idempotent. found=false when unknown.
//
// A relay that never had a token JTI (declared automatically when it connected) is given a
// synthetic one for the duration of the revocation, so that the invariant holds; the revoked flag
// is what refuses its connections.
func (s *Store) RevokeRelayNode(ctx context.Context, relayID, reason string) (info RelayTokenInfo, found bool, err error) {
	err = s.mutate(func(tx *state.Tx) error {
		n, ok := tx.RelayNode(relayID)
		if !ok {
			return nil
		}
		found = true
		info = RelayTokenInfo{JTI: n.JTI, Exp: n.TokenExp, Revoked: n.Revoked}
		now := time.Now().UTC().Truncate(time.Second)
		expires := now.Add(30 * 24 * time.Hour)
		if info.Exp > 0 {
			expires = time.Unix(info.Exp, 0).UTC()
		}
		jti := n.JTI
		if jti == "" {
			jti = "no-token:" + relayID
			n.JTI, n.TokenExp = jti, expires.Unix()
		}
		n.Revoked = true
		if err := putBlacklist(tx, jti, relayID, reason, now, expires); err != nil {
			return err
		}
		return tx.PutRelayNode(n)
	})
	if err != nil {
		return RelayTokenInfo{}, false, fmt.Errorf("RevokeRelayNode: %w", err)
	}
	if found {
		log.Printf("Relay revoked: relay_id=%q jti_known=%v", relayID, info.JTI != "")
	}
	return info, found, nil
}

// BlacklistJTI blacklists a JTI (30 days when exp is unknown).
func (s *Store) BlacklistJTI(ctx context.Context, jti, relayID, reason string, exp int64) error {
	expires := time.Now().UTC().Add(30 * 24 * time.Hour)
	if exp > 0 {
		expires = time.Unix(exp, 0).UTC()
	}
	r := reason
	return s.AddToBlacklist(ctx, jti, relayID, expires.Format(time.RFC3339), &r)
}
