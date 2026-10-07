package state

import "sort"

// Snapshot is an immutable, consistent view of the state (the model published by the last
// durable write). Reads are lock-free index lookups; every value returned is a copy.
type Snapshot struct{ m *model }

// WriteSeq is the monotone write counter of the file this snapshot comes from.
func (s Snapshot) WriteSeq() uint64 { return s.m.seq }

func (s Snapshot) Agent(hostname string) (Agent, bool) {
	a, ok := s.m.Agents[hostname]
	return a.clone(), ok
}

func (s Snapshot) Agents() []Agent {
	out := make([]Agent, 0, len(s.m.Agents))
	for _, a := range s.m.Agents {
		out = append(out, a.clone())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Hostname < out[j].Hostname })
	return out
}

func (s Snapshot) AgentCount() int { return len(s.m.Agents) }

func (s Snapshot) AuthorizedKey(hostname string) (AuthorizedKey, bool) {
	k, ok := s.m.AuthorizedKeys[hostname]
	return k, ok
}

func (s Snapshot) EnrollmentToken(id string) (EnrollmentToken, bool) {
	v, ok := s.m.EnrollmentTokens[id]
	return v.clone(), ok
}

func (s Snapshot) EnrollmentTokenByHash(hash string) (EnrollmentToken, bool) {
	id, ok := s.m.enrollByHash[hash]
	if !ok {
		return EnrollmentToken{}, false
	}
	return s.EnrollmentToken(id)
}

func (s Snapshot) EnrollmentTokens() []EnrollmentToken {
	out := make([]EnrollmentToken, 0, len(s.m.EnrollmentTokens))
	for _, v := range s.m.EnrollmentTokens {
		out = append(out, v.clone())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (s Snapshot) PluginToken(id string) (PluginToken, bool) {
	v, ok := s.m.PluginTokens[id]
	return v.clone(), ok
}

func (s Snapshot) PluginTokenByHash(hash string) (PluginToken, bool) {
	id, ok := s.m.pluginByHash[hash]
	if !ok {
		return PluginToken{}, false
	}
	return s.PluginToken(id)
}

func (s Snapshot) PluginTokens() []PluginToken {
	out := make([]PluginToken, 0, len(s.m.PluginTokens))
	for _, v := range s.m.PluginTokens {
		out = append(out, v.clone())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (s Snapshot) RelayParentToken(id string) (RelayParentToken, bool) {
	v, ok := s.m.RelayParentTokens[id]
	return v.clone(), ok
}

func (s Snapshot) RelayParentTokenByJTI(jti string) (RelayParentToken, bool) {
	id, ok := s.m.parentByJTI[jti]
	if !ok {
		return RelayParentToken{}, false
	}
	return s.RelayParentToken(id)
}

func (s Snapshot) RelayParentTokens() []RelayParentToken {
	out := make([]RelayParentToken, 0, len(s.m.RelayParentTokens))
	for _, v := range s.m.RelayParentTokens {
		out = append(out, v.clone())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Blacklisted reports whether jti is in the blacklist (O(1), no I/O).
func (s Snapshot) Blacklisted(jti string) bool { _, ok := s.m.Blacklist[jti]; return ok }

func (s Snapshot) BlacklistEntries() []BlacklistEntry {
	out := make([]BlacklistEntry, 0, len(s.m.Blacklist))
	for _, v := range s.m.Blacklist {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].JTI < out[j].JTI })
	return out
}

func (s Snapshot) RelayNode(relayID string) (RelayNode, bool) {
	v, ok := s.m.RelayNodes[relayID]
	return v.clone(), ok
}

func (s Snapshot) RelayNodeByID(id string) (RelayNode, bool) {
	rid, ok := s.m.relayByID[id]
	if !ok {
		return RelayNode{}, false
	}
	return s.RelayNode(rid)
}

func (s Snapshot) RelayNodes() []RelayNode {
	out := make([]RelayNode, 0, len(s.m.RelayNodes))
	for _, v := range s.m.RelayNodes {
		out = append(out, v.clone())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RelayID < out[j].RelayID })
	return out
}

func (s Snapshot) Config(key string) (string, bool) { v, ok := s.m.ServerConfig[key]; return v, ok }

// LinkToken returns a link token of the registry (schema v2, root only).
func (s Snapshot) LinkToken(id string) (LinkToken, bool) {
	v, ok := s.m.LinkTokens[id]
	return v.clone(), ok
}

func (s Snapshot) LinkTokenByJTI(jti string) (LinkToken, bool) {
	id, ok := s.m.linkByJTI[jti]
	if !ok {
		return LinkToken{}, false
	}
	return s.LinkToken(id)
}

func (s Snapshot) LinkTokens() []LinkToken {
	out := make([]LinkToken, 0, len(s.m.LinkTokens))
	for _, v := range s.m.LinkTokens {
		out = append(out, v.clone())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// LinkTrust returns the trust anchor of a non-root relay (zero when none).
func (s Snapshot) LinkTrust() LinkTrust { return s.m.LinkTrust }

// SchemaVersion is the schema_version of the file the snapshot was loaded from or last written as.
func (s Snapshot) SchemaVersion() int {
	if s.m.schema == 0 {
		return SchemaVersion
	}
	return s.m.schema
}
