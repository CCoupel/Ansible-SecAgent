package handlers

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"sync"
	"time"

	"secagent-server/cmd/secagent-server/internal/config"
	"secagent-server/cmd/secagent-server/internal/ws"
)

// Agent represents a registered agent in the system
type Agent struct {
	Hostname  string `json:"hostname"`
	Status    string `json:"status"`
	LastSeen  string `json:"last_seen"`
	PublicKey string `json:"public_key_pem"`
}

// HostVars represents variables for a single host in Ansible inventory
type HostVars struct {
	AnsibleConnection string `json:"ansible_connection"`
	AnsibleHost       string `json:"ansible_host"`
	RelayStatus       string `json:"secagent_status"`
	RelayLastSeen     string `json:"secagent_last_seen"`
	// Suspended is true for a suspended agent (listed, but every exec/upload/fetch is refused, #173).
	Suspended bool   `json:"secagent_suspended,omitempty"`
	RelayID   string `json:"secagent_relay_id,omitempty"` // relay the host is attached to (declaring relay)
	// RelayChain is the path from the host up to this node, ORIGIN FIRST: [relay closest to the
	// host, ..., direct child of this node]. [] for a host connected to this node itself (#128).
	RelayChain []string `json:"secagent_relay_chain"`
	// NextHop is the direct child relay a task is sent to; omitted for a directly connected host.
	NextHop string `json:"secagent_next_hop,omitempty"`
}

// InventoryGroup is a relay group: the hosts attached to that relay and its child relays.
type InventoryGroup struct {
	Hosts    []string `json:"hosts,omitempty"`
	Children []string `json:"children,omitempty"`
	// Vars are the Ansible group variables published by the relay (RELAY_GROUP_VARS, #139);
	// absent when the relay has none. Values keep their JSON types.
	Vars map[string]json.RawMessage `json:"vars,omitempty"`
}

var (
	localGroupVarsMu sync.RWMutex
	localGroupVars   map[string]any
)

// SetLocalGroupVars sets this node's own group vars (RELAY_GROUP_VARS), served as the vars of its
// own relay group when it has a REPEATER_ID.
func SetLocalGroupVars(m map[string]any) {
	localGroupVarsMu.Lock()
	localGroupVars = m
	localGroupVarsMu.Unlock()
}

// relayGroupVars returns the group vars to publish for each relay group: those stored from the
// relays' hello / snapshot / relay.updated, plus this node's own. Stored content was validated
// on reception and is re-checked here: anything that does not validate is not served.
func relayGroupVars(localID string) map[string]map[string]json.RawMessage {
	out := map[string]map[string]json.RawMessage{}
	stored, err := adminStore.ListRelayGroupVars()
	if err != nil {
		log.Printf("inventory: group vars unavailable: %v", err)
	}
	for id, raw := range stored {
		var generic map[string]any
		if json.Unmarshal([]byte(raw), &generic) != nil || config.ValidateGroupVars(generic) != nil {
			log.Printf("[WARN] inventory: ignoring invalid stored group vars of relay %q", id)
			continue
		}
		var typed map[string]json.RawMessage
		if json.Unmarshal([]byte(raw), &typed) == nil && len(typed) > 0 {
			out[id] = typed
		}
	}
	localGroupVarsMu.RLock()
	local := localGroupVars
	localGroupVarsMu.RUnlock()
	if localID != "" && len(local) > 0 && config.ValidateGroupVars(local) == nil {
		if b, err := json.Marshal(local); err == nil {
			var typed map[string]json.RawMessage
			if json.Unmarshal(b, &typed) == nil {
				out[localID] = typed
			}
		}
	}
	return out
}

// InventoryResponse is the Ansible dynamic inventory format, hierarchical since #128:
// one group per relay (named EXACTLY like the relay, no prefix), child relays as child groups,
// and `all.hosts` still listing every host (flat view kept for existing consumers).
//
//	{
//	  "_meta": {"hostvars": {"minion-A": {"ansible_connection": "relay", "secagent_relay_chain": ["dmz1","zone2"], "secagent_next_hop": "zone2", ...}}},
//	  "all":   {"hosts": ["minion-A", ...], "children": ["zone2"]},
//	  "zone2": {"children": ["dmz1"]},
//	  "dmz1":  {"hosts": ["minion-A"]}
//	}
type InventoryResponse struct {
	All struct {
		Hosts    []string `json:"hosts"`
		Children []string `json:"children,omitempty"`
	} `json:"all"`
	Meta struct {
		Hostvars map[string]HostVars `json:"hostvars"`
	} `json:"_meta"`
	// Groups holds the relay groups; they are flattened at the top level of the JSON document.
	Groups map[string]InventoryGroup `json:"-"`
}

// MarshalJSON flattens Groups next to "all" and "_meta".
func (r InventoryResponse) MarshalJSON() ([]byte, error) {
	doc := map[string]interface{}{"_meta": r.Meta, "all": r.All}
	for name, g := range r.Groups {
		doc[name] = g
	}
	return json.Marshal(doc)
}

// UnmarshalJSON reads "all", "_meta" and every other top-level key as a relay group.
func (r *InventoryResponse) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*r = InventoryResponse{}
	for k, v := range raw {
		switch k {
		case "all":
			if err := json.Unmarshal(v, &r.All); err != nil {
				return err
			}
		case "_meta":
			if err := json.Unmarshal(v, &r.Meta); err != nil {
				return err
			}
		default:
			var g InventoryGroup
			if err := json.Unmarshal(v, &g); err != nil {
				return err
			}
			if r.Groups == nil {
				r.Groups = make(map[string]InventoryGroup)
			}
			r.Groups[k] = g
		}
	}
	return nil
}

// relayGroupName pattern: group names are the exact relay ids; ids that would clobber the
// reserved Ansible groups are never turned into groups.
func reservedGroup(name string) bool { return name == "all" || name == "ungrouped" || name == "_meta" }

// inventoryOptions selects what buildInventory returns.
type inventoryOptions struct {
	OnlyConnected bool
	Relay         string // optional: only the subtree of this relay (hosts attached at or below it)
}

// buildInventory builds the hierarchical inventory of this node: its own agents plus the whole
// descendant tree (relay_routing), grouped by relay.
func buildInventory(opts inventoryOptions) InventoryResponse {
	connectedSet := make(map[string]bool)
	for _, h := range ws.GetConnectedHostnames() {
		connectedSet[h] = true
	}
	now := time.Now().UTC().Format(time.RFC3339)

	var response InventoryResponse
	response.All.Hosts = make([]string, 0)
	response.Meta.Hostvars = make(map[string]HostVars)
	response.Groups = make(map[string]InventoryGroup)

	// Query all enrolled agents from DB
	if adminStore == nil {
		return response // fallback: return empty if no store
	}

	agents, err := adminStore.ListAgents(context.Background(), false)
	if err != nil {
		log.Printf("buildInventoryResponse: ListAgents error: %v", err)
		return response
	}

	// ── group graph (relay id → hosts / child relays), root = "all" or this node's own group ──
	g := newGroupGraph()
	localID, localConfigured := ws.ConfiguredRelayID()
	localGroup := ""
	if localConfigured && !reservedGroup(localID) {
		localGroup = localID
		g.ensure(localGroup)
	}
	root := "all"
	if localGroup != "" {
		root = localGroup
		g.addChild("all", localGroup)
	}

	seenHosts := make(map[string]bool, len(agents))
	var directHosts []string
	for _, agent := range agents {
		isConnected := connectedSet[agent.Hostname]
		if opts.OnlyConnected && !isConnected {
			continue
		}
		seenHosts[agent.Hostname] = true
		status := "disconnected"
		if isConnected {
			status = "connected"
		}
		response.All.Hosts = append(response.All.Hosts, agent.Hostname)
		directHosts = append(directHosts, agent.Hostname)
		response.Meta.Hostvars[agent.Hostname] = HostVars{
			AnsibleConnection: "relay",
			AnsibleHost:       agent.Hostname,
			RelayStatus:       status,
			RelayLastSeen:     now,
			Suspended:         agent.Suspended,
			RelayChain:        []string{},
		}
	}
	if localGroup != "" {
		for _, h := range directHosts {
			g.addHost(localGroup, h)
		}
	}

	// Descendants: every route of relay_routing. Local agents take precedence (already seen).
	if proxyRouter != nil {
		nodes, nErr := adminStore.ListValidRelayNodes()
		routes, rErr := adminStore.ListRelayRoutes()
		if nErr != nil || rErr != nil {
			log.Printf("buildInventory: relay routes unavailable: nodes=%v routes=%v", nErr, rErr)
		} else {
			status := make(map[string]string, len(nodes))
			lastSeen := make(map[string]int64, len(nodes))
			for _, n := range nodes {
				status[n.RelayID] = n.Status
				if n.LastSeen != nil {
					lastSeen[n.RelayID] = *n.LastSeen
				}
				if ws.IsRelayConnected(n.RelayID) {
					status[n.RelayID] = "connected" // live link overrides the stored status
				}
			}
			for _, rt := range routes {
				if seenHosts[rt.Hostname] {
					continue // local agent takes precedence
				}
				topDown := rt.RelayChain
				if len(topDown) == 0 {
					topDown = []string{rt.RelayID} // legacy row: attached to its declaring relay
				}
				nextHop := topDown[0]
				st := status[nextHop]
				if st == "" {
					st = "disconnected"
				}
				if opts.OnlyConnected && st != "connected" {
					continue
				}
				if opts.Relay != "" && !containsID(topDown, opts.Relay) {
					continue
				}
				seenHosts[rt.Hostname] = true
				response.All.Hosts = append(response.All.Hosts, rt.Hostname)
				seen := now
				if ls := lastSeen[nextHop]; ls > 0 {
					seen = time.Unix(ls, 0).UTC().Format(time.RFC3339)
				}
				response.Meta.Hostvars[rt.Hostname] = HostVars{
					AnsibleConnection: "relay",
					AnsibleHost:       rt.Hostname,
					RelayStatus:       st,
					RelayLastSeen:     seen,
					RelayID:           rt.RelayID,
					RelayChain:        reversed(topDown),
					NextHop:           nextHop,
					Suspended:         rt.Suspended, // reported by the relay holding the agent: informative only (#180)
				}
				// groups: the top-level relay hangs under the root, each next relay under the previous one
				parent := root
				for _, id := range topDown {
					if reservedGroup(id) {
						continue
					}
					g.addChild(parent, id)
					parent = id
				}
				if !reservedGroup(rt.RelayID) {
					g.addHost(rt.RelayID, rt.Hostname)
				}
			}
		}
	}

	// Scoping: keep only the subtree of the requested relay.
	if opts.Relay != "" {
		keep := g.reachable(opts.Relay)
		hostKept := make(map[string]bool)
		for id := range keep {
			for _, h := range g.hosts[id] {
				hostKept[h] = true
			}
		}
		var hosts []string
		for _, h := range response.All.Hosts {
			if hostKept[h] {
				hosts = append(hosts, h)
			} else {
				delete(response.Meta.Hostvars, h)
			}
		}
		response.All.Hosts = append(make([]string, 0, len(hosts)), hosts...)
		if len(keep) == 0 {
			return response
		}
		g.restrictTo(keep)
		g.children["all"] = []string{opts.Relay}
	}

	response.All.Children = g.children["all"]
	vars := relayGroupVars(localGroup)
	for id := range g.names {
		if id == "all" {
			continue
		}
		response.Groups[id] = InventoryGroup{Hosts: g.hosts[id], Children: g.children[id], Vars: vars[id]}
	}
	return response
}

func containsID(list []string, id string) bool {
	for _, v := range list {
		if v == id {
			return true
		}
	}
	return false
}

func reversed(in []string) []string {
	out := make([]string, len(in))
	for i, v := range in {
		out[len(in)-1-i] = v
	}
	return out
}

// groupGraph is the relay group tree. Edges that would create a cycle (inconsistent stale
// routes) are dropped so that the inventory is always a valid Ansible inventory.
type groupGraph struct {
	names    map[string]bool
	hosts    map[string][]string
	children map[string][]string
}

func newGroupGraph() *groupGraph {
	return &groupGraph{names: map[string]bool{"all": true}, hosts: map[string][]string{}, children: map[string][]string{}}
}

func (g *groupGraph) ensure(name string) { g.names[name] = true }

func (g *groupGraph) addHost(group, host string) {
	g.ensure(group)
	if !containsID(g.hosts[group], host) {
		g.hosts[group] = append(g.hosts[group], host)
	}
}

// reaches reports whether "to" is reachable from "from" through child edges.
func (g *groupGraph) reaches(from, to string) bool {
	if from == to {
		return true
	}
	seen := map[string]bool{from: true}
	stack := []string{from}
	for len(stack) > 0 {
		cur := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for _, c := range g.children[cur] {
			if c == to {
				return true
			}
			if !seen[c] {
				seen[c] = true
				stack = append(stack, c)
			}
		}
	}
	return false
}

func (g *groupGraph) addChild(parent, child string) {
	g.ensure(parent)
	g.ensure(child)
	if containsID(g.children[parent], child) {
		return
	}
	if g.reaches(child, parent) { // would close a cycle
		log.Printf("[WARN] inventory: ignoring group edge %q -> %q (cycle in stale routing data)", parent, child)
		return
	}
	g.children[parent] = append(g.children[parent], child)
}

// reachable returns the group "start" and every group below it ("" set when start is unknown).
func (g *groupGraph) reachable(start string) map[string]bool {
	if !g.names[start] || start == "all" {
		return nil
	}
	out := map[string]bool{start: true}
	stack := []string{start}
	for len(stack) > 0 {
		cur := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for _, c := range g.children[cur] {
			if !out[c] {
				out[c] = true
				stack = append(stack, c)
			}
		}
	}
	return out
}

func (g *groupGraph) restrictTo(keep map[string]bool) {
	for id := range g.names {
		if id != "all" && !keep[id] {
			delete(g.names, id)
			delete(g.hosts, id)
			delete(g.children, id)
		}
	}
	for id, kids := range g.children {
		var kept []string
		for _, c := range kids {
			if keep[c] {
				kept = append(kept, c)
			}
		}
		g.children[id] = kept
	}
}

// parseOnlyConnected reads the only_connected query parameter (default false).
func parseOnlyConnected(r *http.Request) bool {
	if connStr := r.URL.Query().Get("only_connected"); connStr != "" {
		if val, err := strconv.ParseBool(connStr); err == nil {
			return val
		}
	}
	return false
}

// relayParamPattern validates the optional `relay` scoping parameter (a relay id).
var relayParamPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$`)

// parseInventoryOptions reads only_connected and the optional relay scope; a malformed relay is a 400.
func parseInventoryOptions(w http.ResponseWriter, r *http.Request) (inventoryOptions, bool) {
	opts := inventoryOptions{OnlyConnected: parseOnlyConnected(r)}
	if rel := r.URL.Query().Get("relay"); rel != "" {
		if !relayParamPattern.MatchString(rel) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_relay"})
			return opts, false
		}
		opts.Relay = rel
	}
	return opts, true
}

// GetInventory returns all enrolled agents in Ansible JSON inventory format.
// Authenticated by plugin token (port 7770 — used by Ansible connection plugin).
// Query parameter: only_connected (bool) - filter to connected agents only.
func GetInventory(w http.ResponseWriter, r *http.Request) {
	// Plugin token authentication (SECURITY.md §6)
	if _, ok := requirePluginAuth(w, r); !ok {
		return
	}
	opts, ok := parseInventoryOptions(w, r)
	if !ok {
		return
	}
	response := buildInventory(opts)
	log.Printf("Inventory requested: only_connected=%v relay=%q count=%d", opts.OnlyConnected, opts.Relay, len(response.All.Hosts))
	writeJSON(w, http.StatusOK, response)
}

// AdminGetInventory returns the same inventory but authenticated by admin token.
// Used by the CLI `inventory list` command via port 7771 (admin port).
func AdminGetInventory(w http.ResponseWriter, r *http.Request) {
	if !requireAdminAuth(w, r) {
		return
	}
	opts, ok := parseInventoryOptions(w, r)
	if !ok {
		return
	}
	response := buildInventory(opts)
	log.Printf("Admin inventory requested: only_connected=%v relay=%q count=%d", opts.OnlyConnected, opts.Relay, len(response.All.Hosts))
	writeJSON(w, http.StatusOK, response)
}
