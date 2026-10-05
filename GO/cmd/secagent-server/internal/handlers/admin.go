package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"secagent-server/cmd/secagent-server/internal/hooks"
	"secagent-server/cmd/secagent-server/internal/storage"
	"secagent-server/cmd/secagent-server/internal/ws"
)

// adminStore is the shared store injected at server startup.
var adminStore *storage.Store

// serverStartTime records when the server started (for uptime reporting).
var serverStartTime = time.Now()

// SetAdminStore injects the storage.Store instance used by admin handlers.
// Must be called once at server startup before serving requests.
func SetAdminStore(s *storage.Store) {
	adminStore = s
}

// requireAdminAuth checks for a valid Bearer ADMIN_TOKEN header.
// Returns false and writes 401 if auth fails.
func requireAdminAuth(w http.ResponseWriter, r *http.Request) bool {
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing_authorization"})
		return false
	}

	token := authHeader[7:]
	if token != server.AdminToken {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_admin_token"})
		return false
	}
	return true
}

// writeJSON writes an HTTP JSON response.
func writeJSON(w http.ResponseWriter, code int, body interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		log.Printf("writeJSON encode error: %v", err)
	}
}

// ========================================================================
// GET /api/admin/minions
// ========================================================================

// MinionSummary is the list view of an agent (no large fields).
type MinionSummary struct {
	Hostname   string `json:"hostname"`
	Status     string `json:"status"`
	LastSeen   string `json:"last_seen"`
	Suspended  bool   `json:"suspended"`
	EnrolledAt string `json:"enrolled_at"`
}

// AdminListMinions returns all enrolled agents with summary fields.
// GET /api/admin/minions
func AdminListMinions(w http.ResponseWriter, r *http.Request) {
	if !requireAdminAuth(w, r) {
		return
	}

	if adminStore == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "store_not_initialized"})
		return
	}

	agents, err := adminStore.ListAgents(context.Background(), false)
	if err != nil {
		log.Printf("AdminListMinions: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_error"})
		return
	}

	// Build a set of currently connected hostnames from the live WS registry
	connectedSet := make(map[string]bool)
	for _, h := range ws.GetConnectedHostnames() {
		connectedSet[h] = true
	}

	result := make([]MinionSummary, 0, len(agents))
	for _, a := range agents {
		status := a.Status
		if connectedSet[a.Hostname] {
			status = "connected"
		}
		result = append(result, MinionSummary{
			Hostname:   a.Hostname,
			Status:     status,
			LastSeen:   a.LastSeen.UTC().Format(time.RFC3339),
			Suspended:  a.Suspended,
			EnrolledAt: a.EnrolledAt.UTC().Format(time.RFC3339),
		})
	}

	writeJSON(w, http.StatusOK, result)
}

// ========================================================================
// GET /api/admin/minions/{hostname}
// ========================================================================

// MinionDetail is the full detail view of an agent.
type MinionDetail struct {
	Hostname       string                 `json:"hostname"`
	Status         string                 `json:"status"`
	LastSeen       string                 `json:"last_seen"`
	Suspended      bool                   `json:"suspended"`
	EnrolledAt     string                 `json:"enrolled_at"`
	KeyFingerprint string                 `json:"key_fingerprint"`
	Vars           map[string]interface{} `json:"vars"`
}

// AdminGetMinion returns full detail for one agent.
// GET /api/admin/minions/{hostname}
func AdminGetMinion(w http.ResponseWriter, r *http.Request) {
	if !requireAdminAuth(w, r) {
		return
	}

	hostname := r.PathValue("hostname")
	if hostname == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing_hostname"})
		return
	}

	if adminStore == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "store_not_initialized"})
		return
	}

	agent, err := adminStore.GetAgent(context.Background(), hostname)
	if err != nil {
		log.Printf("AdminGetMinion: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_error"})
		return
	}
	if agent == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "agent_not_found"})
		return
	}

	// Parse vars JSON
	var vars map[string]interface{}
	if err := json.Unmarshal([]byte(agent.Vars), &vars); err != nil {
		vars = make(map[string]interface{})
	}

	detail := MinionDetail{
		Hostname:       agent.Hostname,
		Status:         agent.Status,
		LastSeen:       agent.LastSeen.UTC().Format(time.RFC3339),
		Suspended:      agent.Suspended,
		EnrolledAt:     agent.EnrolledAt.UTC().Format(time.RFC3339),
		KeyFingerprint: publicKeyFingerprint(agent.PublicKeyPEM),
		Vars:           vars,
	}

	writeJSON(w, http.StatusOK, detail)
}

// publicKeyFingerprint returns a short human-readable fingerprint of the PEM key
// (first 16 chars of the base64 body, enough to identify).
func publicKeyFingerprint(pem string) string {
	lines := strings.Split(pem, "\n")
	for _, l := range lines {
		if l != "" && !strings.HasPrefix(l, "-----") {
			if len(l) > 16 {
				return l[:16] + "..."
			}
			return l
		}
	}
	return ""
}

// ========================================================================
// POST /api/admin/minions/{hostname}/suspend
// POST /api/admin/minions/{hostname}/resume
// ========================================================================

// AdminSuspendMinion sets suspended=true for an agent.
// POST /api/admin/minions/{hostname}/suspend
func AdminSuspendMinion(w http.ResponseWriter, r *http.Request) {
	if !requireAdminAuth(w, r) {
		return
	}

	hostname := r.PathValue("hostname")
	if hostname == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing_hostname"})
		return
	}

	if adminStore == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "store_not_initialized"})
		return
	}

	found, err := adminStore.SetSuspended(context.Background(), hostname, true)
	if err != nil {
		log.Printf("AdminSuspendMinion: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_error"})
		return
	}
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "agent_not_found"})
		return
	}

	log.Printf("Minion suspended: hostname=%s", hostname)
	writeJSON(w, http.StatusOK, map[string]string{"hostname": hostname, "status": "suspended"})
}

// AdminResumeMinion clears the suspended flag for an agent.
// POST /api/admin/minions/{hostname}/resume
func AdminResumeMinion(w http.ResponseWriter, r *http.Request) {
	if !requireAdminAuth(w, r) {
		return
	}

	hostname := r.PathValue("hostname")
	if hostname == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing_hostname"})
		return
	}

	if adminStore == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "store_not_initialized"})
		return
	}

	found, err := adminStore.SetSuspended(context.Background(), hostname, false)
	if err != nil {
		log.Printf("AdminResumeMinion: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_error"})
		return
	}
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "agent_not_found"})
		return
	}

	log.Printf("Minion resumed: hostname=%s", hostname)
	writeJSON(w, http.StatusOK, map[string]string{"hostname": hostname, "status": "active"})
}

// ========================================================================
// POST /api/admin/minions/{hostname}/set-state
// ========================================================================

// SetStateRequest is the body for set-state.
type SetStateRequest struct {
	Status string `json:"status"` // "connected" or "disconnected"
}

// AdminSetMinionState forces the DB status without touching the WS connection.
// POST /api/admin/minions/{hostname}/set-state
func AdminSetMinionState(w http.ResponseWriter, r *http.Request) {
	if !requireAdminAuth(w, r) {
		return
	}

	hostname := r.PathValue("hostname")
	if hostname == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing_hostname"})
		return
	}

	var req SetStateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json"})
		return
	}

	if req.Status != "connected" && req.Status != "disconnected" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_status"})
		return
	}

	if adminStore == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "store_not_initialized"})
		return
	}

	if err := adminStore.UpdateAgentStatus(context.Background(), hostname, req.Status, ""); err != nil {
		log.Printf("AdminSetMinionState: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_error"})
		return
	}

	log.Printf("Minion state forced: hostname=%s status=%s", hostname, req.Status)
	writeJSON(w, http.StatusOK, map[string]string{"hostname": hostname, "status": req.Status})
}

// ========================================================================
// GET /api/admin/minions/{hostname}/vars
// POST /api/admin/minions/{hostname}/vars
// DELETE /api/admin/minions/{hostname}/vars/{key}
// ========================================================================

// AdminGetMinionVars returns the Ansible vars for an agent.
// GET /api/admin/minions/{hostname}/vars
func AdminGetMinionVars(w http.ResponseWriter, r *http.Request) {
	if !requireAdminAuth(w, r) {
		return
	}

	hostname := r.PathValue("hostname")
	if hostname == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing_hostname"})
		return
	}

	if adminStore == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "store_not_initialized"})
		return
	}

	varsJSON, err := adminStore.GetAgentVars(context.Background(), hostname)
	if err != nil {
		log.Printf("AdminGetMinionVars: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_error"})
		return
	}
	if varsJSON == "" {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "agent_not_found"})
		return
	}

	var vars map[string]interface{}
	if err := json.Unmarshal([]byte(varsJSON), &vars); err != nil {
		vars = make(map[string]interface{})
	}

	writeJSON(w, http.StatusOK, vars)
}

// AdminSetMinionVars adds or updates vars for an agent.
// Body: { "key": "value", ... }
// POST /api/admin/minions/{hostname}/vars
func AdminSetMinionVars(w http.ResponseWriter, r *http.Request) {
	if !requireAdminAuth(w, r) {
		return
	}

	hostname := r.PathValue("hostname")
	if hostname == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing_hostname"})
		return
	}

	var kvPairs map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&kvPairs); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json"})
		return
	}

	if adminStore == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "store_not_initialized"})
		return
	}

	for key, value := range kvPairs {
		if err := adminStore.SetAgentVar(context.Background(), hostname, key, value); err != nil {
			if err.Error() == "agent_not_found" {
				writeJSON(w, http.StatusNotFound, map[string]string{"error": "agent_not_found"})
				return
			}
			log.Printf("AdminSetMinionVars: %v", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_error"})
			return
		}
	}

	log.Printf("Minion vars updated: hostname=%s keys=%d", hostname, len(kvPairs))
	writeJSON(w, http.StatusOK, map[string]string{"hostname": hostname, "status": "updated"})
}

// AdminDeleteMinionVar removes a single var key from an agent.
// DELETE /api/admin/minions/{hostname}/vars/{key}
func AdminDeleteMinionVar(w http.ResponseWriter, r *http.Request) {
	if !requireAdminAuth(w, r) {
		return
	}

	hostname := r.PathValue("hostname")
	key := r.PathValue("key")
	if hostname == "" || key == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing_params"})
		return
	}

	if adminStore == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "store_not_initialized"})
		return
	}

	deleted, err := adminStore.DeleteAgentVar(context.Background(), hostname, key)
	if err != nil {
		if err.Error() == "agent_not_found" {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "agent_not_found"})
			return
		}
		log.Printf("AdminDeleteMinionVar: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_error"})
		return
	}

	if !deleted {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "key_not_found"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"hostname": hostname, "key": key, "status": "deleted"})
}

// ========================================================================
// POST /api/admin/revoke/{hostname}
// ========================================================================

// AdminRevokeMinion blacklists the agent's JTI and closes WS with code 4001.
// POST /api/admin/revoke/{hostname}
func AdminRevokeMinion(w http.ResponseWriter, r *http.Request) {
	if !requireAdminAuth(w, r) {
		return
	}

	hostname := r.PathValue("hostname")
	if hostname == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing_hostname"})
		return
	}

	if adminStore == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "store_not_initialized"})
		return
	}

	ctx := context.Background()

	// Fetch agent to get current JTI
	agent, err := adminStore.GetAgent(ctx, hostname)
	if err != nil {
		log.Printf("AdminRevokeMinion GetAgent: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_error"})
		return
	}
	if agent == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "agent_not_found"})
		return
	}

	// Blacklist current JTI (expires in 25 hours — beyond any normal JWT TTL)
	if agent.TokenJTI != "" {
		expiresAt := time.Now().Add(25 * time.Hour).UTC().Format(time.RFC3339)
		reason := "admin_revoke"
		if err := adminStore.AddToBlacklist(ctx, agent.TokenJTI, hostname, expiresAt, &reason); err != nil {
			log.Printf("AdminRevokeMinion blacklist: %v", err)
			// Continue anyway — close WS regardless
		}
	}

	// Close WS with 4001
	wsDisconnected := ws.CloseAgent(hostname, ws.WSCloseRevoked, "token_revoked")

	// Mark agent as disconnected in DB
	_ = adminStore.UpdateAgentStatus(ctx, hostname, "disconnected", "")

	// Dispatch host.revoked event (async, nil-safe during tests)
	if hooks.GlobalDispatcher != nil {
		hooks.GlobalDispatcher.Dispatch("host.revoked", hostname, "revoked", "")
	}

	log.Printf("Minion revoked: hostname=%s ws_disconnected=%v", hostname, wsDisconnected)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"hostname":        hostname,
		"status":          "revoked",
		"ws_disconnected": wsDisconnected,
	})
}

// ========================================================================
// GET /api/admin/status
// GET /api/admin/stats
// ========================================================================

var (
	linkStatusMu sync.RWMutex
	linkStatusFn func() interface{}
)

// SetLinkStatusFunc wires the parent / push-child link status exposed by GET /api/admin/status (#154).
func SetLinkStatusFunc(fn func() interface{}) {
	linkStatusMu.Lock()
	linkStatusFn = fn
	linkStatusMu.Unlock()
}

// AdminStatus returns server health: db, ws_connections, uptime.
// GET /api/admin/status
func AdminStatus(w http.ResponseWriter, r *http.Request) {
	if !requireAdminAuth(w, r) {
		return
	}

	dbStatus := "ok"
	if adminStore == nil {
		dbStatus = "uninitialized"
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if _, err := adminStore.ListAgents(ctx, false); err != nil {
			dbStatus = "error"
		}
	}

	uptimeSec := int(time.Since(serverStartTime).Seconds())

	body := map[string]interface{}{
		"db":             dbStatus,
		"ws_connections": ws.GetConnectedCount(),
		"uptime":         fmt.Sprintf("%ds", uptimeSec),
	}
	linkStatusMu.RLock()
	links := linkStatusFn
	linkStatusMu.RUnlock()
	if links != nil {
		body["links"] = links()
	}
	writeJSON(w, http.StatusOK, body)
}

// AdminStats returns operational stats: agents_connected, agents_total, tasks_active.
// GET /api/admin/stats
func AdminStats(w http.ResponseWriter, r *http.Request) {
	if !requireAdminAuth(w, r) {
		return
	}

	agentsConnected := ws.GetConnectedCount()

	agentsTotal := 0
	if adminStore != nil {
		agents, err := adminStore.ListAgents(context.Background(), false)
		if err == nil {
			agentsTotal = len(agents)
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"agents_connected": agentsConnected,
		"agents_total":     agentsTotal,
		"tasks_active":     ws.GetPendingTaskCount(),
	})
}

// ========================================================================
// DELETE /api/admin/minions/{hostname}
// ========================================================================

// AdminDeleteMinion permanently removes an agent from the DB.
// Closes the WS connection (code 4000) if active, then dispatches host.deleted.
// Distinct from POST /api/admin/revoke/{hostname} which blacklists but does not delete.
func AdminDeleteMinion(w http.ResponseWriter, r *http.Request) {
	if !requireAdminAuth(w, r) {
		return
	}

	hostname := r.PathValue("hostname")
	if hostname == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing_hostname"})
		return
	}
	if adminStore == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "store_not_initialized"})
		return
	}

	ctx := r.Context()

	// Verify agent exists
	agent, err := adminStore.GetAgent(ctx, hostname)
	if err != nil {
		log.Printf("AdminDeleteMinion GetAgent: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_error"})
		return
	}
	if agent == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "agent_not_found"})
		return
	}

	// Close active WS connection with code 4000 (normal close)
	wsDisconnected := ws.CloseAgent(hostname, ws.WSCloseNormal, "admin_delete")

	// Delete from DB (agents + authorized_keys best-effort)
	deleted, err := adminStore.DeleteAgent(ctx, hostname)
	if err != nil {
		log.Printf("AdminDeleteMinion DeleteAgent: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_error"})
		return
	}
	if !deleted {
		// Race: another request deleted it between GetAgent and DeleteAgent
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "agent_not_found"})
		return
	}

	// Dispatch host.deleted event (async, nil-safe during tests)
	if hooks.GlobalDispatcher != nil {
		hooks.GlobalDispatcher.Dispatch("host.deleted", hostname, "deleted", "")
	}

	log.Printf("Minion deleted: hostname=%s ws_disconnected=%v", hostname, wsDisconnected)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"hostname":        hostname,
		"status":          "deleted",
		"ws_disconnected": wsDisconnected,
	})
}

// ========================================================================
// GET /api/admin/hooks/log
// ========================================================================

// AdminHooksLog returns action_log entries with optional filters.
// Query params: limit (1–200, default 50), event, hostname.
func AdminHooksLog(w http.ResponseWriter, r *http.Request) {
	if !requireAdminAuth(w, r) {
		return
	}
	if adminStore == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "store_not_initialized"})
		return
	}

	limit := 50
	if lStr := r.URL.Query().Get("limit"); lStr != "" {
		n, err := strconv.Atoi(lStr)
		if err != nil || n < 1 || n > 200 {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{
				"error":  "invalid_limit",
				"detail": "must be between 1 and 200",
			})
			return
		}
		limit = n
	}

	filter := storage.ActionLogFilter{
		Event:    r.URL.Query().Get("event"),
		Hostname: r.URL.Query().Get("hostname"),
		Limit:    limit,
	}

	entries, err := adminStore.ListActionLogs(r.Context(), filter)
	if err != nil {
		log.Printf("AdminHooksLog: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_error"})
		return
	}

	type logEntry struct {
		ID             string `json:"id"`
		Event          string `json:"event"`
		Hostname       string `json:"hostname"`
		ActionType     string `json:"action_type"`
		ActionIndex    int    `json:"action_index"`
		ConfigSnapshot string `json:"config_snapshot"`
		Success        bool   `json:"success"`
		Error          string `json:"error"`
		DurationMs     int64  `json:"duration_ms"`
		ExecutedAt     string `json:"executed_at"`
	}

	result := make([]logEntry, 0, len(entries))
	for _, e := range entries {
		result = append(result, logEntry{
			ID:             e.ID,
			Event:          e.Event,
			Hostname:       e.Hostname,
			ActionType:     e.ActionType,
			ActionIndex:    e.ActionIndex,
			ConfigSnapshot: e.ConfigSnapshot,
			Success:        e.Success,
			Error:          e.Error,
			DurationMs:     e.DurationMs,
			ExecutedAt:     e.ExecutedAt.UTC().Format(time.RFC3339),
		})
	}
	writeJSON(w, http.StatusOK, result)
}
