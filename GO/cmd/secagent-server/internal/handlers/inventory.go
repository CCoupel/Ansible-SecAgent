package handlers

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"time"

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
}

// InventoryResponse represents the Ansible dynamic inventory format
// Format matches ARCHITECTURE.md §6 and §14 exactly:
// {
//   "all": { "hosts": ["host-A", "host-B"] },
//   "_meta": {
//     "hostvars": {
//       "host-A": {
//         "ansible_connection": "relay",
//         "ansible_host": "host-A",
//         "secagent_status": "connected",
//         "secagent_last_seen": "2026-03-03T10:00:00Z"
//       }
//     }
//   }
// }
type InventoryResponse struct {
	All struct {
		Hosts []string `json:"hosts"`
	} `json:"all"`
	Meta struct {
		Hostvars map[string]HostVars `json:"hostvars"`
	} `json:"_meta"`
}

// buildInventoryResponse constructs an InventoryResponse from the live WS registry + DB agents.
// Default (onlyConnected=false): return ALL agents with status
// If onlyConnected=true: return only connected agents
func buildInventoryResponse(onlyConnected bool) InventoryResponse {
	connectedHosts := ws.GetConnectedHostnames()
	connectedSet := make(map[string]bool)
	for _, h := range connectedHosts {
		connectedSet[h] = true
	}
	now := time.Now().UTC().Format(time.RFC3339)

	var response InventoryResponse
	response.All.Hosts = make([]string, 0)
	response.Meta.Hostvars = make(map[string]HostVars)

	// Query all enrolled agents from DB
	if adminStore == nil {
		return response // fallback: return empty if no store
	}

	agents, err := adminStore.ListAgents(context.Background(), false)
	if err != nil {
		log.Printf("buildInventoryResponse: ListAgents error: %v", err)
		return response
	}
	for _, agent := range agents {
		isConnected := connectedSet[agent.Hostname]

		// If onlyConnected=true, skip disconnected agents
		if onlyConnected && !isConnected {
			continue
		}

		response.All.Hosts = append(response.All.Hosts, agent.Hostname)
		status := "disconnected"
		if isConnected {
			status = "connected"
		}
		response.Meta.Hostvars[agent.Hostname] = HostVars{
			AnsibleConnection: "relay",
			AnsibleHost:       agent.Hostname,
			RelayStatus:       status,
			RelayLastSeen:     now,
		}
	}
	return response
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

// GetInventory returns all enrolled agents in Ansible JSON inventory format.
// Authenticated by plugin token (port 7770 — used by Ansible connection plugin).
// Query parameter: only_connected (bool) - filter to connected agents only.
func GetInventory(w http.ResponseWriter, r *http.Request) {
	// Plugin token authentication (SECURITY.md §6)
	if _, ok := requirePluginAuth(w, r); !ok {
		return
	}
	onlyConnected := parseOnlyConnected(r)
	response := buildInventoryResponse(onlyConnected)
	log.Printf("Inventory requested: only_connected=%v count=%d", onlyConnected, len(response.All.Hosts))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// AdminGetInventory returns the same inventory but authenticated by admin token.
// Used by the CLI `inventory list` command via port 7771 (admin port).
func AdminGetInventory(w http.ResponseWriter, r *http.Request) {
	if !requireAdminAuth(w, r) {
		return
	}
	onlyConnected := parseOnlyConnected(r)
	response := buildInventoryResponse(onlyConnected)
	log.Printf("Admin inventory requested: only_connected=%v count=%d", onlyConnected, len(response.All.Hosts))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}
