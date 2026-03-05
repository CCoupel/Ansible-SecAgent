package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
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
	RelayStatus       string `json:"relay_status"`
	RelayLastSeen     string `json:"relay_last_seen"`
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
//         "relay_status": "connected",
//         "relay_last_seen": "2026-03-03T10:00:00Z"
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

// GetInventory returns all enrolled agents in Ansible JSON inventory format
// Query parameter: only_connected (bool) - filter to connected agents only
// HTTP 200 - returns Ansible-compatible inventory JSON
func GetInventory(w http.ResponseWriter, r *http.Request) {
	// Parse query parameter
	onlyConnected := false
	if connStr := r.URL.Query().Get("only_connected"); connStr != "" {
		if val, err := strconv.ParseBool(connStr); err == nil {
			onlyConnected = val
		}
	}

	// TODO: Query agents from database (from storage/store.go)
	// store := request.app.state.store
	// agents, err := store.ListAgents(onlyConnected)
	// For now, use mock data
	agents := []map[string]interface{}{
		{
			"hostname":   "agent-1",
			"status":     "connected",
			"last_seen":  "2026-03-05T12:00:00Z",
			"public_key": "-----BEGIN PUBLIC KEY-----\n...",
		},
		{
			"hostname":  "agent-2",
			"status":    "disconnected",
			"last_seen": "2026-03-05T11:30:00Z",
		},
	}

	// Filter if needed
	if onlyConnected {
		filtered := []map[string]interface{}{}
		for _, agent := range agents {
			if status, ok := agent["status"].(string); ok && status == "connected" {
				filtered = append(filtered, agent)
			}
		}
		agents = filtered
	}

	// Build inventory response
	var response InventoryResponse
	response.All.Hosts = make([]string, 0)
	response.Meta.Hostvars = make(map[string]HostVars)

	for _, agent := range agents {
		hostname := agent["hostname"].(string)
		status := "disconnected"
		if s, ok := agent["status"].(string); ok {
			status = s
		}
		lastSeen := ""
		if ls, ok := agent["last_seen"].(string); ok {
			lastSeen = ls
		}

		// Add to hosts list
		response.All.Hosts = append(response.All.Hosts, hostname)

		// Add host variables
		response.Meta.Hostvars[hostname] = HostVars{
			AnsibleConnection: "relay",
			AnsibleHost:       hostname,
			RelayStatus:       status,
			RelayLastSeen:     lastSeen,
		}
	}

	log.Printf("Inventory requested: only_connected=%v count=%d",
		onlyConnected, len(response.All.Hosts))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}
