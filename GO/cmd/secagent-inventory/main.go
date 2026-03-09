// secagent-inventory — Binaire d'inventaire dynamique Ansible pour Ansible-SecAgent.
//
// Usage (Ansible external inventory script protocol) :
//
//	secagent-inventory --list             Retourne tous les hôtes connectés au format JSON Ansible
//	secagent-inventory --host <hostname>  Retourne les hostvars d'un hôte spécifique
//
// Configuration (variables d'environnement) :
//
//	RELAY_SERVER_URL      URL HTTPS du relay server   (défaut: https://localhost:7770)
//	RELAY_TOKEN           Bearer token (ADMIN_TOKEN)  (optionnel)
//	RELAY_CA_BUNDLE       CA bundle PEM custom         (optionnel)
//	RELAY_INSECURE_TLS    "true" pour désactiver TLS  (TESTS UNIQUEMENT)
//	RELAY_ONLY_CONNECTED  "true" pour filtrer hôtes connectés uniquement (défaut: false)
//
// Format de sortie :
//
//	--list : {"all": {"hosts": [...]}, "_meta": {"hostvars": {...}}}
//	--host : {"ansible_connection": "relay", "ansible_host": "...", ...}
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// InventoryResponse est le format retourné par GET /api/inventory
type InventoryResponse struct {
	All struct {
		Hosts []string `json:"hosts"`
	} `json:"all"`
	Meta struct {
		Hostvars map[string]json.RawMessage `json:"hostvars"`
	} `json:"_meta"`
}

// AnsibleInventory est le format de sortie pour --list
type AnsibleInventory struct {
	All  AnsibleGroup                  `json:"all"`
	Meta AnsibleMeta                   `json:"_meta"`
}

// AnsibleGroup représente un groupe Ansible avec ses hôtes
type AnsibleGroup struct {
	Hosts []string `json:"hosts"`
}

// AnsibleMeta contient les hostvars de tous les hôtes
type AnsibleMeta struct {
	Hostvars map[string]json.RawMessage `json:"hostvars"`
}

// config regroupe la configuration du binaire
type config struct {
	serverURL     string
	token         string
	caBundle      string
	insecure      bool
	onlyConnected bool
}

func main() {
	args := os.Args[1:]

	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "Usage: secagent-inventory --list | --host <hostname>\n")
		os.Exit(1)
	}

	cfg := loadConfig()

	switch args[0] {
	case "--list":
		if err := cmdList(cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

	case "--host":
		if len(args) < 2 {
			fmt.Fprintf(os.Stderr, "Usage: secagent-inventory --host <hostname>\n")
			os.Exit(1)
		}
		if err := cmdHost(cfg, args[1]); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

	default:
		fmt.Fprintf(os.Stderr, "Unknown flag: %s\nUsage: secagent-inventory --list | --host <hostname>\n", args[0])
		os.Exit(1)
	}
}

// cmdList implémente --list : GET /api/inventory → JSON Ansible complet
func cmdList(cfg config) error {
	inv, err := fetchInventory(cfg)
	if err != nil {
		return err
	}

	out := AnsibleInventory{
		All: AnsibleGroup{
			Hosts: inv.All.Hosts,
		},
		Meta: AnsibleMeta{
			Hostvars: inv.Meta.Hostvars,
		},
	}

	if out.All.Hosts == nil {
		out.All.Hosts = []string{}
	}
	if out.Meta.Hostvars == nil {
		out.Meta.Hostvars = map[string]json.RawMessage{}
	}

	return printJSON(out)
}

// cmdHost implémente --host <hostname> : retourne les hostvars d'un hôte
func cmdHost(cfg config, hostname string) error {
	inv, err := fetchInventory(cfg)
	if err != nil {
		// En cas d'erreur réseau, retourner {} (comportement Ansible attendu)
		fmt.Println("{}")
		return nil
	}

	if vars, ok := inv.Meta.Hostvars[hostname]; ok {
		return printJSON(vars)
	}

	// Hôte inconnu → retourner {} (comportement Ansible standard)
	fmt.Println("{}")
	return nil
}

// fetchInventory appelle GET /api/inventory et retourne la réponse parsée
func fetchInventory(cfg config) (*InventoryResponse, error) {
	client, err := newHTTPClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("HTTP client: %w", err)
	}

	url := cfg.serverURL + "/api/inventory"
	// Always pass only_connected parameter explicitly
	if cfg.onlyConnected {
		url += "?only_connected=true"
	} else {
		url += "?only_connected=false"
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}

	if cfg.token != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.token)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("server returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var inv InventoryResponse
	if err := json.NewDecoder(resp.Body).Decode(&inv); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	return &inv, nil
}

// newHTTPClient crée un client HTTP avec la configuration TLS appropriée
func newHTTPClient(cfg config) (*http.Client, error) {
	tlsCfg := &tls.Config{} //nolint:gosec

	if cfg.insecure {
		tlsCfg.InsecureSkipVerify = true //nolint:gosec
	} else if cfg.caBundle != "" {
		pem, err := os.ReadFile(cfg.caBundle)
		if err != nil {
			return nil, fmt.Errorf("read CA bundle %s: %w", cfg.caBundle, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no valid certs in CA bundle %s", cfg.caBundle)
		}
		tlsCfg.RootCAs = pool
	}

	transport := &http.Transport{
		TLSClientConfig: tlsCfg,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}, nil
}

// printJSON sérialise v en JSON indenté sur stdout
func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// loadConfig charge la configuration depuis les variables d'environnement
func loadConfig() config {
	return config{
		serverURL:     getenv("RELAY_SERVER_URL", "https://localhost:7770"),
		token:         getenv("RELAY_TOKEN", ""),
		caBundle:      getenv("RELAY_CA_BUNDLE", ""),
		insecure:      getenv("RELAY_INSECURE_TLS", "") == "true",
		onlyConnected: getenv("RELAY_ONLY_CONNECTED", "") == "true",
	}
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
