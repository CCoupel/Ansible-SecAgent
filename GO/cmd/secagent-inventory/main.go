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
//	RELAY_INSECURE_TLS    "true" pour désactiver la vérification TLS (TESTS UNIQUEMENT) :
//	                      avertissement sur stderr à chaque exécution ; refusé si l'URL n'est pas
//	                      une adresse de bouclage, sauf RELAY_INSECURE_TLS_ACK=i-understand-the-risk
//	RELAY_INSECURE_TLS_ACK  confirmation explicite pour désactiver TLS vers un serveur non-bouclage
//	RELAY_ONLY_CONNECTED  "true" pour filtrer hôtes connectés uniquement (défaut: false)
//	RELAY_SCOPE           id d'un relay : limite l'inventaire à sa descendance (optionnel)
//
// Format de sortie :
//
//	--list : {"all": {"hosts": [...], "children": [...]}, "<relay>": {"hosts": [...], "children": [...]}, "_meta": {"hostvars": {...}}}
//	--host : {"ansible_connection": "relay", "ansible_host": "...", ...}
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	neturl "net/url"
	"os"
	"strings"
	"time"
)

// InventoryResponse est le format retourné par GET /api/inventory.
// Depuis #128 l'inventaire est hiérarchique : un groupe par relay (nom exact du relay) en plus de
// "all" et "_meta", avec les relays enfants comme groupes enfants.
type InventoryResponse struct {
	All struct {
		Hosts    []string `json:"hosts"`
		Children []string `json:"children,omitempty"`
	} `json:"all"`
	Meta struct {
		Hostvars map[string]json.RawMessage `json:"hostvars"`
	} `json:"_meta"`
	// Groups contient les groupes de relays (clés de premier niveau autres que all / _meta).
	Groups map[string]AnsibleGroup `json:"-"`
}

// UnmarshalJSON lit "all", "_meta" et toute autre clé comme groupe de relay.
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
			var g AnsibleGroup
			if err := json.Unmarshal(v, &g); err != nil {
				return err
			}
			if r.Groups == nil {
				r.Groups = make(map[string]AnsibleGroup)
			}
			r.Groups[k] = g
		}
	}
	return nil
}

// AnsibleInventory est le format de sortie pour --list
type AnsibleInventory struct {
	All    AnsibleGroup            `json:"all"`
	Meta   AnsibleMeta             `json:"_meta"`
	Groups map[string]AnsibleGroup `json:"-"`
}

// MarshalJSON aplatit les groupes de relays à côté de "all" et "_meta".
func (a AnsibleInventory) MarshalJSON() ([]byte, error) {
	doc := map[string]any{"_meta": a.Meta, "all": a.All}
	for name, g := range a.Groups {
		doc[name] = g
	}
	return json.Marshal(doc)
}

// UnmarshalJSON est l'inverse de MarshalJSON.
func (a *AnsibleInventory) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*a = AnsibleInventory{}
	for k, v := range raw {
		switch k {
		case "all":
			if err := json.Unmarshal(v, &a.All); err != nil {
				return err
			}
		case "_meta":
			if err := json.Unmarshal(v, &a.Meta); err != nil {
				return err
			}
		default:
			var g AnsibleGroup
			if err := json.Unmarshal(v, &g); err != nil {
				return err
			}
			if a.Groups == nil {
				a.Groups = make(map[string]AnsibleGroup)
			}
			a.Groups[k] = g
		}
	}
	return nil
}

// AnsibleGroup représente un groupe Ansible avec ses hôtes et ses groupes enfants
type AnsibleGroup struct {
	Hosts    []string `json:"hosts"`
	Children []string `json:"children,omitempty"`
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
	insecureAck   string // RELAY_INSECURE_TLS_ACK : doit valoir insecureAckValue pour un serveur non-bouclage
	onlyConnected bool
	scopeRelay    string // optional: only the subtree of this relay (RELAY_SCOPE)
}

func main() {
	args := os.Args[1:]

	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "Usage: secagent-inventory --list | --host <hostname>\n")
		os.Exit(1)
	}

	cfg := loadConfig()

	// Garde TLS : avant toute requête, pour --list comme pour --host (qui masque les erreurs réseau).
	if err := checkInsecureTLS(cfg, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

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

// insecureAckValue est la valeur exigée dans RELAY_INSECURE_TLS_ACK pour désactiver la vérification
// TLS vers un serveur qui n'est pas en bouclage.
const insecureAckValue = "i-understand-the-risk"

// isLoopbackURL indique si l'URL pointe vers localhost, 127.0.0.0/8 ou ::1.
func isLoopbackURL(raw string) bool {
	u, err := neturl.Parse(raw)
	if err != nil {
		return false
	}
	host := u.Hostname()
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// checkInsecureTLS applique la garde de RELAY_INSECURE_TLS. Sans RELAY_INSECURE_TLS elle ne fait rien.
// Sinon : refus si l'URL n'est pas en bouclage et que l'ACK explicite manque ; avertissement sur w
// (stderr — stdout reste du JSON pur) dans les autres cas. Le token n'est jamais écrit.
func checkInsecureTLS(cfg config, w io.Writer) error {
	if !cfg.insecure {
		return nil
	}
	if !isLoopbackURL(cfg.serverURL) && cfg.insecureAck != insecureAckValue {
		return fmt.Errorf("RELAY_INSECURE_TLS=true refused: server URL %q is not a loopback address "+
			"(localhost, 127.0.0.0/8, ::1); set RELAY_INSECURE_TLS_ACK=%s to confirm", cfg.serverURL, insecureAckValue)
	}
	_, err := fmt.Fprintf(w, "[SECURITY WARNING] TLS verification disabled (RELAY_INSECURE_TLS=true) for %s\n", cfg.serverURL)
	return err
}

// cmdList implémente --list : GET /api/inventory → JSON Ansible complet
func cmdList(cfg config) error {
	inv, err := fetchInventory(cfg)
	if err != nil {
		return err
	}

	out := AnsibleInventory{
		All: AnsibleGroup{
			Hosts:    inv.All.Hosts,
			Children: inv.All.Children,
		},
		Meta: AnsibleMeta{
			Hostvars: inv.Meta.Hostvars,
		},
		Groups: inv.Groups,
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
	if cfg.scopeRelay != "" {
		url += "&relay=" + neturl.QueryEscape(cfg.scopeRelay)
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
	defer closeBody(resp.Body)

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

// closeBody ferme body et journalise toute erreur sur stderr.
// Utilisé en defer pour satisfaire errcheck tout en respectant le contrat Ansible :
// stdout = JSON uniquement, les diagnostics vont sur stderr.
func closeBody(body io.Closer) {
	if err := body.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "warning: close response body: %v\n", err)
	}
}

// loadConfig charge la configuration depuis les variables d'environnement
func loadConfig() config {
	return config{
		serverURL:     getenv("RELAY_SERVER_URL", "https://localhost:7770"),
		token:         getenv("RELAY_TOKEN", ""),
		caBundle:      getenv("RELAY_CA_BUNDLE", ""),
		insecure:      getenv("RELAY_INSECURE_TLS", "") == "true",
		insecureAck:   getenv("RELAY_INSECURE_TLS_ACK", ""),
		onlyConnected: getenv("RELAY_ONLY_CONNECTED", "") == "true",
		scopeRelay:    getenv("RELAY_SCOPE", ""),
	}
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
