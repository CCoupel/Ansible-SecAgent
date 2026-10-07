// secagent-inventory — Binaire d'inventaire dynamique Ansible pour Ansible-SecAgent.
//
// Usage (Ansible external inventory script protocol) :
//
//	secagent-inventory --list             Retourne tous les hôtes connectés au format JSON Ansible
//	secagent-inventory --host <hostname>  Retourne les hostvars d'un hôte spécifique
//
// Configuration (variables d'environnement) :
//
//	RELAY_SERVER_URL      URL HTTPS du relay server, ou LISTE d'URL séparées par des virgules
//	                      (relay actif/passif, #167) — défaut: https://localhost:7770
//	RELAY_TOKEN           Bearer token (ADMIN_TOKEN)  (optionnel)
//	RELAY_CA_BUNDLE       CA bundle PEM custom         (optionnel)
//	RELAY_INSECURE_TLS    "true" pour désactiver la vérification TLS (TESTS UNIQUEMENT) :
//	                      avertissement sur stderr à chaque exécution ; refusé si l'URL n'est pas
//	                      une adresse de bouclage, sauf RELAY_INSECURE_TLS_ACK=i-understand-the-risk
//	RELAY_INSECURE_TLS_ACK  confirmation explicite pour désactiver TLS vers un serveur non-bouclage
//	RELAY_INVENTORY_VERBOSE "1" pour afficher sur stderr le détail des adresses en échec (diagnostic)
//	RELAY_ONLY_CONNECTED  "true" pour filtrer hôtes connectés uniquement (défaut: false)
//	RELAY_SCOPE           id d'un relay : limite l'inventaire à sa descendance (optionnel)
//
// Format de sortie :
//
//	--list : {"all": {"hosts": [...], "children": [...]}, "<relay>": {"hosts": [...], "children": [...]}, "_meta": {"hostvars": {...}}}
//	--host : {"ansible_connection": "relay", "ansible_host": "...", ...}
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	neturl "net/url"
	"os"
	"strings"
	"time"

	"secagent-server/internal/endpoints"
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

// normalizeGroup garantit qu'aucun champ du groupe n'est sérialisé en null : Ansible rejette tout
// l'inventaire sur un `"hosts": null` (groupe sans hôte direct : racine d'arbre, relay intermédiaire).
// hosts est toujours un tableau ; children et vars sont omis quand ils sont vides.
func normalizeGroup(g AnsibleGroup) AnsibleGroup {
	if g.Hosts == nil {
		g.Hosts = []string{}
	}
	if len(g.Children) == 0 {
		g.Children = nil
	}
	if len(g.Vars) == 0 {
		g.Vars = nil
	}
	return g
}

// MarshalJSON aplatit les groupes de relays à côté de "all" et "_meta", en normalisant tous les groupes
// (y compris ceux repassés tels quels depuis le serveur) et _meta.hostvars (objet, jamais null).
func (a AnsibleInventory) MarshalJSON() ([]byte, error) {
	meta := a.Meta
	hv := make(map[string]json.RawMessage, len(meta.Hostvars))
	for h, v := range meta.Hostvars {
		if len(v) == 0 || string(v) == "null" {
			v = json.RawMessage("{}")
		}
		hv[h] = v
	}
	meta.Hostvars = hv
	doc := map[string]any{"_meta": meta, "all": normalizeGroup(a.All)}
	for name, g := range a.Groups {
		doc[name] = normalizeGroup(g)
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
	// Vars sont les group vars Ansible publiées par le relay (#139) ; absentes sans RELAY_GROUP_VARS.
	// Les valeurs gardent leur type JSON.
	Vars map[string]json.RawMessage `json:"vars,omitempty"`
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
	configureLogging(os.Stderr, getenv("RELAY_INVENTORY_VERBOSE", "") == "1")

	// Garde TLS : avant toute requête, pour --list comme pour --host (qui masque les erreurs réseau).
	if err := checkInsecureTLS(cfg, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	warnPlainHTTP(cfg, os.Stderr)

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

// checkInsecureTLS applique la garde de RELAY_INSECURE_TLS à CHAQUE adresse de RELAY_SERVER_URL.
// Sans RELAY_INSECURE_TLS elle ne fait rien. Sinon : refus si une adresse n'est pas en bouclage et
// que l'ACK explicite manque ; avertissement sur w (stderr — stdout reste du JSON pur) dans les
// autres cas. Le token n'est jamais écrit.
func checkInsecureTLS(cfg config, w io.Writer) error {
	if !cfg.insecure {
		return nil
	}
	urls, err := endpoints.Parse(cfg.serverURL)
	if err != nil {
		return fmt.Errorf("RELAY_SERVER_URL: %w", err)
	}
	shown := make([]string, 0, len(urls))
	for _, u := range urls {
		if !isLoopbackURL(u.String()) && cfg.insecureAck != insecureAckValue {
			return fmt.Errorf("RELAY_INSECURE_TLS=true refused: server URL %q is not a loopback address "+
				"(localhost, 127.0.0.0/8, ::1); set RELAY_INSECURE_TLS_ACK=%s to confirm", u.String(), insecureAckValue)
		}
		shown = append(shown, u.String())
	}
	_, err = fmt.Fprintf(w, "[SECURITY WARNING] TLS verification disabled (RELAY_INSECURE_TLS=true) for %s\n", strings.Join(shown, ","))
	return err
}

// warnPlainHTTP warns (on w = stderr, stdout stays pure JSON) for every address that uses http://
// towards a host that is not a loopback address: the bearer token would travel in clear. It never
// refuses and never writes the token.
func warnPlainHTTP(cfg config, w io.Writer) {
	urls, err := endpoints.Parse(cfg.serverURL)
	if err != nil {
		return
	}
	for i, u := range urls {
		if strings.EqualFold(u.Scheme, "http") && !isLoopbackURL(u.String()) {
			_, _ = fmt.Fprintf(w, "[SECURITY WARNING] address #%d (%s) uses http://: the token is sent in clear, https is required outside localhost\n", i+1, u.Host)
		}
	}
}

// configureLogging keeps the failed-attempt diagnostics of internal/endpoints (slog warnings that
// Ansible would show as errors while the inventory succeeds) out of stderr, unless
// RELAY_INVENTORY_VERBOSE=1. When EVERY address fails the final error carries the detail anyway.
func configureLogging(w io.Writer, verbose bool) {
	if verbose {
		slog.SetDefault(slog.New(slog.NewTextHandler(w, nil)))
		return
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
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

// Délais (#167) : le timeout de 10 s du client HTTP vaut PAR ADRESSE ; fetchTotalTimeout plafonne
// l'ensemble des essais (une liste de 16 adresses muettes ne bloque pas Ansible plus de 30 s).
const maxInventoryBytes = 256 << 20

// variables only so that the tests can shorten them.
var (
	perAddressTimeout = 10 * time.Second
	fetchTotalTimeout = 30 * time.Second
)

// inventoryReply is what one address answered: any HTTP status except 503.
type inventoryReply struct {
	status int
	body   []byte
}

// fetchInventory appelle GET /api/inventory sur les adresses de RELAY_SERVER_URL (dans l'ordre de
// la liste : process éphémère, rien n'est mémorisé) et retourne la réponse parsée.
//
// La requête est un GET idempotent : on passe à l'adresse suivante sur un échec de connexion, un
// timeout, une coupure en cours de réponse ou un 503 (instance en cours d'arrêt / passive). Tout
// autre statut (401, 403, 404, 500…) est renvoyé tel quel : c'est une réponse du serveur, pas un
// problème de disponibilité, et aucune autre adresse n'est essayée.
//
// Contrat endpoints.MarkSent : DialFirst classe un échec « avant envoi » tant qu'aucun octet de
// requête n'est parti. Ici tout passe par net/http, suivi automatiquement (httptrace) : rien à
// marquer. TOUT FUTUR DIAL BRUT (connexion TCP, upgrade WebSocket…) DEVRA appeler
// endpoints.MarkSent(ctx) juste avant sa première écriture.
func fetchInventory(cfg config) (*InventoryResponse, error) {
	urls, err := endpoints.Parse(cfg.serverURL)
	if err != nil {
		return nil, fmt.Errorf("RELAY_SERVER_URL: %w", err)
	}
	client, err := newHTTPClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("HTTP client: %w", err)
	}

	query := "?only_connected=false"
	if cfg.onlyConnected {
		query = "?only_connected=true"
	}
	if cfg.scopeRelay != "" {
		query += "&relay=" + neturl.QueryEscape(cfg.scopeRelay)
	}

	ctx, cancel := context.WithTimeout(context.Background(), fetchTotalTimeout)
	defer cancel()

	var tried []string
	for i, u := range urls {
		reply, err := fetchFromAddress(ctx, client, u, query, cfg.token)
		if err == nil {
			if reply.status >= 300 && reply.status < 400 {
				// the Location (target URL) is deliberately not echoed
				return nil, fmt.Errorf("server returned %d: redirection refused (never followed, the token is sent to the configured addresses only)", reply.status)
			}
			if reply.status != http.StatusOK {
				return nil, fmt.Errorf("server returned %d: %s", reply.status, strings.TrimSpace(string(reply.body)))
			}
			var inv InventoryResponse
			if err := json.Unmarshal(reply.body, &inv); err != nil {
				return nil, fmt.Errorf("decode response: %w", err)
			}
			return &inv, nil
		}
		// the reason never carries the token nor the query string (redacted by endpoints / see below)
		tried = append(tried, fmt.Sprintf("#%d %s: %s", i+1, u.Host, err))
		if ctx.Err() != nil {
			break
		}
	}
	untried := ""
	if n := len(urls) - len(tried); n > 0 {
		untried = fmt.Sprintf(", %d not tried (time budget)", n)
	}
	return nil, fmt.Errorf("relay unreachable, %d address(es) tried%s: %s", len(tried), untried, strings.Join(tried, "; "))
}

// fetchFromAddress asks ONE address through endpoints.DialFirst (per-address timeout, failure
// classification). A failure after the request left (timeout, reset) is also an "unavailable"
// answer here because the GET is idempotent: the caller moves on to the next address.
func fetchFromAddress(ctx context.Context, client *http.Client, u *neturl.URL, query, token string) (*inventoryReply, error) {
	rotor, err := endpoints.NewRotor([]*neturl.URL{u}, endpoints.Backoff{})
	if err != nil {
		return nil, err
	}
	var cause error // the dial error itself (DialFirst wraps it with a position that would be misleading here)
	reply, _, err := endpoints.DialFirst(ctx, rotor, perAddressTimeout,
		func(actx context.Context, au *neturl.URL) (r *inventoryReply, derr error) {
			defer func() { cause = derr }()
			target := strings.TrimRight(au.String(), "/") + "/api/inventory" + query
			req, err := http.NewRequestWithContext(actx, http.MethodGet, target, nil)
			if err != nil {
				return nil, fmt.Errorf("build request: %w", err)
			}
			if token != "" {
				req.Header.Set("Authorization", "Bearer "+token)
			}
			req.Header.Set("Accept", "application/json")
			resp, err := client.Do(req)
			if err != nil {
				return nil, unwrapURLError(err)
			}
			defer closeBody(resp.Body)
			if resp.StatusCode == http.StatusServiceUnavailable {
				return nil, endpoints.MarkBeforeSend(errors.New("HTTP 503 (instance unavailable)"))
			}
			body, err := io.ReadAll(io.LimitReader(resp.Body, maxInventoryBytes))
			if err != nil {
				return nil, fmt.Errorf("read response: %w", err)
			}
			return &inventoryReply{status: resp.StatusCode, body: body}, nil
		})
	if err != nil {
		if cause != nil {
			return nil, cause
		}
		return nil, err
	}
	return reply, nil
}

// unwrapURLError drops the URL (query string included) that net/http embeds in its errors.
func unwrapURLError(err error) error {
	var ue *neturl.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
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
		// NO redirection is ever followed: the bearer token must only reach the configured
		// addresses, never a host named by a Location header. A 3xx is reported as an error.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
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
