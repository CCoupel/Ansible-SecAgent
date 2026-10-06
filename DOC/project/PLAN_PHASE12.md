# Plan d'implémentation — Phase 12 : Proxy/Gateway Multi-Zone

> **ARCHIVE HISTORIQUE** — plan d'une phase passée, conservé pour mémoire ; ne reflète plus l'architecture v3.0.3 (état fichier, TLS natif, actif/passif, plus de NATS/SQLite/Caddy). Références vivantes : `DOC/common/ARCHITECTURE.md`, `DOC/server/STATE_SPEC.md`.

> Architecte : planner  
> Date : 2026-05-22  
> Issue GitHub : #99  
> Référence specs : `DOC/common/HLD.md`, `DOC/common/ARCHITECTURE.md`, `DOC/server/SERVER_SPEC.md`  
> Code existant : `GO/cmd/secagent-server/`, `GO/cmd/secagent-minion/`

---

## 1. Contexte et objectif

### Topologie cible

```
[Ansible Control Node]
        │
[Plugin connexion/inventaire]  — REST HTTPS
        │
[PROXY / GATEWAY]         ← port 7770/7772 (même binaire, mode=proxy)
   /            \
[Relay DMZ1]   [Relay DMZ2]   ← mode pull : WS /ws/relay
     │                │          mode push : REST /api/exec
[Agents A,B]   [Agents C,D]
```

### Principe de conception

1. **Même binaire** : `secagent-server` activé en mode proxy via `PROXY_MODE=true` (env) ou flag `--proxy`.
2. **Mode hybride** : un proxy peut aussi avoir des agents directement connectés (via `/ws/agent`) — pas de restriction.
3. **Mode pull** : les relays initient la connexion vers le proxy (`WSS /ws/relay`) — symétrique au modèle agent→relay.
4. **Mode push** : le proxy initie des connexions HTTP REST vers des relays configurés en DB.
5. **Inventaire unifié** : le proxy agrège les inventaires de tous ses relays → GET /api/inventory transparent.
6. **Routage de tâches** : POST /api/exec/{hostname} sur le proxy → lookup hostname→relay → forward.
7. **Chaînage** : un relay peut lui-même être un proxy (flag `is_proxy: true` dans le handshake).
8. **Auth mutuelle** : nouveau rôle JWT `relay` (en plus de `agent`, `plugin`, `admin`).

### Composants impactés

| Composant | Impact |
|---|---|
| `GO/cmd/secagent-server/` | Extension principale — nouveau mode proxy |
| `GO/cmd/secagent-server/internal/ws/` | Nouveau handler `/ws/relay` |
| `GO/cmd/secagent-server/internal/proxy/` | **Nouveau package** — client push, router, registry |
| `GO/cmd/secagent-server/internal/storage/` | Nouvelles tables `relay_nodes` + `relay_routing` |
| `GO/cmd/secagent-server/internal/auth/` | Nouveau rôle `relay` dans Sign/Verify |
| `GO/cmd/secagent-server/internal/handlers/` | Modification exec/inventory/admin |
| `GO/cmd/secagent-server/internal/cli/` | Nouvelles commandes `relays` |
| `DEPLOYMENT/qualif/` | Docker Compose multi-zones |
| `DOC/` | HLD, ARCHITECTURE, CHANGELOG |

### Composants NON impactés

- `GO/cmd/secagent-minion/` — les agents se connectent aux relays (pas au proxy)
- `PYTHON/` — les plugins utilisent le même endpoint GET /api/inventory transparent
- `GO/cmd/secagent-inventory/` — utilise GET /api/inventory, transparent

---

## 2. Contrats API (contract-first)

### 2.1 Nouveau endpoint WS — Mode pull

```
WSS /ws/relay
Authorization: Bearer <JWT rôle "relay">
Port : 7772 (et 7770 pour compat)
```

**Messages Relay → Proxy :**

```json
// Handshake initial
{ "type": "relay_hello", "relay_id": "dmz1", "version": "1.0", "is_proxy": false }

// Mise à jour inventaire (envoyé à la connexion puis sur changement)
{ "type": "inventory_update",
  "agents": [
    { "hostname": "host-A", "status": "connected", "last_seen": "2026-05-22T15:00:00Z" },
    { "hostname": "host-B", "status": "disconnected", "last_seen": "2026-05-22T14:00:00Z" }
  ]
}

// Ack d'une tâche dispatchée
{ "type": "task_ack", "task_id": "uuid", "status": "running" }

// Stdout streaming
{ "type": "task_stdout", "task_id": "uuid", "data": "output line\n" }

// Résultat final d'une tâche exec
{ "type": "task_result", "task_id": "uuid", "rc": 0, "stdout": "...", "stderr": "", "truncated": false }

// Résultat d'un upload
{ "type": "upload_result", "task_id": "uuid", "rc": 0 }

// Résultat d'un fetch
{ "type": "fetch_result", "task_id": "uuid", "rc": 0, "data": "<base64>" }
```

**Messages Proxy → Relay :**

```json
// Dispatch d'une tâche exec
{ "type": "task_dispatch", "task_id": "uuid", "hostname": "host-A",
  "cmd": "python3 /tmp/module.py", "stdin": null, "timeout": 30, "become": false, "become_method": "sudo" }

// Dispatch d'un upload
{ "type": "file_upload", "task_id": "uuid", "hostname": "host-A",
  "dest": "/tmp/module.py", "data": "<base64>", "mode": "0700" }

// Dispatch d'un fetch
{ "type": "file_fetch", "task_id": "uuid", "hostname": "host-A", "src": "/etc/config.yml" }

// Annulation
{ "type": "task_cancel", "task_id": "uuid", "hostname": "host-A" }
```

### 2.2 Nouveaux endpoints REST Admin (port 7771)

```
# Enregistrer un relay en mode push
POST /api/admin/relays
{ "relay_id": "dmz1", "url": "https://dmz1.example.com:7770",
  "description": "Zone DMZ1 Production", "token": "secagent_relay_..." }
→ 201 { "id": "uuid", "relay_id": "dmz1", "mode": "push", "status": "pending" }

# Lister les relays configurés
GET /api/admin/relays
→ 200 { "relays": [ { "id": "...", "relay_id": "dmz1", "mode": "push|pull",
                       "connected": true, "agent_count": 5, "last_seen": "..." } ] }

# Supprimer un relay configuré
DELETE /api/admin/relays/{id}
→ 204

# Statut temps réel des relays connectés
GET /api/admin/relays/status
→ 200 { "relays": [ { "relay_id": "dmz1", "mode": "pull", "connected": true,
                       "agent_count": 5, "is_proxy": false, "last_seen": "..." } ] }
```

### 2.3 Endpoint GET /api/inventory (modifié sur proxy)

Comportement unchanged pour les clients (plugins). En interne, le proxy agrège :

```json
{
  "all": { "hosts": ["host-A", "host-B", "host-C", "host-D"] },
  "_meta": {
    "hostvars": {
      "host-A": {
        "ansible_connection": "relay",
        "ansible_host": "host-A",
        "secagent_status": "connected",
        "secagent_last_seen": "...",
        "secagent_relay_id": "dmz1"   ← NEW: relay source
      }
    }
  }
}
```

### 2.4 Nouvelles tables SQLite

```sql
-- Relays configurés (mode push) ou enregistrés (mode pull)
CREATE TABLE IF NOT EXISTS relay_nodes (
    id          TEXT PRIMARY KEY,       -- UUID interne
    relay_id    TEXT NOT NULL UNIQUE,   -- ex: "dmz1"
    url         TEXT,                   -- URL relay (mode push uniquement)
    description TEXT,
    token_hash  TEXT,                   -- hash du token d'auth (mode push)
    mode        TEXT NOT NULL DEFAULT 'pull',  -- 'push' | 'pull'
    is_proxy    INTEGER NOT NULL DEFAULT 0,    -- 1 si le relay est lui-même un proxy
    created_at  INTEGER NOT NULL,
    last_seen   INTEGER,
    status      TEXT NOT NULL DEFAULT 'disconnected'
);

-- Table de routage hostname → relay_id (mise à jour par inventory_update)
CREATE TABLE IF NOT EXISTS relay_routing (
    hostname    TEXT PRIMARY KEY,
    relay_id    TEXT NOT NULL,
    updated_at  INTEGER NOT NULL,
    FOREIGN KEY (relay_id) REFERENCES relay_nodes(relay_id)
);
```

### 2.5 Nouveau rôle JWT `relay`

```json
{
  "sub": "dmz1",
  "role": "relay",
  "jti": "uuid",
  "iat": 1234567890,
  "exp": 1234567890
}
```

Permissions:
- `open_relay_ws` : ouvrir `/ws/relay`
- `read_inventory` : GET /api/inventory (pour le chaînage push → le proxy lit l'inventaire du relay)

---

## 3. Sous-tâches détaillées

### 12.1 — Configuration du mode proxy

**Agent :** `dev-relay`  
**Dépendances :** aucune (tâche initiale)  
**Durée estimée :** 0.5j  

**Description :**  
Ajouter la détection du mode proxy dans `main.go` et la configuration associée.

**Fichiers à créer/modifier :**
- `GO/cmd/secagent-server/internal/config/proxy.go` — **CRÉER** struct `ProxyConfig`
- `GO/cmd/secagent-server/main.go` — lire `PROXY_MODE`, passer config au router

**Comportement attendu :**
- `PROXY_MODE=true` (ou `--proxy`) → le serveur démarre en mode proxy
- En mode proxy, log `[PROXY] Mode proxy activé` au démarrage
- `ProxyConfig` contient : `Enabled bool`, `PushRelays []RelayEndpoint` (chargé depuis env `PROXY_RELAYS` ou fichier config)
- En l'absence de `PROXY_MODE`, comportement identique à aujourd'hui (mode relay normal)

**Critères d'acceptation :**
- [ ] `PROXY_MODE=true go run main.go` démarre sans erreur
- [ ] `PROXY_MODE=false go run main.go` est identique à l'état actuel (aucune régression)
- [ ] `ProxyConfig` est injecté dans les handlers et le WS handler
- [ ] Tests unitaires `config/proxy_test.go` : parsing env vars

---

### 12.2 — Storage : tables relay_nodes et relay_routing

**Agent :** `dev-relay`  
**Dépendances :** 12.1  
**Durée estimée :** 0.5j  

**Description :**  
Ajouter les nouvelles tables à la DDL SQLite et les méthodes CRUD associées.

**Fichiers à créer/modifier :**
- `GO/cmd/secagent-server/internal/storage/store.go` — ajouter DDL `relay_nodes` + `relay_routing`
- `GO/cmd/secagent-server/internal/storage/store_relay.go` — **CRÉER** méthodes CRUD
- `GO/cmd/secagent-server/internal/storage/store_relay_test.go` — **CRÉER** tests

**Méthodes à implémenter (`store_relay.go`) :**
```go
func (s *Store) UpsertRelayNode(node RelayNode) error
func (s *Store) GetRelayNode(relayID string) (*RelayNode, error)
func (s *Store) ListRelayNodes() ([]RelayNode, error)
func (s *Store) DeleteRelayNode(id string) error
func (s *Store) UpdateRelayStatus(relayID, status string, lastSeen int64) error
func (s *Store) UpsertRelayRouting(hostname, relayID string) error
func (s *Store) GetRelayForHostname(hostname string) (string, error)  // returns relay_id
func (s *Store) BulkUpsertRelayRouting(relayID string, hostnames []string) error
func (s *Store) DeleteRelayRoutingByRelay(relayID string) error
```

**Critères d'acceptation :**
- [ ] Migration DDL idempotente (IF NOT EXISTS)
- [ ] Tous les tests CRUD passent
- [ ] `BulkUpsertRelayRouting` fonctionne avec 100+ hostnames sans erreur

---

### 12.3 — Auth : rôle JWT `relay`

**Agent :** `dev-relay`  
**Dépendances :** 12.1  
**Durée estimée :** 0.5j  

**Description :**  
Étendre le système JWT pour supporter le rôle `relay`. Créer les endpoints admin de gestion des relay tokens.

**Fichiers à créer/modifier :**
- `GO/cmd/secagent-server/internal/auth/jwt.go` — ajouter `SignRelay(relayID string)`
- `GO/cmd/secagent-server/internal/handlers/admin_relays.go` — **CRÉER** endpoints CRUD relays
- `GO/cmd/secagent-server/main.go` — router les nouveaux endpoints admin (port 7771)

**Comportement :**
- `SignRelay(relayID)` produit un JWT avec `role: "relay"`, `sub: relayID`
- `Verify(token)` retourne le rôle dans les claims — le WS handler `/ws/relay` vérifie `role == "relay"`
- Les tokens relay sont générés via `POST /api/admin/tokens` avec `"role": "relay"` (réutilise le système plugin_tokens)

**Critères d'acceptation :**
- [ ] `SignRelay("dmz1")` produit un JWT valide avec `role: relay`
- [ ] Un JWT `role: agent` ne peut pas ouvrir `/ws/relay`
- [ ] Un JWT `role: relay` ne peut pas ouvrir `/ws/agent`
- [ ] Tests unitaires dans `auth/jwt_test.go`

---

### 12.4 — WS /ws/relay — Mode pull (relay → proxy)

**Agent :** `dev-relay`  
**Dépendances :** 12.2, 12.3  
**Durée estimée :** 2j  

**Description :**  
Nouveau handler WebSocket sur le proxy que les relays utilisent pour se connecter (mode pull). Symétrique au `/ws/agent` mais pour des relays.

**Fichiers à créer/modifier :**
- `GO/cmd/secagent-server/internal/ws/relay_handler.go` — **CRÉER** `RelayHandler`
- `GO/cmd/secagent-server/internal/ws/relay_handler_test.go` — **CRÉER**
- `GO/cmd/secagent-server/main.go` — router `/ws/relay` si PROXY_MODE=true

**Comportement attendu :**
1. Handshake : le relay se connecte avec `Authorization: Bearer <JWT role=relay>`
2. Validation JWT : rôle doit être `relay`
3. Le relay envoie `relay_hello` → proxy enregistre `relay_id`, met à jour DB `relay_nodes` status=`connected`
4. Le relay envoie `inventory_update` → proxy appelle `BulkUpsertRelayRouting(relayID, hostnames)`
5. Le proxy peut envoyer `task_dispatch` → le relay forward à son agent via `/ws/agent` existant
6. Le relay répond avec `task_ack`, `task_stdout`, `task_result` → le proxy résout le future bloquant
7. Déconnexion du relay → proxy marque status=`disconnected`, supprime routing table entrées

**State global `relay_handler.go` :**
```go
var (
    relayConnections = make(map[string]*RelayConnection)  // relay_id → conn
    relayPendingTasks = make(map[string]chan RelayTaskResult)  // task_id → chan
)
```

**Codes de fermeture WS relay :**
- `4010` : Token relay révoqué
- `4011` : Token relay expiré
- `4000` : Fermeture normale

**Critères d'acceptation :**
- [ ] Un relay peut se connecter avec JWT valide
- [ ] Un relay avec JWT invalide reçoit 401
- [ ] `inventory_update` met à jour la routing table (storage)
- [ ] `task_dispatch` envoyé par le proxy est reçu et traitable
- [ ] Déconnexion propre : routing table nettoyée
- [ ] Tests unitaires avec fake WebSocket

---

### 12.5 — Client proxy push (proxy → relay)

**Agent :** `dev-relay`  
**Dépendances :** 12.2, 12.3  
**Durée estimée :** 1.5j  

**Description :**  
En mode push, le proxy initie des connexions HTTP REST vers les relays configurés. Le proxy appelle directement les endpoints existants du relay (`POST /api/exec`, `GET /api/inventory`).

**Fichiers à créer :**
- `GO/cmd/secagent-server/internal/proxy/client.go` — **CRÉER** `RelayClient`
- `GO/cmd/secagent-server/internal/proxy/push_manager.go` — **CRÉER** goroutine de gestion push
- `GO/cmd/secagent-server/internal/proxy/client_test.go` — **CRÉER**

**Architecture `client.go` :**
```go
type RelayClient struct {
    RelayID    string
    BaseURL    string
    Token      string        // Bearer token pour s'authentifier au relay
    httpClient *http.Client  // avec TLS configuré
}

func (c *RelayClient) GetInventory(ctx context.Context) ([]AgentRecord, error)
func (c *RelayClient) Exec(ctx context.Context, hostname string, req ExecRequest) (*ExecResponse, error)
func (c *RelayClient) Upload(ctx context.Context, hostname string, req UploadRequest) error
func (c *RelayClient) Fetch(ctx context.Context, hostname string, req FetchRequest) (*FetchResponse, error)
```

**`push_manager.go` :** goroutine qui poll `GET /api/inventory` de chaque relay configuré toutes les 30s et met à jour `relay_routing`.

**Critères d'acceptation :**
- [ ] `RelayClient.GetInventory()` parse correctement la réponse Ansible inventory format
- [ ] `RelayClient.Exec()` transmet correctement tous les champs (stdin, become, timeout)
- [ ] Reconnexion avec backoff (max 60s) si le relay est injoignable
- [ ] Tests avec `httptest.NewServer`

---

### 12.6 — Router de tâches proxy → relay

**Agent :** `dev-relay`  
**Dépendances :** 12.4, 12.5  
**Durée estimée :** 1.5j  

**Description :**  
Modification des handlers `exec.go` et `inventory.go` pour router vers le relay approprié quand on est en mode proxy.

**Fichiers à modifier :**
- `GO/cmd/secagent-server/internal/handlers/exec.go` — intercept si PROXY_MODE + hostname dans routing table
- `GO/cmd/secagent-server/internal/handlers/inventory.go` — agrégation multi-relay si PROXY_MODE
- `GO/cmd/secagent-server/internal/proxy/router.go` — **CRÉER** logique de routage centralisée

**Logique de routage (`router.go`) :**
```go
type ProxyRouter struct {
    store       *storage.Store
    relayConns  map[string]*ws.RelayConnection  // relay_id → conn (pull)
    relayClients map[string]*RelayClient         // relay_id → client (push)
}

func (r *ProxyRouter) RouteExec(ctx context.Context, hostname string, req ExecRequest) (*ExecResponse, error)
func (r *ProxyRouter) RouteUpload(ctx context.Context, hostname string, req UploadRequest) error
func (r *ProxyRouter) RouteFetch(ctx context.Context, hostname string, req FetchRequest) (*FetchResponse, error)
func (r *ProxyRouter) AggregateInventory(ctx context.Context, onlyConnected bool) (*InventoryResponse, error)
```

**Comportement `exec.go` en mode proxy :**
1. Lookup `hostname` dans `relay_routing` → obtenir `relay_id`
2. Si relay_id trouvé → `ProxyRouter.RouteExec(hostname, req)`
3. Si relay_id non trouvé → chercher dans agents locaux (agents connectés directement)
4. Si non trouvé du tout → HTTP 503 `{ "error": "host_not_found" }`

**Comportement `inventory.go` en mode proxy :**
- Agrège agents locaux + inventaires de tous les relays (routing table)
- Déduplique par hostname (le hostname le plus récemment vu gagne)
- Ajoute `secagent_relay_id` dans les hostvars

**Critères d'acceptation :**
- [ ] POST /api/exec/host-A → routé vers relay DMZ1 si host-A est dans DMZ1
- [ ] POST /api/exec/host-local → traité localement si agent direct
- [ ] GET /api/inventory → union de tous les relays + agents locaux
- [ ] HTTP 503 `host_not_found` si hostname inconnu de tous les relays
- [ ] Tests avec mock ProxyRouter

---

### 12.7 — Inventaire unifié et synchronisation

**Agent :** `dev-relay`  
**Dépendances :** 12.4, 12.5  
**Durée estimée :** 1j  

**Description :**  
Assurer la synchronisation en temps réel de l'inventaire dans les deux modes (pull/push).

**Mode pull :** les relays envoient `inventory_update` sur changement (connexion/déconnexion d'agent). Le proxy met à jour `relay_routing` immédiatement.

**Mode push :** le `push_manager` poll GET /api/inventory toutes les 30s. Configurable via `PROXY_INVENTORY_POLL_INTERVAL` (défaut: 30s).

**Fichiers à modifier/créer :**
- `GO/cmd/secagent-server/internal/proxy/inventory_sync.go` — **CRÉER** goroutine de sync
- `GO/cmd/secagent-server/internal/ws/relay_handler.go` — déjà géré en 12.4 pour le mode pull

**Comportement :**
- Un agent qui se connecte à relay DMZ1 → relay envoie `inventory_update` → proxy voit immédiatement host-A comme disponible
- Un agent qui se déconnecte de relay DMZ1 → idem, statut `disconnected` dans l'inventaire agrégé
- Startup : le proxy demande un `inventory_update` immédiat au relay dès la connexion WS ouverte (déjà prévu dans 12.4 via `relay_hello` → relay envoie snapshot initial)

**Critères d'acceptation :**
- [ ] Connexion d'un agent → visible dans GET /api/inventory sur le proxy en < 2s (mode pull)
- [ ] Déconnexion d'un agent → statut `disconnected` dans < 2s (mode pull)
- [ ] Mode push : inventaire synchronisé en < 31s
- [ ] Pas de doublon de hostname entre relays (déduplication)

---

### 12.8 — Chaînage proxy → proxy

**Agent :** `dev-relay`  
**Dépendances :** 12.4, 12.6  
**Durée estimée :** 1j  

**Description :**  
Un relay peut lui-même être un proxy. Le chaînage est supporté via le flag `is_proxy: true` dans le handshake `relay_hello`.

**Comportement :**
- En mode pull : quand un "relay" se connecte au proxy avec `is_proxy: true`, le proxy sait qu'il doit router vers ce nœud les hostnames qui lui appartiennent (même mécanique)
- En mode push : le `RelayClient` est configuré pour pointer vers un proxy (pas seulement un relay simple)
- Le chaînage fonctionne automatiquement car les interfaces (REST /api/exec, /api/inventory) sont identiques entre un relay et un proxy
- Limitation : pas de détection de cycle (à documenter)

**Fichiers à modifier :**
- `GO/cmd/secagent-server/internal/ws/relay_handler.go` — stocker `is_proxy` dans `RelayNode`
- `GO/cmd/secagent-server/internal/storage/store_relay.go` — champ `is_proxy` déjà prévu (§2.4)

**Critères d'acceptation :**
- [ ] Topologie proxy-A → proxy-B → relay-C → agents fonctionne
- [ ] GET /api/inventory sur proxy-A retourne les agents de relay-C
- [ ] POST /api/exec/host-C sur proxy-A est routé via proxy-B → relay-C → host-C
- [ ] Test d'intégration avec 3 niveaux (proxy-A, proxy-B, relay-C)

---

### 12.9 — CLI : commandes `relays`

**Agent :** `dev-relay`  
**Dépendances :** 12.2, 12.3  
**Durée estimée :** 0.5j  

**Description :**  
Nouvelles commandes CLI pour administrer les relays connectés au proxy.

**Fichiers à créer :**
- `GO/cmd/secagent-server/internal/cli/relays.go` — **CRÉER**

**Commandes :**
```bash
secagent-server relays list [--format table|json|yaml]
  → Liste tous les relays (connectés + déconnectés)
  → Colonnes : relay_id, mode, is_proxy, connected, agent_count, last_seen

secagent-server relays get <relay_id> [--format table|json|yaml]
  → Détail d'un relay + liste des hostnames routés vers lui

secagent-server relays status [--format table|json|yaml]
  → Statut temps réel (query port 7771)

secagent-server relays add --id <relay_id> --url <url> --token <token> [--description <desc>]
  → Enregistrer un relay en mode push (appelle POST /api/admin/relays)

secagent-server relays remove <relay_id>
  → Supprimer un relay configuré (appelle DELETE /api/admin/relays/{id})
```

**Critères d'acceptation :**
- [ ] `relays list` affiche les colonnes correctes
- [ ] `relays get dmz1` retourne les hostnames associés
- [ ] `relays add` crée bien l'entrée en DB
- [ ] Code de sortie 2 si relay non trouvé

---

### 12.10 — Tests d'intégration topologie DMZ simulée

**Agent :** `test-writer`  
**Dépendances :** 12.4, 12.5, 12.6, 12.7, 12.8  
**Durée estimée :** 2j  

**Description :**  
Écrire les tests d'intégration simulant une topologie multi-zones complète.

**Fichiers à créer :**
- `GO/cmd/secagent-server/internal/proxy/integration_test.go` — tests Go avec composants réels en mémoire
- `DEPLOYMENT/qualif/docker-compose-proxy.yml` — topology Docker multi-relay

**Scénarios de test :**

**Tests unitaires Go (`integration_test.go`) :**
1. `TestProxyModeExecRouting` : proxy → relay (mode pull) → agent → résultat retourné au proxy
2. `TestProxyInventoryAggregation` : 2 relays avec 3 agents chacun → proxy retourne 6 agents
3. `TestProxyHostNotFound` : hostname inconnu → HTTP 503 `host_not_found`
4. `TestProxyRelayDisconnect` : relay se déconnecte → ses hostnames retirés de l'inventaire
5. `TestProxyChaining` : proxy-A → proxy-B → agent C — exec successful
6. `TestProxyPushMode` : proxy initie la connexion vers relay, routing table créée

**Docker Compose simulé (`docker-compose-proxy.yml`) :**
```yaml
# Topologie :
# proxy (port 7770/7772)
#   ├── relay-dmz1 (pull mode)
#   │     ├── agent-host-a
#   │     └── agent-host-b
#   └── relay-dmz2 (push mode)
#         ├── agent-host-c
#         └── agent-host-d
```

**Critères d'acceptation :**
- [ ] 6 tests Go passent (go test ./internal/proxy/... -v)
- [ ] docker-compose-proxy.yml démarre 1 proxy + 2 relays + 4 agents sans erreur
- [ ] curl proxy:7770/api/inventory retourne 4 hosts
- [ ] curl proxy:7770/api/exec/host-c exécute une commande sur agent-host-c

---

### 12.11 — Infrastructure Docker Compose multi-zones

**Agent :** `infra`  
**Dépendances :** 12.1  
**Durée estimée :** 0.5j  

**Description :**  
Créer les configurations Docker Compose pour la qualification multi-zones.

**Fichiers à créer :**
- `DEPLOYMENT/qualif/docker-compose-proxy.yml` — topology complète
- `DEPLOYMENT/qualif/.env.proxy` — variables d'environnement
- `DEPLOYMENT/qualif/README-proxy.md` — guide de démarrage

**Variables d'environnement du proxy :**
```
PROXY_MODE=true
JWT_SECRET_KEY=...
ADMIN_TOKEN=...
NATS_URL=nats://nats:4222
DATABASE_URL=sqlite:////data/relay.db
```

**Variables d'environnement d'un relay en mode pull :**
- Relay standard (pas de config proxy spéciale)
- Le relay s'authentifie avec un token JWT rôle `relay` fourni par le proxy

**Critères d'acceptation :**
- [ ] `docker compose -f docker-compose-proxy.yml up` démarre sans erreur
- [ ] Tous les services passent le healthcheck
- [ ] Le proxy est accessible sur port 7773 (pour éviter conflit avec qualif standard)

---

### 12.12 — Documentation

**Agent :** `doc-updater`  
**Dépendances :** 12.1 → 12.11  
**Durée estimée :** 0.5j  

**Description :**  
Mettre à jour la documentation vivante.

**Fichiers à modifier :**
- `DOC/common/HLD.md` — ajouter schéma topologie proxy/gateway multi-zone
- `DOC/common/ARCHITECTURE.md` — ajouter §23 mode proxy (config, protocole, routing)
- `DOC/server/SERVER_SPEC.md` — documenter les nouveaux endpoints + rôle `relay`
- `CHANGELOG.md` — entrée Phase 12
- `DOC/project/README_CDP.md` — mettre à jour la liste des phases

**Critères d'acceptation :**
- [ ] HLD.md contient le nouveau schéma ASCII multi-zone
- [ ] ARCHITECTURE.md §23 décrit le protocole WS relay↔proxy et le routage
- [ ] SERVER_SPEC.md liste les nouveaux endpoints `/api/admin/relays/*` et `/ws/relay`
- [ ] CHANGELOG.md contient l'entrée Phase 12 avec la date et le résumé

---

## 4. Dépendances et ordre d'exécution

```
Phase 12 — Dépendances

12.1 (Config proxy)
  ├── 12.2 (Storage relay tables)
  │     ├── 12.4 (WS /ws/relay pull) ─── 12.6 (Router tâches)
  │     │                            │       └── 12.10 (Tests intégration)
  │     ├── 12.5 (Client push)   ────┘
  │     └── 12.3 (Auth rôle relay)
  │           ├── 12.4
  │           └── 12.5
  ├── 12.7 (Inventaire sync) ← dépend 12.4 + 12.5
  ├── 12.8 (Chaînage) ← dépend 12.4 + 12.6
  ├── 12.9 (CLI relays) ← dépend 12.2 + 12.3
  ├── 12.11 (Infra Docker) ← dépend 12.1 seulement
  └── 12.12 (Doc) ← dépend tout

Séquence recommandée :
  Sprint 1 : 12.1 → [12.2, 12.3, 12.11] en parallèle
  Sprint 2 : [12.4, 12.5] en parallèle (dépendent de 12.2 + 12.3)
  Sprint 3 : [12.6, 12.7, 12.9] en parallèle (dépendent de 12.4 ou 12.5)
  Sprint 4 : [12.8, 12.10] en parallèle (dépendent de 12.6)
  Sprint 5 : 12.12 (doc, dépend de tout)
```

---

## 5. Résumé — Assignations et livrables

| Sous-tâche | Titre | Agent | Livrable |
|---|---|---|---|
| **12.1** | Config mode proxy | `dev-relay` | `internal/config/proxy.go` + main.go modifié |
| **12.2** | Storage relay_nodes + relay_routing | `dev-relay` | `store_relay.go` + tests |
| **12.3** | Auth JWT rôle relay + endpoints admin relays | `dev-relay` | `admin_relays.go` + auth/jwt.go |
| **12.4** | WS /ws/relay — mode pull | `dev-relay` | `ws/relay_handler.go` + tests |
| **12.5** | Client proxy push | `dev-relay` | `proxy/client.go` + `push_manager.go` |
| **12.6** | Router tâches proxy→relay | `dev-relay` | `proxy/router.go` + handlers modifiés |
| **12.7** | Inventaire unifié et synchronisation | `dev-relay` | `proxy/inventory_sync.go` |
| **12.8** | Chaînage proxy→proxy | `dev-relay` | Modification relay_handler.go + store_relay.go |
| **12.9** | CLI commandes `relays` | `dev-relay` | `cli/relays.go` |
| **12.10** | Tests d'intégration topologie DMZ | `test-writer` | `proxy/integration_test.go` + docker-compose-proxy.yml |
| **12.11** | Infrastructure Docker Compose multi-zones | `infra` | `DEPLOYMENT/qualif/docker-compose-proxy.yml` |
| **12.12** | Documentation | `doc-updater` | HLD.md, ARCHITECTURE.md §23, CHANGELOG.md |

**Total : 12 sous-tâches** — 3 agents principaux (dev-relay, test-writer, infra/doc-updater)

---

## 6. Critères d'acceptation Phase 12 (issue #99)

- [ ] **12.A** Mode proxy activable via `PROXY_MODE=true` — relay standard non impacté
- [ ] **12.B** Connexion pull fonctionnelle : relay se connecte à `/ws/relay`, proxy route les tâches
- [ ] **12.C** Connexion push fonctionnelle : proxy initie connexions REST vers relays configurés
- [ ] **12.D** GET /api/inventory sur le proxy retourne l'union de tous les agents de tous les relays
- [ ] **12.E** POST /api/exec/{hostname} sur le proxy route vers le relay qui a l'agent
- [ ] **12.F** Chaînage proxy→proxy : 3 niveaux (proxy-A → proxy-B → relay-C → agent) fonctionnel
- [ ] **12.G** Auth mutuelle : JWT rôle `relay` — un token agent ne peut pas ouvrir `/ws/relay`
- [ ] **12.H** Tests d'intégration avec topologie DMZ simulée (go test) : 6 scénarios passent
- [ ] **12.I** `secagent-server relays list` liste les relays connectés
- [ ] **12.J** Docker Compose multi-zones démarre et valide la topologie complète

---

*Plan créé le 2026-05-22 — Architecte planner — Ansible-SecAgent Phase 12*
