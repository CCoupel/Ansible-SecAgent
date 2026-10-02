# Changelog — Ansible-SecAgent

All notable changes to this project will be documented in this file.

---

## [v2.0.0] — 2026-10-02 — Phase 12 : Proxy/Gateway multi-zone

### Added
- **Mode Proxy/Gateway** (`PROXY_MODE=true`) — `secagent-server` peut désormais fonctionner en tant que proxy/gateway agrégeant plusieurs zones réseau (DMZ, clusters distants…)
  - **Mode pull** : les relays initient la connexion vers le proxy via `WSS /ws/relay` (JWT rôle `relay`)
  - **Mode push** : le proxy initie des connexions REST HTTP vers des relays configurés en DB, avec poll inventaire (défaut 30s, configurable via `PROXY_INVENTORY_POLL_INTERVAL`)
  - **Inventaire unifié** : `GET /api/inventory` agrège les agents de tous les relays connectés + agents directs
  - **Routage transparent** : `POST /api/exec/{host}`, `/api/upload/{host}`, `/api/fetch/{host}` routés automatiquement vers le relay propriétaire de l'hôte
  - **Chaînage proxy→proxy** : topologies hiérarchiques multi-niveaux (`is_proxy: true` dans `relay_hello`)
  - **Protection anti-boucle** : en-tête `X-Relay-Hops` (budget initial 8) — HTTP 508 si épuisé
- **Protocole WebSocket `/ws/relay`** — 10 types de messages bidirectionnels (`relay_hello`, `relay_ack`, `agent_list`, `agent_list_ack`, `task_dispatch`, `file_upload`, `file_fetch`, `task_result`, `upload_result`, `fetch_result`) + codes de fermeture dédiés (4010/4011)
- **Nouveau rôle JWT `relay`** — rôle distinct de `agent`/`plugin`/`admin`, créé via `POST /api/admin/tokens` avec `"role": "relay"`
- **Package `internal/proxy/`** — `ProxyRouter`, `RelayClient`, `PushManager` (goroutine de poll)
- **Handler `ws/relay_handler.go`** — gestion des connexions relay en mode pull, routing map en mémoire, résolution des futures bloquantes
- **Endpoints admin relays** (port 7771) :
  - `POST /api/admin/relays` — enregistrer un relay mode push
  - `GET /api/admin/relays` — liste des relays configurés
  - `DELETE /api/admin/relays/{id}` — supprimer un relay
  - `GET /api/admin/relays/status` — statut temps réel
- **CLI** : `secagent-server relays list|get|status|add|remove` (`internal/cli/relays.go`)
- **Tables SQLite** : `relay_nodes` (statut, mode, is_proxy, URL, token_hash) + `relay_routing` (hostname → relay_id)
- **Docker Compose multi-zones** : `DEPLOYMENT/qualif/docker-compose-proxy.yml` — topologie proxy + 2 relays + agents simulés

### Changed
- `handlers/exec.go` — intercept proxy : lookup `relay_routing` avant dispatch local
- `handlers/inventory.go` — agrégation multi-relay si `PROXY_MODE=true`
- `storage/store.go` — DDL étendue (tables `relay_nodes`, `relay_routing`)
- `DOC/common/ARCHITECTURE.md` — §23 Mode Proxy/Gateway multi-zone ajouté
- `DOC/server/SERVER_SPEC.md` — §9 Mode Proxy (endpoints, protocole WS, variables)

### Fixed
- **PushManager HTTP 401** (`e9672dc`) — AdminCreateRelay was SHA-256 hashing tokens before storing for push-mode relays, while PushManager sent token_hash directly as Bearer token. Now stores plain token, fixing 401 errors on relay polls. (Note: e9672dc and be17cee share identical server code.)
- **Docker-compose configuration** (`be17cee`) — docker-compose.proxy.yml now uses direct SQLite paths without URI prefix (e.g., `/data/relay.db`) instead of problematic prefixes, and updates PROXY_RELAYS configuration.

### Known Limitations

The following are **known issues** and **operational constraints**:

1. **Non-empty stdin + become/become_pass returns rc=1** (executor.go, issue #100) — When a task with `become` or `become_pass` receives non-empty stdin, `bytesReader` returns `fmt.Errorf("EOF")` instead of `io.EOF`, causing executor to fail with rc=1. Correction envisaged in v3.0.
   - **Qualification result**: Confirmed in E2E-4 test (cat with stdin non-empty → rc=1).

2. **Child process timeout only kills /bin/sh** (executor.go) — Context timeout kills only the shell process, not descendant processes spawned by the playbook. Grandchild processes may continue running. Correction envisaged in v3.0.

3. **SQLite path handling** (store.go:165, store.go:167-168) — Configuration must use direct paths without URI prefix. In docker-compose or environment, use absolute paths (e.g., `/data/relay.db`). This is an operational constraint.
   - **Qualification**: Confirmed in be17cee docker-compose.proxy.yml (uses `/data/relay*.db` paths directly).

4. **Enrollment token bootstrap is manual** (A2) — Enrollment tokens must be created manually **after** each relay's database is initialized, before agents can enroll. This is a one-time operational procedure per fresh deployment:
   ```bash
   docker exec relay-dmz1 /app/secagent-server tokens create \
     --role enrollment --hostname-pattern '.*' --reusable --expires 24h
   ```
   - **Reference**: See deployment procedure in qualification report (§9).

5. **PROXY_RELAYS does not auto-seed relay_nodes** (A4) — The `PROXY_RELAYS` environment variable is parsed at startup but does not automatically create entries in the `relay_nodes` table. Relay nodes must be registered manually via CLI **after** deployment with fresh volumes:
   ```bash
   docker exec relay-proxy /app/secagent-server relays add \
     --id dmz1 --mode push --url http://relay-dmz1:7770 \
     --token <plugin_token>
   ```
   Relay nodes must point to port 7770 (API endpoint) for exec/upload/fetch operations. The `PROXY_RELAYS` configuration in docker-compose.proxy.yml points to port 7771 for inventory polling only (GET /api/inventory).
   - **Qualification**: Confirmed in be17cee qualif (manual relay node registration required, port 7770 used for exec routing).

6. **Enrollment token hostname pattern is anchored regex** — The hostname pattern in enrollment tokens is validated as an **anchored regex** (e.g., `.*` matches all hostnames, `^prod-.*\.example\.com$` matches specific pattern).

**Deprecation Notice**: v3.0 (issue #123) replaces `PushManager` and `PROXY_RELAYS` with a new WebSocket relay chain architecture with improved event propagation. Users on v2.0.0 with push-mode relays should plan migration to v3.0 architecture.

### Tests
- 917/920 tests unitaires et intégration passent (QA VALIDATED)
- 6 scénarios d'intégration proxy (`internal/proxy/integration_test.go`)
- Tests chaînage 3 niveaux (`internal/proxy/chaining_test.go`)

---

## [v1.1.0] — 2026-05-22 — Phase 11 : Event Hooks Unifiés

### Added
- **Système de hooks unifié** (`internal/hooks/`) — actions déclenchées par événements agent via fichier JSON de configuration (`RELAY_HOOKS_CONFIG`, défaut `/etc/secagent-server/hooks.json`)
  - 4 types d'action : `webhook` (HTTP POST + HMAC-SHA256), `shell` (subprocess + env SECAGENT_*), `file` (append O_CREATE), `api` (méthode configurable)
  - Moteur de template : `{{hostname}}`, `{{event}}`, `{{timestamp}}`, `{{status}}`, `{{enrolled_at}}`
  - Dispatcher asynchrone (queue 1000, non-bloquant) avec hot-reload via `SIGHUP`
- **Table `action_log`** — trace toutes les exécutions d'actions (remplace `webhook_deliveries`)
- **CLI** : `secagent-server hooks status` et `secagent-server hooks log [--limit] [--event] [--hostname] [--format]`
- **Route** `GET /api/admin/hooks/log` — consultation des logs d'action via API admin
- **Dispatch événements** : `host.new` (enrollment), `host.up`/`host.down` (WebSocket), `host.revoked`, `host.deleted`
- **Spec** `DOC/server/HOOKS_SPEC.md` — documentation complète du système

### Removed
- Package `internal/webhooks/` — remplacé par `internal/hooks/`
- Tables SQLite `webhooks` et `webhook_deliveries` — remplacées par `action_log`
- Routes CRUD admin webhooks (`POST/GET/DELETE /api/admin/webhooks/...`)
- Fichiers : `store_webhooks.go`, `admin_webhooks.go`

### Fixed
- **`internal/storage/store.go`** — parsing `DATABASE_URL` avec préfixe `sqlite:///` corrigé (off-by-one → `strings.HasPrefix` longest-first)

### Infrastructure
- `GO/Dockerfile` — chemin build corrigé (`./cmd/server` → `./cmd/secagent-server`)
- `GO/Dockerfile.caddy` — nouveau, Caddyfile baked dans l'image (compatibilité remote Docker)
- `GO/docker-compose.yml` — NATS via args CLI, Caddy build context, DATABASE_URL chemin direct

---

## Phases précédentes

### Phase 10 — Enrollment Token (clôturée)
- Système de tokens d'enrollment pré-signés (issues #87–#96)
- API admin : génération, révocation, liste tokens
- Validation côté agent : phase 0 enrollment

### Phases 1–9 (clôturées)
- Infrastructure serveur, agent minion, plugins Ansible, inventaire, authentification JWT, NATS JetStream, WebSocket multiplexé, CLI cobra, sécurité RSA-4096
