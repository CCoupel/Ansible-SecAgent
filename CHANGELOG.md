# Changelog — Ansible-SecAgent

All notable changes to this project will be documented in this file.

---

## [Unreleased]

### Added
- (future features for next milestone)

### Changed (breaking)
- **Le Store passe sur le fichier d'état, SQLite et CGO sont retirés (#160)** : `STATE_DIR` (défaut `/data`, créé par `secagent-server state init`) remplace `DATABASE_URL` ; `DATABASE_URL` définie = **erreur au démarrage** (aucune migration d'un ancien `relay.db`). Enrôlement et révocation d'un relay en une seule mutation ; statut, `last_seen`, routage et `relay_chain` en mémoire ; purge horaire de la blacklist ; `last_used_*` des tokens plugin approximatifs (champ `last_used_approximate`). Tokens relay : `token_hash` (pull) et `token_secret` scellé (push) distincts. Sans garde d'écriture le serveur est en lecture seule. Binaire et image serveur en `CGO_ENABLED=0`.

### Added
- **Actif/passif dans `secagent-server` (#163)** : une instance démarre secondaire (aucun port, aucun état chargé, rien d'écrit hors `relay.lock`), devient maître par le verrou, charge l'état puis ouvre ses ports ; `BeforeWrite` branché sur le verrou. Perte du verrou : listeners et WebSockets fermés (`1001`, jamais `4001`), hooks non vidés, sortie code 75. SIGTERM : verrou supprimé, reprise < 5 s. Garde de `write_seq` (rejeu d'une copie plus ancienne refusé). `secagent-server status --local` et fichier `RELAY_STATUS_FILE` (healthcheck sans port). `/health` : `role`, `instance_id`. **`RELAY_SINGLE_INSTANCE` supprimée** (ignorée avec un avertissement : le verrou est toujours actif).

### Removed
- **NATS JetStream retiré du serveur et du déploiement (#178)** : aucun usage fonctionnel (l'exec passe par WebSocket direct), aucune perte. Suppression de `internal/broker`, de `GO/nats.conf`, des services/volumes `nats*` des Compose hors prod, des dépendances `nats-io` du `go.mod`. `NATS_URL` encore définie : un seul `[WARN] NATS_URL is obsolete and ignored`, démarrage normal.
- **[BREAKING]** `GET /api/admin/status` et `secagent-server server status` ne renvoient plus le champ `nats`.

### Added
- **Fichier d'état et verrou (#159, #162)** : package `state` (fichier d'état unique, écriture atomique, group commit, `secagent-server state init`), package `lock` (verrou d'exclusivité du maître, variante A). Pas encore branchés au serveur (#160, #163).

### Changed
- **Journal des actions de hooks (#161)** : `action_log` (SQLite) remplacé par un journal JSON Lines append-only `actions.log` (`RELAY_ACTION_LOG`, défaut `STATE_DIR/actions.log`), sans fsync par ligne, rotation par taille (10 Mio × 5). Le `config_snapshot` ne contient plus aucun secret (il enregistrait en clair le secret HMAC et les en-têtes d'authentification des webhooks).

### Security
- **#176** : suppression de `completedResults` et de `GET /api/async_status/{task_id}` (map sans mutex, non bornée, sans appelant en production).
- **#169** : `/ws/agent` refuse (401, avant l'upgrade) un JTI blacklisté, remplacé ou un agent inconnu ; fail closed.
- **#177** : `X-Forwarded-For` n'est pris en compte que derrière `TRUSTED_PROXY_CIDRS` (vide par défaut = ignoré).
- **#173** : `agents.suspended` appliqué à exec/upload/fetch (503 `agent_suspended`, relayé par les parents).

---

## [v3.0.2] — 2026-10-05 — Events et Inventaire Hiérarchique

### Added
- **Propagation d'événements (#126)** :
  - Types d'événements : `host.up`, `host.down`, `host.new`, `host.conflict`, `relay.updated`
  - Chaîne d'événement **ordre origine-first** (relay le plus proche de l'agent d'abord)
  - Variables de hook : `{{relay_chain}}` (JSON) et `{{relay_origin}}` (premier relay)
  - Filtre hook `relay_chain_contains:<relay_id>` validé au chargement (fail-closed)
  - Sémaphore hooks : `RELAY_HOOKS_MAX_CONCURRENT_ACTIONS` (défaut 64) — actions excédentaires rejetées silencieusement avec log limité
  - Re-snapshot atomique lors de changements de topologie : coalescé (200 ms debounce, 2 s min gap), rate limit 40/60s par lien
  - `host.conflict` : exact (1 événement par changement de propriétaire), ancien propriétaire cède au nouveau
- **Inventaire hiérarchique (#128, #139)** :
  - Groupes Ansible = noms exacts des relays (ex: `dmz1`, `zone-a`) — pas de transformation
  - Hiérarchie récursive : nœud sans REPEATER_ID, `all.children` = relays enfants directs, chaque groupe `g.children` = relays enfants du relay `g` ; nœud avec REPEATER_ID (même sans `?relay=`), `all.children` = `[<id_du_nœud>]` ; paramètre `?relay=<id>`, `all.children` = `[<id>]`
  - Chaîne `secagent_relay_chain` : ordre origine-first (ex: `["zone-a", "dmz1"]`)
  - Variable `secagent_next_hop` : relay enfant direct vers lequel router
  - Paramètre `?relay=<id>` : limite l'inventaire à la descendance du relay spécifié
  - **Group vars (#139)** : `RELAY_GROUP_VARS` JSON persisté dans `relay_nodes.group_vars`, transmis en `relay_hello`, `topology_snapshot`, `relay.updated`
  - Validation group vars : refus du snapshot/hello en bloc si JSON invalide ; interdits : `ansible_*` (sauf `ansible_python_interpreter` validé sans `..`), `secagent_*` ; marqueurs Jinja interdits
  - Noms de groupes avec tirets (ex: `zone-a`) déclenchent avertissement Ansible — à silencer avec `ANSIBLE_TRANSFORM_INVALID_GROUP_CHARS=ignore` (recommandation : nommer les relays avec underscores)
- **Extraction du câblage dans `internal/server` (#155)** :
  - Variables `API_ADDR` (défaut `:7770`), `ADMIN_ADDR` (défaut `:7771`), `WS_ADDR` (défaut `:7772`)
  - Validation `relay_id` partout : API admin `POST /api/admin/relays` 400 `invalid_relay_id`, `/ws/relay` upgrade 401, stockage
- **CI job « Inventaire Ansible »** : ansible-core 2.21.4 épinglé, `ANSIBLE_E2E=1 go test -race -run 'Ansible'` valide la sortie réelle de `secagent-inventory`
- **Test de migration v3.0.0 → v3.0.2** (9229c74) : migration de base couverte par test permanent, idempotente, aucune perte de ligne, relays hérités et routes utilisables

### Changed
- Aucun plugin Python d'inventaire n'est livré — utiliser le binaire GO `secagent-inventory` (v3.0.2+) pour l'inventaire Ansible
- Table SQLite `relay_nodes` : colonne `group_vars` TEXT (JSON des variables pour ce relay), `relay_chain` TEXT (chaîne JSON pour ce relay)
- Table SQLite `relay_routing` : `relay_chain` TEXT (chaîne JSON) — désormais sérialisée correctement pour les profondeurs > 3 niveaux
- Documentation :
  - DOC/server/SERVER_SPEC.md §9.5 : ordre chaîne corrigé, `secagent_next_hop` explicité, paramètre `?relay=<id>` documenté, avertissement noms Ansible et configuration (§9.5b)
  - DOC/inventory/INVENTORY_SPEC.md : RELAY_SCOPE variable, exemples avec ordre correct et `secagent_next_hop`
  - DOC/contracts/REST_PLUGIN.md §2 : paramètre `relay`, réponse hiérarchique, chaînes correctes

### Fixed
- #155 : extraction du câblage (API_ADDR, ADMIN_ADDR, WS_ADDR défauts précis — la variable SERVER_ADDR n'existait pas)
- Validation `relay_id` cohérente partout (format `^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$`)
- buildSnapshot (server/helpers.go) déclare maintenant les chaînes réelles (relay_nodes.relay_chain) au lieu d'aplatir à [self, relay] : profondeur 5+ niveaux correcte (46a68fa)

### Known Limitations
- #141 : Signature des tokens par la racine (actuellement chaque relay signe avec sa propre clé)
- #146 : Rôles JWT relay-child / relay-parent : aligner le code (rôle unique « relay ») sur SECURITY.md §2 (décision arbitrage)
- #147 : Option de CA personnalisée pour le TLS du client repeater vers le parent (sans skip-verify)
- #151 : Filtrage SSRF des cibles de dial du Dialer push (loopback, link-local, métadonnées cloud)
- #152 : Colonne `relay_nodes.token_hash` : séparer hash (pull) et token chiffré (push)
- #156 : Rate limit des topology_snapshot par identité (relay_id) et non par lien : reconnexion doit refaire compter

---

## [v3.0.1] — 2026-10-04 — Repeater Relay Chain

### Added
- **Protocole repeater complet** : topologie arbre (un relay enfant a un seul parent), deux modes d'ouverture (`pull` enfant→parent, `push` parent→enfant) (#124, #125, #140)
  - **Mode pull** (enfant ouvre vers parent) : variables `REPEATER_ID`, `REPEATER_UPSTREAM_URL`, `REPEATER_UPSTREAM_TOKEN` ; l'enfant s'auto-enregistre via `relay_hello` (#124, #125)
  - **Mode push** (parent ouvre vers enfant) : token relay-parent chiffré AES-GCM avec `RSA_MASTER_KEY`, API `POST /api/admin/relays` (#140)
  - **Handshake symétrique** : `relay_hello` (client, relay_id == jwt.sub) → `relay_ack` (serveur, relay_id du serveur + ancestors) → `topology_snapshot` (enfant) ; rejet 4010 si identity mismatch ou boucle détecté (#148)
  - **Validation client** : `relay_ack.relay_id` vérifié vs identité attendue ; changement d'identité du pair = 4010 permanent
- **Hierarchical routing** (#127) :
  - `next-hop` task forwarding vers l'agent direct ou enfant relais
  - Agent local **prioritaire** sur la table de routage (ne peut pas être détourné par un relay déclarant le même hostname) — raison sécurité : `stdin` (become_pass) reste local
  - Limit `MAX_AGENT_LIST_HOSTS` (défaut 10 000) avec rejet (4012) si dépassé ; `host.conflict` événement émis une seule fois par changement de propriétaire (#149)
  - Gestion `relay_chain` ascendant à chaque événement
- **Révocation relay tokens** (#153) :
  - `POST /api/admin/relays/{id}/revoke` et `tokens revoke <relay_id>` : blacklist du JTI + fermeture (4010) du lien actif
  - Tokens relay-parent : CLI `tokens create --role relay-parent --sub <parent> --expires <d>` (max 365 j, obligatoire) (#150)
  - Métadonnées persistées (JTI, expiry, revoked) ; jamais le token en clair en DB
  - Relais antérieurs (#153) sans JTI : révoqués par le drapeau seul (legacy_token=true)
- **État du lien amont** (#154) :
  - `/health` (port 7770) : HTTP 200 maintenu, drapeau `degraded` seul (pas d'exposition de topologie)
  - `/api/admin/status` et `secagent-server server status` (port 7771) : tableau LINK/PEER/STATE/SINCE/REASON avec détail des liens, avertissement « operator action required » si dégradé
  - États `connected`, `retrying` (non-terminal), `refused_permanent` (terminal, action requise)
  - Texte du close frame assaini (pas de révélation d'identités du pair en logs/statuts)
- **Codes de fermeture `/ws/relay`** (#148, #153) :
  - `4010` (refus permanent) : token révoqué, identity mismatch, boucle détectée → arrêt client (log ERROR « operator action required »), pas de reconnexion. Sur un lien push établi, le Dialer devient terminal (cf. #153)
  - `4012` (refus corrigible) : snapshot invalide, conflict de routage → reconnexion avec backoff (5 s → 60 s)
  - `4011` (token expiré) : non utilisé pour l'instant (réservé)
  - **HTTP 401 avant upgrade** (token invalide à la reconnexion) : **pas** terminal, permet au parent de redémarrer

### Changed
- Les spécifications v3.0 (§23 ARCHITECTURE.md, §8-9 SERVER_SPEC.md, §2 SECURITY.md) sont désormais **implémentées et validées** (#124–#154)
- Tables SQLite : `relay_nodes` (jti, token_exp, revoked), `relay_routing` (hierarchical avec relay_chain), `relay_parent_tokens` (métadonnées)
- CLI `relays` renommée implicitement : accès via `secagent-server relays add|list|get|remove` (port 7771)
- Variables d'environnement : `REPEATER_ID`, `REPEATER_UPSTREAM_URL`, `REPEATER_UPSTREAM_TOKEN`, `RSA_MASTER_KEY` (push), `MAX_AGENT_LIST_HOSTS`, `MAX_SNAPSHOT_HOSTS` ajoutées
- Docker Compose qualif : support topologie repeater (parent + 2 enfants)

### Fixed
- **Sécurité** : relay-parent tokens ne fuient jamais en logs, seul output one-shot au create (#150); relay-child tokens jamais loggés (#150)
- Refus permanent (4010) ne fuite jamais le token dans la raison (texte borné **200 octets max**, tronqué sur une frontière de caractère UTF-8) ; détection boucle + identity mismatch fail-closed (#148, #140)
- Une trame close 4010 reçue sur un lien push établi rend le Dialer terminal (refused_permanent, log ERROR, pas de reconnexion, degraded=true dans /health) (#153)
- Validation symétrique `relay_hello.relay_id == jwt.sub` (serveur) et `relay_ack.relay_id` vs identité attendue (client) (#148)
- CI : timeout per-package 300s sous -race (#145) ; golangci-lint v2.14.0 (46 //nolint:errcheck retirés) (#133, #144)
- Tests race : awaitCondition dans relay_handler_test (#145) ; flaky sleeps dans repeater, handlers, proxy (#145)

### Known Limitations
- `#152` : colonne `relay_nodes.token_hash` trompeuse (hash pour pull, token chiffré pour push) — renommage envisagé
- `#126` : un hôte dans la profondeur n'est pas routable vers l'ancêtre jusqu'au prochain snapshot du parent
- `#146` : rôle relay-child créé manuellement (pas de CLI) ; hiérarchie PKI envisagée pour v3.0.2+
- `#151` : SSRF dans la validation dial-out — enregistrement en suivi
- Métrique : aucune infrastructure de métriques n'existe actuellement (raison du lien stockée en texte uniquement)

---

## [v3.0.0] — 2026-10-03 — Fondations (specs seulement)

### Changed
- **Spec du mode repeater (#122)** : topologie en **arbre**, handshake `relay_hello` → `relay_ack` → `topology_snapshot`, deux rôles JWT `relay-child` / `relay-parent`, refus de boucle. **Aucune implémentation en v3.0.0**.
- Les corps d'erreur JSON se terminent par un saut de ligne (`json.Encoder`) (#144).
- La CI bloque sur `gofmt` et `golangci-lint` v2.14.0 (#133, #144).

### Removed
- **PushManager, REST relay polling, variables `PROXY_MODE` / `PROXY_RELAYS`** (#123). Colonne `relay_nodes.mode` conservée mais inerte jusqu'à v3.0.1.

### Fixed
- Parsing de `DATABASE_URL` : chemin absolu correct (#131).
- `hostname_pattern` : ancrage strict `^(?:pattern)$` (#143).
- `logExecSafe` : pas d'adresses mémoire (#142).
- 157 erreurs golangci-lint corrigées (#144) ; test flaky corrigé (#145).

### Added
- Script `scripts/bootstrap-qualif.sh` (#135).
- Badge CI, `GO/.golangci.yml` v2 (#133).

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

1. **Non-empty stdin + become/become_pass returns rc=1** (executor.go, issue #100) — When a task with `become` or `become_pass` receives non-empty stdin, `bytesReader` returns `fmt.Errorf("EOF")` instead of `io.EOF`, causing executor to fail with rc=1. Correction envisaged in v3.0.0.
   - **Qualification result**: Confirmed in E2E-4 test (cat with stdin non-empty → rc=1).

2. **Child process timeout only kills /bin/sh** (executor.go) — Context timeout kills only the shell process, not descendant processes spawned by the playbook. Grandchild processes may continue running. Correction envisaged in v3.0.0.

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

**Deprecation Notice**: v3.0.0 (issue #123) replaces `PushManager` and `PROXY_RELAYS` with a new WebSocket relay chain architecture with improved event propagation. Users on v2.0.0 with push-mode relays should plan migration to v3.0.0 architecture.

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
