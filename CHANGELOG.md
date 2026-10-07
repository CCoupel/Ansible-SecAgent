# Changelog — Ansible-SecAgent

All notable changes to this project will be documented in this file.

---

## [Unreleased]

### v3.0.4 — Jetons de lien relay signés par la racine (#141, #146) — en cours

**⚠️ BREAKING CHANGES — une seule rupture, pas de fenêtre HS256, pas de retour arrière vers v3.0.3**

- **[BREAKING] Rôle `relay` supprimé** : `/ws/relay` n'accepte plus que les rôles `relay-child` (lien pull) et `relay-parent` (lien push), jetons **JWT Ed25519 (`alg=EdDSA`)** avec `iss` (racine), `sub`, `aud`, `kid`, `jti`, `exp`. Tout jeton HS256 (`relay`, ancien `relay-parent`) est refusé (`link_role_legacy` / `link_alg_not_allowed`). Les jetons `agent`, `plugin`, `enrollment` et admin ne changent pas : **les agents restent connectés**.
- **[BREAKING] Les jetons de lien sont émis par la racine** (`tokens create --role relay-child|relay-parent --sub X --aud Y`, `POST /api/admin/tokens`) : `409 not_root` sur un nœud qui a un parent, `503 master_key_required` sans `RSA_MASTER_KEY`. Un `relay-parent` n'est **plus minté par l'enfant**.
- **[BREAKING] `POST /api/admin/relays` en mode pull ne minte ni ne renvoie plus de jeton** (`jwt_token` supprimé) : le jeton `relay-child` est minté sur la racine et configuré sur l'enfant (`REPEATER_UPSTREAM_TOKEN`).
- **[BREAKING] Ancre de confiance obligatoire pour les relays non racine** : `REPEATER_ROOT_LINK_KEY_FILE` (clé publique racine, `keys link-pubkey`) et `REPEATER_ROOT_ID` ; sans ancre un relay refuse tout lien entrant (close `4010`).
- **[BREAKING] `schema_version` 2 du fichier d'état** (`link_tokens`, `link_trust`, `server_config.link_signing_key_*`) : migration automatique v1→v2 au premier démarrage du maître (sauvegarde `relay.state.v1.bak`), mais **un binaire v3.0.3 refuse un état v2** (`ErrSchemaVersion`) : monter les deux instances d'une paire ensemble ; retour arrière = restaurer la sauvegarde + binaires v3.0.3 + anciens jetons.
- **Limites de concurrence et budget stdout (#179)** : `MAX_TASKS_PER_AGENT` (10), `MAX_TASKS_INFLIGHT` (1000), `MAX_STDOUT_BUFFER_TOTAL` (1 Gio). L'API plugin peut répondre `429 agent_busy` / `429 too_many_tasks` (+ `Retry-After`) et `503 memory_budget_exhausted` à l'admission d'`exec`, `upload` et `fetch` ; le plugin Ansible les remonte en `AnsibleConnectionFailure` explicite, sans rejeu. Voir `DOC/contracts/REST_PLUGIN.md` §3.
- Ajouts : rotation de la clé racine (`keys rotate-link`, `retire-link-previous`, double acceptation), révocation propagée de proche en proche (`link_revocations`, `link_keys`, `link_state`), `GET /api/admin/link/{pubkey,status}`. Voir `DOC/security/DECISION_141.md`.

### Added
- (future features for next milestone)

---

## [v3.0.3] — 2026-10-06 — Relay Actif/Passif et État sans SQLite

**⚠️ BREAKING CHANGES — Migration Required**

### Migration et Avis de Sécurité

**Migration (obligatoire)** : 
- **Tokens agent sans `role: "agent"`** sont refusés en 401 après la mise à jour. Les agents doivent **se ré-enrôler** (nouveau jeton d'enrôlement, redémarrage du minion).
- **État vierge, aucune migration de `relay.db`** — v3 repart de zéro. Anciens tokens, hôtes et configurations sont perdus ; tous les agents se ré-enrôlent.
- **`DATABASE_URL` définie = erreur au démarrage** — utiliser `STATE_DIR` (défaut `/data`).
- Exécutez `secagent-server state init` pour initialiser le nouvel état avant le 1er démarrage.

**Avis de sécurité** (#181, #192, #193) :
- **Toutes les versions antérieures, dont v1.0.0 et v2.0.0 (défaut présent depuis v1.0.0)** : `POST /api/token/refresh` n'authentifiait pas l'appelant et `POST /api/register` sans jeton d'enrôlement émettait un JWT sans preuve de possession de la clef privée ni contrôle de la blacklist. Conséquences : **contournement de la révocation** (un agent révoqué qui garde sa clef obtenait un nouveau JTI) et **remplacement du JTI** d'un agent par un tiers (déni de service). **Corrigé en v3.0.3** : route supprimée, enrôlement sans jeton refusé. L'environnement de qualification resté en v2.0.0 est exposé jusqu'à sa migration ; mitigation réseau : bloquer `/api/token/refresh` et restreindre `/api/register` (voir `DOC/security/SECURITY.md` §11, avis 3).
- **v1.0.0 et v2.0.0 affectées** : endpoints `/ws/agent` et `/ws/relay` (mode proxy) acceptaient connexions sans token. Exploitation : usurpation d'agent/relay, interception de tâches et `become_pass`. **Corrigé en v3.0.3**, fail-closed. Mitigations pour déploiements v2.0.0 : restriction réseau des ports 7770/7772 + **rotation des `become_pass`**.
- **v1.0.0 et v2.0.0 affectées** : secrets de webhooks (HMAC, jetons) enregistrés en clair dans `action_log`. Exposition via `GET /api/admin/hooks/log` et via accès au fichier `relay.db`. **Corrigé en v3.0.3** avec journal append-only masqué. Actions : **évaluer et faire tourner les secrets de webhooks** et **purger les anciennes copies de `relay.db`**.

### Changed (breaking)
- **Le Store passe sur le fichier d'état, SQLite et CGO sont retirés (#160)** : `STATE_DIR` (défaut `/data`, créé par `secagent-server state init`) remplace `DATABASE_URL` ; `DATABASE_URL` définie = **erreur au démarrage** (aucune migration d'un ancien `relay.db`). Enrôlement et révocation d'un relay en une seule mutation ; statut, `last_seen`, routage et `relay_chain` en mémoire ; purge horaire de la blacklist ; `last_used_*` des tokens plugin approximatifs (champ `last_used_approximate`). Tokens relay : `token_hash` (pull) et `token_secret` scellé (push) distincts. Sans garde d'écriture le serveur est en lecture seule. Binaire et image serveur en `CGO_ENABLED=0`.

### Added
- **Fichier d'état avec HMAC et anti-rejeu (#159, #160, #162, #163)** : `relay.state` (JSON, authentifié HMAC-SHA-256, crypté champ par champ, écriture atomique) remplace SQLite ; créé par `secagent-server state init` (sans aucune source de données externes, état vierge obligatoire). Verrou d'exclusivité du maître (`relay.lock`, variante A : inode + `instance_id` + battement) avec garde `write_seq` anti-rejeu en mémoire.
- **Actif/passif dans `secagent-server` (#163)** : une instance démarre secondaire (aucun port, aucun état chargé, rien d'écrit hors `relay.lock`), devient maître par le verrou, charge l'état puis ouvre ses ports ; `BeforeWrite` branché sur le verrou. Perte du verrou : listeners et WebSockets fermés (`1001`, jamais `4001`), hooks non vidés, sortie code 75. SIGTERM : verrou supprimé, reprise < 10 s (mesurée 3-6 s : cycle de contrôle ≤ 5 s + pause du candidat 1-2 s). Garde de `write_seq` (rejeu d'une copie plus ancienne refusé). `secagent-server status --local` et fichier `RELAY_STATUS_FILE` (healthcheck sans port). `/health` : `role`, `instance_id`. **`RELAY_SINGLE_INSTANCE` supprimée** (ignorée avec un avertissement : le verrou est toujours actif).
- **TLS natif dans secagent-server (#175)** : `TLS_CERT` et `TLS_KEY` chargés depuis fichiers PEM, appliqués aux ports 7770 (API) et 7772 (WebSocket). Rechargement à chaud via `GetCertificate` sans redémarrage. Port 7771 (admin) : HTTP en clair si loopback, TLS obligatoire si non-loopback (`ADMIN_TLS=true`), ou dérogation explicite `ADMIN_INSECURE_HTTP=true` + `ADMIN_INSECURE_HTTP_ACK=i-understand-the-risk` (warning à chaque démarrage).
- **Journal des actions de hooks masqué (#161)** : `action_log` (SQLite) remplacé par un journal JSON Lines append-only `actions.log` (`RELAY_ACTION_LOG`, défaut `STATE_DIR/actions.log`), sans fsync par ligne, rotation par taille (10 Mio × 5). Le `config_snapshot` ne contient plus aucun secret (masquage systématique des HMAC, tokens et en-têtes d'authentification).
- **Commandes de diagnostic et reprise d'état (#187)** : `secagent-server state verify` (vérifie intégrité HMAC, schema, invariants sans écrire), `secagent-server state restore --from` (restauration atomique d'une copie préalablement vérifiée, avec garde verrou vivant et min-write-seq).
- **Listes d'adresses multi-instances (#164-168)** : agents, plugins et inventaire supportent listes d'adresses ; relay aussi en mode pull/push. Client try-first, roundrobin, distinction « avant envoi » / « après envoi ». Variante DNS supportée nativement.

### Changed
- **TLS_DISABLE=true (tests seul)** — option pour les tests, sinon TLS obligatoire
- **Ports 7770/7771/7772 clarifiés** : 7770 = API publique + `/ws/agent` + `/ws/relay` (compat), 7771 = admin jamais exposé, 7772 = WebSocket (option historique, redondance 7770)

### Added (CI/CD, qualification et déploiement — #170, #171, #174, #188)
- **Chaîne de qualification en conteneurs (#188)** : `DEPLOYMENT/qualif/docker-compose.chain.yml` (racine actif/passif incluse depuis `docker-compose.server.yml`, un relay enfant pull `secagent-child`, deux minions `minion-root` et `minion-child`, listes d'adresses, `REPEATER_CA_FILE` / `RELAY_CA_BUNDLE`, aucun `build:`, aucun `latest`, aucune désactivation de la vérification TLS). Pilotée par `DEPLOYMENT/qualif/chain-test.sh` (`ci-prepare`, `bootstrap`, `smoke`, `failover`, `backup-restore`, `logs`, `down`) et `pki/gen.sh` (CA privée de test, un certificat à SAN multiples, clés non versionnées). Le jeton plugin est écrit dans un fichier 0600 et n'est jamais affiché. Limites assumées : poste de contrôle Ansible = le poste ou le runner qui lance le script (aucune image Ansible n'est publiée) ; enfant push non déployé ; enfant pull en une seule instance ; un seul certificat pour toutes les instances.
- **Jobs CI (`ci.yml`, à chaque push, sans aucune publication)** : « Chaîne en conteneurs » (amorçage, smoke, bascule de la racine), « Sauvegarde et restauration » (`relay.state` et `RSA_MASTER_KEY` sauvegardés séparément, perte du volume ; `state verify` sans clé code 6, mauvaise clé code 2 ; restauration sur volume vierge, minion déjà enrôlé reconnecté sans nouveau jeton), « Répétition à vide de l'archive Compose » (digest factice, archive reproductible vérifiée par comparaison, `SHA256SUMS`, rendu Compose et `check_compose.py` sur l'archive extraite, cas négatifs `latest` / NATS / digest invalide) et « Reproductibilité » (deux builds OCI locaux par image, comparaison des digests, avertissement et couches en cas d'écart). Garde `grep` anti-obsolètes sur `DEPLOYMENT/`.
- **Workflows manuels (#174)** : `candidate-images.yml` (`workflow_dispatch`, entrées `ref` et `publish=true`) publie les images serveur et minion candidates `sha-<commit>@sha256:<digest>` pour la qualif ; `failover.yml` rejoue la bascule en conteneurs avec les vraies péremptions (`docker kill`, processus figé), planifié et manuel. `check_no_publish.py` ne s'applique qu'à `ci.yml`. **Limite connue** : GitHub n'expose `workflow_dispatch` et `schedule` que pour les workflows présents sur la branche par défaut (`main`) ; tant que ces deux fichiers n'y sont pas, ils ne sont pas lançables (la branche `ci/enable-failover-candidate-workflows` prépare cette activation, `schedule` commenté jusqu'à la fusion de v3.0.3).
- **Images `linux/amd64` uniquement (#174 M9)** : `candidate-images.yml` et `release.yml` ne publient que cette plate-forme ; aucune image arm64 en v3.0.3.
- **Archive Compose de release (#174)** : `scripts/ci/build_compose_archive.sh`, script partagé par `release.yml` et la répétition à vide ; archive `secagent-compose-<version>.tar.gz` reproductible, `image:` réécrite en `tag@sha256`, incluse dans `SHA256SUMS`.
- **Tests Ansible async D1-D4 en CI (#171 D)** : `ansible-playbook` réel + plugin réel + minion réel (`internal/integration/ansible_async_test.go`) — D1 `async`+`poll`, D2 fire-and-forget puis `async_status`, D3 arrêt propre du maître (job conservé ; variante `poll: 1` en vol), D4 `kill -9` (2 jobs lus après la reprise, un seul exécuté chacun). Le job « Inventaire Ansible » a un `timeout-minutes: 20`, un venv `ansible-core` + `httpx` épinglés, exige le `PASS` de D1-D4 et interdit tout skip Ansible. **Constat D3** : un `poll` en vol pendant l'arrêt propre peut échouer sans rejeu ; les `poll` suivants atteignent le nouveau maître grâce à la liste d'adresses du plugin.
- **Job d'artefact d'images (`images-artifact`, push uniquement)** : images serveur et minion exportées (`docker save | gzip -n`), binaire `secagent-inventory` linux/amd64, `images.env`, `SHA256SUMS`, en artefact de run `secagent-images-<sha>` conservé 7 jours ; aucun login, push ni `packages: write`.
- **Qualification sans registre** : `chain-test.sh load-images <dir>` (vérifie `SHA256SUMS` puis `docker load`) ; les Compose lisent `pull_policy: ${SECAGENT_PULL_POLICY:-missing}` (`never` pour les images chargées localement) ; `check_compose.py` accepte un tag local en qualif et exige `tag@sha256:<64 hex>` avec `--require-digest` (appliqué à l'archive de release).
- **Mode hôte Docker distant et garde-fous de projet** : projet unique `secagent-qualif` pour la chaîne et les tests de basculement ; `TLS_MODE=volume` + `chain-test.sh push-tls` (certificats dans le volume nommé `secagent-qualif_tls`, sans bind mount) ; `SECAGENT_ENDPOINT_HOST` / `CONTROL_HOST` pour joindre l'hôte distant ; `guard_project` refuse `down`, `teardown` et `backup-restore` sur un hôte distant hors projet `secagent-qualif`, ou si `COMPOSE_PROJECT_NAME` diffère du projet.
- **`PKI_EXTRA_SAN`** (`pki/gen.sh`) : SAN supplémentaires validés (ex. `IP:192.168.1.218,DNS:qualif.lan`) dans le certificat de test ; défaut vide, CI inchangée. `pki/gen.sh` refuse en outre d'écrire des clés dans un dépôt git qui ne les ignore pas.
- **Sauvegarde/restauration par volume nommé** : `backup-restore` passe par un volume `<projet>_backup` alimenté par un flux tar (plus de bind mount local), donc compatible avec un démon Docker distant ; volume supprimé en fin d'opération.

### Fixed (CI/CD)
- **Contrôle NATS de la release** : il scannait aussi `tools/check_compose.py` (qui contient le mot « nats ») et aurait fait échouer la première vraie release ; le contrôle exclut désormais `tools` (corrigé dans `build_compose_archive.sh`).

### Removed (déploiement — #188)
- Compose `qualif/docker-compose.{proxy,minion,ansible}.yml`, `smoke-proxy.sh`, `smoke_test.py`, `Dockerfile.mock`, `Dockerfile.smoke`, `mock_server.py`, `test_plugins.sh`, `.env.proxy`, `DEPLOYMENT/deploy.sh` et `deploy.bat`, `scripts/bootstrap-qualif.sh`, `GO/Dockerfile.ansible` et `DEPLOYMENT/ANSIBLE_DEPLOYMENT.md`. Remplacés par la chaîne ci-dessus.

### Removed
- **NATS JetStream retiré du serveur et du déploiement (#178)** : aucun usage fonctionnel (l'exec passe par WebSocket direct), aucune perte. Suppression de `internal/broker`, de `GO/nats.conf`, des services/volumes `nats*` des Compose hors prod, des dépendances `nats-io` du `go.mod`. `NATS_URL` encore définie : un seul `[WARN] NATS_URL is obsolete and ignored`, démarrage normal.
- **[BREAKING]** `GET /api/admin/status` et `secagent-server server status` ne renvoient plus le champ `nats`.
- **Kubernetes et Helm retirés (#170, #157)** : déploiement cible = Docker Compose multi-hôtes actif/passif (prod). Helm et K8s ne sont plus cibles supportées.
- **Caddy et scripts deploy.sh / deploy.bat retirés (#174, #188)** : TLS natif dans le serveur ; Compose sans reverse proxy ; déploiement par Compose direct.

### Security
- **#192** : `POST /api/token/refresh` supprimée (404 pour tout appelant) — aucun client, et elle contournait la révocation / remplaçait le JTI d'un agent sans l'authentifier (v1.0.0 à v2.0.0). Le JWT se renouvelle par ré-enrôlement (401) ou message `rekey`.
- **#193** : seconde porte de contournement fermée — un agent révoqué ne peut plus se ré-enrôler avec un jeton réutilisable ou à pattern large (drapeau persistant, voir Breaking changes).
- **#192c** : `POST /api/register` sans `enrollment_token` refusé (`403 enrollment_token_required`, identique quels que soient hostname et clef). Le flux « clef pré-autorisée » est supprimé ; `authorized_keys` n'est plus consultée à l'enrôlement.
- **#191** : le plugin Ansible n'accepte plus qu'un fichier de jeton **régulier, appartenant à l'utilisateur effectif et en mode 0600/0400** ; lien symbolique (`O_NOFOLLOW`), FIFO, socket et périphérique sont refusés (aucune requête envoyée, jamais le jeton dans le message). `O_NOFOLLOW` ne protège que le dernier composant du chemin : protéger le répertoire parent.
- **#169** : `/ws/agent` refuse (401, avant l'upgrade) un JTI blacklisté, remplacé ou un agent inconnu ; fail closed. Bearer obligatoire, pas de repli `?hostname=`.
- **#177** : `X-Forwarded-For` n'est pris en compte que derrière `TRUSTED_PROXY_CIDRS` (vide par défaut = ignoré).
- **#173** : `agents.suspended` appliqué à exec/upload/fetch (503 `agent_suspended`, relayé par les parents).
- **#176** : suppression de `completedResults` et de `GET /api/async_status/{task_id}` (map sans mutex, non bornée, sans appelant en production).
- **#175b** : port 7771 (admin) refuse HTTP en clair si non-loopback, sauf dérogation explicite.

### Breaking changes (v3.0.3, en plus de la migration d'état)
- **Révocation persistante d'un agent (#193)** : la révocation pose un drapeau `revoked` dans l'état (même écriture que la blacklist, `schema_version` inchangé, champ optionnel). Un hôte révoqué est refusé à l'enrôlement (`403 agent_revoked`, jeton non consommé, même réutilisable), au `rekey` et au handshake WS, sans limite de durée. Levée explicite : `DELETE /api/admin/minions/{hostname}` (pas de `unrevoke`). **⚠ Retour arrière** : un binaire antérieur refuse un état contenant `"revoked": true` (décodeur strict). Révocations antérieures : réparées au démarrage du maître tant que la blacklist (25 h) les contient, les plus anciennes doivent être refaites.
- `POST /api/token/refresh` n'existe plus (404). Aucun client du dépôt ne l'utilisait.
- `POST /api/register` sans `enrollment_token` répond 403 `enrollment_token_required` : tout enrôlement exige un jeton `secagent_enr_…` (`secagent-server tokens create --role enrollment`). `POST /api/admin/authorize` et `minions authorize` subsistent mais ne donnent plus aucun droit d'enrôlement.
- Plugin de connexion : le **fichier de jeton par défaut est `/etc/ansible/secagent_plugin.jwt`** (plus de repli sur `/tmp`) et doit être en `0600` (ou `0400`), appartenir à l'utilisateur d'Ansible et ne pas être un lien symbolique ni un fichier spécial : **un fichier de jeton existant en 0644 est désormais refusé** (`chmod 600`).

### Fixed
- **Plugin de connexion : variables d'hôte et `[secagent_connection]` ignorées** : la classe s'appelait `ConnectionPlugin` ; Ansible déduit le type du plugin du nom de la classe, `get_option()` échouait et seul `RELAY_*` était lu. Classe renommée `Connection` (`ConnectionPlugin` reste un alias). Ordre de priorité désormais effectif, pour `server`, `token_file`, `ca_bundle`, `timeout`, `connect_timeout`, avec les deux modes de chargement : variable d'hôte `ansible_secagent_*` > `RELAY_*` > `[secagent_connection]` > défaut. **Changement de comportement : une variable d'hôte passe désormais avant l'environnement** (un `ansible_secagent_server` ou `ansible_secagent_token_file` d'inventaire, jusque-là sans effet, s'applique maintenant).
- **#190** : plugin de connexion — le `stdin` de `exec_command` est envoyé en **base64** des octets bruts (champ omis s'il n'y a pas de données), comme le serveur et le minion l'attendent ; auparavant le stdin n'arrivait pas à la commande (0 octet reçu : `python3 -` ne produisait rien).
- **#192 (audit)** : un message WS `rekey` n'est plus envoyé si le nouveau JTI n'a pas pu être persisté (l'agent aurait reçu un jeton refusé au handshake suivant).
- Les binaires précompilés `*.exe` ne sont plus suivis par git (`.gitignore`).

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
