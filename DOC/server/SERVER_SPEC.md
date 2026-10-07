# secagent-server — Spécifications techniques

> Référence complète pour le composant secagent-server (GO).
> Source canonique : `DOC/common/ARCHITECTURE.md` §2, §5, §6, §15, §20, §21, §22
> Sécurité : `DOC/security/SECURITY.md` §2 (rôles), §5 (rotation), §6 (tokens plugin)
> **Contrats d'interface** : `DOC/contracts/REST_PLUGIN.md` · `DOC/contracts/REST_ENROLLMENT.md` · `DOC/contracts/REST_ADMIN.md` · `DOC/contracts/WEBSOCKET.md` · (`DOC/contracts/NATS.md` : déprécié, NATS retiré en v3.0.3)

---

## 1. Rôle et périmètre

Le secagent-server est le **hub central** du système. Il :
- Expose une API REST HTTPS pour les plugins Ansible
- Maintient les connexions WebSocket avec les agents
- Route les tâches par WebSocket direct (actif/passif HA avec verrou exclusif)
- Gère l'authentification (JWT agents, tokens plugin, ADMIN_TOKEN)
- Expose une CLI d'administration (même binaire, mode cobra)

### Blocs internes (GO)

```
GO/cmd/secagent-server/
├── main.go                          — ports 7770/7771/7772, injection secrets JWT
├── internal/
│   ├── handlers/
│   │   ├── register.go              — POST /api/register (enrollment agent)
│   │   ├── exec.go                  — POST /api/exec|upload|fetch/{hostname}
│   │   ├── inventory.go             — GET /api/inventory (jeton plugin) et variante admin
│   │   ├── plugin_auth.go           — authentification des jetons plugin (IP, hostname)
│   │   ├── admin.go, admin_relays.go, admin_tokens.go — endpoints /api/admin/*
│   │   └── security.go              — rotation des clefs, blacklist
│   ├── ws/
│   │   ├── handler.go               — WSS /ws/agent, ws_connections map
│   │   ├── relay_handler.go         — WSS /ws/relay (liens relay ↔ relay)
│   │   └── jwt.go                   — validation dual-key JWT HMAC-HS256
│   ├── lock/                        — verrou actif/passif (relay.lock)
│   ├── state/
│   │   └── engine.go, file.go, model.go … — fichier d'état JSON (HMAC-SHA256, secrets AES-256-GCM, write_seq anti-rejeu)
│   ├── storage/
│   │   └── store.go                 — interface storage sur state engine (pas de SQLite, aucun CGO)
│   └── cli/
│       ├── root.go                  — cobra root command
│       ├── minions.go               — secagent-server minions *
│       ├── security.go              — secagent-server security keys|tokens|blacklist *
│       ├── tokens.go, relays.go, hooks.go — tokens *, relays *, hooks *
│       ├── state.go, state_tools.go, status_local.go — state init|verify|restore, status --local
│       ├── inventory.go             — secagent-server inventory list
│       └── server.go                — secagent-server server status|stats
```

---

## 2. Architecture des ports

| Port | Exposition | Rôle |
|---|---|---|
| `7770` | Publique (WSS/TLS natif) | API REST agents + plugins + enrollment + `/ws/agent` |
| `7771` | **Admin seulement** — défaut `:7771` (toutes interfaces) ; une adresse non loopback exige `ADMIN_TLS=true` (ou `ADMIN_INSECURE_HTTP` + `ADMIN_INSECURE_HTTP_ACK`), sinon le serveur refuse de démarrer (`server/tls.go` `adminExposure`) | Endpoints admin CLI + API admin |
| `7772` | Publique (TLS natif) | Listener WebSocket dédié : `/ws/agent` et `/ws/relay` (`server/routers.go`) ; port par défaut de `RELAY_WS_URL` du minion. Pas déprécié |

Le port 7771 ne doit **jamais** être publié sur une interface publique (hôte : boucle locale ou réseau d'administration). Seul le **maître** ouvre ces ports ; un secondaire n'en ouvre aucun (§10).

---

## 3. API REST — Endpoints

### Authentification

| Endpoint | Auth requise |
|---|---|
| `POST /api/register` | Aucune en-tête ; **jeton d'enrôlement** `secagent_enr_…` obligatoire dans le body (sans lui : 403 `enrollment_token_required`, #192c) |
| `GET /api/inventory` | `Bearer <jeton plugin>` (`secagent_plg_…`) — un `ADMIN_TOKEN` y est refusé (403) ; la variante admin est `GET /api/inventory` sur 7771 |
| `POST /api/exec/{host}` | `Bearer <jeton plugin>` |
| `POST /api/upload/{host}` | `Bearer <jeton plugin>` |
| `POST /api/fetch/{host}` | `Bearer <jeton plugin>` |
| `POST /api/token/refresh` | **Supprimée (#192)** : 404 pour tout appelant ; le renouvellement passe par le ré-enrôlement (401) ou le message WS `rekey` |
| `/api/admin/*` | `Bearer <ADMIN_TOKEN>` (port 7771 ; `POST /api/admin/authorize` aussi sur 7770 par compatibilité) |
| `WSS /ws/agent` | `Bearer <JWT agent>` (rôle `agent` uniquement) |
| `WSS /ws/relay` | `Bearer <jeton de lien EdDSA, rôle `relay-child` (pull) ou `relay-parent` (push)>`, signé par la racine (v3.0.4, [BREAKING]) |

Les jetons plugin et d'enrôlement sont des **jetons opaques** (`secagent_plg_` / `secagent_enr_` + 64 hex), enregistrés (hachés) dans l'état — pas des JWT. Preuve : `handlers/plugin_auth.go`, `handlers/inventory.go`.

### `POST /api/register` — Enrollment agent (multi-étapes)

**Étape 1 — Initiation :**
```json
Requête : { "hostname": "host-A", "public_key_pem": "...", "enrollment_token": "secagent_enr_..." }
Réponse : { "challenge": "<OAEP(nonce, agent_pubkey) base64>", "server_public_key_pem": "..." }
```

**Étape 2 — Vérification :**
```json
Requête : { "hostname": "host-A", "public_key_pem": "...", "enrollment_token": "secagent_enr_...",
            "challenge_response": "<OAEP(nonce+token, server_pubkey) base64>" }
Réponse : { "jwt_encrypted": "<OAEP(jwt, agent_pubkey) base64>", "token_encrypted": "<même valeur>", "server_public_key_pem": "..." }
```

Le jeton d'enrôlement est revalidé à **chaque** étape. Preuve : `handlers/register.go` (`RegisterRequest`, `ChallengeResponse`, `RegisterResponse`, `registerAgentWithToken`).

**Codes d'erreur** (`handlers/register.go`) :
- `403` : `enrollment_token_required` (requête sans jeton : aucun JWT, aucun JTI posé, réponse identique quels que soient hostname et clef), `token_not_found`, `token_expired`, `token_already_used`, `hostname_not_allowed`, challenge expiré ou invalide (`challenge_*`) (`handlers/register.go:462-475`, `validateEnrollmentToken`)
- `400` : `invalid_request`, `missing_fields`, `invalid_public_key`
- `500` : `db_error`

Un refus `403` est **permanent** pour le minion (exit 78, pas de retry : voir `DOC/contracts/REST_ENROLLMENT.md`).

### `POST /api/exec/{hostname}` — Exécution (bloquant)

```json
Requête : {
  "task_id": "uuid-v4",          // optionnel (généré si absent)
  "cmd": "python3 /tmp/.ansible/tmp/module.py",
  "stdin": "<chaîne|null>",      // transmise telle quelle à l'agent
  "timeout": 30,
  "become": false,
  "become_method": "sudo"
}
Réponse 200 : { "rc": 0, "stdout": "...", "stderr": "", "truncated": false }
Réponse 503  : { "error": "agent_offline" | "agent_disconnected" | <agent suspendu / état indisponible> }
Réponse 504  : { "error": "task_timeout" }
Réponse 429  : { "error": "agent_busy" }
Réponse 500  : { "error": "<erreur renvoyée par l'agent>" }
Réponse 508  : { "error": "relay_loop_detected" }
```

Preuve : `handlers/exec.go` (`writeAgentError`, lignes 232-244 ; `task_timeout` ligne 353). Upload : en plus `400 invalid_base64`, `413 payload_too_large` (`handlers/exec.go:404`).

### `POST /api/upload/{hostname}` — Transfert fichier

```json
Requête : { "task_id": "uuid", "dest": "/tmp/module.py", "data": "<base64>", "mode": "0700" }
Réponse : { "rc": 0 }
```

### `POST /api/fetch/{hostname}` — Récupération fichier

```json
Requête : { "task_id": "uuid", "src": "/etc/myapp/config.yml" }
Réponse : { "rc": 0, "data": "<base64>" }
```

### `GET /api/inventory`

```json
{
  "all": { "hosts": ["host-A", "host-B"] },
  "_meta": {
    "hostvars": {
      "host-A": {
        "ansible_connection": "relay",
        "ansible_host": "host-A",
        "secagent_status": "connected",
        "secagent_last_seen": "2026-03-06T10:00:00Z"
      }
    }
  }
}
```

Query param : `?only_connected=true`

---

## 4. Dispatch des tâches (WebSocket direct)

NATS JetStream est **retiré** (v3.0.3). Le plugin envoie un `POST /api/exec|upload|fetch/{host}` bloquant au relay **maître** ;
celui-ci écrit la tâche sur la WebSocket persistante de l'agent (multiplexage par `task_id`) et attend le résultat. Pour un hôte
situé sous un relay enfant, la tâche est transmise (`task_forward`) le long de la chaîne de relays (§9). Il n'y a ni file, ni
persistance de tâche : une requête en cours pendant une bascule échoue (le plugin ne rejoue pas, #168).

---

## 5. Persistance — fichier d'état `relay.state`

Il n'y a **plus de SQL** (SQLite retiré en v3.0.3, #159/#160). Les données permanentes sont dans le fichier d'état unique
`relay.state` (JSON, authentifié HMAC-SHA-256, secrets chiffrés AES-256-GCM) : voir `DOC/server/STATE_SPEC.md`. Sections du fichier
(`internal/state/model.go`, `Payload`) :

| Section | Contenu |
|---|---|
| `agents` | hostname, `public_key_pem`, `token_jti`, `enrolled_at`, `suspended`, `vars`, `last_seen` |
| `authorized_keys` | hostname, `public_key_pem`, `approved_at`, `approved_by` — écrite par l'enrôlement (`EnrollAgent`) et par `POST /api/admin/authorize` ; **n'est plus consultée par `/api/register`** (#192c) |
| `enrollment_tokens` | id, `token_hash` (SHA-256), `hostname_pattern`, `reusable`, `use_count`, `expires_at`, `created_by` |
| `plugin_tokens` | id, `token_hash`, `description`, `role`, `allowed_ips`, `allowed_hostname_pattern`, `expires_at`, `revoked`, `last_used_at/ip` |
| `relay_parent_tokens` | id, `jti`, `parent_id`, `expires_at`, `revoked_at` (jamais le token) |
| `blacklist` | `jti`, `hostname`, `revoked_at`, `reason`, `expires_at` (purge automatique) |
| `relay_nodes` | configuration d'un relay enfant : `relay_id`, `urls`, `mode` (pull/push), `jti`, `token_exp`, `revoked`, `group_vars`, `token_hash`/`token_secret` (secret chiffré `enc:`) |
| `server_config` | secrets chiffrés : `jwt_secret_current`, `jwt_secret_previous`, `key_rotation_deadline`, clefs RSA du serveur |

Les regexp `hostname_pattern` / `allowed_hostname_pattern` sont validées et ancrées `^(?:pattern)$` à la création (400 `invalid_hostname_pattern` si invalide).

Données volatiles (statut et `last_seen` des agents et relays, routage `relay_routing`, `relay_chain`, `last_used_*` des tokens plugin) : en mémoire seulement ; `last_used_at` / `last_used_ip` des tokens plugin sont **approximatifs** (persistés avec la prochaine écriture du fichier, donc en retard de plusieurs minutes, voire perdus lors d'un arrêt brutal : l'API les signale par `last_used_approximate: true`).

---

## 6. Rotation des clefs (dual-key JWT)

> Protocole complet : `DOC/security/SECURITY.md` §5

```bash
# Déclencher une rotation
secagent-server security keys rotate --grace 24h

# Pendant grace_period : jwt_secret_previous et jwt_secret_current tous deux valides
# Après deadline : jwt_secret_previous = nil, JTIs pré-rotation blacklistés
# Les agents reçoivent WS message {type: "rekey"} → ré-enrollment automatique
```

Validation JWT dual-key (dans `ws/jwt.go`) :
1. Tente `jwt_secret_current`
2. Si échec ET `now < key_rotation_deadline` → tente `jwt_secret_previous`
3. Si échec → reject 401

---

## 7. CLI d'administration

> Specs complètes : `DOC/server/MANAGEMENT_CLI_SPECS.md`

```bash
# Depuis le container du maître (la CLI lit ADMIN_TOKEN dans son environnement ; RELAY_API_URL = liste d'adresses admin)
docker exec <conteneur-du-maitre> secagent-server <commande>

# Minions
secagent-server minions list [--format table|json|yaml]
secagent-server minions get <hostname>
secagent-server minions authorize <hostname> --key-file <clef_publique.pem>   # mémorise une clef dans authorized_keys ; ne donne AUCUN droit d'enrôlement (créer un jeton : tokens create --role enrollment)
secagent-server minions revoke <hostname>
secagent-server minions suspend <hostname>
secagent-server minions resume <hostname>
secagent-server minions set-state <hostname> connected|disconnected
secagent-server minions vars get <hostname> | set <hostname> key=value [key=value…] | delete <hostname> <key>

# Tokens
secagent-server tokens create --role enrollment --hostname-pattern "vp.*" [--reusable] --expires 30d
secagent-server tokens create --role plugin --description "..." --allowed-ips "..." --allowed-hostname-pattern "..." --expires 365d   # --expires : défaut never
secagent-server tokens create --role relay-child --sub <enfant> --aud <parent> [--expires 720h]    # v3.0.4 : RACINE seulement (409 not_root ailleurs), jeton EdDSA
secagent-server tokens create --role relay-parent --sub <parent> --aud <enfant> [--expires 720h]   # idem (plus minté par l'enfant)
secagent-server tokens list [--role plugin|enrollment|relay-child|relay-parent|all]
secagent-server tokens revoke <id>      # jeton de lien : revoked_at + blacklist du JTI + seq++ + fermeture 4010 du lien + push link_revocations

# Clé de signature des liens (racine, v3.0.4)
secagent-server keys link-pubkey            # clé PUBLIQUE PEM à épingler (REPEATER_ROOT_LINK_KEY_FILE)
secagent-server keys rotate-link
secagent-server keys retire-link-previous [--force]    # bloqué tant que des relays n'ont pas confirmé la rotation (R2)
secagent-server keys link-status
secagent-server tokens delete <id>
secagent-server tokens purge [--expired] [--used]     # au moins un des deux

# Sécurité
secagent-server security keys status
secagent-server security keys rotate [--grace 24h]
secagent-server security tokens list
secagent-server security blacklist list
secagent-server security blacklist purge

# Inventaire
secagent-server inventory list [--only-connected]

# Serveur
secagent-server server status [--format json]
secagent-server server stats
secagent-server status --local            # santé locale (fichier de statut), sans API : healthcheck du conteneur

# Relays enfants / hooks / état
secagent-server relays add|list|remove|status      # voir §9.3
secagent-server hooks status|log
secagent-server state init|verify <fichier>|restore --from <fichier>   # voir STATE_SPEC.md
```

---

## 8. Variables d'environnement

| Variable | Requis | Description |
|---|---|---|
| `JWT_SECRET_KEY` | ✅ | Secret HMAC-HS256 pour signer les JWT agents |
| `ADMIN_TOKEN` | ✅ | Token admin (port 7771) |
| `NATS_URL` | — | **Obsolète (#178)** : NATS est retiré ; si la variable est définie, un `[WARN]` est journalisé et elle est ignorée |
| `STATE_DIR` | — | Répertoire du fichier d'état `relay.state` (défaut `/data`), créé par `secagent-server state init` — voir `STATE_SPEC.md` (#160) |
| `STATE_MAX_BYTES` | — | Plafond dur de taille du fichier d'état (défaut 64 Mio) |
| `DATABASE_URL` | — | **Retirée (#160)** : SQLite n'existe plus. Si la variable est définie, le serveur **refuse de démarrer** (aucune migration d'un ancien `relay.db`) |
| `RSA_MASTER_KEY` | ✅ en production | Secret (chaîne, pas une clef RSA) dont dérivent le HMAC du fichier d'état et le chiffrement AES-256-GCM des secrets ; exigé par `state init` (sauf `--insecure-test-mode`) et par le serveur ; identique sur tous les nœuds candidats |
| `REPEATER_ID` | — | Identifiant du relay (ex: `dmz1`) — requis en mode enfant |
| `REPEATER_UPSTREAM_URL` | — | URL WSS du parent (ex: `wss://central:7772`) — requis en mode enfant pull. Liste séparée par des virgules (une adresse par instance du parent, `wss://` uniquement, 16 max) : essayées dans l'ordre, la dernière qui a répondu en premier ; un échec avant envoi passe à l'adresse suivante, un échec après envoi de la requête d'upgrade ne rejoue pas sur une autre |
| `REPEATER_UPSTREAM_TOKEN` | — | Token JWT du relay enfant (rôle `relay`, émis par `relays add` sur le parent) — requis en mode enfant pull |
| `RELAY_GROUP_VARS` | — | Variables Ansible JSON injectées pour ce relay (ex: `{"env":"prod"}`) |
| `API_ADDR` | — | Adresse d'écoute de l'API publique + WS agent/relay (défaut `:7770`) |
| `ADMIN_ADDR` | — | Adresse d'écoute de l'API admin (défaut `:7771`) — ne jamais l'exposer publiquement ; les handlers admin ne sont servis que sur cette adresse (sauf `POST /api/admin/authorize`, par compatibilité) |
| `WS_ADDR` | — | Adresse d'écoute WebSocket (défaut `:7772`) |
| `TLS_CERT` / `TLS_KEY` | ✅ | Certificat (chaîne complète) et clef PEM : TLS natif sur 7770/7772 (et 7771 avec `ADMIN_TLS=true`). Sans paire complète et sans `TLS_DISABLE`, le serveur refuse de démarrer |
| `TLS_DISABLE` | — | `true` = HTTP clair : tests/CI uniquement, jamais en production (booléen strict `true`/`false`) |
| `ADMIN_TLS` | — | `true` = l'API admin sert TLS (requis si `ADMIN_ADDR` n'est pas loopback) |
| `ADMIN_INSECURE_HTTP` / `ADMIN_INSECURE_HTTP_ACK` | — | Dérogation HTTP clair non loopback : `true` **et** `i-understand-the-risk` |
| `RELAY_STATUS_FILE` | — | Fichier de statut local (défaut `/run/secagent/status.json`), hors `STATE_DIR` |
| `RELAY_ACTION_LOG` | — | Chemin du journal des actions de hooks (défaut `STATE_DIR/actions.log`) |
| `TRUSTED_PROXY_CIDRS` | — | CIDR des reverse proxies dont `X-Forwarded-For` est cru (vide = jamais) |
| `RELAY_API_URL` | — | (CLI) liste d'adresses de l'API admin, séparées par des virgules |
| `MAX_SNAPSHOT_RELAYS` | — | Limite nombre relays dans topology_snapshot (défaut 1000) |
| `MAX_SNAPSHOT_HOSTS` | — | Limite nombre hôtes dans topology_snapshot (défaut 10000) |
| `MAX_AGENT_LIST_HOSTS` | — | Limite nombre hôtes dans agent_list par appel (défaut = MAX_SNAPSHOT_HOSTS = 10 000) |
| `MAX_TASKS_PER_AGENT` | — | #179 : tâches simultanées par agent sur ce relay (défaut `10`) ; au-delà : `429 agent_busy`, rien n'est envoyé à l'agent |
| `MAX_TASKS_INFLIGHT` | — | #179 : tâches en vol sur ce relay, tâches relayées (`relayPendingTasks`) comprises (défaut `1000`) ; au-delà : `429 too_many_tasks` |
| `MAX_STDOUT_BUFFER_TOTAL` | — | #179 : budget mémoire global des tampons stdout, en octets (défaut `1073741824` = 1 Gio). Chaque tâche admise **réserve 5 Mo à l'admission** (`(tâches en vol + 1) × 5 Mo ≤ budget`, tâches relayées comprises), sans attendre l'arrivée du stdout : avec le défaut de 1 Gio, au plus **204 tâches simultanées** par relay, quel que soit `MAX_TASKS_INFLIGHT` ; si le budget restant est inférieur à 5 Mo : `503 memory_budget_exhausted` à l'admission. La troncature (`truncated: true`) reste le dernier recours si un tampon dépasse 5 Mo en cours de route. Sauf `GOMEMLIMIT` défini par l'opérateur, le serveur fixe une limite mémoire souple du runtime Go à `budget + 768 Mo` (les messages WebSocket décodés produisent des déchets proportionnels aux tampons) |
| `MAX_WS_MESSAGE_SIZE_RELAY` | — | Taille maximale message WebSocket relay (défaut 10MB) |
| `RELAY_HOOKS_MAX_CONCURRENT_ACTIONS` | — | Nombre de workers des hooks (défaut `64`) — voir §9.7a |
| `RELAY_HOOKS_QUEUE_SIZE` | — | Taille de la file des hooks (défaut `10000`) — voir §9.7a |
| `RELAY_INSECURE_TLS` | — | **Pas une variable du serveur** : lue par `secagent-inventory` (voir INVENTORY_SPEC §3) et par le minion. Pour `secagent-inventory`, une adresse non loopback exige `RELAY_INSECURE_TLS_ACK=i-understand-the-risk` |

---

## 9. Mode Repeater — Arbre Hiérarchique (v3.0.1)

> Architecture complète : `DOC/common/ARCHITECTURE.md` §23

**Changements v3.0.0** :
- Suppression de `REPEATER_UPSTREAMS_FILE` (YAML) — utiliser variables d'environnement simples
- Suppression du mode push REST → WebSocket uniquement (WSS persistant)
- Topologie : arbre strict (un parent max par relay enfant)
- Un seul upstream par relay enfant (pas de multi-upstream)
- Deux modes d'ouverture de connexion : enfant ouvre vers parent (variables REPEATER_UPSTREAM_URL/TOKEN) ou parent ouvre vers enfant (API admin)
- Inventaire : chaque relay expose TOUTE SA DESCENDANCE (agents + sous-relays)

### 9.1 Variables d'environnement (repeater-enfant)

| Variable | Requis | Description |
|---|---|---|
| `REPEATER_ID` | — | Identifiant du relay (`dmz1`) — requis en mode repeater enfant |
| `REPEATER_UPSTREAM_URL` | — | URL(s) WSS du parent (`wss://central:7772[,wss://central2:7772]`) — requise si enfant ouvre vers parent |
| `REPEATER_CA_FILE` | — | Bundle PEM des CA de confiance pour **tous les liens sortants** (lien pull vers le parent, dial-out push vers les enfants, CLI `secagent-server` vers l'API admin). Il **remplace** les CA système (rien d'autre n'est de confiance) ; il n'existe aucune option de non-vérification. Lu au démarrage (redémarrer pour le changer) ; fichier illisible, vide, > 1 Mio, contenant autre chose que des blocs `CERTIFICATE` (une clé privée est refusée) ou sans aucun certificat actuellement valide ⇒ le démarrage est refusé. |
| `REPEATER_UPSTREAM_TOKEN` | — | Token d'authentification du relay enfant — requis si enfant ouvre vers parent |
| `RELAY_GROUP_VARS` | — | Variables Ansible JSON injectées pour ce relay : `{"region":"dmz"}` |

**Mode pur serveur** (défaut, pas de parent) :
```bash
# REPEATER_ID absent → c'est la racine (pas de connexion upstream)
secagent-server
```

**Enfant ouvre vers parent** (configuration sur l'enfant) :
```bash
REPEATER_ID="dmz1"
REPEATER_UPSTREAM_URL="wss://central:7772"
REPEATER_UPSTREAM_TOKEN="${REPEATER_UPSTREAM_TOKEN_DMZ1}"
RELAY_GROUP_VARS='{"region":"dmz"}'
```

**Parent ouvre vers enfant** (parent enregistre enfant via API) : voir §9.3

---

### 9.2 WebSocket `/ws/relay` — Enfant-Parent

```
WSS /ws/relay
Authorization: Bearer <jeton de lien EdDSA : "relay-child" (enfant qui ouvre vers le parent, pull) ou "relay-parent" (parent qui ouvre vers l'enfant, push), sub=relay_id du porteur, aud=relay_id du vérificateur>
Port : 7772 (listener WebSocket dédié) ou 7770 (même handler, compatibilité)
```

**Jetons de lien (v3.0.4, [BREAKING] #141/#146).** `/ws/relay` n'accepte que des JWT **Ed25519** (`alg=EdDSA`) signés par la **racine**, vérifiés **uniquement** par `auth.VerifyLinkToken` (jamais le chemin HS256) : `alg` EdDSA seul, `kid` ∈ {`current`, `previous`} de l'ancre locale, `iss` = `relay_id` de la racine, **`aud` = `relay_id` local**, `role` selon le sens (`relay-child` : le pair est l'enfant, lien pull ; `relay-parent` : le pair est le parent, lien push), `exp`, `jti` non blacklisté. Le rôle `relay` (HS256) est supprimé et refusé (`link_role_legacy`). Le `sub` doit respecter `^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$` et un relay marqué `revoked` est refusé ; sinon refus **HTTP 401** `{"error":"<code>"}` avant l'upgrade (`link_token_malformed`, `link_alg_not_allowed`, `jwt_unknown_kid`, `jwt_missing_kid`, `jwt_wrong_issuer`, `jwt_missing_aud`, `jwt_wrong_aud`, `link_role_mismatch`, `link_role_legacy`, `link_token_expired`, `link_signature_invalid`, `link_token_revoked`).

**Nœud racine / non racine.** La racine n'a ni parent que le nœud ouvre (`REPEATER_UPSTREAM_URL`), ni ancre épinglée (`REPEATER_ROOT_ID`, `REPEATER_ROOT_LINK_KEY_FILE`, `link_trust` non vide). Un enfant en mode push n'a pas d'`UPSTREAM_URL` mais est ancré : c'est un nœud non racine (409 `not_root` au mint, vérification par l'ancre).

**Ancre de confiance.** La racine vérifie avec sa propre clé ; un relay non racine vérifie avec la clé publique racine épinglée (`REPEATER_ROOT_LINK_KEY_FILE`, PEM `PUBLIC KEY` exporté par `keys link-pubkey`) et l'identité racine `REPEATER_ROOT_ID`, persistées dans `link_trust`. **Sans ancre, un relay non racine refuse tout lien entrant** (S21) : upgrade puis **close `4010`** (raison `link_trust_missing`) et `[SECURITY WARNING]` (fail closed).

Délais (`repeater/client.go:40-46`, `ws/relay_handler.go`) : handshake 15 s ; heartbeat WebSocket (ping) 30 s ; `agent_list` toutes les 30 s ; lecture côté serveur : 120 s sans trafic coupe le lien ;
reconnexion de l'enfant : backoff exponentiel 5 s → 60 s.

#### Handshake — Séquence d'établissement (symétrique pour pull et push)

Le client WebSocket (celui qui ouvre) et le serveur (celui qui accepte) établissent la connexion via un handshake bloquant.

**Étape 1 — relay_hello (client → serveur)** :

Le client envoie son identité avec JWT(sub = son REPEATER_ID) :

```json
{"type":"relay_hello", "relay_id":"<client_id>", "ancestors":["parent","grandparent"], "version":"3.1"}
```

Serveur (récepteur) valide :
- ✅ `relay_hello.relay_id` présent ET `relay_hello.relay_id == jwt.sub` (identité du client)
- ✅ Détection de boucle : C ∉ {P} ∪ ancêtres(P) (voir ARCHITECTURE.md §23.2)
- ❌ Rejeter (close **4010** — refus permanent) si l'une de ces vérifications échoue (`relay_handler.go:891-900` enfant entrant, `1315-1335` lien parent)
- ❌ Close **4012** (corrigible) si le premier message n'est pas un `relay_hello` ou si `ancestors` dépasse 32 éléments (`relay_handler.go:1315-1326`) ; en mode pull, le serveur ne vérifie
  pas `ancestors` (le hello du client pull n'est contrôlé que sur `relay_id`)

**Étape 2 — relay_ack (serveur → client)** :

Le serveur répond avec SON identité et la liste de SES ancêtres :

```json
{"type":"relay_ack", "relay_id":"<server_id>", "ancestors":["parent_of_server"], "status":"ok", "timestamp":"..."}
```

**Validation côté client (l'ouvreur)** :
- ✅ Vérifier que `relay_ack.relay_id` correspond à l'identité ATTENDUE du serveur :
  - Mode pull : vérifier contre le parent configuré (REPEATER_UPSTREAM_URL) ou journaliser si première connexion
  - Mode push : vérifier contre `relay_nodes.relay_id` enregistré pour ce relay enfant
- ✅ Mémoriser `relay_ack.ancestors` pour usage dans event_forward (validation relay_chain)
- ❌ Fermer (close **4010** — refus permanent) si l'identité ne correspond pas ou a changé par rapport au lien précédent

**Étape 3 — topology_snapshot (depuis l'enfant)** :

C'est toujours l'enfant (le relay logiquement plus profond) qui envoie son sous-arbre complet :

```json
{
  "type":"topology_snapshot",
  "relays":[{"relay_id":"zone-a", "relay_chain":["dmz1","zone-a"]}],
  "agents":[
    {"hostname":"host-A", "relay_id":"dmz1", "relay_chain":["dmz1"]},
    {"hostname":"host-B", "relay_id":"zone-a", "relay_chain":["dmz1","zone-a"]}
  ]
}
```

Validation du snapshot :
- Pas de cycle (aucun relay_chain ne contient le REPEATER_ID du serveur)
- Pas de doublons hostname
- Nombre de relays ≤ `MAX_SNAPSHOT_RELAYS` (défaut 1000)
- Nombre d'hôtes ≤ `MAX_SNAPSHOT_HOSTS` (défaut 10000)
- Taille du message ≤ `MAX_WS_MESSAGE_SIZE_RELAY` (défaut 10MB)
- Rejeter (close **4012** — refus corrigible — + log) si validation échoue. Contrôles réels (`validateSnapshot`, `relay_handler.go:1395-1470`) : chaque `relay_chain` commence par l'enfant émetteur et se termine par le propriétaire
  (relay ou hôte), ≤ 32 éléments, IDs conformes, sans répétition ni identifiant de ce nœud ou de ses ancêtres ; pas de relay en double ; chaque hôte conforme à `hostnameShape`, sans doublon, rattaché à un relay déclaré
- Refus 4012 aussi : snapshot reçu avant `relay_hello`, **plus de 40 remplacements par 60 s** sur un lien (`relay_handler.go:79,1480-1492`), `group_vars` invalides, relay déjà déclaré par un autre pair ou connecté directement,
  **hôte connecté localement ou déjà routé via un autre pair** (`checkHostConflicts`, `relay_handler.go:354-376`) : un snapshot qui détournerait une route est **refusé**, il n'y a pas de « dernier arrivé gagne » pour les snapshots

**→ Après snapshot validé, la connexion est établie** (relay_nodes, relay_routing, inventaire initialisés)

**Ensuite — agent_list (périodique, heartbeat)** :
```json
{"type":"agent_list", "agents":[{"hostname":"host-A", "status":"connected", "last_seen":"..."}]}
```
Contient **uniquement les agents directs** du relay. Le serveur répond `agent_list_ack` (`count`). Hostnames mal formés ignorés ; liste > `MAX_AGENT_LIST_HOSTS` : close 4012
(`relay_handler.go:946-1005`). Entre relays, le dernier arrivé gagne (avec `host.conflict`), mais un agent connecté localement n'est jamais re-routé (§9.5a).

#### event_forward — Propagation des changements du sous-arbre

Après handshake établi, tous les changements (hôtes, relays) sont notifiés via `event_forward` unifié.

**Événements hôtes** :
```json
{
  "type":"event_forward",
  "event":"host.up|host.down|host.new",
  "hostname":"host-A",
  "relay_id":"dmz1",
  "status":"connected|disconnected",
  "relay_chain":["dmz1"],
  "timestamp":"..."
}
```

**Événements relays** (changements de topologie) :
```json
{
  "type":"event_forward",
  "event":"relay.updated",
  "relay_id":"zone-a",
  "relay_chain":["zone-a","dmz1"],
  "group_vars":{"region":"zone2"},
  "timestamp":"..."
}
```

**Ordre de `relay_chain` dans un `event_forward`** : **origine en premier, pair émetteur en dernier** (`relay_handler.go:1617-1633`) ; pour `relay.updated`, le premier élément est le relay décrit
(`eventShapeError`, `relay_handler.go:1692-1701`). Les snapshots utilisent l'ordre inverse (l'enfant émetteur en premier, le propriétaire en dernier).

**Design** : `event_forward` unifie tous les événements ascendants (hôtes et relays) avec des types distincts (`host.{up,down,new}`, `relay.updated`).

**Logique (topologie arbre, un seul chemin)** :
1. Événement local → transmis au parent par l'uplink, qui ajoute l'ID du relay à `relay_chain`
2. Le parent ajoute son ID à son tour et continue vers la racine
3. **Anti-boucle** : un event dont la chaîne contient l'ID du récepteur est ignoré ; un `event_forward` reçu **du parent** est ignoré et jamais renvoyé vers le haut (`repeater/uplink.go:310`)
4. **Pas de déduplication** : un seul chemin → un seul event
5. **Rate limit par lien** : 200 `event_forward` par seconde (`maxEventsPerSecond`, `relay_handler.go:84`) ; au-delà, les events sont **ignorés** (journalisés), le lien reste ouvert
6. Un event invalide (chaîne > 32, dernier élément ≠ pair authentifié, descendant inconnu, forme invalide, type inconnu, hôte hors du sous-arbre du pair) est **abandonné** sans fermer le lien (`handleEventForward`, `relay_handler.go:1599-1651`)

**Validation du relay_chain à la réception** : Voir ARCHITECTURE.md §23.2 (HAUT-1) pour la règle unifiée. Le code applique une seule règle : `relay_chain[-1]` == le pair authentifié du lien
(`jwt.sub` en pull, identité confirmée par `relay_ack` en push) ; les éléments précédents doivent être des descendants déclarés par ce pair dans son snapshot.

**Événement host.conflict** (détection de détournement de route) :
Quand un relay déclare un hôte dans `topology_snapshot` ou `agent_list` alors qu'il est déjà routé vers un autre relay :
```json
{
  "type":"event_forward",
  "event":"host.conflict",
  "hostname":"host-A",
  "old_relay":"relay-B",
  "new_relay":"relay-A",
  "relay_chain":["relay-A"],
  "timestamp":"..."
}
```
**Comportement** : pour un `agent_list` ou un `host.up`/`host.new` reçus d'un pair, le dernier arrivé gagne entre relays (reroute), **sauf** si l'hôte est un agent connecté localement : il n'est jamais re-routé.
Un `topology_snapshot` qui contredirait une route est refusé (4012), sans `host.conflict`. L'événement est émis une seule fois par changement de propriétaire et par lien (`reportConflictOnce`) ; un `host.conflict` détecté ici est aussi
remonté au parent, et déclenche les hooks `host.conflict` à chaque niveau (`server/server.go:343-353`). ⚠️ **Production** : configurer un hook d'alerte sur `host.conflict` pour détecter les mouvements de route suspects.

#### task_forward et dispatch vers enfant

```json
{
  "type":"task_forward",
  "task_id":"uuid",
  "hostname":"host-C",
  "cmd":"...",
  "timeout":30,
  "become":false
}
```

Enfant qui reçoit `task_forward` lookup sa `relay_routing` pour savoir s'il est l'agent direct ou doit le forwarder.

#### 9.2.1 Messages `link_keys`, `link_revocations`, `link_state` (v3.0.4)

Trois messages JSON sur `/ws/relay`, **parent → enfant** pour les deux premiers (quel que soit le mode pull/push : le lien est symétrique après l'établissement), **enfant → parent** pour `link_state`. Les signatures utilisent le format **défini par `auth/linkjwt.go`** (`SignLinkKeys`, `SignLinkRevocations`, `ApplyLinkKeys`, `VerifyLinkRevocations` : non redéfini ici). La trame envoyée est le message signé de `linkjwt.go` **plus** le champ `"type"` ; le receveur passe la trame telle quelle à `auth.ApplyLinkKeys` / `auth.VerifyLinkRevocations` (le champ `type` est ignoré par ces fonctions). Les clés publiques sont du **base64url sans remplissage** de leurs 32 octets (`ed25519.PublicKey`).

```json
{"type":"link_keys","current_pub":"<b64url 32 o>","current_kid":"<kid>","previous_pub":"<b64url 32 o>","previous_kid":"<kid>","seq":7,"sig":"<b64url>"}
{"type":"link_revocations","seq":8,"entries":[{"jti":"<uuid>","exp":1790000000}],"sig":"<b64url>"}
{"type":"link_state","relay_id":"<relay_id du rapporteur>","seq":8,"current_kid":"<kid>"}
```

- **`link_keys`** : annonce de rotation (`previous_*` présents : `previous_pub` = ancienne `current`, signé par l'**ancienne** `current`, S16/S17) ou de fermeture de la fenêtre (`previous_*` absents, `current` inchangée, signé par `current`). Le receveur la vérifie par `auth.ApplyLinkKeys` depuis son ancre **avant** toute écriture ; en cas de succès il persiste `link_trust` (clés, `kid`, `seq`) ; en cas d'échec (`link_keys_chain_broken`, `link_message_signature_invalid`, `link_message_invalid`) : `[SECURITY WARNING]`, `link_trust` **inchangé**, trame ignorée, **le lien reste ouvert**. `link_message_seq_replay` est bénin (état déjà appliqué : rien à faire). **Rejeu sur un relay déjà à jour** : une trame `link_keys` qui annonce exactement la `current` déjà de confiance (cas d'un relay déployé après la rotation, ancré sur la nouvelle clé, qui reçoit le `link_keys` signé par l'ancienne) est un **no-op idempotent** : aucune erreur, aucun `[SECURITY WARNING]`, rien n'est écrit ni adopté (la `previous` annoncée est ignorée : les jetons de l'ancienne clé restent refusés), la trame est retransmise aux enfants et le relay **confirme** par `link_state` (`seq` = max du `seq` local et de celui de la trame). Une chaîne réellement rompue (clé inconnue, signature fausse, trame mal formée, `kid` incohérent) est refusée avec `[SECURITY WARNING]` et `link_trust` inchangé.
- **`link_revocations`** : `entries` = JTI de jetons de lien révoqués et leur `exp` (secondes Unix). Signée par la `current` racine, vérifiée par `auth.VerifyLinkRevocations` (signature et **`seq` strictement supérieur** au dernier accepté, S18/S19). Le receveur **ajoute** ces JTI à sa blacklist (jusqu'à `exp`, jamais de retrait), persiste `seq`, **ferme en `4010`** le lien actif dont le `jti` y figure, puis retransmet. Une trame invalide est ignorée (`[SECURITY WARNING]`), le lien reste ouvert.
- **`link_state`** (renvoi) : les `link_state` mémorisés par un relay sont renvoyés à son parent après chaque `topology_snapshot` (un parent qui a redémarré, ou une racine qui a basculé, retrouve les confirmations).
- **`link_state`** : accusé **informatif** (non signé, jamais utilisé pour une décision d'accès) : après avoir appliqué un message, le relay annonce son dernier `seq` appliqué et son `kid` courant ; chaque relay le **retransmet vers son parent** avec le `relay_id` d'origine. La racine l'utilise pour `retire-link-previous` (R2) et `GET /api/admin/link/status`.
- **Compteur `seq` unique** (S20) : la racine incrémente un seul compteur (`server_config.link_seq`) à **chaque révocation de jeton de lien, rotation et fermeture de fenêtre**, dans la même mutation d'état que l'événement ; les trames sont émises dans l'ordre des `seq`.
- **À l'établissement du lien** (juste après `relay_ack`, dans cet ordre) : (1) `link_keys` tant qu'une rotation est ouverte (`previous` existe) ; (2) `link_revocations` avec la liste **complète** des révocations non expirées au `seq` courant (omis si `seq` = 0). Ensuite : **incrémental** — `link_keys` à la rotation / fermeture, `link_revocations` avec les seules nouvelles entrées. Un relay non racine renvoie à ses enfants, à leur connexion, les dernières trames reçues de son parent (en mémoire) et retransmet chaque trame **à l'identique** (octets inchangés) dès qu'il l'a vérifiée.
- **Rotation** : une seule en vol — `keys rotate-link` est refusé (`previous_key_not_retired`) tant que `retire-link-previous` n'a pas fermé la précédente ; un relay ne peut donc avoir qu'une rotation de retard. Après `retire-link-previous`, un relay resté sur l'ancienne ancre ne peut plus vérifier la chaîne : il est refusé (`jwt_unknown_kid`) jusqu'à ré-épinglage de la nouvelle clé publique (d'où le contrôle `rotation_unconfirmed`).
- **Racine injoignable** : les liens établis continuent (vérification locale) ; aucune nouvelle révocation ne descend jusqu'au retour du lien (rattrapage par la liste complète). Remède d'urgence local : `POST /api/admin/relays/{id}/revoke` sur le parent concerné.

#### Codes de fermeture WebSocket `/ws/relay` (#148)

| Code | Nature | Signification | Comportement du pair qui reçoit le close |
|---|---|---|---|
| `4010` | **Refus permanent** (émis : `relay_id` ≠ `jwt.sub`, boucle, nœud n'acceptant pas de parent, et à la révocation / remplacement du token / suppression du relay — `handlers/admin_relays.go:284,460,552`) | Identité non autorisée pour ce lien : **jeton de lien révoqué (`link_revocations`, `tokens revoke`)**, **relay non racine sans ancre de confiance (`link_trust_missing`)**, `relay_id` ≠ `jwt.sub`, identité du pair différente de celle attendue, boucle détectée (C ∈ {P} ∪ ancêtres(P)) | **Ne pas reconnecter** : le client pull ou le dialer push s'arrête (état terminal, log ERROR « operator action required » ) ; une action opérateur est nécessaire (#153 : une trame 4010 sur un lien push établi rend le Dialer terminal) |
| `4011` | **Non émis** | Constante réservée (`ws/relay_handler.go:37`), jamais envoyée ni traitée : un token expiré est refusé par un **401** avant l'upgrade | — |
| `4012` | **Refus corrigible** | Erreur protocolaire ou de validation pouvant se résoudre : `topology_snapshot` invalide / reçu avant `relay_hello` / au-delà de 40 remplacements par minute / en conflit de routage ou de relay, `agent_list` trop longue, premier message ≠ `relay_hello`, slot « parent unique » occupé | Reconnexion avec backoff exponentiel (5 s → 60 s max) |
| `4000` | Constante définie, non émise sur les liens relay | — | — |

> Un refus HTTP 401 avant l'upgrade (token invalide, révoqué à la reconnexion, secret non configuré) n'a pas de code de fermeture : le client le traite comme une erreur de connexion (backoff 5 s → 60 s). Un refus 401 à la reconnexion n'est **pas** terminal pour un parent qui redémarre.

---

### État du lien amont et des liens push (#148, #153, #154)

Après un refus **permanent** (close 4010), le client pull s'arrête définitivement (boucle ou token révoqué) et le dialer push devient terminal (refusal permanent sur un lien établi, log ERROR « operator action required »). Le nœud devient une racine isolée mais **continue de servir** ses agents directs et sa descendance. Il n'est donc **pas** redémarré : l'état est exposé pour alerter. Les refus **corrigibles** (4012, conflit, snapshot invalide) déclenchent une reconnexion avec backoff.

| Interface | Contenu |
|---|---|
| `GET /health` (port 7770, **public**) | HTTP **200** maintenu (pas de redémarrage par la liveness). Uniquement le booléen `degraded` (vrai si un lien est `refused_permanent`), absent sur une racine sans lien : **aucun** relay_id, état ni raison (divulgation de topologie). |
| `secagent-server server status` / `GET /api/admin/status` (port 7771, **admin**) | Bloc `links` : `upstream` (`mode` pull/push, `peer`, `state`, `reason`, `since`) et `push_children[]` (`relay_id` + même état) ; tableau LINK/PEER/STATE/SINCE/REASON et avertissement « operator action required » si dégradé. La raison est assainie (caractères de contrôle remplacés, **200 octets max**, tronquée sur une frontière de caractère UTF-8). |

États : `connected`, `retrying` (connexion initiale, lien perdu, refus corrigible 4012, annulation : **pas** terminal), `refused_permanent` (terminal : action opérateur requise — token révoqué/remplacé, identité ou boucle à corriger, puis redémarrage ou nouvelle déclaration). La raison est bornée (**200 octets max**, tronquée sur une frontière de caractère UTF-8) et ne contient jamais de token. Pas de métrique : aucune infrastructure de métriques n'existe aujourd'hui. Une sortie du processus (code dédié / `REPEATER_EXIT_ON_PERMANENT_REFUSAL`) n'est pas retenue pour l'instant ; une sonde de readiness distincte relèvera de #136.

### 9.3 Admin endpoints et CLI (port 7771)

```bash
# relay_nodes.mode=pull : enfant ouvre vers parent (auto-enregistrement via relay_hello)
# relay_nodes.mode=push : parent ouvre vers enfant (déclaration via API)

# List tous les relays
GET /api/admin/relays?only_connected=false
→ 200 { "relays": [ { "relay_id": "dmz1", "mode": "pull",
                       "connected": true, "agent_count": 5,
                       "last_seen": "..." } ] }

# Enregistrer un enfant à joindre (mode=push : parent ouvre la connexion)
POST /api/admin/relays
{
  "relay_id": "dmz1",
  "urls": ["wss://dmz1-a.internal:7772", "wss://dmz1-b.internal:7772"],   // l'URL est celle du relay ENFANT, wss:// seulement
  "token": "${REPEATER_UPSTREAM_TOKEN_DMZ1}",
  "mode": "push"
}
→ 201
# `urls` : adresses des instances du relay enfant, essayées dans l'ordre (la dernière qui a répondu
# est réessayée en premier). `url` (chaîne) reste accepté (= liste d'un élément) ; `url` ET `urls`
# ensemble → 400. Chaque adresse : wss:// uniquement, sans userinfo, sans doublon, 16 max, et refusée
# si elle vise loopback / lien-local / métadonnées cloud (169.254.169.254) / 0.0.0.0 / multicast
# (les plages RFC1918 sont acceptées). Une adresse refusée refuse toute la liste (400, l'adresse n'est
# jamais répétée dans l'erreur). Réponses et liste : `urls` (+ `url` = première adresse, compat).

# Politique de dial configurable (#151, lue une fois au démarrage, tout changement = redémarrage ; toute valeur
# invalide refuse le démarrage). Règle appliquée à CHAQUE IP résolue et à l'IP effectivement dialée (donc aussi
# contre le DNS rebinding), à l'enregistrement, au démarrage des dialers et à chaque reconnexion, dans cet ordre :
#   1. interdits intégrés, jamais levables : lien-local, métadonnées cloud (169.254.169.254, fd00:ec2::254,
#      100.100.100.200, 192.0.0.192, 168.63.129.16), non spécifiée, 0.0.0.0/8, multicast, broadcast  -> "builtin"
#   2. loopback, sauf REPEATER_DIAL_ALLOW_LOOPBACK=true (booléen strict, défaut false ; [SECURITY WARNING] au
#      démarrage ; développement et CI seulement)                                                    -> "loopback"
#   3. adresse dans REPEATER_DIAL_DENY_CIDRS (CIDR séparés par des virgules)                          -> "deny"
#   4. REPEATER_DIAL_ALLOW_CIDRS non vide et adresse hors liste                                       -> "not_allowed"
#   5. sinon acceptée (RFC 1918 et CGNAT restent acceptés par défaut).
# deny l'emporte ; ALLOW ne lève jamais un interdit intégré ; avec ALLOW non vide ET ALLOW_LOOPBACK=true la
# loopback doit aussi figurer dans ALLOW. IPv4 mappée en IPv6 jugée comme l'IPv4. Syntaxe : CIDR canonique
# (pas de bits d'hôte), "/0" interdit, pas d'entrée vide ni de doublon ni d'espace, 256 entrées max par liste.
# Le refus (400 à l'enregistrement, [SECURITY WARNING] au démarrage) donne le relay_id et la catégorie
# (builtin|loopback|deny|not_allowed), jamais l'adresse ni le jeton. Les redirections HTTP 3xx ne sont jamais suivies.

# Revoke a relay (#153) : blacklist du JTI + drapeau revoked + close 4010 du lien actif
POST /api/admin/relays/{id}/revoke
→ 200 { "revoked": true, "blacklisted": true, "legacy_token": false, "disconnected": true }

# Remove relay (blackliste aussi le token et coupe le lien)
# 409 relay_not_revoked si le relais n'a pas de JTI suivi (émis avant #153, ou relay push) et n'est pas déjà
# révoqué : « revoke the relay first » — sinon l'ancien token pourrait se reconnecter. Aucun contournement.
DELETE /api/admin/relays/{relay_id}
→ 204
```

**CLI :**
```bash
secagent-server relays list
secagent-server relays status
secagent-server relays add --id <relay_id> [--description …] [--mode pull]           # pull : JWT affiché une fois
secagent-server relays add --id <relay_id> --mode push --url wss://enfant-a:7772[,wss://enfant-b:7772] --token <token>   # push : --url accepte une liste séparée par des virgules (`cli/relays.go:118-124`)
secagent-server relays remove <uuid>
# Pas de `relays get/revoke/delete` : la révocation se fait par l'API POST /api/admin/relays/{id}/revoke
```

---

### 9.4 Authentification repeater-to-parent

**Deux rôles JWT distincts** :

**Rôle `relay`** (appelé « relay-child » ailleurs ; présenté par l'enfant au handshake) :
- Permissions : ouvrir `/ws/relay`, envoyer `relay_hello`, `agent_list`, `event_forward`
- Restrictions : pas d'accès `/api/inventory`, `/api/exec`, `/ws/agent`, `/api/admin`
- JWT créé sur : le relay parent (l'entité qui accueille l'enfant)
- JWT signé par : JWT_SECRET_KEY du relay parent (vérification par le parent récepteur)

**Rôle `relay-parent`** (présenté par le parent au handshake en mode push) :
- Permissions : ouvrir `/ws/relay` (en tant que WS client vers l'enfant)
- Restrictions : pas d'accès `/api/inventory`, `/api/exec`, `/ws/agent`, `/api/admin`
- JWT créé sur : le relay enfant (l'entité qui accepte l'ouverture)
- JWT signé par : JWT_SECRET_KEY du relay enfant (vérification par l'enfant récepteur)

**Modèle de signature (HAUT-6)** : Chaque relay crée et signe ses tokens avec sa JWT_SECRET_KEY :
- `relay` (créé par le parent) : parent signe, enfant ne peut pas valider (isolation clef)
- relay-parent (créé par l'enfant) : enfant signe, parent ne peut pas valider (isolation clef)
- Jamais de signature centralisée par la racine (évolution envisagée pour v3.0.1+)

Les tokens relay sont créés via CLI avec le rôle approprié :

**Rôle `relay`** (créé sur le parent, présenté par l'enfant qui ouvre vers le parent) :
> *Pas encore disponible via `tokens create`* (modèle de rôles complet : #146). Aujourd'hui le JWT de l'enfant
> (rôle `relay`, 30 j) est émis à l'enregistrement : `POST /api/admin/relays` (`relays add`, mode pull).

**Relay-parent** (créé sur l'enfant, présenté par le parent qui ouvre vers l'enfant — #150) :
```bash
# Sur dmz1 (enfant) :
secagent-server tokens create --role relay-parent \
  --sub central \
  --expires 90d
```
- Adossé à `POST /api/admin/tokens` (`role=relay-parent`, `sub`, `expires_at`), réservé à l'admin.
- `--expires` **obligatoire**, plafond **365 j** ; `sub` = `relay_id` du parent (identité qu'il présentera dans `relay_hello`).
- Le JWT (signé avec la `JWT_SECRET_KEY` de l'enfant) est **affiché une seule fois** ; seules ses métadonnées (id, JTI, sub, expiration, révocation) sont persistées (table `relay_parent_tokens`), jamais le token ; `tokens list --role relay-parent` ne le montre pas.
- `tokens revoke <id>` : le JTI entre en blacklist **et** le lien parent actif est fermé (close 4010) ; le parent ne peut plus se reconnecter avec ce token (401).
- Le parent donne ensuite ce token à `POST /api/admin/relays` (`mode=push`, `url=wss://…`, `token`).

**Sécurité :** 
- Tokens jamais loggés en clair
- JWT_SECRET_KEY unique par relay (jamais partagé)
- Chaque relay valide les tokens reçus avec sa propre clé

---

### 9.5 Inventaire Ansible hiérarchique (toute la descendance)

**Chaque relay retourne TOUTE SA DESCENDANCE** (agents + sous-relays comme groupes récursifs) :

```json
GET /api/inventory  (sur relay central)
{
  "all": {
    "children": ["dmz1", "zone2"],
    "hosts": ["host-C"]
  },
  "dmz1": {
    "hosts": ["host-A","host-B"],
    "children": ["zone-a"],
    "vars": {"region":"dmz"}
  },
  "zone-a": {
    "hosts": ["host-D","host-E"],
    "children": [],
    "vars": {"zone":"a"}
  },
  "zone2": {
    "hosts": ["host-C"],
    "children": [],
    "vars": {}
  },
  "_meta": {
    "hostvars": {
      "host-A": {
        "ansible_connection":"relay",
        "secagent_next_hop":"dmz1",
        "secagent_relay_chain":["dmz1"]
      },
      "host-D": {
        "ansible_connection":"relay",
        "secagent_next_hop":"zone-a",
        "secagent_relay_chain":["zone-a","dmz1"]
      }
    }
  }
}
```

**Groupes** : nommés exactement du relay (ex: `dmz1`, `zone-a`, pas de préfixe ni de transformation). Un groupe par relay dans la descendance, hiérarchie récursive. 
- **Nœud sans REPEATER_ID** (racine) : `all.children` = relays enfants directs (ex: `["dmz1"]`) ; chaque groupe `g` a `.children` = relays enfants du relay `g`.
- **Nœud avec REPEATER_ID** (même sans paramètre `?relay=`) : `all.children` = `[<id_du_nœud>]` (le relay lui-même) ; ses enfants relays se trouvent sous `<id_du_nœud>.children`.
- **Paramètre `?relay=<id>`** : limite l'inventaire à la descendance du relay `<id>` ; `all.children` = `[<id>]`.
- **Noms de groupes contenant des tirets** (ex: `zone-a`) déclenchent un avertissement Ansible (« Invalid characters in group names ») — voir §9.5b ci-dessous.

**Chaîne `secagent_relay_chain`** : ordre **origine en premier** (relay le plus proche de l'agent en premier). Exemple :
- Topologie : root ← dmz1 ← zone-a
- Agent `host-D` connecté à zone-a directement : chaîne = `["zone-a"]`
- Agent `host-D` via zone-a (enfant de dmz1) vu de root : chaîne = `["zone-a", "dmz1"]` (zone-a d'abord, origin de l'agent ; root en dernier)

**`secagent_next_hop`** : relay enfant direct du nœud courant vers lequel router la tâche (dernier élément de la chaîne `secagent_relay_chain`, ou le relay direct si chaîne vide). Pour `host-D` chez root, `next_hop = "zone-a"`.

**Cas `relay_chain = []`** : agent connecté **directement** au relay qui sert l'inventaire (pas d'intermédiaire). Exemple : `host-C` connecté à `zone2` et interrogation de `zone2` retourne `secagent_relay_chain = []` et `secagent_next_hop = "zone2"` (mais `next_hop` n'est visible que pour l'agent direct ; si querying la racine, les hostvars de `host-C` omettent `next_hop` car le routage est direct sur zone2).

**Paramètre `?relay=<id>`** (depuis v3.0.2) : limite l'inventaire à la descendance du relay spécifié. Retourne uniquement les groupes et hôtes sous `<id>`, avec les chaînes recalculées relativement à `<id>`. Erreur **400** si `<id>` est mal formé (format `^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$`, voir validation `relayIDShape`).

**Cloisonnement** : obtenu via authentification JWT (rôles, tokens), pas par limitation de profondeur.

**Collision REPEATER_ID/hostname** : pas de contrôle automatique ; mitigation = naming convention.

---

### 9.5b Noms de groupes Ansible avec tirets — Avertissement et configuration

**Contexte** : Un nom de relay peut contenir des tirets (format `^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$`) — ex: `zone-a`. Ansible considère comme « valides » uniquement les noms de groupe de type identifiant Python (lettres, chiffres, `_`). Un tiret déclenche l'avertissement « Invalid characters in group names ».

**Comportement Ansible (ansible-core 2.21.4+)** :

La directive `TRANSFORM_INVALID_GROUP_CHARS` (alias `force_valid_group_names` dans `ansible.cfg`) contrôle ce comportement :

| Valeur | Comportement |
|---|---|
| `never` (défaut) | Avertissement seulement ; le groupe est créé avec son nom exact et utilisable |
| `ignore` | Pas d'avertissement ; le groupe est créé avec son nom exact (même qu'`never`, sans log) |
| `always` | Remplace caractères invalides par `_` (ex: `zone-a` → `zone_a`) ; attention aux collisions |
| `silently` | Même que `always` mais sans avertissement |

**Recommandations** :

1. **Pour Ansible** : utiliser `ANSIBLE_TRANSFORM_INVALID_GROUP_CHARS=ignore` (env var) ou dans `ansible.cfg` :
   ```ini
   [defaults]
   force_valid_group_names = ignore
   ```
   **Ne pas utiliser `always` ou `silently`** : si deux relays `zone-a` et `zone_a` coexistent, la transformation rendrait leurs groupes identiques → collision.

2. **Pour secagent** : les noms de relay ne sont **jamais** transformés (ni par le serveur, ni par `secagent-inventory`). Utiliser des underscores dans les noms de relay (ex: `zone_a` au lieu de `zone-a`) évite l'avertissement sans réglage Ansible.

---

### 9.5a Routage hiérarchique — Priorité agent local (#127)

**Écart assumé vs spec : agent local prioritaire** :

Un hôte connecté directement au relay GAGNE TOUJOURS sur la table `relay_routing`, même si déclaré via `agent_list` d'un enfant. **Justification sécurité** :
- Exécution directe sur l'hôte local : `stdin` (become_pass) ne sort jamais du relay
- Forwarding vers relay enfant : `stdin` doit traverser les réseaux intermédiaires, risque d'exposition
- Un relay ne peut donc pas détourner les tâches d'un hôte local en se déclarant propriétaire

**Comportement** :
1. Agent X connecté via `/ws/agent` au relay R → `relay_routing(hostname=X, relay_id=R)` avec lookup direct de la WS
2. Même si relay E (enfant) envoie `agent_list` déclarant l'agent X → `host.conflict` émis une seule fois, X reste routé vers R
3. Test : `TestAgentList_ClaimOnLocalAgentCreatesNoRoute` (routage non créé) et `TestAgentList_RepeatedClaimEmitsConflictOnce`

**Résolu en v3.0.2 (#126)** : Un hôte profond est maintenant routable chez l'ancêtre après un `topology_snapshot` du parent intermédiaire. Les événements se propagent correctement via `event_forward`.

---

### 9.6 Données des relays enfants (état fichier)

Plus de tables SQL : ces données sont dans `relay.state` (`relay_nodes`, `relay_parent_tokens`, `blacklist`, voir §5 et `internal/state/model.go`) ;
le routage (`relay_routing` : clé simple `hostname`, `relay_id`, `hop_type` agent|relay, `relay_chain`) et le statut/`last_seen` sont **en mémoire**
(reconstruits par `topology_snapshot`). Champs de `relay_nodes` : `relay_id`, `urls`, `mode`, `jti`, `token_exp`, `revoked`, `group_vars`,
`token_hash` (pull : SHA-256 du JWT complet, pas du JTI) ou `token_secret` (push : token chiffré AES-256-GCM, préfixe `enc:`).

**Changement clé** : clé de routage simple `hostname` (pas de composite). Topologie arbre = un seul chemin par hôte.

**Sémantique mode** (v3.0.1) :
- `pull` = connexion WSS entrante (enfant se connecte, auto-registration relay_hello); le `jti` est relevé et persisté ; `token_hash` = SHA-256 du JWT complet
- `push` = connexion WSS sortante (parent ouvre vers enfant, déclaré via API); token persisté chiffré (enc:AES-GCM)

**Notes** :
- Le champ `token_hash` d'un relay pull stocke le SHA-256 du JWT complet (pas du JTI) ; le token d'un relay push est dans `token_secret` (chiffré).
- Relais antérieurs à #153 (sans `jti`) : `revoked` = true suffit pour refuser ; un `DELETE` d'un tel relais ne peut pas blacklister de JTI inexistant (contrainte : révoquer avant de supprimer)
- `relay_parent_tokens` : jamais le token en clair persisté ; métadonnées uniquement pour audit et gestion du cycle de vie

---

### 9.7 Événements et propagation (#126 v3.0.2)

**Types d'événements supportés** (envoyés via `event_forward` lors de changements) :

| Type | Déclencheur | Chaîne | Remarques |
|---|---|---|---|
| `host.up` | Agent se connecte via `/ws/agent` | `[relay_id]` (l'agent direct) | Propagé au parent par l'uplink (et exécute les hooks locaux) ; reçu d'un enfant, il met à jour la route sauf si l'hôte est connecté localement |
| `host.down` | Agent se déconnecte | `[relay_id]` | — |
| `host.new` | Agent apparaît via `agent_list` d'un enfant | `[relay_id_origine, relay_parent, ...]` (chaîne de l'agent) | — |
| `host.conflict` | Un relay déclare un hôte déjà routé vers un autre relay | `[relay_id_nouveau_propriétaire]` (l'hôte va au nouveau proprietaire) | Rare ; indicatif d'une mal-configuration ou d'une attaque (détournement de route). Un événement max par changement de propriétaire. |
| `relay.updated` | `group_vars` d'un relay changeant | `[relay_id]` | Permet aux hooks de réagir à la mise à jour des variables d'un relay |

**Sémantique chaîne** :
- Chaque relay ajoute son propre ID à la chaîne lors du relayage vers le parent
- Un `event_forward` reçu du parent n'est jamais renvoyé vers le haut (`repeater/uplink.go:310`)
- Anti-boucle : un relay refuse de transmettre si son ID est déjà dans la chaîne

**Rate limit** : chaque lien accepte **40 `topology_snapshot` de remplacement par 60 s** (`relay_handler.go:79-80`) ; au-delà, fermeture WebSocket **4012** (refus corrigible), l'enfant se reconnecte avec backoff. L'uplink regroupe les changements : délai de 200 ms puis au moins 2 s entre deux snapshots (`repeater/client.go:43-44`). Les `event_forward` sont limités à 200/s par lien (§9.2).

**Variables de hook** : lors de l'exécution d'un hook, les événements injectent deux variables supplémentaires (`hooks/dispatcher.go:41-56`) :
- `{{relay_chain}}` : chaîne séparée par des virgules, origine en premier (ex : `zone-a,dmz1`) ; variable d'environnement `SECAGENT_RELAY_CHAIN` (shell) ; tableau JSON `relay_chain` dans le corps d'un webhook
- `{{relay_origin}}` : premier élément de la chaîne (relay d'où l'événement provient ; ex: `zone-a`) ; `SECAGENT_RELAY_ORIGIN`

**Filtrage des hooks** (`relay_chain_contains`) : Permet un hook d'accepter les événements seulement si un relay spécifique figure dans la chaîne :
```json
{ "hooks": [ { "event": "host.up", "filter": { "relay_chain_contains": "dmz1" }, "actions": [ … ] } ] }
```
(configuration JSON, voir `DOC/server/HOOKS_SPEC.md` ; un objet `filter` vide est refusé, `hooks/config.go:22-62`)
Le filtre est validé au chargement de la config (fichier rejeté en bloc si malformé ; config précédente conservée au SIGHUP) — **fail-closed**.

---

### 9.7a Workers hooks et file (`RELAY_HOOKS_MAX_CONCURRENT_ACTIONS`, `RELAY_HOOKS_QUEUE_SIZE`)

**Pool de workers** (#183) : `RELAY_HOOKS_MAX_CONCURRENT_ACTIONS` (défaut `64`) workers, chacun avec sa file FIFO ; un événement va au worker désigné par le hachage de son hostname (ordre préservé par hôte).

| Variable | Défaut | Description |
|---|---|---|
| `RELAY_HOOKS_MAX_CONCURRENT_ACTIONS` | `64` | Nombre de workers = événements traités en parallèle |
| `RELAY_HOOKS_QUEUE_SIZE` | `10000` | Événements en file, tous workers confondus |

**Comportement** : contre-pression (les actions attendent dans la file, aucune n'est abandonnée tant que la file n'est pas pleine) ; au-delà de la file, rejet **compté** (`hooks_dropped_events`) avec un `[WARN]` agrégé par minute. Détails, ordre, compteurs, arrêt : `DOC/server/HOOKS_SPEC.md` §9b.

---

### 9.7b Group Vars — Comportements Observés (v3.0.2+)

**Publication et Visibilité** :
- Les `group_vars` sont publiés via `relay_hello` (mode pull), `topology_snapshot` (synchronisation et remplacements), et `relay.updated` (mise à jour isolée)
- Un relay **sans agent n'apparaît pas dans l'inventaire Ansible**, donc ses `group_vars` ne s'affichent pas non plus
- Seuls les groupes ayant des hôtes (directs ou via descendants) sont exposés

**Héritage dans la Hiérarchie** :
- Un sous-relay **hérite des `group_vars` du relay parent** (comportement Ansible)
- **Précédence** : si le relay parent et le sous-relay définissent la même clé, la **valeur du groupe enfant l'emporte**
  - Exemple : parent a `{"env":"prod"}`, enfant a `{"env":"staging", "team":"ops"}` → enfant expose `env=staging`, `team=ops`, et hérite toutes autres clés du parent

**Noms de variables réservées Ansible** :
- Noms réservés (ex: `tags`, `retries`) passent la validation RELAY_GROUP_VARS du serveur
- Ansible affiche un avertissement : `Found variable using reserved name` (avertissement seulement, pas erreur)
- **Recommandation** : éviter ces noms ; consulter la documentation Ansible

**Validation des `group_vars`** :
- Valides au démarrage (variable `RELAY_GROUP_VARS`) et rejetées sans start si invalides
- Valides en `relay_hello`, `topology_snapshot`, `relay.updated` ; rejet partiel si invalide (snapshot/hello rejeté, event.updated ignoring juste cette mise à jour)
- Interdits : `ansible_*` (sauf `ansible_python_interpreter` sans `..`), `secagent_*`, Jinja markers (`{{}}`, `{%%}`), dépassement de bornes
- Jamais loggés en clair (JSON peut contenir secrets)

---

### 9.8 Déploiement des relays

Les fichiers Compose de référence sont `DEPLOYMENT/prod/docker-compose.server.yml` (racine) et `DEPLOYMENT/prod/docker-compose.child.yml`
(surcharge d'un relay enfant : `REPEATER_ID`, `REPEATER_UPSTREAM_URL`, `REPEATER_UPSTREAM_TOKEN`, `RELAY_GROUP_VARS`), et
`DEPLOYMENT/qualif/docker-compose.*.yml`. Il n'y a ni NATS (`NATS_URL`), ni Caddy, ni `RELAY_PLUGIN_TOKEN` ; le TLS est natif
(`TLS_CERT`/`TLS_KEY`, plus `ADMIN_TLS=true` si l'API admin est liée à une adresse non loopback). Voir `DEPLOYMENT/prod/README.md`.

---

### 9.9 Récapitulatif modifications (v3.0.1)

| Aspect | Changement |
|---|---|
| **Config** | Variables simples (REPEATER_UPSTREAM_URL, REPEATER_UPSTREAM_TOKEN) — plus de YAML |
| **Topologie** | Arbre strict (un parent max par relay enfant, un seul chemin par hôte) |
| **Upstream** | Un seul upstream (le parent) — plus de multi-upstream |
| **Routage** (état) | `relay_routing` : clé simple `hostname` (pas de composite), plus de priority |
| **Routage** | Lookup simple `hostname` (un seul chemin, pas de sélection multi-chemins) |
| **Events** | Remontée parent-à-parent, pas de déduplication (un seul chemin) |
| **Anti-cycle** | Rejet si `REPEATER_ID ∈ relay_chain` |
| **Auth** | Deux rôles JWT fixés : `relay` (dit « relay-child », enfant ouvre) + `relay-parent` (parent ouvre) ; chaque relay signe ses tokens avec sa JWT_SECRET_KEY |
| **Suppression** | REPEATER_UPSTREAMS_FILE, seen-set, event_id dedup, priority, multi-upstream |


### CLI d'administration : `RELAY_API_URL` en liste (#165)

`RELAY_API_URL` accepte une liste d'adresses séparées par des virgules (une par instance du relay). Une
lecture (GET) passe à l'adresse suivante sur tout échec de transport ; une écriture n'est retentée sur
une autre adresse que si l'échec a eu lieu AVANT l'écriture de la requête (connexion refusée, DNS, TLS) :
une requête partie peut avoir été appliquée et n'est jamais rejouée ailleurs. `relays add --url` prend
une liste séparée par des virgules (corps `urls`).


## 10. Actif/passif : cycle de vie d'une instance (#163)

Plusieurs instances d'un même relay partagent `STATE_DIR` ; **une seule** est maître (elle ouvre les ports et écrit l'état), les autres attendent. Une racine n'est jamais active en plusieurs exemplaires : on passe à l'échelle par l'arbre de relays.

**Démarrage** (`internal/server.RunInstance`) : 1. configuration et **certificats TLS validés avant tout** (un certificat invalide ne devient même pas candidat : aucun `relay.lock` créé) ; 2. boucle de verrou : tant qu'il n'est pas maître, le processus n'ouvre **aucun port** (7770, 7771, 7772), ne charge pas l'état, ne lance ni lien montant, ni dialer push, ni hooks, et n'écrit **rien** dans `STATE_DIR` hors `relay.lock` ; 3. promu : battement et contrôles du verrou démarrent, l'état est chargé (rejeu refusé, cf. STATE_SPEC) puis `Build` ; 4. les ports ne s'ouvrent qu'après promotion **et** chargement de l'état ; `BeforeWrite` est branché sur `CheckOwnership`. Un échec de `Build` (état invalide, rejeu) supprime le propre `relay.lock` de l'instance et sort avec le code 1.

**Perte du verrou** (identité changée, verrou supprimé, auto-retrait) : arrêt du processus, pas de rétrogradation en mémoire. Dans l'ordre : hooks et liens annulés (**sans vidage de la file** : aucune action n'est exécutée au nom d'un ancien maître), listeners fermés, **toutes les WebSockets fermées en `1001 Going Away`** (jamais `4001`, qui interdit la reconnexion : les minions et les relays rebouclent sur leur liste d'adresses, #165/#166), aucune écriture d'état, code de sortie **75**. La policy de redémarrage du Compose relance l'instance en secondaire. Les appels REST du plugin en cours pendant la bascule **échouent** (le plugin ne rejoue pas, #168).

**Arrêt propre** (SIGTERM / SIGINT) : WebSockets fermées en 1001, ports fermés, file des hooks vidée (bornée), état fermé, puis **suppression de `relay.lock`** : un secondaire reprend aussitôt. Exigence : reprise **< 10 s** (cohérent avec `STOP_MAX_S` de l'infra) ; elle se compose d'un cycle de contrôle du secondaire (≤ 5 s), de la pause du candidat (1-2 s) et du chargement de l'état — mesurée par QA entre 3,3 et 4,0 s (rapports #163b). Après un crash ou `kill -9` le fichier `relay.lock` n'est pas relâché : le secondaire attend sa péremption (5 min sans battement, `MasterStale`, `lock/params.go:46-55`). Le protocole du verrou ne change pas.

**Observabilité** : `/health` (maître seul) ajoute `role` et `instance_id`. Fichier de statut **local** `RELAY_STATUS_FILE` (défaut `/run/secagent/status.json`, `0600`, refusé s'il est dans `STATE_DIR`) : rôle (`secondary` / `candidate` / `master` / `lost`), `instance_id`, état (`waiting`, `loading`, `ready`, `failed`, `lost`), compteur de battement, horodatages du dernier battement réussi (maître) ou du dernier contrôle (secondaire) tirés du verrou lui-même, périodes du verrou ; aucun secret. `secagent-server status --local` le lit sans ouvrir de port ni appeler l'API : code **0** pour un maître dont le dernier battement a moins de 2 × la période de battement ou un secondaire dont le dernier contrôle a moins de 3 × la période de contrôle ; non nul si le fichier est absent, trop ancien (processus figé), `failed` ou `lost`. C'est le healthcheck du conteneur.

| Code de sortie | Sens |
|---|---|
| 0 | arrêt demandé (SIGTERM/SIGINT) |
| 1 | démarrage refusé (configuration, certificat, état invalide, rejeu) ou erreur serveur |
| 75 | verrou maître perdu : relancer (en secondaire) |

**Mode lecture seule visible (#163)** : une écriture refusée parce que l'instance n'a pas de garde confirmée (`no write guard`), a perdu le verrou (`lock lost`) ou ne peut pas le confirmer (`ownership not confirmed`) répond `503 {"error":"state_read_only","reason":…}`, journalisé une fois par minute. `/api/admin/status`, `secagent-server server status` et `status --local` exposent `state_mode` (`read_write` / `read_only`), le rôle, l'`instance_id`, le `write_seq` et le dernier battement.
