# secagent-server — Spécifications techniques

> Référence complète pour le composant secagent-server (GO).
> Source canonique : `DOC/common/ARCHITECTURE.md` §2, §5, §6, §15, §20, §21, §22
> Sécurité : `DOC/security/SECURITY.md` §2 (rôles), §5 (rotation), §6 (tokens plugin)
> **Contrats d'interface** : `DOC/contracts/REST_PLUGIN.md` · `DOC/contracts/REST_ENROLLMENT.md` · `DOC/contracts/REST_ADMIN.md` · `DOC/contracts/WEBSOCKET.md` · `DOC/contracts/NATS.md`

---

## 1. Rôle et périmètre

Le secagent-server est le **hub central** du système. Il :
- Expose une API REST HTTPS pour les plugins Ansible
- Maintient les connexions WebSocket avec les agents
- Route les tâches via NATS JetStream (HA multi-nodes)
- Gère l'authentification (JWT agents, tokens plugin, ADMIN_TOKEN)
- Expose une CLI d'administration (même binaire, mode cobra)

### Blocs internes (GO)

```
GO/cmd/server/
├── main.go                          — ports 7770/7771/7772, injection secrets JWT
├── internal/
│   ├── handlers/
│   │   ├── register.go              — POST /api/register (enrollment agent)
│   │   ├── exec.go                  — POST /api/exec|upload|fetch/{hostname}
│   │   ├── inventory.go             — GET /api/inventory
│   │   └── admin.go                 — tous les endpoints /api/admin/*
│   ├── ws/
│   │   ├── handler.go               — WSS /ws/agent, ws_connections map
│   │   └── jwt.go                   — validation dual-key JWT HMAC-HS256
│   ├── broker/
│   │   └── nats.go                  — NATS JetStream, streams RELAY_TASKS/RESULTS
│   ├── storage/
│   │   └── store.go                 — SQLite (modernc), toutes les tables
│   └── cli/
│       ├── root.go                  — cobra root command
│       ├── minions.go               — secagent-server minions *
│       ├── security.go              — secagent-server security keys|tokens *
│       ├── inventory.go             — secagent-server inventory list
│       └── server.go                — secagent-server server status|stats
```

---

## 2. Architecture des ports

| Port | Exposition | Rôle |
|---|---|---|
| `7770` | Publique (via Caddy HTTPS) | API REST agents + plugins + enrollment |
| `7771` | **Container-interne uniquement** (`expose:`, jamais `ports:`) | Endpoints admin CLI |
| `7772` | Publique (via Caddy WSS) | WebSocket agents uniquement |

Le port 7771 ne doit **jamais** être exposé hors du container.

---

## 3. API REST — Endpoints

### Authentification

| Endpoint | Auth requise |
|---|---|
| `POST /api/register` | Aucune (enrollment token dans le body) |
| `GET /api/inventory` | `Bearer <PLUGIN_TOKEN>` |
| `POST /api/exec/{host}` | `Bearer <PLUGIN_TOKEN>` |
| `POST /api/upload/{host}` | `Bearer <PLUGIN_TOKEN>` |
| `POST /api/fetch/{host}` | `Bearer <PLUGIN_TOKEN>` |
| `POST /api/token/refresh` | JWT agent expiré |
| `POST /api/admin/*` | `Bearer <ADMIN_TOKEN>` (port 7771) |
| `WSS /ws/agent` | `Bearer <JWT agent>` |

### `POST /api/register` — Enrollment agent (multi-étapes)

**Étape 1 — Initiation :**
```json
Requête : { "hostname": "host-A", "pubkey_pem": "...", "enrollment_token": "secagent_enr_..." }
Réponse : { "challenge": "<OAEP(nonce, agent_pubkey) base64>" }
```

**Étape 2 — Vérification :**
```json
Requête : { "hostname": "host-A", "response": "<OAEP(nonce+token, server_pubkey) base64>" }
Réponse : { "jwt_encrypted": "<OAEP(jwt, agent_pubkey) base64>" }
```

**Codes d'erreur :**
- `403` : token invalide/expiré/déjà utilisé
- `409` : hostname déjà enregistré avec une autre clef
- `400` : challenge incorrect

### `POST /api/exec/{hostname}` — Exécution (bloquant)

```json
Requête : {
  "task_id": "uuid-v4",
  "cmd": "python3 /tmp/.ansible/tmp/module.py",
  "stdin": "<base64|null>",
  "timeout": 30,
  "become": false,
  "become_method": "sudo"
}
Réponse 200 : { "rc": 0, "stdout": "...", "stderr": "", "truncated": false }
Réponse 503  : { "error": "agent_offline" }
Réponse 504  : { "error": "timeout" }
Réponse 500  : { "error": "agent_disconnected" }
Réponse 429  : { "error": "agent_busy" }
```

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

## 4. NATS JetStream

```
Stream RELAY_TASKS
  Subjects    : tasks.{hostname}
  Retention   : WorkQueue (supprimé après ack)
  MaxAge      : 300s
  MaxMsgSize  : 1MB
  Replicas    : 3

Stream RELAY_RESULTS
  Subjects    : results.{task_id}
  Retention   : Limits
  MaxAge      : 60s
  MaxMsgSize  : 5MB
  Replicas    : 3
```

**Routage HA :** Plugin POST sur Node #2 → publie `tasks.host-A` → Node #1 (qui a la WS) reçoit → forward à l'agent → résultat via `results.{task_id}` → Node #2 résout le futur bloquant.

---

## 5. Persistance — Schéma SQLite

```sql
-- Agents enregistrés
CREATE TABLE agents (
    hostname      TEXT PRIMARY KEY,
    pubkey_pem    TEXT NOT NULL,
    enrolled_at   INTEGER NOT NULL,
    last_seen_at  INTEGER,
    status        TEXT DEFAULT 'disconnected'
);

-- Tokens d'enrollment (single-use)
CREATE TABLE enrollment_tokens (
    id          TEXT PRIMARY KEY,
    token_hash  TEXT NOT NULL UNIQUE,
    hostname    TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    used        INTEGER DEFAULT 0,
    used_at     INTEGER,
    created_by  TEXT
);

-- Tokens plugin (connection + inventory)
CREATE TABLE plugin_tokens (
    id               TEXT PRIMARY KEY,
    token_hash       TEXT NOT NULL UNIQUE,
    description      TEXT,
    role             TEXT NOT NULL,        -- "plugin"
    allowed_ips      TEXT,                 -- CIDRs CSV | NULL
    allowed_hostname TEXT,                 -- hostname déclaré | NULL
    created_at       INTEGER NOT NULL,
    expires_at       INTEGER,
    last_used_at     INTEGER,
    last_used_ip     TEXT,
    revoked          INTEGER DEFAULT 0
);

-- Blacklist JTI (révocation agents)
CREATE TABLE blacklist (
    jti         TEXT PRIMARY KEY,
    hostname    TEXT,
    revoked_at  INTEGER NOT NULL,
    reason      TEXT,
    expires_at  INTEGER NOT NULL           -- pour purge automatique
);

-- Configuration serveur (secrets chiffrés AES-256-GCM)
CREATE TABLE server_config (
    key    TEXT PRIMARY KEY,
    value  TEXT NOT NULL                   -- chiffré avec RSA_MASTER_KEY
);
-- Clefs stockées : jwt_secret_current, jwt_secret_previous,
--                  key_rotation_deadline, rsa_private_key_pem, rsa_public_key_pem
```

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
# Accès exclusif depuis le container (port 7771 interne)
docker exec relay-api secagent-server <commande>

# Minions
secagent-server minions list [--format table|json|yaml]
secagent-server minions get <hostname>
secagent-server minions authorize <hostname>    # enrollment token
secagent-server minions revoke <hostname>
secagent-server minions suspend <hostname>
secagent-server minions resume <hostname>
secagent-server minions vars get|set|delete <hostname> [key] [value]

# Tokens
secagent-server tokens create --role plugin --description "..." --allowed-ips "..." --allowed-hostname "..." --expires 365d
secagent-server tokens list [--role plugin|enrollment|all]
secagent-server tokens revoke <id>
secagent-server tokens delete <id>
secagent-server tokens purge --expired

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
```

---

## 8. Variables d'environnement

| Variable | Requis | Description |
|---|---|---|
| `JWT_SECRET_KEY` | ✅ | Secret HMAC-HS256 pour signer les JWT agents |
| `ADMIN_TOKEN` | ✅ | Token admin (port 7771) |
| `NATS_URL` | ✅ | URL NATS JetStream (`nats://nats:4222`) |
| `DATABASE_URL` | — | SQLite path (`relay.db`) ou PostgreSQL URL |
| `RSA_MASTER_KEY` | ✅ | Clef AES-256-GCM pour chiffrer les secrets en DB |
| `RELAY_PLUGIN_TOKEN` | ✅ | Token statique pour les plugins Ansible |
| `REPEATER_ID` | — | Identifiant du relay (ex: `dmz1`) — requis en mode enfant |
| `REPEATER_UPSTREAM_URL` | — | URL WSS du parent (ex: `wss://central:7772`) — requis en mode enfant-push |
| `REPEATER_UPSTREAM_TOKEN` | — | Token d'authentification du relay enfant — requis en mode enfant-push |
| `RELAY_GROUP_VARS` | — | Variables Ansible JSON injectées pour ce relay (ex: `{"env":"prod"}`) |
| `SERVER_ADDR` | — | Adresse d'écoute (défaut `:7770`) |
| `TLS_CERT` / `TLS_KEY` | — | Certificats TLS directs (sinon Caddy) |

---

## 9. Mode Repeater — Arbre Hiérarchique (v3.0)

> Architecture complète : `DOC/common/ARCHITECTURE.md` §23

**Changements v3.0** :
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
| `REPEATER_UPSTREAM_URL` | — | URL WSS du parent (`wss://central:7772`) — requise si enfant ouvre vers parent |
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
REPEATER_UPSTREAM_TOKEN="secagent_relay_dmz1_xxx"
RELAY_GROUP_VARS='{"region":"dmz"}'
```

**Parent ouvre vers enfant** (parent enregistre enfant via API) : voir §9.3

---

### 9.2 WebSocket `/ws/relay` — Enfant-Parent

```
WSS /ws/relay
Authorization: Bearer <JWT rôle="???" à confirmer, sub=REPEATER_ID>
Port : 7772 (relay handler)
```

#### Handshake et agent_list

**Enfant → Parent :**
```json
{"type":"relay_hello", "node_type":"relay", "relay_id":"dmz1", "version":"3.0"}

{"type":"agent_list", "agents":[
  {"hostname":"host-A", "status":"connected", "last_seen":"..."},
  {"hostname":"host-B", "status":"connected", "last_seen":"..."}
]}
```

**Parent répond :**
```json
{"type":"relay_ack", "relay_id":"dmz1", "status":"ok", "timestamp":"..."}
```

**Note :** `agent_list` contient **uniquement les agents directs du relay** (pas les agents des relays enfants). Chaque relay reporte son propre sous-domaine.

#### event_forward — Propagation upstream

```json
{
  "type":"event_forward",
  "event":"host.up|host.down|host.new",
  "hostname":"host-A",
  "status":"connected",
  "relay_chain":["dmz1"],
  "timestamp":"..."
}
```

**Logique (topologie arbre, un seul chemin)** :
1. Ajouter son `REPEATER_ID` à `relay_chain` avant transmettre au parent
2. Parent reçoit, ajoute son ID, continue jusqu'à la racine
3. **Anti-boucle** : le relay refuse de transmettre si `REPEATER_ID ∈ relay_chain` (cycle de config)
4. **Pas de déduplication** : un seul chemin par hôte → un seul event (pas de doublons)

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

---

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
  "url": "wss://dmz1.internal:7772",
  "token": "secagent_relay_central_to_dmz1_xxx",
  "mode": "push"
}
→ 201

# Remove relay
DELETE /api/admin/relays/{relay_id}
→ 204
```

**CLI :**
```bash
secagent-server relays list
secagent-server relays get <relay_id>
secagent-server relays add <relay_id> --url <url> --token <token> --mode <push|pull>
```

---

### 9.4 Authentification repeater-to-parent

**Deux rôles JWT distincts** (à proposer dans SECURITY.md §2) :

**Rôle A (Enfant → Parent, dial=up)** :
- Permissions : ouvrir `/ws/relay`, envoyer `relay_hello`, `agent_list`, `event_forward`
- Restrictions : pas d'accès `/api/inventory`, `/api/exec`, `/ws/agent`, `/api/admin`
- Noms proposés : `relay-child` ou `relay-upstream-client` — **à confirmer**

**Rôle B (Parent → Enfant, dial=down)** :
- Permissions : ouvrir `/ws/relay` (en tant que serveur)
- Noms proposés : `relay-parent` ou `relay-downstream-server` — **à confirmer**

Les tokens relay sont créés via `POST /api/admin/tokens` :
```bash
secagent-server tokens create --role <role-A-ou-B> \
  --sub dmz1 \
  --expires 90d \
  --description "relay dmz1"
```

**Sécurité :** Tokens jamais loggés en clair ; chaque relay enfant a un token distinct.

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
        "secagent_relay_chain":["dmz1","zone-a"]
      }
    }
  }
}
```

**Groupes** : nommés exactement du relay (ex: `dmz1`, `zone-a`) — **pas de préfixe**.

**Cloisonnement** : obtenu via authentification JWT (rôles, tokens), pas par limitation de profondeur.

**Collision REPEATER_ID/hostname** : pas de contrôle automatique ; mitigation = naming convention.

---

### 9.6 Schéma SQLite (tables repeater)

```sql
CREATE TABLE IF NOT EXISTS relay_nodes (
    id          TEXT PRIMARY KEY,
    relay_id    TEXT NOT NULL UNIQUE,
    description TEXT,
    token_hash  TEXT,
    mode        TEXT NOT NULL DEFAULT 'pull',  -- "pull" (entrante) | "push" (sortante vers enfant)
    created_at  INTEGER NOT NULL,
    last_seen   INTEGER,
    status      TEXT NOT NULL DEFAULT 'pending'  -- "connected"|"disconnected"|"pending"
);

CREATE TABLE IF NOT EXISTS relay_routing (
    hostname    TEXT PRIMARY KEY,              -- clé simple (un seul chemin par hôte)
    relay_id    TEXT NOT NULL,                 -- relay auquel l'agent se connecte directement
    hop_type    TEXT CHECK(hop_type IN ('agent','relay')),
    relay_chain TEXT,                          -- JSON sérialisé ["dmz1","zone-a"]
    updated_at  INTEGER NOT NULL
);
```

**Changement clé** : clé simple `hostname` (pas de composite). Topologie arbre = un seul chemin par hôte.

**Sémantique mode** (v3.0) :
- `pull` = connexion WSS entrante (enfant se connecte, auto-registration relay_hello)
- `push` = connexion WSS sortante (parent ouvre vers enfant, déclaré via API)

---

### 9.7 Docker Compose qualification v3.0

```yaml
services:
  central:
    image: secagent-server:3.0
    environment:
      JWT_SECRET_KEY: ${JWT_SECRET_KEY}
      ADMIN_TOKEN: ${ADMIN_TOKEN}
      NATS_URL: nats://nats:4222
      RELAY_GROUP_VARS: '{"env":"prod"}'
    ports:
      - "7770:7770"   # API REST
      - "7771:7771"   # Admin CLI
      - "7772:7772"   # WebSocket

  relay-dmz1:
    image: secagent-server:3.0
    environment:
      JWT_SECRET_KEY: ${JWT_SECRET_KEY}
      REPEATER_ID: "dmz1"
      REPEATER_UPSTREAM_URL: "wss://central:7772"
      REPEATER_UPSTREAM_TOKEN: "secagent_relay_dmz1_xxx"
      NATS_URL: nats://nats:4222
      RELAY_GROUP_VARS: '{"region":"dmz"}'
    depends_on:
      - central
    ports:
      - "7773:7770"
      - "7774:7772"
```

---

### 9.8 Récapitulatif modifications (v3.0)

| Aspect | Changement |
|---|---|
| **Config** | Variables simples (REPEATER_UPSTREAM_URL, REPEATER_UPSTREAM_TOKEN) — plus de YAML |
| **Topologie** | Arbre strict (un parent max par relay enfant, un seul chemin par hôte) |
| **Upstream** | Un seul upstream (le parent) — plus de multi-upstream |
| **Schéma DB** | `relay_routing` : clé simple `hostname` (pas de composite), plus de priority |
| **Routage** | Lookup simple `hostname` (un seul chemin, pas de sélection multi-chemins) |
| **Events** | Remontée parent-à-parent, pas de déduplication (un seul chemin) |
| **Anti-cycle** | Rejet si `REPEATER_ID ∈ relay_chain` |
| **Auth** | Deux rôles JWT (à proposer : enfant ouvre vers parent, parent ouvre vers enfant) |
| **Suppression** | REPEATER_UPSTREAMS_FILE, seen-set, event_id dedup, priority, multi-upstream |
