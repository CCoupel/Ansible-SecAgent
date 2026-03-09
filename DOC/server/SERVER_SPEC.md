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
| `SERVER_ADDR` | — | Adresse d'écoute (défaut `:7770`) |
| `TLS_CERT` / `TLS_KEY` | — | Certificats TLS directs (sinon Caddy) |
