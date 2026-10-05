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
GO/cmd/secagent-server/
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

-- Tokens d'enrollment
CREATE TABLE enrollment_tokens (
    id               TEXT PRIMARY KEY,
    token_hash       TEXT NOT NULL UNIQUE,      -- SHA-256(token)
    hostname_pattern TEXT NOT NULL,             -- regexp Go validée, ancrée ^(?:pattern)$ à la validation
                                                 -- ex: "vp.*", "web[0-9]+", "web1|db"
                                                 -- invalide si ne compile pas → rejet 400 "invalid_hostname_pattern"
    reusable         INTEGER DEFAULT 0,         -- 0 = one-shot, 1 = permanent
    use_count        INTEGER DEFAULT 0,         -- nb d'enrollements via ce token
    last_used_at     INTEGER,                   -- horodatage dernier usage
    created_at       INTEGER NOT NULL,
    expires_at       INTEGER,                   -- NULL = jamais expiré
    created_by       TEXT                       -- "admin-cli", "terraform", etc.
);

-- Tokens plugin (connection + inventory)
CREATE TABLE plugin_tokens (
    id                      TEXT PRIMARY KEY,
    token_hash              TEXT NOT NULL UNIQUE,  -- SHA-256(token)
    description             TEXT,
    role                    TEXT NOT NULL,         -- "plugin"
    allowed_ips             TEXT,                  -- CIDRs CSV | NULL
    allowed_hostname_pattern TEXT,                 -- regexp Go validée, ancrée ^(?:pattern)$ à la validation
                                                    -- ex: "ansible-control-[0-9]+", "web1|db"
                                                    -- invalide si ne compile pas → rejet 400 "invalid_hostname_pattern"
                                                    -- NULL = aucune restriction hostname
    created_at              INTEGER NOT NULL,
    expires_at              INTEGER,
    last_used_at            INTEGER,
    last_used_ip            TEXT,
    revoked                 INTEGER DEFAULT 0
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
secagent-server tokens create --role relay-parent --sub <parent_relay_id> --expires 90d   # #150 : minté sur l'ENFANT, --expires obligatoire (max 365d)
secagent-server tokens list [--role plugin|enrollment|relay-parent|all]
secagent-server tokens revoke <id>      # relay-parent : blacklist du JTI + fermeture (4010) du lien parent actif
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
| `RSA_MASTER_KEY` | ✅ | Clef AES-256-GCM pour chiffrer les secrets en DB (tokens push relay) |
| `RELAY_PLUGIN_TOKEN` | ✅ | Token statique pour les plugins Ansible |
| `REPEATER_ID` | — | Identifiant du relay (ex: `dmz1`) — requis en mode enfant |
| `REPEATER_UPSTREAM_URL` | — | URL WSS du parent (ex: `wss://central:7772`) — requis en mode enfant pull |
| `REPEATER_UPSTREAM_TOKEN` | — | Token JWT relay-child du relay enfant — requis en mode enfant pull |
| `RELAY_GROUP_VARS` | — | Variables Ansible JSON injectées pour ce relay (ex: `{"env":"prod"}`) |
| `API_ADDR` | — | Adresse d'écoute de l'API publique + WS agent/relay (défaut `:7770`) |
| `ADMIN_ADDR` | — | Adresse d'écoute de l'API admin (défaut `:7771`) — ne jamais l'exposer publiquement ; les handlers admin ne sont servis que sur cette adresse (sauf `POST /api/admin/authorize`, par compatibilité) |
| `WS_ADDR` | — | Adresse d'écoute WebSocket (défaut `:7772`) |
| `TLS_CERT` / `TLS_KEY` | — | Certificats TLS directs (sinon Caddy) |
| `MAX_SNAPSHOT_RELAYS` | — | Limite nombre relays dans topology_snapshot (défaut 1000) |
| `MAX_SNAPSHOT_HOSTS` | — | Limite nombre hôtes dans topology_snapshot (défaut 10000) |
| `MAX_AGENT_LIST_HOSTS` | — | Limite nombre hôtes dans agent_list par appel (défaut = MAX_SNAPSHOT_HOSTS = 10 000) |
| `MAX_WS_MESSAGE_SIZE_RELAY` | — | Taille maximale message WebSocket relay (défaut 10MB) |
| `RELAY_HOOKS_MAX_CONCURRENT_ACTIONS` | — | Limite goroutines simultanées pour exécution des hooks (défaut `64`) — voir §9.7a |
| `RELAY_INSECURE_TLS` | — | Utilisé par le binaire `secagent-inventory` (v3.0.2+) : accepter certificats TLS auto-signés. Requiert `RELAY_INSECURE_TLS_ACK=i-understand-the-risk` pour éviter les acceptations accidentelles (fail-closed) |

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
REPEATER_UPSTREAM_TOKEN="${REPEATER_UPSTREAM_TOKEN_DMZ1}"
RELAY_GROUP_VARS='{"region":"dmz"}'
```

**Parent ouvre vers enfant** (parent enregistre enfant via API) : voir §9.3

---

### 9.2 WebSocket `/ws/relay` — Enfant-Parent

```
WSS /ws/relay
Authorization: Bearer <JWT rôle="relay-child ou relay-parent selon le sens d'ouverture", sub=REPEATER_ID>
Port : 7772 (relay handler)
```

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
- ❌ Rejeter (close **4010** — refus permanent) si l'une de ces vérifications échoue

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
- Rejeter (close **4012** — refus corrigible — + log) si validation échoue

**→ Après snapshot validé, la connexion est établie** (relay_nodes, relay_routing, inventaire initialisés)

**Ensuite — agent_list (périodique, heartbeat)** :
```json
{"type":"agent_list", "agents":[{"hostname":"host-A", "status":"connected", "last_seen":"..."}]}
```
Contient **uniquement les agents directs** du relay.

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
  "relay_chain":["dmz1","zone-a"],
  "group_vars":{"region":"zone2"},
  "timestamp":"..."
}
```

**Design** : `event_forward` unifie tous les événements ascendants (hôtes et relays) avec des types distincts (`host.{up,down,new}`, `relay.updated`).

**Logique (topologie arbre, un seul chemin)** :
1. Événement local → relay ajoute son REPEATER_ID à relay_chain
2. Transmet au parent, parent ajoute son ID, continue vers la racine
3. **Anti-boucle** : refuse de transmettre si REPEATER_ID ∈ relay_chain
4. **Pas de déduplication** : un seul chemin → un seul event
5. **Rate limit par relay** : à dimensionner à l'implémentation selon la charge attendue (pour éviter une inondation d'events par un relay compromis)

**Validation du relay_chain à la réception** : Voir ARCHITECTURE.md §23.2 (HAUT-1) pour la règle unifiée :
- Mode pull : relay_chain[-1] == jwt.sub (JWT relay-child du WS client)
- Mode push : relay_chain[-1] == relay_ack.relay_id du pair serveur

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
**Comportement** : le dernier arrivé gagne (reroute vers le nouveau relay). ⚠️ **Production** : Configurer un hook d'alerte sur `host.conflict` pour détcter les mouvements de route suspects.

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

#### Codes de fermeture WebSocket `/ws/relay` (#148)

| Code | Nature | Signification | Comportement du pair qui reçoit le close |
|---|---|---|---|
| `4010` | **Refus permanent** | Identité non autorisée pour ce lien : token révoqué, `relay_id` ≠ `jwt.sub`, identité du pair différente de celle attendue, boucle détectée (C ∈ {P} ∪ ancêtres(P)) | **Ne pas reconnecter** : le client pull ou le dialer push s'arrête (état terminal, log ERROR « operator action required » ) ; une action opérateur est nécessaire (#153 : une trame 4010 sur un lien push établi rend le Dialer terminal) |
| `4011` | Token expiré | Token relay expiré (TTL dépassé) | Rafraîchir le token puis reconnecter |
| `4012` | **Refus corrigible** | Erreur protocolaire ou de validation pouvant se résoudre : `topology_snapshot` invalide / déjà reçu / reçu avant `relay_hello`, conflit de routage ou de relay déclaré, slot « parent unique » occupé | Reconnexion avec backoff exponentiel (5 s → 60 s max) |
| `4000` | Normal | Fermeture normale ou initiée par le client | — |
| `1000` | Normal | Fermeture WebSocket standard | — |

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
  "url": "wss://dmz1.internal:7772",
  "token": "${REPEATER_UPSTREAM_TOKEN_DMZ1}",
  "mode": "push"
}
→ 201

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
secagent-server relays get <relay_id>
secagent-server relays add <relay_id> --url <url> --token <token> --mode <push|pull>
```

---

### 9.4 Authentification repeater-to-parent

**Deux rôles JWT distincts** :

**Rôle `relay-child`** (présenté par l'enfant au handshake) :
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
- relay-child (créé par le parent) : parent signe, enfant ne peut pas valider (isolation clef)
- relay-parent (créé par l'enfant) : enfant signe, parent ne peut pas valider (isolation clef)
- Jamais de signature centralisée par la racine (évolution envisagée pour v3.0.1+)

Les tokens relay sont créés via CLI avec le rôle approprié :

**Relay-child** (créé sur le parent, présenté par l'enfant qui ouvre vers le parent) :
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
- RELAY_PLUGIN_TOKEN unique par relay (jamais partagé)
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
- **À la racine** : `all.children` = relays enfants directs ; chaque groupe `g` a `.children` = relays enfants du relay `g`.
- **Depuis un relay avec REPEATER_ID** (via scoping `?relay=<id>`) : `all.children` = `[<id>]` (le relay lui-même) ; ses enfants relays se trouvent sous `<id>.children`.
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

### 9.6 Schéma SQLite (tables repeater)

```sql
CREATE TABLE IF NOT EXISTS relay_nodes (
    id              TEXT PRIMARY KEY,
    relay_id        TEXT NOT NULL UNIQUE,
    description     TEXT,
    token_hash      TEXT,                   -- ⚠️ misnomer: SHA-256(JTI) pour pull; AES-GCM(token) préfixé enc: pour push (#152)
    jti             TEXT,                   -- JWT JTI du token relay (pour blacklist #153, colonne NULL pour mode push)
    token_exp       INTEGER,                -- exp du JWT (expiration timestamp pour purge blacklist)
    token_encrypted TEXT,                   -- token relay mode=push chiffré AES-256-GCM avec RSA_MASTER_KEY (#140)
    revoked         INTEGER DEFAULT 0,      -- flag révocation (#153); legacy relais (sans jti) révoqués par ce flag seul
    mode            TEXT NOT NULL DEFAULT 'pull',  -- "pull" (entrante) | "push" (sortante vers enfant)
    created_at      INTEGER NOT NULL,
    last_seen       INTEGER,
    status          TEXT NOT NULL DEFAULT 'pending'  -- "connected"|"disconnected"|"pending"
);

CREATE TABLE IF NOT EXISTS relay_parent_tokens (
    id              TEXT PRIMARY KEY,       -- UUID publique du token
    jti             TEXT NOT NULL UNIQUE,   -- JWT JTI pour blacklist à la révocation
    parent_id       TEXT NOT NULL,          -- relay_id du parent (cli --sub) — validé contre relay_hello
    description     TEXT,
    created_at      INTEGER NOT NULL,
    expires_at      INTEGER NOT NULL,       -- exp du JWT (obligatoire, max 365j)
    revoked_at      INTEGER                 -- timestamp révocation (NULL si actif); INSERT blacklist(jti) à cet instant
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

**Sémantique mode** (v3.0.1) :
- `pull` = connexion WSS entrante (enfant se connecte, auto-registration relay_hello); token persisté en tant que JTI
- `push` = connexion WSS sortante (parent ouvre vers enfant, déclaré via API); token persisté chiffré (enc:AES-GCM)

**Notes** :
- `token_hash` (colonne) mal nommée (#152) : elle stocke soit un hash (pull) soit du token chiffré (push). Renommage envisagé.
- Relais antérieurs à #153 (sans `jti`) : `revoked` = true suffit pour refuser ; un `DELETE` d'un tel relais ne peut pas blacklister de JTI inexistant (contrainte : révoquer avant de supprimer)
- `relay_parent_tokens` : jamais le token en clair persisté ; métadonnées uniquement pour audit et gestion du cycle de vie

---

### 9.7 Événements et propagation (#126 v3.0.2)

**Types d'événements supportés** (envoyés via `event_forward` lors de changements) :

| Type | Déclencheur | Chaîne | Remarques |
|---|---|---|---|
| `host.up` | Agent se connecte via `/ws/agent` | `[relay_id]` (l'agent direct) | Non propagé à l'ancêtre si l'agent n'est qu'un agent local du relay |
| `host.down` | Agent se déconnecte | `[relay_id]` | — |
| `host.new` | Agent apparaît via `agent_list` d'un enfant | `[relay_id_origine, relay_parent, ...]` (chaîne de l'agent) | — |
| `host.conflict` | Un relay déclare un hôte déjà routé vers un autre relay | `[relay_id_nouveau_propriétaire]` (l'hôte va au nouveau proprietaire) | Rare ; indicatif d'une mal-configuration ou d'une attaque (détournement de route). Un événement max par changement de propriétaire. |
| `relay.updated` | `group_vars` d'un relay changeant | `[relay_id]` | Permet aux hooks de réagir à la mise à jour des variables d'un relay |

**Sémantique chaîne** :
- Chaque relay ajoute son propre ID à la chaîne lors du relayage vers le parent
- Un événement local n'est pas re-forwardé au parent (évite les boucles)
- Anti-boucle : un relay refuse de transmettre si son ID est déjà dans la chaîne

**Rate limit** : Chaque lien relay-parent peut accepter **40 topology_snapshot** replacements par 60 s. Au-delà, fermeture WebSocket **4012** (refus corrigible) ; le relay enfant se reconnecte avec backoff.

**Variables de hook** : Lors de l'exécution d'un hook, les événements injectent deux variables supplémentaires :
- `{{relay_chain}}` : chaîne d'événement JSON (ex: `["zone-a","dmz1"]`)
- `{{relay_origin}}` : premier élément de la chaîne (relay d'où l'événement provient ; ex: `"zone-a"`)

**Filtrage des hooks** (`relay_chain_contains`) : Permet un hook d'accepter les événements seulement si un relay spécifique figure dans la chaîne :
```yaml
hooks:
  - event: "host.up"
    filter: "relay_chain_contains:dmz1"
    cmd: "notify-mgmt.sh {{hostname}}"
```
Le filtre est validé au chargement de la config (fichier rejeté en bloc si malformé ; config précédente conservée au SIGHUP) — **fail-closed**.

---

### 9.7a Sémaphore hooks et concurrence (`RELAY_HOOKS_MAX_CONCURRENT_ACTIONS`)

**Limite** : le nombre d'actions (commandes, webhooks) exécutées en parallèle par relay pour éviter un débordement de goroutines ou d'I/O en cas de tempête d'événements.

| Variable | Défaut | Description |
|---|---|---|
| `RELAY_HOOKS_MAX_CONCURRENT_ACTIONS` | `64` | Max goroutines simultanées pour les hooks (tous types confondus : commandes, webhooks) |

**Comportement au-delà de la limite** :
- Action rejetée silencieusement (ne bloque pas le dispatcher)
- Compteur `DroppedActions()` incrémenté
- Log `[SECURITY WARNING]` (1 fois sur 100 pour éviter la saturation log) : hostname en format sûr, ID relay

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

### 9.8 Docker Compose qualification v3.0.1

```yaml
services:
  central:
    image: secagent-server:3.0.1
    environment:
      JWT_SECRET_KEY: ${JWT_SECRET_KEY}
      ADMIN_TOKEN: ${ADMIN_TOKEN}
      RSA_MASTER_KEY: ${RSA_MASTER_KEY}
      RELAY_PLUGIN_TOKEN: ${RELAY_PLUGIN_TOKEN}
      NATS_URL: nats://nats:4222
      RELAY_GROUP_VARS: '{"env":"prod"}'
      TLS_CERT: /etc/secagent/certs/server.crt
      TLS_KEY: /etc/secagent/certs/server.key
    expose:
      - "7771"   # Admin CLI — container-interne uniquement
    ports:
      - "443:7770"    # HTTPS (API REST via Caddy)
      - "7772:7772"   # WSS (WebSocket termination par Caddy)

  relay-dmz1:
    image: secagent-server:3.1
    environment:
      JWT_SECRET_KEY: ${JWT_SECRET_KEY_DMZ1}
      ADMIN_TOKEN: ${ADMIN_TOKEN}
      REPEATER_ID: "dmz1"
      REPEATER_UPSTREAM_URL: "wss://central:7772"
      REPEATER_UPSTREAM_TOKEN: ${REPEATER_UPSTREAM_TOKEN_DMZ1}
      RSA_MASTER_KEY: ${RSA_MASTER_KEY_DMZ1}
      NATS_URL: nats://nats:4222
      RELAY_PLUGIN_TOKEN: ${RELAY_PLUGIN_TOKEN_DMZ1}
      RELAY_GROUP_VARS: '{"region":"dmz"}'
      TLS_CERT: /etc/secagent/certs/server.crt
      TLS_KEY: /etc/secagent/certs/server.key
    expose:
      - "7771"   # Admin CLI — container-interne uniquement
    ports:
      - "7774:7772"   # WSS (WebSocket pour agents enfants)
```

---

### 9.8 Récapitulatif modifications (v3.0.1)

| Aspect | Changement |
|---|---|
| **Config** | Variables simples (REPEATER_UPSTREAM_URL, REPEATER_UPSTREAM_TOKEN) — plus de YAML |
| **Topologie** | Arbre strict (un parent max par relay enfant, un seul chemin par hôte) |
| **Upstream** | Un seul upstream (le parent) — plus de multi-upstream |
| **Schéma DB** | `relay_routing` : clé simple `hostname` (pas de composite), plus de priority |
| **Routage** | Lookup simple `hostname` (un seul chemin, pas de sélection multi-chemins) |
| **Events** | Remontée parent-à-parent, pas de déduplication (un seul chemin) |
| **Anti-cycle** | Rejet si `REPEATER_ID ∈ relay_chain` |
| **Auth** | Deux rôles JWT fixés : `relay-child` (enfant ouvre) + `relay-parent` (parent ouvre) ; chaque relay signe ses tokens avec sa JWT_SECRET_KEY |
| **Suppression** | REPEATER_UPSTREAMS_FILE, seen-set, event_id dedup, priority, multi-upstream |
