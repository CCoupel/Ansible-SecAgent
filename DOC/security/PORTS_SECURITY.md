# Architecture des ports — Séparation sécurité v3.0.3

**Date** : 2026-10-06  
**Version** : v3.0.3 (état fichier, TLS natif, WebSocket direct)  
**Objectif** : Isoler les canaux par rôle (agent/plugin/admin) pour prévenir les risques d'authentification croisée.

---

## Vue d'ensemble

```
┌──────────────────────────────────────────────────────┐
│ Serveur Ansible-SecAgent (secagent-server GO)        │
│                                                      │
│  Port 7770 — API REST + WebSocket agent (TLS natif) │
│             ├─ POST /api/register (enrollment)      │
│             ├─ GET /ws/agent (persistent WS)        │
│             └─ GET /health (liveness)               │
│                                                      │
│  Port 7771 — Admin CLI (loopback par défaut)        │
│             ├─ HTTP local (loopback)                │
│             └─ HTTPS si ADMIN_TLS=true              │
│                                                      │
│  Port 7772 — WebSocket agent historique (compat)    │
│             └─ Redondant avec 7770 (TLS natif)      │
└──────────────────────────────────────────────────────┘
```

---

## Port 7770 — Agent & Plugin (API REST + WebSocket)

**Rôle** : Canal unique pour agents (minion) et plugins Ansible (connection + inventory)

**Interfaces** :
```
POST   /api/register           → Enrollment agent (pre-authorized)
GET    /ws/agent               → WebSocket persistante (agents + plugins)
GET    /health                 → Health check (public)
GET    /api/agents             → List agents (admin JWT)
POST   /api/inventory          → Dynamic inventory (admin JWT)
```

**Authentification** :
- `/api/register` : **Pré-autorisé** par clef publique (RSA-4096 agent, stockée en mémoire au démarrage depuis `STATE_DIR`)
- `/ws/agent` : **JWT signé** (rôle `agent` pour minion, rôle `plugin` pour Ansible, rôle `admin` pour inventory)
- Health : **Publique** (aucune auth)

**Flux nominal (agent)** :
```
1. Agent : POST /api/register {hostname, pubkey_pem, enrollment_token}
2. Serveur : Valide enrollment_token + pubkey_pem
3. Serveur : Répond challenge RSA-OAEP
4. Agent : Déchiffre, répond nonce
5. Serveur : Valide, émet JWT(rôle=agent)
6. Agent : Ouvre WebSocket /ws/agent avec JWT Bearer
7. Serveur : Accepte WS, dispatch les tâches par `task_id` (multiplexe)
8. Agent : Reçoit exec/put_file/fetch_file/cancel, exécute, répond
```

**Flux nominal (plugin)** :
```
1. Plugin Ansible : POST /api/register pour obtenirJWT(rôle=plugin)
   OR : Inclure JWT(rôle=plugin) en header Authorization
2. Plugin : POST /ws/agent avec JWT(rôle=plugin) (WebSocket)
3. Serveur : Accepte WS, démultiplexe par task_id
4. Plugin : Envoie exec pour un host
5. Serveur : Route vers minion via sa WS /ws/agent
6. Minion : Exécute, envoie résultat
7. Serveur : Route résultat vers plugin WS
```

**Flux nominal (inventory)** :
```
1. Control Node Ansible : GET /api/inventory avec JWT(rôle=admin)
2. Serveur : Valide JWT, retourne liste agents + facts (JSON)
3. Ansible : Popule inventory dynamique
```

**Cas de sécurité** :
- ✓ Seuls agents avec clef pré-autorisée + enrollment_token valide → JWT(rôle=agent)
- ✓ Seuls plugins avec JWT(rôle=plugin) ou enrollment_token → WebSocket dispatch
- ✓ JWT signé + validé à chaque message, révocation via JTI blacklist
- ✓ Tokens expirés → fermeture WS code 4002 (re-enrollment)
- ✓ Tokens révoqués → fermeture WS code 4001 (arrêt définitif, exit code 77)
- ✓ Enrollment refusé (403) → exit code 78 (ne pas redémarrer, créer nouveau token)

---

## Port 7771 — Admin CLI

**Rôle** : Interface d'administration locale (opérateurs)

**Interfaces** :
```
GET    /healthz                 → Healthcheck (aucune auth)
EXEC   secagent-server admin    → CLI cobra (local stdin/stdout)
```

**Authentification** :
- Loopback (`127.0.0.1`, `::1`) : **HTTP** (aucune auth requise)
- Réseau admin (non-loopback) : **HTTPS** (TLS obligatoire, `ADMIN_TLS=true`)

**Comportement** :
- Si `ADMIN_ADDR=127.0.0.1:7771` (défaut) : loopback uniquement, HTTP accepté
- Si `ADMIN_ADDR=0.0.0.0:7771` : réseau ouvert, HTTPS obligatoire (`ADMIN_TLS=true`)
- Si `ADMIN_INSECURE_HTTP=true` : HTTP accepté partout (tests uniquement) + `ADMIN_INSECURE_HTTP_ACK=i-understand-the-risk` exact requis

**Fonctionnalités** :
```bash
# Gestion des tokens
secagent-server admin token create --role agent --duration 1h
secagent-server admin token revoke <jti>

# Gestion de l'état
secagent-server state init                    # Initialiser une fois
secagent-server state verify                  # Vérifier cohérence
secagent-server state restore --from backup   # Restaurer depuis backup

# Statut du relay
secagent-server status --local                # Statut local (verrou, agents, uptime)
```

**Cas de sécurité** :
- ✓ Loopback uniquement par défaut (admin local sur la machine du relay)
- ✓ Si réseau admin : TLS obligatoire (ADMIN_TLS=true) + certificat identique au 7770/7772
- ✓ Pas d'authentification requise sur loopback (confiance système)

---

## Port 7772 — WebSocket Agent (Compatibilité historique)

**Rôle** : Redondance avec port 7770, même interface WebSocket

**Interfaces** :
```
GET    /ws/agent               → WebSocket persistante (identique à 7770)
```

**Authentification** : Identique à 7770 (`JWT` rôle `agent` ou `plugin`)

**TLS** : Natif (WSS, même certificat que 7770)

**Raison** : Certains déploiements héritents pointent vers 7772. Supporté pour compatibilité v3.0.3, sera supprimé en v4.0.0.

**Configuration agents** :
```bash
# Agents peuvent utiliser soit 7770 soit 7772 pour WebSocket
export RELAY_WS_URL="wss://relay:7772/ws/agent"  # Historique
# OU
export RELAY_WS_URL="wss://relay:7770/ws/agent"  # Préféré v3.0.3+
```

---

## Matrice de Sécurité

| Port | Endpoint | Auth | Agent | Plugin | Admin | Notes |
|------|----------|------|-------|--------|-------|-------|
| **7770** | POST /api/register | Pre-authorized | ✓ | ✗ | ✗ | RSA-OAEP challenge |
| **7770** | GET /ws/agent | JWT(agent) | ✓ | ✗ | ✗ | Task dispatch |
| **7770** | GET /ws/agent | JWT(plugin) | ✗ | ✓ | ✗ | Task proxy |
| **7770** | GET /api/agents | JWT(admin) | ✗ | ✗ | ✓ | List agents |
| **7770** | GET /api/inventory | JWT(admin) | ✗ | ✗ | ✓ | Dynamic inventory |
| **7770** | GET /health | None | ✓ | ✓ | ✓ | Liveness probe |
| **7771** | /healthz | None (loopback) | ✓ | ✗ | ✓ | Admin health |
| **7771** | CLI (state/admin) | Local stdin | ✗ | ✗ | ✓ | Opérateurs |
| **7772** | GET /ws/agent | JWT(agent/plugin) | ✓ | ✓ | ✗ | Compat v3.0.3 only |

---

## Variables de Configuration

### Relay Server (secagent-server)

```bash
# Ports (non configurables, défauts fixes)
# 7770 : API + WebSocket
# 7771 : Admin CLI
# 7772 : WebSocket compat

# Adresse admin
ADMIN_ADDR="127.0.0.1:7771"         # Loopback par défaut
ADMIN_ADDR="0.0.0.0:7771"           # Réseau ouvert (TLS requis)

# TLS
TLS_CERT="/etc/secagent/tls.crt"    # Certificat PEM
TLS_KEY="/etc/secagent/tls.key"     # Clef privée PEM
TLS_DISABLE=                        # À ne jamais définir (sauf test local)

# Admin TLS (si ADMIN_ADDR non-loopback)
ADMIN_TLS=false                     # Loopback : HTTP OK
ADMIN_TLS=true                      # Réseau : HTTPS obligatoire
ADMIN_INSECURE_HTTP=true            # Tests seul, avec ACK
ADMIN_INSECURE_HTTP_ACK="i-understand-the-risk"
```

### Agents (secagent-minion)

```bash
# Enrollment API (HTTPS)
RELAY_SERVER_URL="https://relay:7770"          # Défaut
RELAY_SERVER_URL="https://relay1:7770,https://relay2:7770"  # Multi-adresses

# WebSocket (WSS)
RELAY_WS_URL="wss://relay:7770/ws/agent"       # Préféré
RELAY_WS_URL="wss://relay:7772/ws/agent"       # Compat historique
RELAY_WS_URL="wss://relay1:7770/ws/agent,wss://relay2:7770/ws/agent"  # Failover
```

**Important** : `RELAY_SERVER_URL` et `RELAY_WS_URL` doivent avoir le même nombre d'adresses (pairées par position).

---

## Règles Firewall Recommandées

```bash
# Port 7770 — Agents + Plugins (réseau agents + Ansible Control Nodes)
ufw allow from 192.168.1.0/24 to any port 7770   # Réseau agents
ufw allow from 10.0.0.0/8 to any port 7770       # Réseau control nodes

# Port 7771 — Admin (loopback par défaut, réseau admin si ADMIN_ADDR défini)
ufw allow from 127.0.0.1 to any port 7771        # Loopback
ufw allow from 10.0.1.0/24 to any port 7771      # Réseau admin (opt.)

# Port 7772 — WebSocket compat (si utilisé, même règles que 7770)
ufw allow from 192.168.1.0/24 to any port 7772
ufw allow from 10.0.0.0/8 to any port 7772

# Refuser tout le reste
ufw default deny incoming
```

---

## Docker Compose — Binding

```yaml
secagent-server:
  ports:
    # API + WebSocket — publié, TLS natif
    - "7770:7770"
    # Admin CLI — loopback par défaut
    - "127.0.0.1:7771:7771"
    # WebSocket compat — publié
    - "7772:7772"
  environment:
    ADMIN_ADDR: "127.0.0.1:7771"
    TLS_CERT: "/run/secrets/tls.crt"
    TLS_KEY: "/run/secrets/tls.key"
```

Pour publier admin sur réseau d'administration :
```yaml
ports:
  - "10.0.1.50:7771:7771"    # Réseau admin uniquement
environment:
  ADMIN_ADDR: "0.0.0.0:7771"
  ADMIN_TLS: "true"
```

---

## Codes de Sortie Significatifs

| Code | Condition | Comportement | Mitigations |
|------|-----------|--------------|-------------|
| 77 | Agent révoqué (JTI blacklisté, WS close 4001) | Arrêt définitif — `RestartPreventExitStatus=77` | L'opérateur crée nouveau token d'enrôlement |
| 78 | Enrollment refusé (403 persistant) | Arrêt définitif — `RestartPreventExitStatus=78` | L'opérateur crée nouveau token d'enrôlement |
| 75 | Verrou perdu (master crash) | Redémarrage (relay passif) | Failover automatique (multi-hôtes) |

---

## Limitations Connues v3.0.3

| Risque | Description | Mitigation |
|--------|-------------|-----------|
| Rejeu de tâches après arrêt à froid | Perte de `write_seq`, état replayé | Backups réguliers + permissions `0700` sur STATE_DIR |
| DoS : promotion forcée | Un attaquant peut forcer la basculement relay.lock forgée | Autoriser écritures STATE_DIR au relay seul (`uid:gid 10001`) |
| REPEATER_CA_FILE non-rechargée | Rotation de CA nécessite redémarrage/failover | Redémarrer le relay passif, puis basculer |
| Rotation RSA_MASTER_KEY | Tous les agents doivent se ré-enrôler | Planifier en fenêtre maintenance |

Voir `DOC/security/SECURITY.md` section "Avis de sécurité" pour les vulnérabilités antérieures corrigées en v3.0.3.

---

## Vérification de Configuration

```bash
# Vérifier les bindings
ss -tulpn | grep 777

# Vérifier les certificats TLS
openssl x509 -in $TLS_CERT -text -noout

# Tester l'enrollment
curl -X POST -k https://relay:7770/api/register \
  -H "Content-Type: application/json" \
  -d '{"hostname":"test","pubkey_pem":"...","enrollment_token":"..."}'

# Tester l'admin healthz (loopback)
curl http://127.0.0.1:7771/healthz

# Tester l'inventaire
curl -k -H "Authorization: Bearer $ADMIN_JWT" https://relay:7770/api/inventory
```

---

## Documentation Référence

- [DOC/server/SERVER_SPEC.md](../server/SERVER_SPEC.md) — Spécifications techniques complètes
- [DOC/agent/AGENT_SPEC.md](../agent/AGENT_SPEC.md) — Protocole enrollment et WebSocket agent
- [DOC/security/SECURITY.md](./SECURITY.md) — Modèle de sécurité complet + avis v3.0.3
- [DEPLOYMENT/README.md](../../DEPLOYMENT/README.md) — Configuration déploiement
