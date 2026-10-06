# Architecture des ports — Séparation sécurité v3.0.3

**Date** : 2026-10-06  
**Version** : v3.0.3 (état fichier, TLS natif, WebSocket direct)  
**Objectif** : Isoler les canaux par rôle (agent/plugin/admin) pour prévenir les risques d'authentification croisée.

---

## Vue d'ensemble

```
┌──────────────────────────────────────────────────────────────┐
│ secagent-server (GO) — instance MAÎTRE                       │
│                                                              │
│  Port 7770 — API REST (TLS natif)         [API_ADDR]         │
│     ├─ GET  /health                       (public)           │
│     ├─ POST /api/register                 (enrôlement)       │
│     ├─ POST /api/token/refresh                               │
│     ├─ GET  /api/inventory                (jeton plugin)     │
│     ├─ POST /api/exec|upload|fetch/{host} (jeton plugin)     │
│     ├─ GET  /ws/agent, /ws/relay          (WebSocket)        │
│     └─ POST /api/admin/authorize          (compat, ADMIN_TOKEN)│
│                                                              │
│  Port 7771 — Admin (ADMIN_TOKEN)          [ADMIN_ADDR]       │
│     └─ /api/admin/*, GET /api/inventory   (HTTPS ou loopback)│
│                                                              │
│  Port 7772 — WebSocket dédié (TLS natif)  [WS_ADDR]          │
│     └─ /ws/agent, /ws/relay                                  │
└──────────────────────────────────────────────────────────────┘
```

Seul le maître ouvre ces ports : une instance secondaire (passive) **n'ouvre aucun port** tant qu'elle n'a pas acquis le verrou (voir `DEPLOYMENT/prod/README.md`). Les trois adresses sont configurables (`API_ADDR`, `ADMIN_ADDR`, `WS_ADDR` ; défauts `:7770`, `:7771`, `:7772`, `server/config.go:27-36`). Les routes sont définies dans `GO/cmd/secagent-server/internal/server/routers.go`.

---

## Port 7770 — API REST (agents, plugins Ansible)

**Rôle** : enrôlement des agents, API REST bloquante utilisée par les plugins Ansible (connexion + inventaire), et — par compatibilité — WebSocket `/ws/agent` et `/ws/relay`.

**Interfaces** (`routers.go:35-43,101`) :
```
GET    /health                    → Liveness (public, sans authentification)
POST   /api/register              → Enrôlement agent (jeton d'enrôlement ou clef pré-autorisée)
POST   /api/token/refresh         → Renouvellement de JWT agent
GET    /api/inventory             → Inventaire dynamique (jeton PLUGIN)
POST   /api/exec/{hostname}       → Exécution de commande (jeton PLUGIN, bloquant)
POST   /api/upload/{hostname}     → Envoi de fichier (jeton PLUGIN, bloquant)
POST   /api/fetch/{hostname}      → Récupération de fichier (jeton PLUGIN, bloquant)
GET    /ws/agent                  → WebSocket persistante des agents (JWT rôle agent)
GET    /ws/relay                  → WebSocket entre relays
POST   /api/admin/authorize       → Pré-autorisation d'une clef (ADMIN_TOKEN ; aussi sur 7771)
```

Il n'existe **pas** de route `GET /healthz`, `GET /api/agents` ni `POST /api/inventory` : ces chemins répondent `404`.

**Authentification** :
- `/api/register` : jeton d'enrôlement (`secagent_enr_…`, opaque) + challenge RSA-OAEP, ou clef publique pré-autorisée par `POST /api/admin/authorize` (flux historique) — voir `DOC/contracts/REST_ENROLLMENT.md`
- `/ws/agent` : **JWT signé de rôle `agent` uniquement** ; un JWT d'un autre rôle est refusé (`ws/handler.go:409`)
- `/api/inventory`, `/api/exec`, `/api/upload`, `/api/fetch` : **jeton plugin** `secagent_plg_…` (chaîne opaque, **pas un JWT**), vérifié contre l'empreinte SHA-256 de l'état, avec expiration, révocation, `allowed_ips` et `allowed_hostname_pattern` (`handlers/plugin_auth.go`). Un `ADMIN_TOKEN` y est refusé (`403`)
- `/health` : publique

**Flux nominal (agent)** :
```
1. Agent : POST /api/register {hostname, public_key_pem, enrollment_token}
2. Serveur : valide le jeton et le hostname, répond {challenge, server_public_key_pem}
3. Agent : déchiffre le nonce, renvoie challenge_response chiffré avec la clef du serveur
4. Serveur : valide, émet un JWT (rôle agent) chiffré avec la clef publique de l'agent
5. Agent : ouvre la WebSocket /ws/agent avec le JWT en Bearer
6. Serveur : dispatche exec/put_file/fetch_file/cancel par `task_id` (multiplexé)
```

**Flux nominal (plugin Ansible)** — REST bloquant, pas de WebSocket côté plugin :
```
1. Plugin : POST /api/exec/{hostname} avec Authorization: Bearer <jeton plugin>
2. Serveur : valide le jeton plugin, route la tâche vers la WebSocket /ws/agent du minion
3. Minion : exécute, répond sur sa WebSocket
4. Serveur : renvoie le résultat dans la réponse HTTP de l'étape 1
(idem pour /api/upload/{hostname} et /api/fetch/{hostname})
```

**Flux nominal (inventaire)** :
```
1. Contrôleur Ansible (secagent-inventory) : GET /api/inventory avec le jeton plugin
2. Serveur : valide le jeton, renvoie l'inventaire JSON (agents + variables)
```

**Cas de sécurité** :
- ✓ Seuls les agents enrôlés (jeton d'enrôlement valide, ou clef pré-autorisée) obtiennent un JWT de rôle `agent`
- ✓ Les plugins n'ont jamais de WebSocket : `/ws/agent` n'accepte que le rôle `agent`
- ✓ JWT agent signé, révocation par blacklist de JTI
- ✓ Agent révoqué → fermeture WS code `4001` (arrêt définitif, code de sortie 77)
- ✓ Enrôlement refusé (`403`) → code de sortie 78 (pas de redémarrage ; créer un nouveau jeton)
- ✓ Le serveur n'émet que `4000` (agent supprimé), `4001` (révocation) et `1001` (arrêt/perte du verrou) vers les agents ; `4002` existe comme constante mais n'est jamais émis, et `4003`/`4004` n'existent pas (`DOC/contracts/WEBSOCKET.md` §5)

---

## Port 7771 — Admin

**Rôle** : API d'administration utilisée par le CLI `secagent-server` et par les opérateurs.

**Interfaces** : toutes les routes `/api/admin/*` (agents, jetons, relays, rotation des clefs, statut, journal des hooks) et `GET /api/inventory` (version administrateur de l'inventaire). Liste complète : `DOC/contracts/REST_ADMIN.md`. Il n'y a pas de route `/healthz` ni de `/health` sur ce port.

**Authentification** : **toujours** `Authorization: Bearer <ADMIN_TOKEN>`. Il n'existe **aucune exemption pour la boucle locale** : une requête sans jeton reçoit `401` (`missing_authorization`), un jeton faux `401` (`invalid_admin_token`) (`handlers/admin.go` `requireAdminAuth`). `ADMIN_TOKEN` est une chaîne secrète partagée, pas un JWT.

**Exposition** (`server/tls.go` `adminExposure`) — le serveur **refuse de démarrer** si l'API admin servirait du HTTP clair sur une adresse non loopback sans dérogation :
- `ADMIN_ADDR` : **défaut `:7771`** (toutes les interfaces). Avec ce défaut et sans `ADMIN_TLS=true`, le démarrage échoue (message « the admin API (:7771) would serve plain HTTP on a non-loopback address »)
- `ADMIN_ADDR=127.0.0.1:7771` : loopback, HTTP accepté
- `ADMIN_TLS=true` (avec `TLS_CERT`/`TLS_KEY`) : le port admin sert le même certificat que 7770/7772 ; requis pour toute adresse non loopback
- `ADMIN_INSECURE_HTTP=true` **et** `ADMIN_INSECURE_HTTP_ACK=i-understand-the-risk` : dérogation explicite (HTTP clair sur un réseau, `[SECURITY WARNING]` au démarrage) — le jeton admin circule en clair, à réserver à un réseau d'administration protégé par ailleurs

**Commandes courantes** :
```bash
# Jetons (rôles : enrollment, plugin, relay-parent)
secagent-server tokens create --role enrollment --hostname-pattern "web[0-9]+" --expires 1h
secagent-server tokens create --role plugin --description "ansible-control" --expires 365d
secagent-server tokens revoke <id>            # jetons plugin / relay-parent

# Gestion de l'état (hors ligne, sans API)
secagent-server state init                    # une seule fois ; exige RSA_MASTER_KEY
secagent-server state verify <file>           # vérifie un fichier d'état (exige RSA_MASTER_KEY)
secagent-server state restore --from <file>   # restaure depuis une sauvegarde (arrêter toutes les instances)

# Statut
secagent-server status --local                # statut local (fichier RELAY_STATUS_FILE, sans port ni API)
secagent-server server status                 # vue API du maître (GET /api/admin/status)
```

`secagent-server admin …` n'existe pas : `admin` n'est pas une sous-commande, et le binaire lancé avec un argument inconnu démarre le serveur au lieu d'afficher une erreur.

**Cas de sécurité** :
- ✓ Authentification par `ADMIN_TOKEN` sur chaque requête, y compris depuis la machine locale
- ✓ Pas de HTTP clair sur un réseau sans dérogation explicite (double accusé) ; avertissement `[SECURITY WARNING]` quand elle est utilisée
- ✓ Si `ADMIN_TLS=true` : même certificat que 7770/7772

---

## Port 7772 — WebSocket dédié

**Rôle** : listener WebSocket dédié (`WS_ADDR`). C'est la valeur **par défaut** de `RELAY_WS_URL` côté minion (`wss://localhost:7772/ws/agent`, `secagent-minion/main.go:407`) ; le code ne le marque pas comme déprécié.

**Interfaces** (`routers.go:97-101`) :
```
GET    /ws/agent               → WebSocket persistante des agents
GET    /ws/relay               → WebSocket entre relays
```
Les deux mêmes routes sont aussi servies sur 7770.

**Authentification** : identique à 7770 — `/ws/agent` n'accepte que le JWT de rôle `agent` (aucun jeton plugin ni admin).

**TLS** : natif (WSS, même certificat que 7770).

**Configuration agents** :
```bash
# Défaut du minion :
export RELAY_WS_URL="wss://relay:7772/ws/agent"
# Ou via le port API :
export RELAY_WS_URL="wss://relay:7770/ws/agent"
```
Le chemin `/ws/agent` est **obligatoire** dans `RELAY_WS_URL` : le minion se connecte à l'URL telle quelle.

---

## Matrice de Sécurité

| Port | Endpoint | Auth | Agent | Plugin | Admin | Notes |
|------|----------|------|-------|--------|-------|-------|
| **7770** | POST /api/register | jeton d'enrôlement ou clef pré-autorisée | ✓ | ✗ | ✗ | Challenge RSA-OAEP |
| **7770 / 7772** | GET /ws/agent | JWT(rôle agent) | ✓ | ✗ | ✗ | Dispatch de tâches ; autre rôle refusé |
| **7770** | POST /api/exec, /api/upload, /api/fetch | jeton plugin | ✗ | ✓ | ✗ | REST bloquant |
| **7770** | GET /api/inventory | jeton plugin | ✗ | ✓ | ✗ | `ADMIN_TOKEN` refusé (403) |
| **7770** | GET /health | aucune | ✓ | ✓ | ✓ | Liveness |
| **7771** | /api/admin/*, GET /api/inventory | ADMIN_TOKEN | ✗ | ✗ | ✓ | Aucun accès sans jeton, même en loopback |

---

## Variables de Configuration

### Serveur (secagent-server)

```bash
# Adresses d'écoute (configurables)
API_ADDR=":7770"       # défaut
WS_ADDR=":7772"        # défaut
ADMIN_ADDR=":7771"     # défaut : toutes les interfaces -> impose ADMIN_TLS=true (sinon le serveur refuse de démarrer)
ADMIN_ADDR="127.0.0.1:7771"   # loopback : HTTP admin accepté

# TLS
TLS_CERT="/etc/secagent/tls.crt"    # Certificat PEM
TLS_KEY="/etc/secagent/tls.key"     # Clef privée PEM
TLS_DISABLE=                        # Ne jamais définir en production (tests uniquement)

# Admin
ADMIN_TLS=true                      # TLS sur le port admin (même certificat)
ADMIN_INSECURE_HTTP=true            # dérogation : HTTP clair hors loopback (réseau protégé)
ADMIN_INSECURE_HTTP_ACK="i-understand-the-risk"   # accusé obligatoire avec la dérogation
```

### Agents (secagent-minion)

```bash
# Enrôlement (HTTPS)
RELAY_SERVER_URL="https://relay:7770"          # Défaut : https://localhost:7770
RELAY_SERVER_URL="https://relay1:7770,https://relay2:7770"  # Multi-adresses

# WebSocket (WSS) — défaut : wss://localhost:7772/ws/agent
RELAY_WS_URL="wss://relay:7772/ws/agent"
RELAY_WS_URL="wss://relay1:7772/ws/agent,wss://relay2:7772/ws/agent"  # Failover
```

**Important** : `RELAY_SERVER_URL` et `RELAY_WS_URL` doivent avoir le même nombre d'adresses (pairées par position).

---

## Règles Firewall Recommandées

```bash
# Port 7770 — Agents + Plugins (réseau agents + Ansible Control Nodes)
ufw allow from 192.168.1.0/24 to any port 7770   # Réseau agents
ufw allow from 10.0.0.0/8 to any port 7770       # Réseau control nodes

# Port 7771 — Admin (hôte local ou réseau d'administration ; jamais le réseau agents)
ufw allow from 127.0.0.1 to any port 7771        # Loopback
ufw allow from 10.0.1.0/24 to any port 7771      # Réseau admin (opt.)

# Port 7772 — WebSocket dédié (même règles que 7770 ; défaut du minion)
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
    # Admin — publié sur la boucle locale de l'hôte seulement
    - "127.0.0.1:7771:7771"
    # WebSocket dédié — publié
    - "7772:7772"
  environment:
    # Dans le conteneur, l'API admin écoute sur toutes les interfaces : TLS obligatoire
    ADMIN_ADDR: "0.0.0.0:7771"
    ADMIN_TLS: "true"
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
| 78 | Enrollment refusé (403 : jeton invalide, expiré ou consommé) ou absence de `RELAY_ENROLLMENT_TOKEN` | Arrêt définitif — `RestartPreventExitStatus=78` | L'opérateur crée nouveau token d'enrôlement |
| 75 | Verrou maître **perdu par une instance vivante** (`server/instance.go:38`) — un crash ne produit pas ce code | Redémarrage en secondaire | Failover automatique (multi-hôtes) |

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

# Tester l'enrollment (--cacert : vérification TLS ; n'utiliser `-k` qu'en dev/qualif avec certificat auto-signé)
curl -X POST --cacert ca.pem https://relay:7770/api/register \
  -H "Content-Type: application/json" \
  -d '{"hostname":"test","public_key_pem":"...","enrollment_token":"..."}'

# Tester la liveness (public)
curl --cacert ca.pem https://relay:7770/health

# Tester l'API admin (ADMIN_TOKEN obligatoire, HTTPS si ADMIN_TLS=true)
curl --cacert ca.pem -H "Authorization: Bearer $ADMIN_TOKEN" https://127.0.0.1:7771/api/admin/status

# Tester l'inventaire (jeton plugin, port 7770)
curl --cacert ca.pem -H "Authorization: Bearer $PLUGIN_TOKEN" https://relay:7770/api/inventory
```

---

## Documentation Référence

- [DOC/server/SERVER_SPEC.md](../server/SERVER_SPEC.md) — Spécifications techniques complètes
- [DOC/agent/AGENT_SPEC.md](../agent/AGENT_SPEC.md) — Protocole enrollment et WebSocket agent
- [DOC/security/SECURITY.md](./SECURITY.md) — Modèle de sécurité complet + avis v3.0.3
- [DEPLOYMENT/README.md](../../DEPLOYMENT/README.md) — Configuration déploiement
