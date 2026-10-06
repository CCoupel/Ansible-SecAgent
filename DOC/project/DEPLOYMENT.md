# Ansible-SecAgent — Deployment Guide v3.0.3

## Architecture

Ansible-SecAgent v3.0.3 est composé de trois éléments :

### 1. **Serveur Relay** (secagent-server GO)
- **Transports** : HTTP REST + WebSocket persistante (TLS natif sur tous les ports)
- **Ports** :
  - **7770** : API REST + WebSocket agent (enrollment `/api/register` + task dispatch `/ws/agent`)
  - **7771** : Admin CLI (loopback par défaut, HTTPS si réseau)
  - **7772** : WebSocket agent historique (deprecated, compat v3.0.3 only)
- **État** : Fichier JSON (`relay.state`) sur stockage partagé NFS
- **Verrou** : Actif/passif avec exclusion mutuellement exclusive (`relay.lock`)
- **Pas de NATS** : Dispatch direct WebSocket par `task_id`

**Network** : Docker bridge ou host (agents et plugins connectent en sortie)

### 2. **Agents** (secagent-minion GO)
- **Déploiement** : Systemd ou Docker container sur chaque hôte cible
- **Connexion** : WebSocket persistante sortante vers relay (port 7770 ou 7772)
- **Enrollment** : POST /api/register (RSA-4096 + JWT) une seule fois
- **Exécution** : Subprocess par tâche, isolation complète, max 10 concurrentes (configurable)
- **Codes de sortie** : 0-7 normal, 77 (revoked - no restart), 78 (enrollment refused - no restart)

**Network** : Host network (agents sur 192.168.1.100-102, relay sur 192.168.1.218)

### 3. **Plugin Ansible** (connection + inventory, Python)
- **Connection plugin** : Route exec/put_file/fetch_file vers relay via REST HTTP bloquant
- **Inventory plugin** : Récupère la liste des agents enrôlés via API admin
- **Cible** : Port 7770 (API unified + WebSocket)
- **Authentification** : JWT signé (rôle `plugin` ou `admin`)

---

## Déploiement en Qualification

### Prérequis
- Docker et Docker Compose installés
- Certificats TLS auto-signés générés : `DEPLOYMENT/qualif/tls.crt` + `tls.key`
- Variables d'environnement : `DEPLOYMENT/qualif/.env` (STATE_DIR, JWT_SECRET_KEY, etc.)
- **Pas de NATS, pas de FastAPI, pas de Caddy** — v3.0.3+ utilise GO server natif + TLS natif

### Étape 1 : Initialiser l'état du relay

```bash
cd DEPLOYMENT/qualif
mkdir -p state logs
docker compose run --rm secagent-server state init
# Génère relay.state (fichier d'état JSON) avec RSA_MASTER_KEY auto-généré
```

Vérifier l'initialisation :
```bash
docker compose exec relay secagent-server state verify
# Exit code 0 = OK, state cohérent
```

### Étape 2 : Lancer le relay

```bash
docker compose up -d relay
docker compose logs relay | grep -i "listening\|port 7770"
# Attendre : "Relay listening on 7770, 7771, 7772"
```

Healthcheck :
```bash
curl -k https://localhost:7770/health
# {"status":"ok","agents":0,"uptime_seconds":N}
```

### Étape 3 : Générer token d'enrôlement et déployer agents

```bash
# Créer un token d'enrôlement valide 1h
TOKEN=$(docker compose exec relay \
  secagent-server admin token create --role agent --duration 1h | grep -oE '[a-zA-Z0-9._-]{100,}')

# Passer le token aux agents via .env ou docker exec
docker compose set-env minion-01 RELAY_ENROLLMENT_TOKEN=$TOKEN
docker compose set-env minion-02 RELAY_ENROLLMENT_TOKEN=$TOKEN
docker compose set-env minion-03 RELAY_ENROLLMENT_TOKEN=$TOKEN

# Démarrer les agents
docker compose up -d minion-01 minion-02 minion-03

# Vérifier la connexion
sleep 5
docker compose logs minion-01 | grep -i "enrolled\|connected"
# Attendre : "Enrolled successfully" + "WebSocket open"
```

### Étape 4 : Vérifier l'inventaire

```bash
# Récupérer JWT admin
ADMIN_JWT=$(docker compose exec relay \
  secagent-server admin token create --role admin --duration 1h | grep -oE '[a-zA-Z0-9._-]{100,}')

# Requêter l'inventaire dynamique
curl -k -H "Authorization: Bearer $ADMIN_JWT" \
  https://localhost:7770/api/inventory | jq .
# Doit afficher les 3 agents avec leurs facts
```

---

## Codes de Sortie et Redémarrage

### Agents (codes systemd significatifs)

```ini
[Service]
# Redémarrage automatique sur erreurs normales
Restart=on-failure
RestartSec=30s
StartLimitIntervalSec=600
StartLimitBurst=5

# NE PAS redémarrer sur ces codes
RestartPreventExitStatus=77 78

# Code 77 (Revoked) : JTI blacklisté — opérateur doit créer nouveau token
# Code 78 (Enrollment Refused) : 403 persistant — opérateur doit créer nouveau token
```

### Relay (codes significatifs)

| Code | Cause | Action |
|------|-------|--------|
| 0 | Arrêt propre | Normal |
| 75 | Verrou perdu (master crash) | Redémarrage par container policy → promotion passif |

---

## Gestion des Erreurs et Reprise

## Gestion des Tokens Relay (v3.0.1)

### Créer un token relay-parent (pour mode push)

Sur l'enfant (dmz1), créer un token que le parent utilisera :

```bash
docker exec secagent-server secagent-server tokens create \
  --role relay-parent \
  --sub central \
  --expires 90d \
  --description "Token pour central→dmz1 push mode"

# Sortie : secagent_relay_parent_xxxxxxxx (affiché UNE SEULE FOIS)
# Transmettre ce token au parent pour POST /api/admin/relays
```

### Lister les tokens relay-parent

```bash
docker exec secagent-server secagent-server tokens list --role relay-parent

# Sortie : id, parent_id (sub), expires_at, revoked_at
```

### Révoquer un token relay-parent

```bash
docker exec secagent-server secagent-server tokens revoke <token-id>

# Effets :
# - JTI blacklisté
# - Lien parent actif fermé (close 4010 permanent)
# - Parent ne peut plus se reconnecter avec ce token (401)
```

### Révoquer un relay enfant (mode pull)

```bash
# Via API (port 7771, admin)
curl -X POST http://localhost:7771/api/admin/relays/dmz1/revoke \
  -H "Authorization: Bearer <ADMIN_TOKEN>"

# Via CLI
docker exec secagent-server secagent-server relays revoke dmz1

# Effets :
# - JTI du token enfant blacklisté
# - Lien enfant fermé (close 4010 permanent)
# - Enfant ne peut plus se reconnecter
```

### Supprimer un relay (legacy ou post-revocation)

⚠️ **Règle importante** : Toujours révoquer AVANT de supprimer (sinon 409 relay_not_revoked)

```bash
# 1. Révoquer d'abord
docker exec secagent-server secagent-server relays revoke dmz1

# 2. Puis supprimer
docker exec secagent-server secagent-server relays delete dmz1

# Ou via API
curl -X DELETE http://localhost:7771/api/admin/relays/dmz1 \
  -H "Authorization: Bearer <ADMIN_TOKEN>"
```

---

## Commandes Utiles

### Voir les logs du serveur
```bash
export DOCKER_HOST=tcp://192.168.1.218:2375
docker logs relay-api --follow
docker logs relay-nats --follow
```

### Voir les logs des agents
```bash
docker logs secagent-minion-01 --follow
docker logs secagent-minion-02 --follow
docker logs secagent-minion-03 --follow
```

### Arrêter complètement
```bash
# Minions
cd ansible_minion && docker compose down

# Server
cd ../ansible_server && docker compose down
```

### Redémarrer un agent
```bash
docker restart secagent-minion-02
```

### Nettoyer les volumes (données persistantes)
```bash
docker volume rm ansible_minion_secagent_agent_01_data
docker volume rm ansible_minion_secagent_agent_02_data
docker volume rm ansible_minion_secagent_agent_03_data
docker volume rm ansible_server_secagent_data
docker volume rm ansible_server_nats_data
```

---

## Variables d'Environnement

### Server Core (.env)
```
JWT_SECRET_KEY=dev-secret-key-for-qualification-only-change-in-prod
ADMIN_TOKEN=dev-admin-token-for-qualification-only-change-in-prod
NATS_URL=nats://nats:4222
DATABASE_URL=relay.db
RSA_MASTER_KEY=dev-rsa-master-key-for-push-tokens-change-in-prod
RELAY_PLUGIN_TOKEN=dev-plugin-token-change-in-prod
```

### Server Network Binding (v3.0.2)
```
API_ADDR=:7770                     # Écoute API publique + WS agent/relay (défaut :7770)
ADMIN_ADDR=:7771                   # Écoute API admin (défaut :7771, JAMAIS exposé)
WS_ADDR=:7772                      # Écoute WebSocket (défaut :7772)
TLS_CERT=/path/to/cert.pem         # Certificat TLS (optionnel, sinon Caddy)
TLS_KEY=/path/to/key.pem           # Clef TLS (optionnel, sinon Caddy)
```

### Server Repeater Mode (enfant pull)
```
REPEATER_ID=dmz1                               # ID unique du relay enfant (format ^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$)
REPEATER_UPSTREAM_URL=wss://central:7772      # URL WSS du parent (liste séparée par des virgules : une par instance)
REPEATER_UPSTREAM_TOKEN=<jwt-relay-child>     # Token JWT rôle relay-child
RELAY_GROUP_VARS={"region":"dmz"}             # Variables Ansible JSON (v3.0.2+)
```

### Server Repeater Mode (enfant push - parent déclaré)
```
# Sur le parent (central): enregistrer l'enfant via API
# POST /api/admin/relays
# {
#   "relay_id": "dmz1",
#   "urls": ["wss://dmz1.internal:7772"],
#   "token": "<jwt-relay-parent>",
#   "mode": "push"
# }
```

### Server Limits (Repeater)
```
MAX_SNAPSHOT_HOSTS=10000                        # Limite hôtes dans topology_snapshot (défaut 10000)
MAX_SNAPSHOT_RELAYS=1000                        # Limite relays dans topology_snapshot (défaut 1000)
MAX_AGENT_LIST_HOSTS=10000                      # Limite hôtes dans agent_list heartbeat (défaut 10000)
MAX_WS_MESSAGE_SIZE_RELAY=10485760              # Taille max message WebSocket relay (défaut 10MB)
```

### Server Hooks (v3.0.2)
```
RELAY_HOOKS_CONFIG=/etc/secagent/hooks.json     # Chemin fichier hooks (optionnel)
RELAY_HOOKS_MAX_CONCURRENT_ACTIONS=64           # Limit goroutines hook actions (défaut 64)
```

### Client `secagent-inventory` (v3.0.2)
```
RELAY_SERVER_URL=https://relay.example.com:7770  # URL du relay server
RELAY_TOKEN=secagent_plugin_xxxxx                # Bearer token (RELAY_PLUGIN_TOKEN du serveur)
RELAY_SCOPE=zone-a                              # ID du relay (optionnel, v3.0.2+) — limite inventaire à ce sous-arbre
RELAY_CA_BUNDLE=/path/to/ca.pem                 # CA custom (optionnel)
RELAY_INSECURE_TLS=false                        # true = skip vérif TLS (DEV/QUALIF SEULEMENT)
RELAY_INSECURE_TLS_ACK=i-understand-the-risk    # Confirmation si RELAY_INSECURE_TLS=true et serveur non-loopback
RELAY_ONLY_CONNECTED=false                      # true = hôtes connectés uniquement
```

### Agents (definis dans docker-compose.yml)
```
RELAY_SERVER_URL=http://localhost:7770
RELAY_HOSTNAME=qualif-host-01
RELAY_DATA_DIR=/var/lib/secagent-minion
```

---

## Architecture Réseau

```
┌─────────────────────────────────────────┐
│     192.168.1.218 (Docker Host)         │
├─────────────────────────────────────────┤
│                                         │
│  ┌─ ansible_server (bridge net) ────┐  │
│  │ ┌──────────┐                     │  │
│  │ │ relay-nats (4222/6222/8222) │  │  │
│  │ └─────┬────┘                     │  │
│  │       │                          │  │
│  │ ┌─────▼────────────────────────┐ │  │
│  │ │ relay-api (7770/7771/7772)  │ │  │
│  │ │ - Enrollment + WebSocket     │ │  │
│  │ │ - Plugin REST API            │ │  │
│  │ │ - Admin inventory            │ │  │
│  │ └────▲─┬───────────────────────┘ │  │
│  │      │ │                          │  │
│  │ ┌────┘ └───────────────────────┐ │  │
│  │ │ caddy (7443 TLS)             │ │  │
│  │ └─────────────────────────────┘ │  │
│  └───────────┬──────────────────────┘  │
│              │                          │
│  ┌───────────▼──────────────────────┐  │
│  │ ansible_minion (host network)    │  │
│  │                                  │  │
│  │ ┌──────────────────────────────┐ │  │
│  │ │ secagent-minion-01 (localhost)   │ │  │
│  │ │ secagent-minion-02 (localhost)   │ │  │
│  │ │ secagent-minion-03 (localhost)   │ │  │
│  │ └──────────────────────────────┘ │  │
│  └──────────────────────────────────┘  │
│                                         │
└─────────────────────────────────────────┘
```

Les agents (host network) accèdent au server (bridge network) via `localhost:7770`.

---

## Prochain Pas : Production (Kubernetes)

La configuration de production utilisera :
- **Helm Chart** pour le déploiement serveur
- **DaemonSet** pour les agents (un par nœud)
- **StatefulSet** pour NATS JetStream (persistance)
- **Secrets** pour les tokens JWT/admin
- **Ingress** pour le TLS/proxy

Voir `ARCHITECTURE.md` pour les détails complets.


## Supervision du lien amont (relay enfant)

Après un refus **permanent** (close 4010, identité changée, boucle), le client repeater (pull) ou le dialer (push) s'arrête : le nœud devient de fait une racine isolée mais **continue de servir** ses agents directs et sa descendance. Il n'est donc **pas** redémarré : l'état est exposé pour alerter.

| Interface | Contenu |
|---|---|
| `GET /health` (port 7770, **public**) | HTTP **200** maintenu (pas de redémarrage par la liveness). Uniquement le booléen `degraded` (vrai si un lien est `refused_permanent`), absent sur une racine sans lien : **aucun** relay_id, état ni raison (divulgation de topologie). |
| `secagent-server server status` / `GET /api/admin/status` (port 7771, **admin**) | Bloc `links` : `upstream` (`mode` pull/push, `peer`, `state`, `reason`, `since`) et `push_children[]` (`relay_id` + même état) ; tableau LINK/PEER/STATE/SINCE/REASON et avertissement « operator action required » si dégradé. La raison est assainie (caractères de contrôle remplacés, **200 octets max**, tronquée sur une frontière de caractère UTF-8). |

États : `connected`, `retrying` (connexion initiale, lien perdu, refus corrigible 4012, annulation : **pas** terminal), `refused_permanent` (terminal : action opérateur requise — token révoqué/remplacé, identité ou boucle à corriger, puis redémarrage ou nouvelle déclaration). La raison est bornée (**200 octets max**, tronquée sur une frontière de caractère UTF-8) et ne contient jamais de token. Une trame close 4010 sur un lien push établi rend le Dialer terminal (log ERROR « operator action required », pas de reconnexion ; 4012 et les autres codes restent corrigibles). Pas de métrique : aucune infrastructure de métriques n'existe aujourd'hui. Une sortie du processus (code dédié / `REPEATER_EXIT_ON_PERMANENT_REFUSAL`) n'est pas retenue pour l'instant ; une sonde de readiness distincte relèvera de #136.



## Adresses d'écoute (#155)

Le serveur écoute par défaut sur `:7770` (API publique + WebSocket), `:7771` (API admin) et `:7772` (WebSocket). Elles se changent par `API_ADDR`, `ADMIN_ADDR` et `WS_ADDR` (format `hôte:port` ou `:port`, une valeur mal formée arrête le démarrage). Les handlers d'administration ne sont servis que sur `ADMIN_ADDR` : ne publiez pas ce port hors du réseau d'administration. Un port déjà utilisé fait échouer le démarrage immédiatement.
