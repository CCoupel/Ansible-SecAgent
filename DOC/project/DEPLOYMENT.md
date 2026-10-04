# Ansible-SecAgent — Deployment Guide

## Architecture

Ansible-SecAgent est composé de deux éléments distincts :

### 1. **ansible_server** — Serveur Relay (Phase 2)
- **NATS JetStream** : Message broker pour les tâches/résultats
- **relay-api** : FastAPI multi-port (7770/7771/7772)
  - 7770 : Client (enrollment + WebSocket)
  - 7771 : Plugin (exec/upload/fetch)
  - 7772 : Inventory (admin)
- **Caddy** : Reverse proxy TLS (optionnel, port 7443)

**Network** : bridge (ansible_server_default)

### 2. **ansible_minion** — Agents Clients (Phase 1)
- **secagent-minion-01** : qualif-host-01
- **secagent-minion-02** : qualif-host-02
- **secagent-minion-03** : qualif-host-03

Chaque agent :
- S'enregistre auprès du serveur via POST /api/register
- Établit une WebSocket persistante pour recevoir les tâches
- Exécute les playbooks Ansible en tant que processus subprocess

**Network** : host (accès direct au localhost:7770 du serveur)

---

## Déploiement en Qualification

### Prérequis
- Docker Remote API accessible : `tcp://192.168.1.218:2375`
- Variables d'environnement définies dans `ansible_server/.env`

### Étape 1 : Déployer le Server

```bash
cd ansible_server
export DOCKER_HOST=tcp://192.168.1.218:2375
docker compose up --build -d
```

Vérifier que le serveur est healthy :
```bash
docker compose ps
curl http://192.168.1.218:7770/health
# {"status":"ok","db":"ok","nats":"ok"}
```

### Étape 2 : Déployer les Minions

```bash
cd ../ansible_minion
export DOCKER_HOST=tcp://192.168.1.218:2375
docker compose up --build -d
```

Vérifier les inscriptions des agents :
```bash
docker logs secagent-minion-01
docker logs secagent-minion-02
docker logs secagent-minion-03
# Rechercher : "WebSocket connecté — en attente de tâches"
```

### Étape 3 : Pré-autoriser les agents (une seule fois)

Les agents doivent être pré-autorisés dans la table `authorized_keys` avant le premier enrollment.

```bash
# Récupérer les clefs publiques
docker cp secagent-minion-01:/var/lib/secagent-minion/public_key.pem /tmp/pk01.pem
docker cp secagent-minion-02:/var/lib/secagent-minion/public_key.pem /tmp/pk02.pem
docker cp secagent-minion-03:/var/lib/secagent-minion/public_key.pem /tmp/pk03.pem

# Autoriser chaque agent
ADMIN_TOKEN="dev-admin-token-for-qualification-only-change-in-prod"
API="http://192.168.1.218:7770/api/admin/authorize"

for i in 01 02 03; do
  PK=$(cat /tmp/pk${i}.pem | jq -Rs .)
  curl -X POST "$API" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"hostname\": \"qualif-host-${i}\", \"public_key_pem\": $PK, \"approved_by\": \"setup-script\"}"
done

# Redémarrer les agents pour qu'ils s'inscrivent
docker restart secagent-minion-01 secagent-minion-02 secagent-minion-03
```

---

## Vérification de l'Inventaire Dynamique

Une fois les agents connectés, interroger l'inventaire via le plugin :

```bash
# Générer un JWT plugin (valide 1h)
export JWT_SECRET_KEY="dev-secret-key-for-qualification-only-change-in-prod"

TOKEN=$(python3 << 'EOF'
import json, uuid, base64, hmac, hashlib
from datetime import datetime, timezone

header = {"alg": "HS256", "typ": "JWT"}
header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b'=')

jti = str(uuid.uuid4())
now = int(datetime.now(timezone.utc).timestamp())
payload = {
    "sub": "test",
    "role": "plugin",
    "jti": jti,
    "iat": now,
    "exp": now + 3600,
}
payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=')

message = header_b64 + b'.' + payload_b64
signature = hmac.new("dev-secret-key-for-qualification-only-change-in-prod".encode(), message, hashlib.sha256).digest()
signature_b64 = base64.urlsafe_b64encode(signature).rstrip(b'=')

print((header_b64 + b'.' + payload_b64 + b'.' + signature_b64).decode())
EOF
)

# Récupérer l'inventaire
curl -s http://192.168.1.218:7770/api/inventory \
  -H "Authorization: Bearer $TOKEN" | jq .
```

---

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

### Server Repeater Mode (enfant pull)
```
REPEATER_ID=dmz1                               # ID unique du relay enfant
REPEATER_UPSTREAM_URL=wss://central:7772      # URL WSS du parent
REPEATER_UPSTREAM_TOKEN=<jwt-relay-child>     # Token JWT rôle relay-child
RELAY_GROUP_VARS={"region":"dmz"}             # Variables Ansible JSON
```

### Server Repeater Mode (enfant push - parent déclaré)
```
# Sur le parent (central): enregistrer l'enfant via API
# POST /api/admin/relays
# {
#   "relay_id": "dmz1",
#   "url": "wss://dmz1.internal:7772",
#   "token": "<jwt-relay-parent>",
#   "mode": "push"
# }
```

### Limites (Repeater)
```
MAX_SNAPSHOT_HOSTS=10000           # Limite hôtes dans topology_snapshot (défaut 10000)
MAX_SNAPSHOT_RELAYS=1000           # Limite relays dans topology_snapshot (défaut 1000)
MAX_AGENT_LIST_HOSTS=10000         # Limite hôtes dans agent_list heartbeat (défaut 10000)
MAX_WS_MESSAGE_SIZE_RELAY=10MB     # Taille max message WebSocket relay
```

### Agents (définis dans docker-compose.yml)
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

