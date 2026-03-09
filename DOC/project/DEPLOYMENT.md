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

### Server (.env)
```
JWT_SECRET_KEY=dev-secret-key-for-qualification-only-change-in-prod
ADMIN_TOKEN=dev-admin-token-for-qualification-only-change-in-prod
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
