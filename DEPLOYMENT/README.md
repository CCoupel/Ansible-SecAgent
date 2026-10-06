# Ansible-SecAgent Deployment Guide

## Overview

Ce répertoire contient les configurations Docker Compose pour déployer Ansible-SecAgent en qualif et production.

**Architecture v3.0.3 :**
- **Relay Server** : daemon GO, TLS natif (ports 7770 API+/ws/agent, 7771 admin, 7772 compat), état fichier JSON + verrou exclusif
- **Relay Agents** : secagent-minion sur chaque hôte cible, WebSocket persistante sortante
- **Ansible Control Node** : container Ansible avec plugin connection secagent (Python)
- **Multi-hôte actif/passif** : verrou d'exclusivité (1 relay actif, N relays passifs)

---

## Architecture Multi-hôtes Actif/Passif

```
┌─────────────────────────────────────┐
│   NFS Partagé (STATE_DIR)          │
│   - relay.state (HMAC-SHA256)      │
│   - relay.lock (verrou exclusif)   │
│   - actions.log (JSON Lines)       │
└─────────────────────────────────────┘
           ▲            ▲            ▲
           │            │            │
      ┌────▼──┐    ┌─────▼──┐    ┌─────▼──┐
      │Relay-1│    │Relay-2 │    │Relay-3 │
      │ACTIF  │    │Passif  │    │Passif  │
      └───┬───┘    └────────┘    └────────┘
          │
          ├─► PORT 7770 (API + /ws/agent, TLS natif)
          ├─► PORT 7771 (Admin, loopback par défaut)
          └─► PORT 7772 (compat, WebSocket agent)
```

**Comportement :**
- Relay actif : acquiert le verrou, traite les tâches
- Relays passifs : essaient périodiquement d'acquérir le verrou, reprennent si actif crash
- Agents : se reconnectent automatiquement en cas de failover

---

## Déploiement Qualif (Single-host Compose)

### 1. Préparation de l'environnement

```bash
cd DEPLOYMENT

# Créer les répertoires
mkdir -p qualif/state qualif/logs

# Générer certificats TLS (auto-signés pour tests)
openssl req -x509 -newkey rsa:2048 -keyout qualif/tls.key -out qualif/tls.crt \
  -days 365 -nodes -subj "/CN=localhost"

# Créer fichier .env local
cat > qualif/.env <<EOF
STATE_DIR=./state
TLS_CERT=./tls.crt
TLS_KEY=./tls.key
ADMIN_ADDR=127.0.0.1:7771
ADMIN_TLS=false
RELAY_PRIVATE_KEY=/etc/secagent-minion/id_rsa
RELAY_JWT_PATH=/etc/secagent-minion/token.jwt
RELAY_SERVER_URL=https://relay:7770
RELAY_WS_URL=wss://relay:7772/ws/agent
EOF
```

### 2. Lancer Docker Compose

```bash
# Voir docker-compose.yml (fourni)
docker compose -f qualif/docker-compose.yml up -d

# Vérifier état
docker compose -f qualif/docker-compose.yml ps
```

### 3. Initialiser l'état du relay

```bash
# Créer le fichier d'état vierge
docker compose -f qualif/docker-compose.yml exec relay \
  secagent-server state init

# Vérifier l'initialisation
docker compose -f qualif/docker-compose.yml exec relay \
  secagent-server state verify
# Sortie attendue : exit code 0 (OK)
```

### 4. Enrôler les agents

```bash
# Générer un token d'enrôlement (depuis l'admin local)
TOKEN=$(docker compose -f qualif/docker-compose.yml exec -it relay \
  secagent-server admin token create --role agent --duration 1h | grep -oE '[a-zA-Z0-9._-]+' | tail -1)

# Passer le token aux agents
docker compose -f qualif/docker-compose.yml set-env minion-01 RELAY_ENROLLMENT_TOKEN=$TOKEN
docker compose -f qualif/docker-compose.yml restart minion-01

# Vérifier la connexion
docker compose -f qualif/docker-compose.yml logs minion-01 | grep -i "enrolled\|connected"
```

### 5. Vérifier le déploiement

```bash
# Healthcheck local
docker compose -f qualif/docker-compose.yml exec relay \
  secagent-server status --local

# Vérifier les agents
curl -k -H "Authorization: Bearer $ADMIN_TOKEN" \
  https://localhost:7770/api/agents

# Port bindings
netstat -an | grep 777
# Doit afficher : 7770, 7771, 7772
```

---

## Déploiement Production (Multi-hôtes Compose)

### 1. Préparation NFS partagé

```bash
# Sur le serveur NFS (ex. nas.example.com)
sudo mkdir -p /export/secagent-state
sudo chmod 700 /export/secagent-state
sudo exportfs -a

# Sur chaque hôte production
sudo mkdir -p /mnt/secagent-state
sudo mount -t nfs -o hard,intr nas.example.com:/export/secagent-state /mnt/secagent-state
sudo chmod 700 /mnt/secagent-state

# Ajouter à /etc/fstab pour persistance au reboot
echo "nas.example.com:/export/secagent-state /mnt/secagent-state nfs hard,intr,_netdev 0 0" | sudo tee -a /etc/fstab
```

### 2. Configuration multi-hôtes

**Sur hôte relay-1 (actif) :**
```bash
STATE_DIR=/mnt/secagent-state
TLS_CERT=/etc/secagent/tls.crt
TLS_KEY=/etc/secagent/tls.key
ADMIN_ADDR=127.0.0.1:7771
ADMIN_TLS=false
```

**Sur hôtes relay-2, relay-3 (passifs) :**
```bash
# Même STATE_DIR, même certificats TLS
STATE_DIR=/mnt/secagent-state
TLS_CERT=/etc/secagent/tls.crt
TLS_KEY=/etc/secagent/tls.key
ADMIN_ADDR=127.0.0.1:7771  # Loopback (admin local uniquement)
ADMIN_TLS=false
```

### 3. Lancer compose sur chaque hôte

```bash
docker compose -f prod/docker-compose.yml up -d
```

**Résultat attendu :**
- Relay-1 : acquiert le verrou après 30s (beat), devient ACTIF
- Relay-2, Relay-3 : restent en attente, relancent la tentative toutes les 30s

### 4. Promotion qualif → prod (image digest pinning)

```bash
# Récupérer le digest de l'image déjà validée en qualif
DIGEST=$(docker inspect secagent-server:v3.0.3 | jq -r '.[0].RepoDigests[0]')

# Mettre à jour prod/docker-compose.yml avec le digest exact
sed -i "s|image: secagent-server:.*|image: ${DIGEST}|g" prod/docker-compose.yml

# Commiter et déployer
git commit -m "prod: pin secagent-server digest ${DIGEST}"
docker compose -f prod/docker-compose.yml pull
docker compose -f prod/docker-compose.yml up -d
```

---

## Configuration des Ports

| Port | Service | Interface | TLS | Usage |
|------|---------|-----------|-----|-------|
| 7770 | REST API + /ws/agent | `0.0.0.0` | ✓ HTTPS/WSS natif | Agents + Plugins |
| 7771 | Admin CLI | `127.0.0.1` par défaut | TLS optionnel (loopback) | Opérateurs locaux |
| 7772 | WebSocket (compat) | `0.0.0.0` | ✓ WSS natif | Redondance avec 7770 |

**Règles TLS :**
- Port 7770 : TLS obligatoire (HTTPS et WSS)
- Port 7771 : Loopback = HTTP par défaut ; si non-loopback, TLS obligatoire (ADMIN_TLS=true)
- Port 7772 : TLS obligatoire (compatible avec 7770)

---

## Variables d'Environnement

### Relay Server (secagent-server)

| Variable | Default | Required | Description |
|----------|---------|----------|-------------|
| `STATE_DIR` | `/data` | Oui | Répertoire d'état partagé (NFS pour multi-hôtes) |
| `TLS_CERT` | — | Sauf test | Fichier certificat TLS (PEM) |
| `TLS_KEY` | — | Sauf test | Fichier clef TLS (PEM) |
| `TLS_DISABLE` | — | Non | Désactiver TLS (tests uniquement) |
| `ADMIN_ADDR` | `:7771` | Non | Adresse d'écoute admin (ex: `127.0.0.1:7771`) |
| `ADMIN_TLS` | `false` | Non | Activer TLS sur admin si non-loopback |
| `ADMIN_INSECURE_HTTP` | `false` | Non | Autoriser HTTP sur admin (tests, avec ACK) |
| `REPEATER_CA_FILE` | — | Non | CA bundle pour relais (non-rechargé à chaud) |
| `REPEATER_UPSTREAM_URL` | — | Non | URL du relay parent en mode relais |

### Minion Agents (secagent-minion)

| Variable | Default | Description |
|----------|---------|-------------|
| `RELAY_SERVER_URL` | `https://localhost:7770` | URL(s) HTTPS pour enrollment (liste séparée par `,`, pairée par position avec RELAY_WS_URL) |
| `RELAY_WS_URL` | `wss://localhost:7772/ws/agent` | URL(s) WSS pour WebSocket (liste, pairée par position avec RELAY_SERVER_URL) |
| `RELAY_PRIVATE_KEY` | `/etc/secagent-minion/id_rsa` | Clef privée RSA-4096 (stockée 0600) |
| `RELAY_JWT_PATH` | `/etc/secagent-minion/token.jwt` | Token JWT courant (réécrit à chaque enrollment) |
| `RELAY_MAX_TASKS` | `10` | Tâches concurrentes max |
| `RELAY_STDOUT_MAX` | `5242880` | Buffer stdout max (5MB) |
| `RELAY_INSECURE_TLS` | `false` | Désactiver vérif TLS (tests uniquement) |

### Multi-adresses (Failover)

**Exemple à 2 relays :**
```bash
# RELAY_SERVER_URL et RELAY_WS_URL doivent avoir le même nombre d'adresses
export RELAY_SERVER_URL="https://relay1.example.com:7770,https://relay2.example.com:7770"
export RELAY_WS_URL="wss://relay1.example.com:7772/ws/agent,wss://relay2.example.com:7772/ws/agent"

# Les deux listes sont pairées :
# - relay1 = index 0
# - relay2 = index 1
```

---

## Gestion des Erreurs et Reprise

### Codes de Sortie

**Relay :**
| Code | Cause | Action |
|------|-------|--------|
| 0 | Arrêt propre | Normal |
| 75 | Verrou perdu (crash du maître) | Redémarrage auto par systemd/docker |

**Minion :**
| Code | Cause | Comportement |
|------|-------|-------------|
| 0-7 | Erreurs normales | Redémarrage par policy |
| 77 | Revoked (JTI blacklisté) | **NE PAS redémarrer** — état terminal |
| 78 | Enrollment refused (403 persistant) | **NE PAS redémarrer** — l'opérateur crée nouveau token |

**Systemd config recommandée (agents) :**
```ini
[Service]
Restart=on-failure
RestartSec=30s
RestartPreventExitStatus=77 78
StartLimitIntervalSec=600
StartLimitBurst=5
```

### Vérification et Restauration d'État

```bash
# Vérifier l'état du relay
secagent-server state verify

# Si HMAC invalid ou schema corrompu : restauration depuis backup
secagent-server state restore --from /backup/relay.state.bak

# Codes de sortie :
# 0 = OK
# 2 = HMAC invalid
# 3 = schema unknown
# 4 = invariant violated
# 5 = file unreadable
# 6 = RSA_MASTER_KEY missing
# 7 = write_seq too low
# 8 = instance alive (restore bloqué)
```

---

## Monitorage et Santé

### Health Check Local

```bash
# Sur le relay
secagent-server status --local
# Sortie : state fichier + verrou + uptime + agents connectés

# Liveness check depuis conteneur
curl -f http://localhost:7771/healthz || exit 1
```

### Logs

**Relay :**
```bash
# JSON Lines append-only
tail -f /data/actions.log | jq .

# Secrets masqués automatiquement (HMAC, tokens, en-têtes)
```

**Minion :**
```bash
journalctl -u secagent-minion -f
# become_pass masqué dans tous les logs
```

---

## Limitations Connues v3.0.3

| Limitation | Impact | Mitigation |
|-----------|--------|-----------|
| Rejeu après arrêt à froid | write_seq gardée perdue | Backups réguliers + permissions 0700 |
| DoS : promotion forcée via relay.lock forgée | Un attaquant peut forcer la basculement | Autoriser écritures STATE_DIR à relay seul |
| REPEATER_CA_FILE non-rechargée à chaud | Rotation de CA nécessite redémarrage/failover | Redémarrer le relay inactif, puis basculer |
| Rotation RSA_MASTER_KEY : ré-enrôlement obligatoire | Tous les agents doivent se ré-enrôler | Planifier rotation pendant fenêtre maintenance |

---

## Troubleshooting

### Le relay ne démarre pas

```bash
# Vérifier les certificats TLS
openssl x509 -in $TLS_CERT -text -noout

# Vérifier l'état du fichier
secagent-server state verify

# Logs
docker logs relay | grep -i error
```

### Les agents ne se connectent pas

```bash
# Vérifier enrollment
docker logs minion-01 | grep -i "enroll\|403\|401"

# Vérifier URLs (multi-adresses)
echo $RELAY_SERVER_URL
echo $RELAY_WS_URL

# Test de connectivité
curl -k -v https://relay:7770/api/agents
```

### Failover vers passif ne se fait pas

```bash
# Vérifier verrou
ls -la /mnt/secagent-state/relay.lock

# Vérifier NFS
mount | grep secagent-state

# Logs du passif
docker logs relay-2 | grep -i "lock\|stale\|promote"
```

---

## Documentation Référence

- [DOC/server/SERVER_SPEC.md](../DOC/server/SERVER_SPEC.md) — Spécifications techniques du relay
- [DOC/agent/AGENT_SPEC.md](../DOC/agent/AGENT_SPEC.md) — Spécifications de l'agent
- [DOC/security/SECURITY.md](../DOC/security/SECURITY.md) — Modèle de sécurité v3.0.3
- [DOC/project/DEPLOYMENT.md](../DOC/project/DEPLOYMENT.md) — Guide opérationnel complet
