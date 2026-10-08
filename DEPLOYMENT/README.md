# Ansible-SecAgent Deployment Guide

## Overview

Ce répertoire contient les configurations Docker Compose pour déployer Ansible-SecAgent en qualif et production.

**Architecture v3.0.3 :**
- **Relay Server** : daemon GO, TLS natif (7770 API + `/ws/agent` + `/ws/relay`, 7771 admin, 7772 listener WebSocket dédié `/ws/agent` + `/ws/relay`), état fichier + verrou exclusif
- **Relay Agents** : secagent-minion sur chaque hôte cible, WebSocket persistante sortante
- **Ansible Control Node** : Ansible avec le plugin de connexion `relay` (Python, `SECAGENT-PYTHON/`)
- **Multi-hôte actif/passif** : verrou d'exclusivité (1 instance maître, N secondaires)

Fichiers Compose **réels** de ce répertoire :

| Fichier | Rôle |
|---|---|
| `qualif/docker-compose.server.yml` | Qualif : 2 instances (`secagent-server-a`, `-b`) sur un volume d'état partagé |
| `qualif/docker-compose.chain.yml` | Qualif : chaîne de relais (#188) — inclut le fichier ci-dessus, ajoute un relay enfant pull (`secagent-child`) et deux minions (`minion-root`, `minion-child`) |
| `prod/docker-compose.server.yml` | Prod : relay racine (service `secagent-server`), identique sur N hôtes |
| `prod/docker-compose.child.yml` | Surcharge pour un relay enfant |

Scripts de qualif : `qualif/chain-test.sh` (`ci-prepare`, `bootstrap`, `smoke`, `failover`, `backup-restore`, `logs`, `down`),
`qualif/failover-test.sh` (bascule en conteneurs), `qualif/pki/gen.sh` (CA privée de test et certificat à SAN multiples ;
clés non versionnées). Voir [qualif/README.md](qualif/README.md) et [prod/README.md](prod/README.md).

Les anciens Compose `qualif/docker-compose.{minion,proxy,ansible}.yml`, `deploy.sh` / `deploy.bat` et `scripts/bootstrap-qualif.sh`
ont été **supprimés** (#188) ; il n'existe ni `qualif/docker-compose.yml` ni `prod/docker-compose.yml`.
Pas de NATS, pas de Caddy ni de reverse proxy : TLS natif dans le serveur.

**Images** : `linux/amd64` uniquement (publiées pour cette seule plate-forme par `candidate-images.yml` et `release.yml`) ;
aucune image arm64 n'est fournie en v3.0.3. Le poste de contrôle Ansible n'est pas un conteneur Compose : c'est le poste
qui lance `chain-test.sh` (plugin `SECAGENT-PYTHON`, binaire `secagent-inventory`, `ansible-core`).

---

## Architecture Multi-hôtes Actif/Passif

```
┌─────────────────────────────────────┐
│   NFS Partagé (STATE_DIR)          │
│   - relay.state (HMAC-SHA256)      │
│   - relay.lock (fichier O_EXCL +   │
│     battement)                     │
│   - actions.log (JSON Lines)       │
└─────────────────────────────────────┘
           ▲            ▲            ▲
           │            │            │
      ┌────▼──┐    ┌─────▼──┐    ┌─────▼──┐
      │Relay-1│    │Relay-2 │    │Relay-3 │
      │MAÎTRE │    │Second. │    │Second. │
      └───┬───┘    └────────┘    └────────┘
          │        (aucun port ouvert)
          ├─► PORT 7770 (API + /ws/agent + /ws/relay, TLS natif)
          ├─► PORT 7771 (Admin ; ADMIN_TLS=true hors boucle locale)
          └─► PORT 7772 (WebSocket dédié /ws/agent + /ws/relay)
```

**Comportement :**
- Instance maître : détient `relay.lock`, ouvre les ports, traite les tâches, bat le verrou toutes les 30 s
- Secondaires : **n'ouvrent aucun port** ; sondent le verrou toutes les 5 s
- Arrêt propre du maître : verrou relâché, reprise en 3,3 à 4,0 s (mesuré)
- Crash / `kill -9` / perte de l'hôte : le verrou n'est **pas** libéré par le système de fichiers (fichier `O_EXCL`, pas un `flock`) ; il reste jusqu'à péremption (5 min sans battement), puis un secondaire est promu
- Agents : se reconnectent automatiquement vers la liste d'adresses ; seul le maître répond

---

## Déploiement Qualif (Single-host Compose)

Version pas à pas : [DOC/project/QUICKSTART.md](../DOC/project/QUICKSTART.md). Résumé :

### 1. Préparation de l'environnement

```bash
cd DEPLOYMENT/qualif

# Certificat TLS auto-signé (le SAN est obligatoire)
mkdir -p tls
openssl req -x509 -newkey rsa:2048 -keyout tls/tls.key -out tls/tls.crt \
  -days 365 -nodes -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
chmod 0644 tls/tls.key      # lisible par l'UID 10001 du conteneur (essai local UNIQUEMENT)

# Secrets (hors dépôt) : JWT_SECRET_KEY, ADMIN_TOKEN, RSA_MASTER_KEY
cp qualif.env.example qualif.env

export SECAGENT_IMAGE=ghcr.io/ccoupel/secagent-server:sha-<commit>@sha256:<digest>
export QUALIF_TLS_DIR="$PWD/tls"
```

Le Compose fixe `ADMIN_ADDR=0.0.0.0:7771` et `ADMIN_TLS=true` : une adresse admin non loopback
**sans** `ADMIN_TLS=true` (ou dérogation `ADMIN_INSECURE_HTTP` + ACK) fait refuser le démarrage du serveur.

### 2. Initialiser l'état du relay (avant le premier démarrage)

Le serveur ne crée jamais son état implicitement : sans `relay.state` il refuse de démarrer.
`state init` **exige** `RSA_MASTER_KEY` (secret dont dérivent l'HMAC de l'état et le chiffrement AES-256-GCM de ses secrets).

```bash
docker compose -p secagent-qualif -f docker-compose.server.yml run --rm secagent-server-a state init

# Vérifier : le chemin du fichier est obligatoire, RSA_MASTER_KEY requis (code 6 sinon)
docker compose -p secagent-qualif -f docker-compose.server.yml run --rm secagent-server-a \
  state verify /data/relay.state
# Sortie attendue : exit code 0 (OK)
```

### 3. Lancer Docker Compose

```bash
docker compose -p secagent-qualif -f docker-compose.server.yml up -d
docker compose -p secagent-qualif -f docker-compose.server.yml ps
```

### 4. Enrôler les agents

Les jetons se créent avec la CLI du serveur, via l'API admin (7771, TLS ; `ADMIN_TOKEN` pris dans l'environnement du conteneur) :

```bash
srv() {
  docker compose -p secagent-qualif -f docker-compose.server.yml exec \
    -e RELAY_API_URL=https://localhost:7771 -e REPEATER_CA_FILE=/certs/tls.crt \
    secagent-server-a secagent-server "$@"
}

# Jeton d'enrôlement opaque : secagent_enr_ + 64 hex (77 caractères), affiché UNE seule fois
TOKEN=$(srv tokens create --role enrollment --expires 1h | grep -oE 'secagent_enr_[0-9a-f]{64}' | tail -1)

# Révoquer un jeton plugin ou relay-parent
srv tokens list
srv tokens revoke <id>
```

Rôles : `enrollment`, `plugin`, `relay-parent` (pas de rôle `agent` ni `admin`, pas d'option `--duration`
mais `--expires`, défaut `never`). Le jeton est ensuite passé à l'agent par la variable d'environnement
`RELAY_ENROLLMENT_TOKEN` (voir les variables ci-dessous) ; l'agent n'a pas de fichier de configuration.
Il n'existe pas de commande `docker compose set-env` : renseigner l'environnement du service ou de l'unité systemd.

### 5. Vérifier le déploiement

```bash
# Santé locale d'une instance (maître ou secondaire sain : code 0)
docker compose -p secagent-qualif -f docker-compose.server.yml exec secagent-server-a \
  secagent-server status --local

# Santé HTTP du maître (jeton non requis)
curl -s --cacert tls/tls.crt https://localhost:7770/health
# {"instance_id":"...","role":"master","status":"ok","timestamp":"..."}

# Inventaire : exige un jeton PLUGIN (ADMIN_TOKEN -> 403)
PLG=$(srv tokens create --role plugin --description verif --expires 1h | grep -oE 'secagent_plg_[0-9a-f]{64}' | tail -1)
curl -s --cacert tls/tls.crt -H "Authorization: Bearer $PLG" https://localhost:7770/api/inventory | jq .

# Ports : seul le maître écoute (le secondaire n'ouvre aucun port)
ss -ltn | grep -E ':(7770|7771|7772|8770|8771|8772)'
```

Les routes `/healthz` et `/api/agents` n'existent pas (404). L'API admin (7771) sans jeton répond 401.

---

## Déploiement Production (Multi-hôtes Compose)

Le guide de référence est [prod/README.md](prod/README.md) (stockage, vérification, sauvegarde). Résumé :

### 1. Préparation NFS partagé

```bash
# Sur le serveur NFS (ex. nas.example.com)
sudo mkdir -p /export/secagent-state
sudo chown 10001:10001 /export/secagent-state
sudo chmod 700 /export/secagent-state
sudo exportfs -a

# Sur chaque hôte production : montage `hard` (jamais `soft`), puis fstab
sudo mkdir -p /mnt/secagent-state
echo "nas.example.com:/export/secagent-state /mnt/secagent-state nfs4 rw,hard,nfsvers=4.1,noatime,actimeo=1,_netdev 0 0" | sudo tee -a /etc/fstab
sudo mount /mnt/secagent-state
```

Stockage non testé avec `prod/tools/test_shared_storage.py` = non supporté.

### 2. Configuration (identique sur tous les hôtes)

```bash
cd DEPLOYMENT/prod
cp .env.example .env            # SECAGENT_VERSION, STATE_HOST_DIR, TLS_CERT_DIR, ADMIN_PUBLISH_ADDR...
# Secrets : un fichier par secret dans ./secrets (jwt_secret_key, admin_token, rsa_master_key), mode 0400, hors dépôt :
# voir prod.env.example (v3.0.4, #196 : plus de secret en variable d'environnement)
```

`STATE_DIR`, `ADMIN_ADDR=0.0.0.0:7771` (dans le conteneur), `ADMIN_TLS=true` et les chemins TLS sont fixés par
`docker-compose.server.yml` ; l'admin n'est publié que sur `ADMIN_PUBLISH_ADDR` (boucle locale par défaut).
`TLS_DISABLE` ne doit jamais être défini en production.

### 3. Initialiser l'état (une seule fois), puis lancer sur chaque hôte

```bash
# Depuis UN seul hôte, avant de démarrer les autres
docker compose -p secagent-prod-<relay_id> -f docker-compose.server.yml run --rm --no-deps secagent-server state init

# Sur chaque hôte
docker compose -p secagent-prod-<relay_id> -f docker-compose.server.yml up -d
```

**Résultat attendu :**
- Une instance prend `relay.lock` et devient maître (ports ouverts)
- Les autres sont secondaires : aucun port ouvert, sondage du verrou toutes les 5 s

### 4. Promotion qualif → prod (image pinning)

La version se fixe par `SECAGENT_VERSION` dans `.env` ; dans l'archive de release
(`secagent-compose-<version>.tar.gz`), la ligne `image:` est réécrite en `...:vX.Y.Z@sha256:<digest>`
(jamais `latest`, jamais de construction locale). Vérifier `SHA256SUMS`, puis :

```bash
docker compose -p secagent-prod-<relay_id> -f docker-compose.server.yml pull
docker compose -p secagent-prod-<relay_id> -f docker-compose.server.yml up -d
```

---

## Configuration des Ports

Les adresses d'écoute sont configurables : `API_ADDR` (défaut `:7770`), `ADMIN_ADDR` (défaut `:7771`), `WS_ADDR` (défaut `:7772`).

| Port | Service | Défaut | TLS | Usage |
|------|---------|--------|-----|-------|
| 7770 | REST API + `/ws/agent` + `/ws/relay` | `:7770` (toutes interfaces) | ✓ HTTPS/WSS natif | Agents + Plugins + relays |
| 7771 | API d'administration (jeton `ADMIN_TOKEN` toujours exigé) | `:7771` (toutes interfaces !) | `ADMIN_TLS=true` | Opérateurs / CLI |
| 7772 | Listener WebSocket dédié (`/ws/agent`, `/ws/relay`) | `:7772` | ✓ WSS natif | Agents (défaut de `RELAY_WS_URL`) |

7772 n'est pas déprécié : c'est le port WebSocket par défaut des agents. Seule l'instance maître ouvre ces ports.

**Règles TLS :**
- 7770 et 7772 : TLS obligatoire (HTTPS et WSS) ; `TLS_DISABLE=true` est réservé aux tests/CI
- 7771 : le défaut `:7771` n'est **pas** loopback. Hors loopback, le serveur refuse de démarrer sans `ADMIN_TLS=true`
  (ou la dérogation `ADMIN_INSECURE_HTTP=true` + `ADMIN_INSECURE_HTTP_ACK=i-understand-the-risk`) ; pour un HTTP en
  boucle locale, définir explicitement `ADMIN_ADDR=127.0.0.1:7771`. Booléens stricts : `true` / `false` exacts.
- La CLI atteint l'admin via `RELAY_API_URL` (défaut `http://localhost:7771`), `REPEATER_CA_FILE` pour une CA privée.

---

## Variables d'Environnement

### Relay Server (secagent-server)

| Variable | Default | Required | Description |
|----------|---------|----------|-------------|
| `STATE_DIR` | `/data` | Oui | Répertoire d'état partagé (NFS pour multi-hôtes) |
| `JWT_SECRET_KEY` | — | Oui | Secret JWT (identique sur tous les nœuds candidats) |
| `ADMIN_TOKEN` | — | Oui | Jeton de l'API d'administration |
| `RSA_MASTER_KEY` | — | Oui | Secret dont dérivent l'HMAC de l'état et le chiffrement AES-256-GCM de ses secrets (pas une clef RSA) ; requis par `state init/verify/restore` |
| `API_ADDR` / `WS_ADDR` | `:7770` / `:7772` | Non | Adresses d'écoute API et WebSocket |
| `TLS_CERT` | — | Sauf test | Fichier certificat TLS (PEM) |
| `TLS_KEY` | — | Sauf test | Fichier clef TLS (PEM) |
| `TLS_DISABLE` | — | Non | Désactiver TLS (**tests/CI uniquement**, jamais en production) |
| `ADMIN_ADDR` | `:7771` | Non | Adresse d'écoute admin (ex: `127.0.0.1:7771`) |
| `ADMIN_TLS` | `false` | Non | TLS sur l'admin ; **obligatoire** si `ADMIN_ADDR` n'est pas loopback |
| `ADMIN_INSECURE_HTTP` | `false` | Non | Dérogation HTTP admin hors loopback, exige `ADMIN_INSECURE_HTTP_ACK=i-understand-the-risk` |
| `RELAY_STATUS_FILE` | `/run/secagent/status.json` | Non | Statut local de `status --local` (local au conteneur, jamais sur le partage) |
| `RELAY_ACTION_LOG` | `<STATE_DIR>/actions.log` | Non | Chemin du journal d'actions (rotation 10 Mio × 5) |
| `TRUSTED_PROXY_CIDRS` | — | Non | CIDR des reverse proxies de confiance (en-tête `X-Forwarded-For`) |
| `REPEATER_CA_FILE` | — | Non | CA bundle pour relais et CLI (non-rechargé à chaud) |
| `REPEATER_UPSTREAM_URL` | — | Non | URL(s) du relay parent en mode relais |

### Minion Agents (secagent-minion)

Aucun fichier de configuration : variables d'environnement uniquement.

| Variable | Default | Description |
|----------|---------|-------------|
| `RELAY_SERVER_URL` | `https://localhost:7770` | URL(s) HTTPS pour enrollment (liste séparée par `,`, pairée par position avec RELAY_WS_URL) |
| `RELAY_WS_URL` | `wss://localhost:7772/ws/agent` | URL(s) WSS pour WebSocket (liste, pairée par position). Le chemin `/ws/agent` est **obligatoire** : l'URL est utilisée telle quelle |
| `RELAY_ENROLLMENT_TOKEN` | — (requis) | Jeton d'enrôlement `secagent_enr_…` ; absent ou refusé : sortie 78 |
| `RELAY_AGENT_HOSTNAME` | hostname de l'hôte | Nom sous lequel l'agent s'enrôle |
| `RELAY_PRIVATE_KEY` | `/etc/secagent-minion/id_rsa` | Clef privée RSA-4096 (générée si absente, 0600) |
| `RELAY_JWT_PATH` | `/etc/secagent-minion/token.jwt` | Token JWT courant (réécrit à chaque enrollment) |
| `RELAY_CA_BUNDLE` | magasin système | Bundle CA PEM personnalisé |
| `RELAY_ASYNC_DIR` | `/var/lib/secagent-minion/async` | Registre des tâches async |
| `MAX_CONCURRENT_TASKS` | `10` | Tâches concurrentes max |
| `RELAY_INSECURE_TLS` | `false` | Désactiver vérif TLS (**tests uniquement**) |

Il n'existe pas de variable pour la taille de stdout (tampon fixe de 5 MiB, avec troncature et indicateur).

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

### Lancement du binaire

`secagent-server` sans sous-commande **démarre le serveur** en avant-plan : il n'y a pas d'option `-d` (daemon),
et `--help` ou une sous-commande inconnue (ex. `admin …`) démarre aussi le serveur au lieu d'afficher l'aide.
Sous-commandes CLI : `minions security inventory server tokens hooks relays state status help completion`
(aide : `secagent-server tokens --help`).

### Codes de Sortie

**Relay :**
| Code | Cause | Action |
|------|-------|--------|
| 0 | Arrêt propre | Normal |
| 1 | Démarrage refusé (configuration, état absent ou invalide, certificat, rejeu) ou erreur serveur | Corriger la cause ; **sans `relay.state` le serveur refuse de démarrer** |
| 75 | Verrou **perdu par une instance vivante** (EX_TEMPFAIL) ; un crash ne produit pas 75 | Redémarrage auto (`restart: unless-stopped`), l'instance repart secondaire |

**Minion :**
| Code | Cause | Comportement |
|------|-------|-------------|
| 1 | Échec ou arrêt sur erreur (clef, enrôlement non permanent, dispatcher…) | Redémarrage par policy |
| 77 | Revoked (JTI blacklisté) | **NE PAS redémarrer** — état terminal |
| 78 | Enrollment refused (jeton absent, refusé 403, expiré ou consommé ; aucun retry) | **NE PAS redémarrer** — l'opérateur crée nouveau token |

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
# Vérifier un fichier d'état (chemin obligatoire ; RSA_MASTER_KEY requis dans l'environnement)
secagent-server state verify "$STATE_DIR/relay.state"

# Si HMAC invalid ou schema corrompu : restauration depuis backup (TOUTES les instances arrêtées).
# `restore` revérifie le fichier, sauvegarde l'état courant en relay.state.bak-<UTC> et journalise
# dans state-restore.log. Options : --state-dir, --min-write-seq, --i-know-no-instance-is-running
secagent-server state restore --from /backup/relay.state

# Codes de sortie :
# 0 = OK
# 2 = HMAC invalid
# 3 = schema unknown
# 4 = invariant violated
# 5 = file unreadable
# 6 = RSA_MASTER_KEY missing
# 7 = write_seq too low
# 8 = instance alive (restore uniquement : verrou frais)
```

---

## Monitorage et Santé

### Health Check Local

```bash
# Sur le relay
secagent-server status --local
# Lit le statut local (RELAY_STATUS_FILE) : code 0 = maître sain ou secondaire sain ;
# non nul = fichier absent, activité du verrou trop ancienne (process figé), démarrage échoué ou verrou perdu.

# Vue API du maître (via l'admin, avec ADMIN_TOKEN)
secagent-server server status

# Liveness HTTP du maître (7770, sans jeton) : {"instance_id":...,"role":"master","status":"ok","timestamp":...}
curl -f --cacert tls.crt https://localhost:7770/health
```

Il n'existe pas de route `/healthz`. Un secondaire n'ouvre aucun port : sa santé se juge par `status --local`.

### Logs

**Relay :**
```bash
# Journal JSON Lines : <STATE_DIR>/actions.log (ou RELAY_ACTION_LOG), rotation 10 Mio × 5 fichiers
tail -f /data/actions.log | jq .

# Secrets masqués (voir DOC/security/SECURITY.md)
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

# Vérifier l'état du fichier (sans relay.state le serveur refuse de démarrer : `state init`)
secagent-server state verify "$STATE_DIR/relay.state"

# Logs
docker compose -p <projet> -f docker-compose.server.yml logs | grep -i error
```

### Les agents ne se connectent pas

```bash
# Vérifier enrollment
journalctl -u secagent-minion | grep -i "enroll\|403\|401"   # code 78 = jeton refusé

# Vérifier URLs (multi-adresses)
echo $RELAY_SERVER_URL
echo $RELAY_WS_URL

# Test de connectivité
curl -v --cacert tls.crt https://relay:7770/health   # -k réservé aux essais avec certificat auto-signé
```

### Failover vers passif ne se fait pas

```bash
# Vérifier verrou
ls -la /mnt/secagent-state/relay.lock

# Vérifier NFS
mount | grep secagent-state

# Logs du passif
docker logs <conteneur-secondaire> | grep -i "lock\|stale\|promote"

# Rappel : après un crash/kill -9 du maître, la promotion attend la péremption du verrou (5 min)
```

---

## Documentation Référence

- [DOC/server/SERVER_SPEC.md](../DOC/server/SERVER_SPEC.md) — Spécifications techniques du relay
- [DOC/agent/AGENT_SPEC.md](../DOC/agent/AGENT_SPEC.md) — Spécifications de l'agent
- [DOC/security/SECURITY.md](../DOC/security/SECURITY.md) — Modèle de sécurité v3.0.3
- [DOC/project/DEPLOYMENT.md](../DOC/project/DEPLOYMENT.md) — Guide opérationnel complet
