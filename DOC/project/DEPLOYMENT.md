# Ansible-SecAgent — Deployment Guide v3.0.3

## Architecture

Ansible-SecAgent v3.0.3 est composé de trois éléments :

### 1. **Serveur Relay** (secagent-server GO)
- **Transports** : HTTP REST + WebSocket persistante (TLS natif sur tous les ports)
- **Ports** :
  - **7770** : API REST + WebSocket agent (enrollment `/api/register` + task dispatch `/ws/agent`)
  - **7771** : API d'administration (jeton `ADMIN_TOKEN` toujours exigé). Défaut d'écoute `:7771` (**toutes interfaces**, pas la boucle locale) : hors loopback, `ADMIN_TLS=true` est obligatoire, sinon le serveur refuse de démarrer
  - **7772** : listener WebSocket dédié (`/ws/agent`, `/ws/relay`), défaut de `RELAY_WS_URL` des agents (`wss://localhost:7772/ws/agent`) ; 7770 sert aussi ces chemins
  - Seule l'instance **maître** ouvre ces ports ; les secondaires n'en ouvrent aucun
- **État** : Fichier JSON (`relay.state`) sur stockage partagé NFS
- **Verrou** : actif/passif, fichier `relay.lock` créé en `O_EXCL` avec battement (30 s) ; pas un `flock` : après un crash il subsiste jusqu'à péremption (5 min)
- **Pas de NATS** : Dispatch direct WebSocket par `task_id`

**Network** : Docker bridge ou host (agents et plugins connectent en sortie)

### 2. **Agents** (secagent-minion GO)
- **Déploiement** : Systemd ou Docker container sur chaque hôte cible
- **Connexion** : WebSocket persistante sortante vers `/ws/agent` du relay (port 7772 par défaut, ou 7770)
- **Enrollment** : POST /api/register (RSA-4096 + JWT) une seule fois
- **Exécution** : Subprocess par tâche, isolation complète, max 10 concurrentes (configurable)
- **Codes de sortie** : 1 = échec (redémarrage par la politique), 77 (revoked - no restart), 78 (enrollment absent/refused - no restart)

**Network** : Host network (agents sur 192.168.1.100-102, relay sur 192.168.1.218)

### 3. **Plugin Ansible** (connection + inventory, Python)
- **Connection plugin** : Route exec/put_file/fetch_file vers relay via REST HTTP bloquant
- **Inventory** : `secagent-inventory` (binaire Go) récupère la liste des agents via `GET /api/inventory`
- **Cible** : Port 7770 (API unified + WebSocket)
- **Authentification** : jeton **plugin** opaque (`secagent_plg_` + 64 hex), créé par `tokens create --role plugin` ; `ADMIN_TOKEN` est refusé (403) sur `/api/inventory`

---

## Déploiement en Qualification

Pas à pas détaillé : [QUICKSTART.md](QUICKSTART.md). Compose réel : `DEPLOYMENT/qualif/docker-compose.server.yml`
(services `secagent-server-a` et `secagent-server-b`). La topologie en chaîne (racine + relay enfant pull + 2 minions) est dans
`DEPLOYMENT/qualif/docker-compose.chain.yml`, pilotée par `DEPLOYMENT/qualif/chain-test.sh` (voir `DEPLOYMENT/qualif/README.md`).
Les anciens Compose `proxy`, `minion` et `ansible` ont été supprimés (#188). Images `linux/amd64` uniquement.

### Prérequis
- Docker et Docker Compose installés
- Certificat TLS auto-signé **avec SAN** : `tls/tls.crt` + `tls/tls.key` (répertoire désigné par `QUALIF_TLS_DIR`)
- Secrets du serveur : `DEPLOYMENT/qualif/qualif.env` (copie de `qualif.env.example` : `JWT_SECRET_KEY`, `ADMIN_TOKEN`, `RSA_MASTER_KEY`)
- Image : `SECAGENT_IMAGE` (candidate `sha-<commit>@sha256:<digest>`)
- **Pas de NATS, pas de FastAPI, pas de Caddy** — v3.0.3+ utilise GO server natif + TLS natif

### Étape 1 : Initialiser l'état du relay

```bash
cd DEPLOYMENT/qualif
docker compose -p secagent-qualif -f docker-compose.server.yml run --rm secagent-server-a state init
# Crée relay.state dans le volume d'état. EXIGE RSA_MASTER_KEY (qualif.env) : ce secret n'est jamais
# auto-généré ; il dérive l'HMAC de l'état et le chiffrement AES-GCM de ses secrets (pas une clef RSA).
# La clef RSA-4096 du serveur et le secret JWT sont générés par `init`.
```

Vérifier l'initialisation :
```bash
docker compose -p secagent-qualif -f docker-compose.server.yml run --rm secagent-server-a \
  state verify /data/relay.state
# Exit code 0 = OK, état cohérent (le chemin est obligatoire ; RSA_MASTER_KEY requis, code 6 sinon)
```

### Étape 2 : Lancer le relay

```bash
docker compose -p secagent-qualif -f docker-compose.server.yml up -d
docker compose -p secagent-qualif -f docker-compose.server.yml logs | grep -i "listening"
```

Healthcheck (sur l'instance maître) :
```bash
curl --cacert tls/tls.crt https://localhost:7770/health
# {"instance_id":"...","role":"master","status":"ok","timestamp":"..."}
```
(`-k` n'est acceptable que pour un essai local avec certificat auto-signé.)

### Étape 3 : Générer token d'enrôlement et déployer agents

```bash
# Raccourci : CLI du serveur dans l'instance a (API admin en TLS)
srv() {
  docker compose -p secagent-qualif -f docker-compose.server.yml exec \
    -e RELAY_API_URL=https://localhost:7771 -e REPEATER_CA_FILE=/certs/tls.crt \
    secagent-server-a secagent-server "$@"
}

# Jeton d'enrôlement valide 1 h : `secagent_enr_` + 64 hex (77 caractères), pas un JWT
TOKEN=$(srv tokens create --role enrollment --expires 1h | grep -oE 'secagent_enr_[0-9a-f]{64}' | tail -1)

# Le jeton est passé à l'agent par la variable d'environnement RELAY_ENROLLMENT_TOKEN
# (unité systemd, `docker run -e`, etc.). `docker compose set-env` n'existe pas.
```

Rôles de jeton : `enrollment`, `plugin`, `relay-parent` ; la révocation (`tokens revoke <id>`) ne vaut que pour
`plugin` et `relay-parent`. Les agents sont démarrés selon la section « Agents (variables d'environnement) » ci-dessous
(unité systemd, ou service `minion-*` de `docker-compose.chain.yml` pour l'essai de qualif ; `docker-compose.minion.yml` a été supprimé) ;
vérifier leurs logs : enrôlement puis ouverture de la WebSocket.

### Étape 4 : Vérifier l'inventaire

```bash
# Jeton PLUGIN (l'inventaire refuse ADMIN_TOKEN avec 403)
PLG=$(srv tokens create --role plugin --expires 1h | grep -oE 'secagent_plg_[0-9a-f]{64}' | tail -1)

curl --cacert tls/tls.crt -H "Authorization: Bearer $PLG" \
  https://localhost:7770/api/inventory | jq .
# Doit afficher les agents enrôlés
```

### Qualification sans registre (artefact de run CI + `docker load`)

Aucun pull GHCR n'est requis en qualif : chaque **push** construit les images serveur et minion (job `images-artifact`) et les publie en **artefact du run** `secagent-images-<sha>` (7 jours : archives `docker save`, binaire `secagent-inventory`, `images.env`, `SHA256SUMS` ; aucun push de registre). Procédure complète et variables : `DEPLOYMENT/qualif/README.md` (« Images sans registre »).

```bash
gh run download <id-du-run> -n secagent-images-<sha-complet> -D images
export DOCKER_HOST=tcp://192.168.1.218:2375      # ou `docker -H tcp://…` ; réseau de confiance uniquement
bash DEPLOYMENT/qualif/chain-test.sh load-images images   # vérifie SHA256SUMS puis docker load sur l'hôte distant
set -a; . images/images.env; set +a                       # tags locaux ci-<sha12>, SECAGENT_PULL_POLICY=never
```

Le déploiement se fait ensuite dans le projet Compose **`secagent-qualif`** (mode hôte distant : `TLS_MODE=volume`, `chain-test.sh push-tls`, `SECAGENT_ENDPOINT_HOST`, `PKI_EXTRA_SAN`). `down`, `teardown` et `backup-restore` sont refusés sur un hôte distant pour tout autre projet.

**Production** : le Compose de la release exige des images **`tag@sha256:<digest>`** (`vX.Y.Z@sha256:…`, jamais `latest`, jamais de tag local) ; la répétition à vide de l'archive de release le vérifie par `check_compose.py --require-digest`. Les images chargées par `docker load` ne sont acceptées qu'en qualif.

---

## Codes de Sortie et Redémarrage

### Agents (codes systemd significatifs)

```ini
[Service]
# Redémarrage automatique sur erreur (code 1)
Restart=on-failure
RestartSec=30s
StartLimitIntervalSec=600
StartLimitBurst=5

# NE PAS redémarrer sur ces codes
RestartPreventExitStatus=77 78

# Code 77 (Revoked) : JTI blacklisté — opérateur doit créer nouveau token
# Code 78 (Enrollment Refused) : jeton absent ou refusé (403) — opérateur doit créer nouveau token
```

### Relay (codes significatifs)

| Code | Cause | Action |
|------|-------|--------|
| 0 | Arrêt propre | Normal |
| 1 | Démarrage refusé (configuration, état absent ou invalide…) ou erreur serveur | Corriger ; sans `relay.state` le serveur refuse de démarrer et ne se ré-initialise pas |
| 75 | Verrou perdu par une instance **vivante** (un crash ne produit pas 75) | Redémarrage par container policy → repart secondaire |

---

## Gestion des Erreurs et Reprise

### Révoquer un agent, lever la révocation, retour arrière (#193)

```bash
# Révoquer : drapeau persistant + blacklist du JTI en une écriture, WS fermée en 4001, le minion sort en code 77
docker exec secagent-server secagent-server minions revoke <hostname>
# (ou : curl --cacert tls.crt -X POST -H "Authorization: Bearer $ADMIN_TOKEN" https://localhost:7771/api/admin/revoke/<hostname>)

# Effet : l'hôte est refusé à l'enrôlement (403 agent_revoked, jeton non consommé, même avec un jeton réutilisable),
# au rekey et à la connexion WS, sans limite de durée (le drapeau survit à la blacklist de 25 h).

# Lever la révocation : seule voie = supprimer l'agent (pas de « unrevoke ») ; ses variables sont perdues
curl --cacert tls.crt -X DELETE -H "Authorization: Bearer $ADMIN_TOKEN" https://localhost:7771/api/admin/minions/<hostname>
# puis créer un jeton d'enrôlement et ré-enrôler le minion (RELAY_ENROLLMENT_TOKEN) : le JWT local devenu invalide
# est rejeté en 401 à la connexion WS, ce qui déclenche le ré-enrôlement ; l'effacer à la main n'est pas nécessaire
docker exec secagent-server secagent-server tokens create --role enrollment --hostname-pattern "<hostname>" --expires 1h
```

- Si l'écriture est refusée (instance secondaire / état en lecture seule), la révocation répond une erreur et la WS n'est **pas** fermée : réessayer sur le maître.
- **Retour arrière vers une version antérieure à #193** : un état contenant au moins un agent révoqué est **refusé au démarrage** (décodeur strict) avec `state: corrupt state file: payload: json: unknown field "revoked"` — message d'une corruption, mais le fichier est valide ; l'ancien binaire peut aussi basculer sur `relay.state.prev` (état plus ancien, révocation éventuellement absente). Lever d'abord les révocations (`DELETE` ci-dessus) ou restaurer un état antérieur (`state verify`, `state restore --from`).
- **Mise à jour depuis un état sans drapeau** : au démarrage, le maître pose le drapeau aux agents dont le JTI courant est encore en blacklist (25 h). Une révocation plus ancienne est oubliée : **révoquer à nouveau** l'hôte.

## Gestion des Tokens Relay (v3.0.1)

### Créer un token relay-parent (pour mode push)

Sur l'enfant (dmz1), créer un token que le parent utilisera :

```bash
docker exec secagent-server secagent-server tokens create \
  --role relay-parent \
  --sub central \
  --expires 90d

# Sortie : JWT signé par ce nœud (affiché UNE SEULE FOIS ; --description ne vaut que pour les jetons plugin)
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

### Identifiant d'un relay : l'UUID, pas le `relay_id`

Les routes `/api/admin/relays/{id}/revoke` et `DELETE /api/admin/relays/{id}`, ainsi que `relays remove <id>`, attendent l'**UUID** du relay (champ `id`), **pas** son nom `relay_id` (`dmz1`) : avec le nom, la réponse est `404 relay_not_found` (`handlers/admin_relays.go` : recherche par `id`). Le tableau de `relays list` n'affiche que le `RELAY_ID` ; l'UUID se lit dans la sortie JSON :

```bash
docker exec secagent-server secagent-server relays list --format json
# [ { "id": "3f1c…-uuid", "relay_id": "dmz1", "mode": "pull", "status": "…", … } ]
# ou, en API : GET https://localhost:7771/api/admin/relays  →  {"relays":[{"id":"<uuid>","relay_id":"dmz1",…}]}
RELAY_UUID=<valeur du champ "id" du relay dont "relay_id" vaut dmz1>
```

### Révoquer un relay enfant (mode pull)

```bash
# Via API uniquement (port 7771, admin ; https si ADMIN_TLS=true) :
# il n'existe pas de sous-commande `relays revoke` ; l'identifiant est l'UUID (voir ci-dessus)
curl --cacert tls.crt -X POST https://localhost:7771/api/admin/relays/$RELAY_UUID/revoke \
  -H "Authorization: Bearer <ADMIN_TOKEN>"

# Effets :
# - JTI du token enfant blacklisté
# - Lien enfant fermé (close 4010 permanent)
# - Enfant ne peut plus se reconnecter
```

### Supprimer un relay (legacy ou post-revocation)

⚠️ **Règle importante** : Toujours révoquer AVANT de supprimer (sinon 409 relay_not_revoked)

```bash
# 1. Révoquer d'abord (API, UUID du relay, voir ci-dessus)
curl --cacert tls.crt -X POST https://localhost:7771/api/admin/relays/$RELAY_UUID/revoke \
  -H "Authorization: Bearer <ADMIN_TOKEN>"

# 2. Puis supprimer (CLI : sous-commandes relays add | list | remove <uuid> | status)
docker exec secagent-server secagent-server relays remove $RELAY_UUID

# Ou via API
curl --cacert tls.crt -X DELETE https://localhost:7771/api/admin/relays/$RELAY_UUID \
  -H "Authorization: Bearer <ADMIN_TOKEN>"
```

---

## Commandes Utiles

### Voir les logs du serveur
```bash
docker compose -p secagent-qualif -f docker-compose.server.yml logs -f
```

### Voir les logs des agents
```bash
journalctl -u secagent-minion -f      # agent sous systemd
docker logs <conteneur-agent> --follow  # agent en conteneur
```

### Arrêter complètement
```bash
docker compose -p secagent-qualif -f docker-compose.server.yml down
```

### Redémarrer un agent
```bash
systemctl restart secagent-minion     # ou : docker restart <conteneur-agent>
```

### Nettoyer l'état (données persistantes)
```bash
# DESTRUCTIF : supprime relay.state, relay.lock, actions.log (volume d'état du Compose qualif)
docker compose -p secagent-qualif -f docker-compose.server.yml down -v
# Le serveur NE se ré-initialise PAS : sans relay.state il refuse de démarrer.
# Refaire `state init` (Étape 1) avant `up`. Tous les agents devront se ré-enrôler.
```

---

## Variables d'Environnement

### Server Core (.env) — v3.0.3

| Variable | Default | Description |
|---|---|---|
| `STATE_DIR` | `/data` | Répertoire d'état (relay.state, relay.lock, actions.log) |
| `JWT_SECRET_KEY`, `ADMIN_TOKEN`, `RSA_MASTER_KEY` | — | Secrets requis (`RSA_MASTER_KEY` : secret HMAC/AES-GCM de l'état, pas une clef RSA) |
| `TLS_CERT` | — | Certificat TLS (PEM, obligatoire en production ; `TLS_DISABLE=true` = tests/CI uniquement, jamais en production) |
| `TLS_KEY` | — | Clef privée TLS (PEM, obligatoire en production) |
| `ADMIN_ADDR` | `:7771` | Adresse admin (toutes interfaces par défaut ; `127.0.0.1:7771` pour la boucle locale) |
| `ADMIN_TLS` | `false` | TLS sur admin ; **obligatoire** si `ADMIN_ADDR` n'est pas loopback (sinon refus de démarrer, ou dérogation `ADMIN_INSECURE_HTTP` + ACK) |

#### Secrets par fichier (`*_FILE`, #196)

Chaque secret peut être donné par une variable **ou** par un fichier : `JWT_SECRET_KEY` / `JWT_SECRET_KEY_FILE`, `ADMIN_TOKEN` / `ADMIN_TOKEN_FILE`, `RSA_MASTER_KEY` / `RSA_MASTER_KEY_FILE`, `REPEATER_UPSTREAM_TOKEN` / `REPEATER_UPSTREAM_TOKEN_FILE` (serveur et CLI), `RELAY_ENROLLMENT_TOKEN` / `RELAY_ENROLLMENT_TOKEN_FILE` (minion). Avantage : le secret n'apparaît plus dans `docker inspect` ni dans l'environnement du processus.

- Les deux définies ensemble : **refus de démarrer**. Une variable vide compte comme non définie.
- Le fichier doit être un fichier **régulier** (ni lien symbolique, ni périphérique), **non vide**, de 64 Kio au plus, avec des permissions `0600` ou plus strictes (aucun droit pour le groupe ni les autres). Les espaces et fins de ligne finaux sont retirés. Sinon : refus de démarrer, le message cite la variable et le chemin, jamais la valeur.
- Les variables directes restent acceptées (rétrocompatible).
- **Docker Compose** : un secret monté dans `/run/secrets/` est en `0444` par défaut, donc **refusé**. Déclarer `mode: 0400` (et `uid`/`gid` de l'utilisateur du service) dans `secrets:` du service, par exemple `secrets: [{source: admin_token, target: admin_token, uid: "0", gid: "0", mode: 0400}]`.
- `REPEATER_ROOT_LINK_KEY_FILE` n'est pas un secret (clé publique) : lecteur à part (fichier régulier, non inscriptible par le groupe ni les autres).
- Les variables `*_FILE` ne sont jamais transmises aux hooks (liste d'environnement autorisé) et un hook ne peut pas les déclarer dans `env`.

#### Minions : exécution en root (BAS-1)

Le minion exécute les tâches Ansible, y compris avec `become`, et doit donc rester **root** sur l'hôte géré. Ne pas lui retirer de capabilities (`CapDrop`) ni le passer en utilisateur non privilégié : les modules Ansible échoueraient. Le durcissement ne s'applique qu'au conteneur de qualif (réseau, système de fichiers en lecture seule, pas de privilèges supplémentaires), pas au minion de production installé par systemd.

**Ports (configurables : `API_ADDR`, `ADMIN_ADDR`, `WS_ADDR`)** — défauts :
- 7770 : API REST + WebSocket
- 7771 : API d'administration
- 7772 : WebSocket dédié

### Server Repeater Mode (enfant pull)
```
REPEATER_ID=dmz1                               # ID unique du relay enfant (format ^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$)
REPEATER_UPSTREAM_URL=wss://central:7772      # URL WSS du parent (liste séparée par des virgules : une par instance)
REPEATER_UPSTREAM_TOKEN=<jwt-relay-child>     # Token JWT rôle relay-child
REPEATER_DIAL_ALLOW_LOOPBACK=false             # true|false strict ; true = dev/CI seulement (lève la loopback, rien d'autre)
REPEATER_DIAL_DENY_CIDRS=                      # ex. 10.9.0.0/16 (réseau du plan de contrôle) : refus supplémentaires
REPEATER_DIAL_ALLOW_CIDRS=                     # ex. 192.168.0.0/16,10.20.0.0/16 : si non vide, liste blanche (deny l'emporte)
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
MAX_TASKS_PER_AGENT=10                          # (#179) tâches simultanées par agent ; au-delà 429 agent_busy
MAX_TASKS_INFLIGHT=1000                         # (#179) tâches en vol sur le relay (relayées comprises) ; au-delà 429 too_many_tasks
MAX_STDOUT_BUFFER_TOTAL=1073741824              # (#179) budget mémoire des tampons stdout, 1 Gio par défaut
```

#### Dimensionner les limites de tâches (#179, v3.0.4)

Chaque tâche admise **réserve 5 Mio** de budget (le maximum de stdout qu'elle peut produire) dès son admission, avant que le stdout n'arrive. Le plafond effectif de tâches simultanées d'un relay est donc `MAX_STDOUT_BUFFER_TOTAL / 5 Mio` :

| `MAX_STDOUT_BUFFER_TOTAL` | tâches simultanées max | pic RSS mesuré (3 000 agents, saturation) |
|---|---|---|
| 1 Gio (défaut) | **204** | ≈ 1,8 Gio |
| 2 Gio | 409 | ≈ 3,5 Gio (estimation) |

- Au-delà du plafond, `exec` / `upload` / `fetch` répondent **`503 memory_budget_exhausted`** avec `Retry-After` ; rien n'est envoyé à l'agent, le plugin Ansible remonte une erreur explicite sans rejouer.
- `MAX_TASKS_INFLIGHT=1000` (défaut) n'est atteignable **que si** `MAX_STDOUT_BUFFER_TOTAL` augmente : avec 1 Gio, le budget mémoire limite avant lui.
- **`forks` d'Ansible** : `forks` ≤ 200 passe sans refus avec les défauts. Pour `forks` 300-400, passer `MAX_STDOUT_BUFFER_TOTAL` à `2147483648` (409 tâches) et prévoir au moins **4 Gio de mémoire** pour le conteneur du relay. Règle : `MAX_STDOUT_BUFFER_TOTAL ≥ forks × 5 Mio` (+ une marge si plusieurs plugins partagent le relay) et mémoire du conteneur ≈ 2 × `MAX_STDOUT_BUFFER_TOTAL` + 200 Mio.
- Sauf `GOMEMLIMIT` défini, le serveur fixe une limite mémoire souple du runtime à `MAX_STDOUT_BUFFER_TOTAL + 768 Mio`.


### Server Hooks (v3.0.2)
```
RELAY_HOOKS_CONFIG=/etc/secagent/hooks.json     # Chemin fichier hooks (optionnel)
RELAY_HOOKS_MAX_CONCURRENT_ACTIONS=64           # Limit goroutines hook actions (défaut 64)
```

### Client `secagent-inventory` (v3.0.2)
```
RELAY_SERVER_URL=https://relay.example.com:7770  # URL du relay server
RELAY_TOKEN=secagent_plg_<64 hex>                # Bearer token plugin (`tokens create --role plugin`) ; RELAY_PLUGIN_TOKEN n'existe pas
RELAY_SCOPE=zone-a                              # ID du relay (optionnel, v3.0.2+) — limite inventaire à ce sous-arbre
RELAY_CA_BUNDLE=/path/to/ca.pem                 # CA custom (optionnel)
RELAY_INSECURE_TLS=false                        # true = skip vérif TLS (DEV/QUALIF SEULEMENT)
RELAY_INSECURE_TLS_ACK=i-understand-the-risk    # Confirmation si RELAY_INSECURE_TLS=true et serveur non-loopback
RELAY_ONLY_CONNECTED=false                      # true = hôtes connectés uniquement
```

### Agents (variables d'environnement ; aucun fichier de configuration)
```
RELAY_SERVER_URL=https://localhost:7770          # défaut ; http:// = QUALIF / TESTS UNIQUEMENT (jamais en production)
RELAY_WS_URL=wss://localhost:7772/ws/agent       # le chemin /ws/agent est obligatoire
RELAY_ENROLLMENT_TOKEN=secagent_enr_<64 hex>
RELAY_AGENT_HOSTNAME=qualif-host-01
RELAY_ASYNC_DIR=/var/lib/secagent-minion/async
RELAY_CA_BUNDLE=/path/to/ca.pem                  # optionnel
MAX_CONCURRENT_TASKS=10
```
Table complète : [DEPLOYMENT/README.md](../../DEPLOYMENT/README.md). `RELAY_HOSTNAME` et `RELAY_DATA_DIR` n'existent pas.

---

## Architecture Réseau v3.0.3

```
┌──────────────────────────────┐
│  Host 1 (192.168.1.218)      │
├──────────────────────────────┤
│                              │
│  secagent-server (GO)        │
│  ├─ Port 7770 (TLS natif)   │
│  ├─ Port 7771 (admin)        │
│  └─ Port 7772 (compat)       │
│                              │
│  STATE_DIR → NFS partagé     │
│  ├─ relay.state              │
│  ├─ relay.lock (verrou)      │
│  └─ actions.log              │
└──────────────────────────────┘

┌──────────────────────────────┐
│  Host 2-N (secondaires)      │
├──────────────────────────────┤
│  secagent-server (identique) │
│  (aucun port ouvert ; sonde  │
│   le verrou toutes les 5 s)  │
│  STATE_DIR → NFS (partagé)   │
└──────────────────────────────┘

┌──────────────────────────────┐
│  Agents (partout)            │
├──────────────────────────────┤
│  secagent-minion (GO)        │
│  → WebSocket vers /ws/agent  │
│  (multi-adresses failover)   │
└──────────────────────────────┘
```

**Production** : Docker Compose multi-hôtes avec NFS `STATE_DIR` partagé. Un relay acquiert le verrou et ouvre ses ports ; les autres sont secondaires et n'ouvrent aucun port.


## Supervision du lien amont (relay enfant)

Après un refus **permanent** (close 4010, identité changée, boucle), le client repeater (pull) ou le dialer (push) s'arrête : le nœud devient de fait une racine isolée mais **continue de servir** ses agents directs et sa descendance. Il n'est donc **pas** redémarré : l'état est exposé pour alerter.

| Interface | Contenu |
|---|---|
| `GET /health` (port 7770, **public**) | HTTP **200** maintenu (pas de redémarrage par la liveness). Uniquement le booléen `degraded` (vrai si un lien est `refused_permanent`), absent sur une racine sans lien : **aucun** relay_id, état ni raison (divulgation de topologie). |
| `secagent-server server status` / `GET /api/admin/status` (port 7771, **admin**) | Bloc `links` : `upstream` (`mode` pull/push, `peer`, `state`, `reason`, `since`) et `push_children[]` (`relay_id` + même état) ; tableau LINK/PEER/STATE/SINCE/REASON et avertissement « operator action required » si dégradé. La raison est assainie (caractères de contrôle remplacés, **200 octets max**, tronquée sur une frontière de caractère UTF-8). |

États : `connected`, `retrying` (connexion initiale, lien perdu, refus corrigible 4012, annulation : **pas** terminal), `refused_permanent` (terminal : action opérateur requise — token révoqué/remplacé, identité ou boucle à corriger, puis redémarrage ou nouvelle déclaration). La raison est bornée (**200 octets max**, tronquée sur une frontière de caractère UTF-8) et ne contient jamais de token. Une trame close 4010 sur un lien push établi rend le Dialer terminal (log ERROR « operator action required », pas de reconnexion ; 4012 et les autres codes restent corrigibles). Pas de métrique : aucune infrastructure de métriques n'existe aujourd'hui. Une sortie du processus (code dédié / `REPEATER_EXIT_ON_PERMANENT_REFUSAL`) n'est pas retenue pour l'instant ; une sonde de readiness distincte relèvera de #136.



## Adresses d'écoute (#155)

Le serveur écoute par défaut sur `:7770` (API publique + WebSocket), `:7771` (API admin) et `:7772` (WebSocket). Elles se changent par `API_ADDR`, `ADMIN_ADDR` et `WS_ADDR` (format `hôte:port` ou `:port`, une valeur mal formée arrête le démarrage). Les handlers d'administration ne sont servis que sur `ADMIN_ADDR` : ne publiez pas ce port hors du réseau d'administration. Un port déjà utilisé fait échouer le démarrage immédiatement.
