# Installer et configurer le serveur racine (`secagent-server`) — v3.0.4

Guide opérateur pour un relay **racine** en production : Docker Compose, actif/passif sur N hôtes, état sur stockage
partagé. Pour un relay **enfant**, lisez ensuite [`INSTALL_RELAY.md`](INSTALL_RELAY.md) ; pour les agents,
[`INSTALL_AGENT.md`](INSTALL_AGENT.md). Un essai local jetable est décrit dans [`QUICKSTART.md`](QUICKSTART.md).

Références (non dupliquées ici) : [`DEPLOYMENT/prod/README.md`](../../DEPLOYMENT/prod/README.md) (Compose de production,
stockage, dimensionnement), [`SERVER_SPEC.md`](../server/SERVER_SPEC.md) (API, variables), [`STATE_SPEC.md`](../server/STATE_SPEC.md),
[`SECURITY.md`](../security/SECURITY.md), [`DEPLOYMENT.md`](DEPLOYMENT.md) (montée de version, rotations).

## 1. Principes à connaître

- **Un seul maître par `STATE_DIR`** : N hôtes lancent le *même* Compose sur le *même* stockage partagé. Une instance prend
  `relay.lock` et devient maître (elle ouvre les ports 7770, 7771, 7772) ; les autres sont *secondaires* et **n'ouvrent
  aucun port**. Il n'y a ni bus de messages, ni base de données, ni reverse proxy : l'état est un fichier (`relay.state`),
  le TLS est natif.
- **Transport** : TLS partout (WSS/HTTPS). `TLS_DISABLE=true` est réservé aux tests et ne doit jamais être défini en production.
- Ports : **7770** API publique + WebSocket (compatibilité), **7772** WebSocket des agents et des relays, **7771** API
  d'administration (jamais exposée publiquement).
- Le serveur **ne crée jamais son état implicitement** : sans `relay.state` il refuse de démarrer (`state init`, §6).

## 2. Prérequis

- Hôtes Linux avec Docker et Docker Compose v2 ; accès à `ghcr.io` (ou images chargées par `docker load`).
- **Stockage partagé** (NFS v4.1 recommandé) monté à l'identique sur tous les hôtes, accessible en écriture à l'UID/GID
  **10001**. **Un stockage non testé est non supporté** : passez `DEPLOYMENT/prod/tools/test_shared_storage.py`
  (procédure dans `DEPLOYMENT/prod/README.md`, « Stockage partagé »). Limite honnête : ce test et la bascule sur **deux
  hôtes réels** n'ont pas été démontrés par l'équipe en v3.0.4 (issue #197 ouverte) ; faites-les chez vous avant la production.
- Un **certificat TLS** (chaîne complète) et sa clé, avec les noms d'accès des clients dans le **SAN** (sans SAN la
  vérification échoue). La clé doit être lisible par l'UID 10001.
- Horloges synchronisées (NTP) : le verrou actif/passif repose sur des délais (maître périmé après 5 minutes sans battement).
- `openssl` pour générer les secrets.

## 3. Récupérer la release et les images

La release GitHub `v3.0.4` contient l'archive Compose `secagent-compose-3.0.4.tar.gz` et `SHA256SUMS-3.0.4.txt`.

```bash
V=3.0.4
mkdir -p /opt/secagent-release && cd /opt/secagent-release     # dossier dédié
curl -fLO "https://github.com/CCoupel/Ansible-SecAgent/releases/download/v${V}/secagent-compose-${V}.tar.gz"
curl -fLO "https://github.com/CCoupel/Ansible-SecAgent/releases/download/v${V}/SHA256SUMS-${V}.txt"
sha256sum --ignore-missing -c "SHA256SUMS-${V}.txt"       # « secagent-compose-3.0.4.tar.gz: OK »
tar xzf "secagent-compose-${V}.tar.gz" && cd "secagent-compose-${V}"
ls -A     # .env.example  README.md  docker-compose.child.yml  docker-compose.server.yml  preflight-secrets.sh  prod.env.example  tools/
```

Dans l'archive, la ligne `image:` est réécrite en `ghcr.io/ccoupel/secagent-server:vX.Y.Z@sha256:<digest>` : **les images
sont référencées par digest, jamais par `latest`**. Le serveur existe aussi avec les étiquettes `3.0.4`, `v3.0.4` et
`latest` (ne pas utiliser `latest` en production). Le binaire seul (`secagent-server-3.0.4-linux-amd64`) est également
publié ; il sert aux commandes locales (`state verify`…), l'image reste la voie de déploiement.

## 4. Configuration non secrète (`.env`)

```bash
cp .env.example .env        # hors dépôt, sur chaque hôte
```

| Variable `.env` | Rôle |
|---|---|
| `SECAGENT_VERSION` | version (`v3.0.4`) pour le tag de l'image (obligatoire) |
| `STATE_HOST_DIR` | point de montage **sur l'hôte** du partage (`/data` dans le conteneur) |
| `TLS_CERT_DIR` | dossier hôte contenant `tls.crt` (chaîne complète) et `tls.key` (monté en lecture seule sur `/certs`) |
| `ADMIN_PUBLISH_ADDR` | adresse d'hôte sur laquelle publier **7771** (défaut `127.0.0.1` ; jamais `0.0.0.0`) |
| `LOG_LEVEL` | `INFO` par défaut |
| `SECRETS_DIR` | dossier des fichiers de secrets (défaut `./secrets`) |
| `SECAGENT_MEM_LIMIT` / `GOMEMLIMIT` | limite mémoire du conteneur (2g) et limite souple du GC (≈ 80 %, `1638MiB`) : **à modifier ensemble** |

Les variables du *serveur* (`STATE_DIR`, `API_ADDR`, `ADMIN_ADDR`, `ADMIN_TLS`, `TLS_CERT`, `TLS_KEY`, limites de
tâches, politique de dial…) sont fixées dans le Compose ; la liste complète et leur effet : `SERVER_SPEC.md` §8.
Booléens **stricts** : `ADMIN_TLS`, `ADMIN_INSECURE_HTTP`, `TLS_DISABLE` n'acceptent que `true` ou `false` exacts. Le
Compose de production fixe `ADMIN_TLS=true` (l'admin écoute sur toutes les interfaces *du conteneur* mais n'est publiée que
sur `ADMIN_PUBLISH_ADDR`).

## 5. Secrets

Trois secrets, **un fichier chacun**, identiques sur *tous* les hôtes d'un même relay, lus via `*_FILE` (ils
n'apparaissent ni dans `docker inspect` ni dans l'environnement du processus) :

| Fichier (`SECRETS_DIR`) | Variable lue | Contenu |
|---|---|---|
| `jwt_secret_key` | `JWT_SECRET_KEY_FILE` | secret HMAC des JWT des agents |
| `admin_token` | `ADMIN_TOKEN_FILE` | jeton de l'API d'administration (port 7771) |
| `rsa_master_key` | `RSA_MASTER_KEY_FILE` | **secret (chaîne), pas une clé RSA** : dérive le HMAC de l'état et le chiffrement AES-256-GCM de ses secrets |

**Règle réelle (hors Swarm)** : Compose monte le fichier *de l'hôte* tel quel et **ignore `uid`/`gid`/`mode`**. Chaque fichier
doit donc **appartenir à l'UID 10001**, être de mode **0400 ou 0600**, régulier (ni lien symbolique, ni répertoire), non
vide, de 64 Kio au plus. Un fichier root 0400 est illisible par le conteneur ; 0440/0444 est refusé par le serveur ; dans les
deux cas il sort au démarrage et redémarre en boucle. N'ajoutez jamais la variable directe en plus (`JWT_SECRET_KEY`… et son
`*_FILE` ensemble = refus de démarrer).

```bash
# Valeurs aléatoires (≥ 32 octets pour RSA_MASTER_KEY, cf. `state rekey`) ; la valeur n'est jamais affichée par le script
openssl rand -base64 48 | tr -d '\n' | sudo ./preflight-secrets.sh --write jwt_secret_key
openssl rand -base64 48 | tr -d '\n' | sudo ./preflight-secrets.sh --write admin_token
openssl rand -base64 48 | tr -d '\n' | sudo ./preflight-secrets.sh --write rsa_master_key

set -a; . ./.env; set +a        # exporte SECRETS_DIR s'il est défini dans .env (le script ne lit pas .env)
./preflight-secrets.sh          # à lancer AVANT chaque `docker compose up` ; code 0 exigé ; --fix pour corriger
```

Note : `preflight-secrets.sh` lit `SECRETS_DIR` et `ROOT_LINK_KEY_FILE` dans l'**environnement du processus**, pas dans `.env` : exportez-les d'abord (`set -a; . ./.env; set +a`) ou passez-les en préfixe de la commande ; `sudo` ne transmet pas l'environnement (`sudo env SECRETS_DIR="$SECRETS_DIR" ./preflight-secrets.sh …`).

Copiez les **mêmes** valeurs sur les autres hôtes (canal sûr). **Sauvegardez `rsa_master_key` hors des hôtes et hors du
partage, en deux copies au moins** : sans elle, tous les champs `enc:` de l'état sont définitivement illisibles et tous les
agents doivent se ré-enrôler. Testez la restauration (`DEPLOYMENT/prod/README.md`, « `RSA_MASTER_KEY` »).

> *Non exécuté ici* (pas de démon Docker dans l'environnement de rédaction) : les commandes `docker compose run … state init`, `up`
> et `exec … secagent-server …` de ce guide sont reprises de `DEPLOYMENT/prod/README.md` et `DEPLOYMENT.md` ; la CLI, elle, a été
> exécutée contre une racine réelle hors conteneur (même binaire, mêmes variables). `state init`, `state verify`, `status --local`
> et `preflight-secrets.sh` ont été rejoués avec les binaires de la release.

## 6. Première mise en service

Sur *un seul* hôte d'abord. Projet Compose conseillé : `secagent-prod-<relay_id>`.

```bash
export COMPOSE_PROJECT_NAME=secagent-prod-central      # exemple

# 1. Initialiser l'état UNE fois (génère la clé RSA-4096 du serveur et le secret JWT, chiffrés sous RSA_MASTER_KEY)
docker compose run --rm --no-deps secagent-server state init
#    Refuse d'agir si relay.state, relay.state.prev ou relay.lock existe déjà dans STATE_DIR.

# 2. Démarrer (puis, plus tard, sur les autres hôtes)
docker compose up -d

# 3. Contrôles
docker compose ps                                          # tous « healthy »
docker compose exec secagent-server secagent-server status --local   # code 0 : maître sain ou secondaire sain
curl -s --cacert <ca.pem> https://<hôte>:7770/health        # seul le MAÎTRE répond sur 7770/7772
```

Vérification de déploiement obligatoire (rendu Compose, 7771 non exposé) : voir `DEPLOYMENT/prod/README.md`,
« Premier déploiement », étape 4 (`tools/check_compose.py`). Exactement **un** hôte doit écouter sur 7770/7771/7772.

`secagent-server state verify <fichier>` contrôle un fichier d'état sans rien écrire ni verrouiller (codes : 0 valide ;
2 HMAC invalide ou fichier falsifié ; 3 `schema_version` inconnue ; 4 invariant violé ; 5 fichier illisible ; 6
`RSA_MASTER_KEY` absente ; 7 `write_seq` sous `--min-write-seq`).

## 7. Administrer : la CLI

La CLI `secagent-server` parle à l'API d'administration (7771) avec `ADMIN_TOKEN[_FILE]` et `RELAY_API_URL` (liste
d'adresses admises, défaut `http://localhost:7771` ; en HTTP elle refuse toute adresse non locale). Dans le conteneur de
production l'admin est en TLS ; l'alias suivant fournit l'URL et la CA :

```bash
srv() {
  docker compose exec -e RELAY_API_URL=https://localhost:7771 -e REPEATER_CA_FILE=/certs/tls.crt \
    secagent-server secagent-server "$@"
}
```

`REPEATER_CA_FILE` désigne le bundle de CA de confiance (il *remplace* les CA système ; aucune option de non-vérification
n'existe). `localhost` doit figurer dans le SAN du certificat — sinon pointez `RELAY_API_URL` vers un nom couvert.

| Besoin | Commande |
|---|---|
| état du serveur | `srv server status`, `srv server stats` |
| jeton d'enrôlement (agent) | `srv tokens create --role enrollment --hostname-pattern '<regexp>' --reusable --expires 30d` |
| jeton plugin Ansible | `srv tokens create --role plugin --description "<usage>" --allowed-ips "<CIDR>" --expires 24h` |
| jetons de lien (racine seulement) | `srv tokens create --role relay-child --sub <enfant> --aud <parent>` / `--role relay-parent --sub <parent> --aud <enfant>` |
| lister / révoquer | `srv tokens list`, `srv tokens revoke <id>` (jeton plugin ou de lien) |
| agents | `srv minions list`, `get <hostname>`, `suspend`, `resume`, `revoke <hostname>` |
| relays enfants | `srv relays list`, `srv relays status`, `srv relays add --id <id> [--mode push …]` |
| clé de lien (racine) | `srv keys link-pubkey`, `rotate-link`, `link-status`, `retire-link-previous [--force]` |
| état (hors ligne) | `state verify`, `state restore`, `state rekey`, `state link-trust reset` (voir ci-dessous) |

Les jetons ne sont **affichés qu'une fois** ; `tokens list` n'en montre que les métadonnées. Les jetons d'enrôlement et
plugin sont des jetons opaques (`secagent_enr_…`, `secagent_plg_…`), pas des JWT. Détail de chaque commande :
`secagent-server <commande> --help`.

## 8. Clé de signature des liens (racine)

La racine signe, avec une clé Ed25519 qu'elle génère à la demande et conserve chiffrée dans son état, les **jetons de
lien** de tous les relays enfants (`relay-child`, `relay-parent`). Elle les vérifie avec cette clé ; les relays non racine
vérifient avec la clé publique racine **épinglée** à leur installation.

```bash
srv keys link-pubkey > root-link.pub     # clé PUBLIQUE (PEM) sur stdout ; « root_id=<id> kid=<kid> » sur stderr
```

`root_id` (le `REPEATER_ID` de la racine) et `root-link.pub` sont ce qu'il faut remettre à chaque relay enfant
(`REPEATER_ROOT_ID`, `REPEATER_ROOT_LINK_KEY_FILE`) : [`INSTALL_RELAY.md`](INSTALL_RELAY.md) §3. Un nœud qui a un parent ou
une ancre épinglée répond `409 not_root` à ces commandes ; sans `RSA_MASTER_KEY`, `503 master_key_required`.
**Compromettre `RSA_MASTER_KEY` avec une copie de `relay.state` permet de forger des jetons de lien pour toute la
hiérarchie** : traitez-la comme le secret de plus haute valeur (`SECURITY.md` §5). La rotation de cette clé de lien
est décrite dans [`INSTALL_RELAY.md`](INSTALL_RELAY.md) §7 et `DEPLOYMENT.md`.

## 9. Limites d'admission (#179)

Le serveur protège sa mémoire en limitant les tâches admises (`exec`, `upload`, `fetch`) ; les défauts conviennent
jusqu'à `forks` ≈ 200 :

| Variable | Défaut | Effet au-delà |
|---|---|---|
| `MAX_TASKS_PER_AGENT` | 10 | `429 agent_busy` |
| `MAX_TASKS_INFLIGHT` | 1000 | `429 too_many_tasks` |
| `MAX_STDOUT_BUFFER_TOTAL` | 1073741824 (1 Gio) | `503 memory_budget_exhausted` + `Retry-After` |

Chaque tâche réserve **5 Mio** à l'admission : avec le défaut de 1 Gio, un relay n'accepte que **204 tâches simultanées**,
quel que soit `MAX_TASKS_INFLIGHT` (1000 n'est atteignable que si le budget augmente). Pour des `forks` de 300 à 400 :
`MAX_STDOUT_BUFFER_TOTAL=2147483648` **et** un conteneur d'au moins 4 Go (`SECAGENT_MEM_LIMIT=4g`, `GOMEMLIMIT=3276MiB`,
à changer ensemble) — voir les commentaires du Compose et `DEPLOYMENT/prod/README.md`, « Dimensionnement ». Le plugin
Ansible remonte ces refus en erreur explicite, sans rejeu. Limite honnête : le `503 memory_budget_exhausted` est couvert
par des tests mais n'a pas été exercé en qualification réelle (il faut ≥ 205 tâches simultanées).

## 10. Sauvegarde, restauration, bascule

- **Sauvegarde** : copiez `relay.state` (ou `relay.state.prev`) **hors hôte et hors du partage**, régulièrement et avant
  toute montée de version ; sauvegardez `rsa_master_key` séparément (§5).
- **Restauration** (tous les relays arrêtés) : `secagent-server state verify <fichier>` puis
  `secagent-server state restore --from <fichier>` (revérifie le fichier, refuse si une instance tient un verrou frais —
  code 8 —, sauvegarde l'état courant en `relay.state.bak-<UTC>`, journalise dans `state-restore.log`). Redémarrez ensuite.
- **Bascule** : arrêt propre du maître (`docker compose stop secagent-server`) → un secondaire devient maître en quelques
  secondes (de l'ordre de 5 à 6 s mesurées en qualification, pour une limite de 10 s). Perte brutale (`kill -9`, hôte perdu) : le verrou n'est pas libéré par le système de
  fichiers ; la reprise attend sa péremption (**≈ 5 minutes**). Un maître qui perd le verrou en étant vivant sort avec le
  code 75 et redémarre secondaire.
- **Rotation de `RSA_MASTER_KEY`** : commande hors ligne `state rekey` (arrêter *tous* les nœuds, une seule exécution sur
  le `STATE_DIR` partagé, sauvegarde obligatoire `relay.state.rekey.<UTC>.bak` lisible avec l'**ancienne** clé : à
  détruire ensuite). La nouvelle clé doit faire au moins 32 octets. Procédure et limites : `SECURITY.md` §11.

## 11. Mise à jour depuis la v3.0.3

La montée v3.0.3 → v3.0.4 est **une rupture unique** des liens relay ↔ relay ; elle ne coupe pas les agents.
**Il n'y a pas de retour arrière supporté vers la v3.0.3.** Lisez en entier
[`DEPLOYMENT.md`](DEPLOYMENT.md), « Montée de version v3.0.3 → v3.0.4 » (étapes 0 à 7), qui fait foi. Points clés pour la
racine :

1. **Sauvegardez** `STATE_DIR` de chaque relay *hors du volume* (+ `state verify`).
2. Racine actif/passif : arrêter le **passif**, monter l'**actif** en v3.0.4, puis le passif. Le maître **migre
   `relay.state` du schéma 1 au schéma 2** à sa première *écriture* (pas au simple démarrage), après avoir copié l'ancien
   fichier dans `relay.state.v1.bak` (0600). Il n'y a pas de bascule possible pendant la fenêtre.
3. Exporter la clé publique racine (`keys link-pubkey`), créer un jeton de lien par lien enfant, puis monter les enfants
   (parents d'abord) avec ancre et jeton : [`INSTALL_RELAY.md`](INSTALL_RELAY.md).
4. Après la montée et avant le trafic de production : rotation de `RSA_MASTER_KEY` par `state rekey` (étape 6 bis).
5. **Retour arrière** : un binaire v3.0.3 **refuse** un état de schéma 2. Le seul chemin est de **restaurer la sauvegarde
   `relay.state.v1.bak`** (ou celle que vous avez prise à l'étape 1) avec les binaires **v3.0.3 et les anciens jetons HS256**,
   en perdant toutes les écritures faites sous v3.0.4 (enrôlements, révocations).
6. **Avant la montée**, prévoyez un jeton d'enrôlement **réutilisable** pour les agents : le redémarrage des relays force la
   reconnexion, donc le ré-enrôlement de ceux dont le JWT (1 h) a expiré (voir [`INSTALL_AGENT.md`](INSTALL_AGENT.md) §7).

## 12. Dépannage

| Symptôme | Cause probable | Action |
|---|---|---|
| le conteneur redémarre en boucle, `relay.state` absent | état non initialisé | `state init` (§6) |
| `state init` échoue | `rsa_master_key` absent | créer le secret (§5) |
| sortie au démarrage, « permission denied » / « permissions too open » sur un secret | propriétaire ≠ 10001 ou mode ≠ 0400/0600 | `sudo ./preflight-secrets.sh --fix` |
| `admin API … plain HTTP on a non-loopback address` | `ADMIN_ADDR` non loopback sans `ADMIN_TLS=true` | ne pas retirer `ADMIN_TLS` du Compose |
| rien n'écoute sur 7770/7772 | cette instance est secondaire | interroger les autres hôtes ; `status --local` indique le rôle |
| `state verify` code 2 | mauvaise `RSA_MASTER_KEY` ou fichier falsifié | vérifier la clé ; restaurer une sauvegarde |
| un binaire v3.0.3 refuse l'état (`unsupported schema_version`) | l'état est en schéma 2 | pas de retour arrière direct : voir §11 point 5 |
| `403 enrollment_token_required` (agent) | `POST /api/register` sans jeton | fournir un jeton d'enrôlement |
| `429 agent_busy` / `too_many_tasks`, `503 memory_budget_exhausted` | limites d'admission | §9 |
| `409 not_root` sur `keys`/`tokens create --role relay-*` | commande lancée sur un relay non racine | l'exécuter sur la racine |
| `[SECURITY WARNING] … link_trust_missing`, fermeture 4010 sur un enfant | relay non racine sans ancre | [`INSTALL_RELAY.md`](INSTALL_RELAY.md) §3 |
| mémoire : OOM-kill | limite trop basse pour le parc ou le budget | §9 et `docker inspect -f '{{.State.OOMKilled}}'` |
