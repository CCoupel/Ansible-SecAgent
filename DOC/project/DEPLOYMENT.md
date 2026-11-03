# Ansible-SecAgent — Deployment Guide v3.0.4

> Guides d'installation pas à pas : [agent](INSTALL_AGENT.md), [serveur racine](INSTALL_SERVER.md), [relays enfants](INSTALL_RELAY.md).

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
- **Ligne de commande** : le minion démarre **sans argument** (toute sa configuration vient de l'environnement). `--version` (ou `-v`) et `--help` (ou `-h`) répondent sans rien démarrer (code 0) ; **tout autre argument est refusé** (erreur sur stderr, code 1, avant toute initialisation : ni clé générée, ni lecture de secret). Ne pas ajouter d'`command:`/`args:` à un service minion.

**Network** : Host network (agents sur 192.0.2.100-102, relay sur 192.0.2.10 (adresses de documentation, RFC 5737))

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
  docker compose -p secagent-qualif -f docker-compose.server.yml exec -T \
    -e RELAY_API_URL=https://localhost:7771 -e REPEATER_CA_FILE=/certs/tls.crt \
    secagent-server-a secagent-server "$@"
}

# Jeton d'enrôlement de démonstration valide 1 h (qualification) : `secagent_enr_` + 64 hex (77 caractères), pas un JWT.
# En PRODUCTION : jeton réutilisable, restreint, longue durée (voir « Agents après un redémarrage de relay »)
#   srv tokens create --role enrollment --reusable --hostname-pattern '^web-.*$' --expires 90d
# --hostname-pattern est OBLIGATOIRE (regexp ancrée) : ici les hôtes qualif-host-01, qualif-host-02…
TOKEN=$(srv tokens create --role enrollment --hostname-pattern 'qualif-host-.*' --expires 1h | grep -oE 'secagent_enr_[0-9a-f]{64}' | tail -1)

# Le jeton est passé à l'agent par la variable d'environnement RELAY_ENROLLMENT_TOKEN
# (unité systemd, `docker run -e`, etc.). `docker compose set-env` n'existe pas.
```

Rôles de jeton : `enrollment`, `plugin`, `relay-child`, `relay-parent` ; la révocation (`tokens revoke <id>`) vaut pour
`plugin`, `relay-child` et `relay-parent`. Les agents sont démarrés selon la section « Agents (variables d'environnement) » ci-dessous
(unité systemd, ou service `minion-*` de `docker-compose.chain.yml` pour l'essai de qualif ; `docker-compose.minion.yml` a été supprimé) ;
vérifier leurs logs : enrôlement puis ouverture de la WebSocket.

### Étape 4 : Vérifier l'inventaire

```bash
# Jeton PLUGIN (l'inventaire refuse ADMIN_TOKEN avec 403)
PLG=$(srv tokens create --role plugin --expires 1h | grep -oE 'secagent_plg_[0-9a-f]{64}' | tail -1)

printf 'Authorization: Bearer %s\n' "$PLG" | curl --cacert tls/tls.crt -H @- \
  https://localhost:7770/api/inventory | jq .
# Doit afficher les agents enrôlés
```

### Qualification sans registre (artefact de run CI + `docker load`)

Aucun pull GHCR n'est requis en qualif : chaque **push** construit les images serveur et minion (job `images-artifact`) et les publie en **artefact du run** `secagent-images-<sha>` (7 jours : archives `docker save`, binaire `secagent-inventory`, `images.env`, `SHA256SUMS` ; aucun push de registre). Procédure complète et variables : `DEPLOYMENT/qualif/README.md` (« Images sans registre »).

```bash
gh run download <id-du-run> -n secagent-images-<sha-complet> -D images
export DOCKER_HOST=tcp://192.0.2.10:2375      # ou `docker -H tcp://…` ; réseau de confiance uniquement
bash DEPLOYMENT/qualif/chain-test.sh load-images images   # vérifie SHA256SUMS puis docker load sur l'hôte distant
set -a; . images/images.env; set +a                       # tags locaux ci-<sha12>, SECAGENT_PULL_POLICY=never
```

Le déploiement se fait ensuite dans le projet Compose **`secagent-qualif`** (mode hôte distant : `TLS_MODE=volume`, `chain-test.sh push-tls`, `SECAGENT_ENDPOINT_HOST`, `PKI_EXTRA_SAN`). `down`, `teardown` et `backup-restore` sont refusés sur un hôte distant pour tout autre projet.

**Production** : le Compose de la release exige des images **`tag@sha256:<digest>`** (`vX.Y.Z@sha256:…`, jamais `latest`, jamais de tag local) ; la répétition à vide de l'archive de release le vérifie par `check_compose.py --require-digest`. Les images chargées par `docker load` ne sont acceptées qu'en qualif.

### Vérifier l'origine d'une image publiée (attestation de provenance signée, #213)

À partir de v3.0.5, chaque image poussée sur GHCR par `release.yml` (job `images`) ou par `candidate-images.yml` reçoit une **attestation de provenance SLSA signée** (`actions/attest-build-provenance`) : signature Sigstore par un certificat éphémère lié à l'identité OIDC du workflow GitHub, enregistrée dans le journal de transparence public (dépôt public), rangée par GitHub et poussée à côté de l'image dans GHCR.

**Ce que l'attestation enregistre** : le dépôt, le **fichier de workflow**, et le **ref et le commit sur lesquels le workflow a été lancé** (`GITHUB_REF` / `GITHUB_SHA`) — pas ceux d'un checkout explicite. Les workflows garantissent que ce sont aussi ceux du code construit :
- `release.yml` : le job `images` **refuse de publier** si le workflow ne tourne pas sur `refs/tags/<tag>` au commit du tag. Lancement manuel : `gh workflow run release.yml --ref vX.Y.Z -f tag=vX.Y.Z` (lancé depuis une branche, il échoue avant tout push).
- `candidate-images.yml` : l'image n'est attestée que si le commit construit est celui du lancement, sur une branche. Lancement attesté : `gh workflow run candidate-images.yml --ref <branche> -f ref=<branche> -f publish=true`. Avec `-f ref=<autre branche ou commit>`, l'image est construite et publiée **sans attestation** (avertissement dans le run) : elle ne doit pas être présentée comme prouvée.

Vérifier **toujours par digest**, et **toujours avec `--source-ref`** en plus de `--signer-workflow` (CLI `gh` ≥ 2.49, commande `gh attestation`). Sans `--source-ref`, une attestation émise par un workflow du même nom lancé depuis **n'importe quelle branche** (par un collaborateur ayant l'accès en écriture) serait acceptée.

```bash
IMG=ghcr.io/ccoupel/secagent-server@sha256:<digest>      # digest de la release (archive Compose, SHA256SUMS) ou de la candidate

# Image de RELEASE : signée par release.yml lancé sur le tag attendu
gh attestation verify "oci://$IMG" --owner CCoupel \
  --signer-workflow CCoupel/Ansible-SecAgent/.github/workflows/release.yml \
  --source-ref refs/tags/vX.Y.Z --deny-self-hosted-runners

# Image CANDIDATE (qualif) : signée par candidate-images.yml lancé sur la branche attendue (ex. main, milestone/vX.Y.Z)
gh attestation verify "oci://$IMG" --owner CCoupel \
  --signer-workflow CCoupel/Ansible-SecAgent/.github/workflows/candidate-images.yml \
  --source-ref refs/heads/<branche> --deny-self-hosted-runners
# optionnel : imposer aussi le commit, lu dans l'étiquette sha-<commit> de la candidate
#   --source-digest <commit>

# Variante : attestation lue dans le registre plutôt que via l'API GitHub (mêmes contraintes)
gh attestation verify "oci://$IMG" --owner CCoupel --bundle-from-oci \
  --signer-workflow CCoupel/Ansible-SecAgent/.github/workflows/release.yml \
  --source-ref refs/tags/vX.Y.Z --deny-self-hosted-runners
```

Code 0 = vérifié. **Ce que cela prouve** : l'image de **ce digest** a été construite et attestée par le workflow nommé du dépôt `CCoupel/Ansible-SecAgent`, sur un runner hébergé par GitHub, lancé sur le ref imposé (`--source-ref`) ; grâce aux gardes ci-dessus, le code construit est celui de ce ref et du commit inscrit ; l'attestation n'a pas été modifiée depuis sa signature. **Ce que cela ne prouve pas** : que le code de ce commit est sûr (revue et tests) ; qu'aucune version modifiée du workflow (gardes comprises, elles sont dans le fichier) n'a tourné sur ce ref ; qu'un **tag** d'image mutable désigne la bonne image (seul le digest compte). Les images antérieures à v3.0.5, et les candidates construites depuis un autre ref que celui du lancement, n'ont pas d'attestation signée (la vérification échoue).

**Ce qui rend la preuve fiable** (réglages du dépôt, à faire avant de s'appuyer sur l'attestation en production) : (1) `--source-ref` à chaque vérification ; (2) la **protection des refs** : *ruleset* sur les tags `v*` (création, mise à jour et suppression réservées au mainteneur — sinon un collaborateur peut pousser un tag `v9.9.9` sur un workflow modifié et obtenir une attestation pour `refs/tags/v9.9.9`) et protection de `main` (et `milestone/*` pour les candidates) ; (3) la limitation de qui peut écrire dans le dépôt et lancer les workflows. Un *Environment* GitHub protégé (relecteur obligatoire, refs autorisées) n'est qu'un **complément** pour les exécutions légitimes : déclaré dans le fichier de workflow, il peut être retiré par l'auteur d'un workflow modifié, et le certificat Sigstore ne porte pas son nom.

**État en v3.0.5 — réglages du dépôt** (faits par le mainteneur dans GitHub, pas par la CI) :
- **Protection de `main`** (Settings → Rules → Rulesets, cible `main`) : pull request obligatoire, ni force-push ni suppression.
- **Environment `release`** (Settings → Environments → `release`), utilisé par le job `images` de `release.yml` : *Deployment branches and tags* = **Selected branches and tags**, règle de **tag** `v*.*.*` uniquement (aucune branche) ; *Required reviewers* = le mainteneur (CCoupel) : chaque publication d'images attend son approbation.
- **Environment `candidate`** (Settings → Environments → `candidate`), utilisé par le job `candidate-images` : *Deployment branches and tags* = **Selected branches and tags**, règles de **branche** `main` et `milestone/*` ; pas de relecteur obligatoire (le lancement exige déjà `publish=true`). Un lancement depuis une autre branche est refusé, même pour une image non attestée.
- Les deux Environments doivent exister **avant** le premier run : un job qui référence un Environment absent le crée **sans aucune règle**.
- **Ruleset de tags `v*` : pas en place.** Tout collaborateur ayant l'accès en écriture peut créer un tag `v*` ; l'Environment `release` l'accepte et une attestation de release vérifiée prouve alors le workflow et le tag, mais **pas** que le tag a été posé par le mainteneur : la confiance repose sur les personnes qui ont l'accès en écriture (aujourd'hui le seul mainteneur). L'approbation requise de l'Environment `release` reste une porte humaine pour les exécutions légitimes, pas une barrière contre l'auteur d'un workflow modifié.

Dans le résumé d'un run `candidate-images`, chaque ligne de promotion indique `ATTESTEE` ou `NON ATTESTEE`.

Les attestations **BuildKit** attachées à l'image (`provenance: true`, `sbom: true`) restent présentes mais **ne sont pas signées** : elles se consultent, sans valeur de preuve, avec `docker buildx imagetools inspect "$IMG" --format '{{json .Provenance}}'` (et `'{{json .SBOM}}'`). Les images ne sont pas signées par cosign (décision v3.0.5).

---

## Arguments du binaire `secagent-server` (v3.0.4)

Le serveur démarre **sans argument** : toute sa configuration vient de l'environnement (`ENTRYPOINT ["/app/secagent-server"]`, aucun `command:` Compose). Tout argument est traité par la CLI d'administration : une commande ou un drapeau inconnu (`kyes`, `-d`, `--config …`) est **refusé** avec une erreur et le code de sortie 1, jamais interprété comme un démarrage de serveur. `--help`, `-h` et `--version` répondent sans rien démarrer. Ne pas ajouter d'`command:`/`args:` à un service serveur.

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

### CLI du serveur dans un conteneur (API admin en TLS)

Le Compose de production active `ADMIN_TLS=true` et l'API admin écoute en HTTPS. La CLI vise par défaut `http://localhost:7771`
(`cli/client.go:25-28`) : sans `RELAY_API_URL` en `https://` **et** `REPEATER_CA_FILE`, les commandes d'administration échouent.
`ADMIN_TOKEN` est déjà dans l'environnement du conteneur (`ADMIN_TOKEN_FILE`) : il n'est jamais passé en argument.

Le Compose de production ne fixe pas de `container_name` (`DEPLOYMENT/prod/docker-compose.server.yml`) : le conteneur s'appelle
`<projet>-secagent-server-1`, et `docker exec secagent-server …` échoue. On passe donc par `docker compose exec` sur le **service**
`secagent-server`, depuis le dossier du Compose de l'hôte concerné (ou avec `-f` / `-p`, ou `COMPOSE_FILE` / `COMPOSE_PROJECT_NAME`). Pour
« la racine », ouvrir la session sur l'hôte de la racine ; pour un relay, sur son hôte. Les fonctions suivantes (elles redéfinissent
l'alias `srv` de l'étape 3, propre à la qualif) servent à toutes les commandes `srv …` / `srvt …` de ce guide :

```bash
srv()  { docker compose exec -T -e RELAY_API_URL=https://localhost:7771 -e REPEATER_CA_FILE=/certs/tls.crt secagent-server secagent-server "$@"; }
srvt() { docker compose exec    -e RELAY_API_URL=https://localhost:7771 -e REPEATER_CA_FILE=/certs/tls.crt secagent-server secagent-server "$@"; }
# Exemple : srv minions list
```

Règle de `-T` : `srv` met `-T` (pas de terminal) pour les commandes non interactives, les sorties redirigées (`> root_link.pub`,
sinon des retours chariot s'y glissent) et les tubes (`srv … | grep …`, `printf … | srv …`), et il fonctionne sans terminal (script, CI).
`srvt` n'a pas `-T` : `docker compose exec` alloue un terminal, nécessaire à la confirmation à taper des commandes destructives (`minions delete`, `relays revoke`, `relays remove`) ; en non interactif on garde `srv` avec `--yes`.

Le certificat du serveur doit contenir `localhost` dans ses SAN (c'est le cas de celui des guides) ; sinon viser un nom présent dans les SAN
dans `RELAY_API_URL`. Les commandes hors ligne (`state …`) n'appellent pas l'API et se lancent avec `docker compose exec secagent-server secagent-server state …` (nœud arrêté : `docker compose run --rm`).

### Révoquer un agent, lever la révocation, retour arrière (#193)

```bash
# Révoquer : drapeau persistant + blacklist du JTI en une écriture, WS fermée en 4001, le minion sort en code 77
srv minions revoke <hostname>

# Effet : l'hôte est refusé à l'enrôlement (403 agent_revoked, jeton non consommé, même avec un jeton réutilisable),
# au rekey et à la connexion WS, sans limite de durée (le drapeau survit à la blacklist de 25 h).

# Lever la révocation : seule voie = supprimer l'agent (pas de « unrevoke ») ; ses variables sont perdues.
# Destructif : confirmation (taper le nom d'hôte) ; sans terminal, refus (code 9) sauf --yes. (v3.0.5, #233)
srvt minions delete <hostname>
# non interactif : minions delete <hostname> --yes
# puis créer un jeton d'enrôlement et ré-enrôler le minion (RELAY_ENROLLMENT_TOKEN) : le JWT local devenu invalide
# est rejeté en 401 à la connexion WS, ce qui déclenche le ré-enrôlement ; l'effacer à la main n'est pas nécessaire
srv tokens create --role enrollment --hostname-pattern "<hostname>" --expires 24h
```

- Si l'écriture est refusée (instance secondaire / état en lecture seule), la révocation répond une erreur et la WS n'est **pas** fermée : réessayer sur le maître.
- **Retour arrière vers une version antérieure à #193** : un état contenant au moins un agent révoqué est **refusé au démarrage** (décodeur strict) avec `state: corrupt state file: payload: json: unknown field "revoked"` — message d'une corruption, mais le fichier est valide ; l'ancien binaire peut aussi basculer sur `relay.state.prev` (état plus ancien, révocation éventuellement absente). Lever d'abord les révocations (`DELETE` ci-dessus) ou restaurer un état antérieur (`state verify`, `state restore --from`).
- **Mise à jour depuis un état sans drapeau** : au démarrage, le maître pose le drapeau aux agents dont le JTI courant est encore en blacklist (25 h). Une révocation plus ancienne est oubliée : **révoquer à nouveau** l'hôte.

## Montée de version v3.0.3 → v3.0.4 (une seule rupture des liens inter-relays)

> Décision et risques : `DOC/security/DECISION_141.md` ; contrat : `SERVER_SPEC.md` §9.2.1 ; CHANGELOG `[BREAKING]`. Les **agents ne sont pas affectés** (leurs jetons HS256 ne changent pas, leurs connexions ne sont pas coupées). Ce qui est coupé, c'est chaque **lien relay ↔ relay** entre la montée du parent et celle de l'enfant : prévoir une fenêtre de coupure annoncée (les tâches vers les descendants échouent pendant la fenêtre ; les tâches locales et les agents directs continuent).
>
> ⚠️ **Retour arrière vers v3.0.3 non supporté** (décision de l'utilisateur) : un binaire v3.0.3 refuse l'état v2 (`ErrSchemaVersion`). Le seul chemin est de restaurer la sauvegarde `relay.state.v1.bak` avec les binaires v3.0.3 **et les anciens jetons HS256**, en perdant toutes les écritures faites sous v3.0.4 (enrôlements, révocations d'agents à rejouer à la main).

**0. Avant** : ne **pas** révoquer les anciens jetons HS256 tant que la v3.0.4 n'est pas validée (ils sont refusés par la v3.0.4 mais permettent le retour arrière). La rotation de `RSA_MASTER_KEY` (la clé maître protège désormais aussi la clé de signature des liens, `SECURITY.md` §5) est **recommandée avant la mise en production, mais elle se fait APRÈS la montée** (étape 6 bis) : `state rekey` n'existe qu'en v3.0.4. Elle accepte un état encore en schéma 1 (la migration v1 → v2 a lieu à la **première écriture du maître**, pas au simple démarrage) et le migre dans la même opération.

1. **Sauvegarder** `STATE_DIR` de chaque relay (copie du volume + `secagent-server state verify relay.state`) : la migration crée aussi `relay.state.v1.bak`, mais une copie hors du volume reste obligatoire.
2. **Racine, paire actif/passif** : arrêter le **passif**, monter l'**actif** en v3.0.4 (le maître migre `relay.state` v1 → v2 à sa première écriture ; le passif v3.0.3 refuserait de toute façon l'état v2), puis monter le **passif**. Il n'y a plus de bascule possible pendant la fenêtre.
3. **Exporter la clé publique de la racine** : `srv keys link-pubkey > root_link.pub` (génère la clé de signature au besoin ; la racine doit avoir `RSA_MASTER_KEY`). `REPEATER_ID` de la racine = l'`iss` attendu par tous les relays (`REPEATER_ROOT_ID`).
4. **Minter les jetons de lien sur la racine, avant de descendre** (un jeton par lien, TTL 720 h par défaut) :
   - lien **pull** (l'enfant X se connecte à son parent P) : `tokens create --role relay-child --sub X --aud P`
   - lien **push** (le parent P ouvre vers l'enfant X) : `tokens create --role relay-parent --sub P --aud X`

   Le jeton n'est affiché qu'une fois ; le placer dans le secret de l'enfant (`REPEATER_UPSTREAM_TOKEN_FILE`, ou `token` de `POST /api/admin/relays` pour un lien push).
5. **Descendre niveau par niveau, parents d'abord** : pour chaque relay, déployer la v3.0.4 avec `REPEATER_ROOT_ID=<REPEATER_ID de la racine>` et `REPEATER_ROOT_LINK_KEY_FILE=<fichier root_link.pub>` (fichier régulier, non inscriptible par le groupe ni les autres) et son nouveau jeton ; même ordre passif/actif pour une paire. Un enfant **sans ancre refuse tout lien entrant** (`4010`, `[SECURITY WARNING]`) ; un enfant en mode push a aussi besoin de l'ancre (il n'a pas d'`UPSTREAM_URL`, mais il a un parent). Monter les parents d'abord évite aussi le bruit `unsupported event kind` des événements `host.suspended` (#180) vers un parent encore en v3.0.3.
6. **Contrôles** : `srv relays status` à chaque niveau (liens `connected`), inventaire de la racine complet (`GET /api/inventory`, comparer le nombre d'hôtes avant/après), smoke `exec` à travers chaque niveau, `srv keys link-status` (chaque relay connu apparaît avec son `kid`), absence de `[SECURITY WARNING] … link_trust_missing` dans les journaux.
**6 bis. Rotation de `RSA_MASTER_KEY`, après la montée et avant d'accepter du trafic de production** (commande hors ligne `secagent-server state rekey`, procédure complète et limites dans `DOC/security/SECURITY.md` §11) : arrêter **les deux** nœuds actif/passif, exécuter une fois `state rekey --yes` sur le `STATE_DIR` partagé avec `RSA_MASTER_KEY_FILE` (ancienne) et `NEW_RSA_MASTER_KEY_FILE` (nouvelle, fichier 0600 : à préférer aux variables saisies au shell, qui restent dans l'historique) — jamais en argument —, la nouvelle clé faisant **au moins 32 octets** (`openssl rand -base64 48`, sinon refus code 11 ; l'ancienne n'est pas contrôlée), redéployer la nouvelle clé sur **tous** les nœuds candidats, redémarrer, vérifier avec `state verify relay.state`. Un nœud encore lancé avec l'ancienne clé refuse l'état (code 2 de `state verify`). La commande écrit `relay.state.rekey.<UTC ns>.bak` (0600, lisible avec l'**ancienne** clé) avant toute modification : à conserver quelques jours comme seul retour arrière, puis à **détruire** avec `relay.state.prev` et les sauvegardes d'avant la rotation. Elle ne change ni `JWT_SECRET_KEY` ni les clés de signature (les jetons émis restent valides). Prérequis : les nœuds du relay sont en v3.0.4 (binaire de `state rekey`) et arrêtés ; sauvegarde de `STATE_DIR` éprouvée. L'état peut être encore en schéma 1 (un maître v3.0.4 démarré au repos n'a rien écrit) : `state rekey` le migre alors en schéma 2 dans la même écriture atomique, après avoir copié l'original dans `relay.state.v1.bak` (en plus de `relay.state.rekey.<UTC ns>.bak`), et le dit dans sa sortie ; le retour arrière vers v3.0.3 reste « `relay.state.v1.bak` + binaires v3.0.3 + **ancienne** clé ». Chaque relay a son propre `STATE_DIR` : répéter l'opération relay par relay (la nouvelle clé doit seulement être identique sur les nœuds d'une même paire actif/passif) ; le lien du relay est coupé pendant l'arrêt de ses nœuds. Un relay installé neuf en v3.0.4 peut être rekeyé juste après `state init`, avant son premier démarrage. **Après une compromission** (la clé a pu être lue avec une copie de `relay.state`) la rotation de la clé maître ne suffit pas, elle ne change pas les secrets eux-mêmes : faire en plus `keys rotate-link` puis `retire-link-previous` (rotation de la clé de signature, ci-dessous), `security keys rotate` (secrets JWT et clé RSA du serveur), puis **détruire** les `relay.state.rekey.*.bak`, `relay.state.prev` et toutes les anciennes sauvegardes de `STATE_DIR` (lisibles avec l'ancienne clé).

**Agents après un redémarrage de relay : JWT d'agent, renouvellement et ré-enrôlement (v3.0.5, #217).** Le JWT d'un agent vit `AGENT_JWT_TTL` (**24 h** par défaut ; 1 h avant v3.0.5) et le relay le **renouvelle** automatiquement sur la WebSocket de chaque agent connecté, toutes les `AGENT_JWT_RENEW_INTERVAL` (défaut TTL/3, soit 8 h), par la trame `rekey` (`SECURITY.md` §5). Un redémarrage, une montée de version ou une bascule du relay plus courts que `TTL − intervalle` (≈ 16 h par défaut) sont donc **sans effet** : les minions se reconnectent avec leur JWT renouvelé, sans jeton d'enrôlement. Au-delà (relay arrêté plus longtemps, ou agent hors ligne plus longtemps), la reconnexion reçoit un `401` et le minion se **ré-enrôle** avec son `RELAY_ENROLLMENT_TOKEN` ; si ce jeton est à usage unique (consommé) ou expiré, il sort en **code 78** (`[FATAL] Enrollment cannot succeed (permanent …) HTTP 403 token_expired`), reste arrêté (`RestartPreventExitStatus=78`) et apparaît `disconnected` dans `minions list` ; côté relay : `WS auth rejected: jwt_invalid … token is expired`. **En production, donner aux minions un jeton d'enrôlement réutilisable, restreint par `--hostname-pattern`, à longue durée** (`tokens create --role enrollment --reusable --hostname-pattern '<regex>' --expires 90d`, par fichier `RELAY_ENROLLMENT_TOKEN_FILE`) : c'est le filet de sécurité de ce cas ; le relay avertit au démarrage (`[WARN] no reusable enrollment token is active`) quand aucun n'existe. Les exemples `--expires 1h` de ce document sont des jetons de démonstration de qualification, pas un modèle de production. Surveiller le code de sortie 78 ; remède : créer un nouveau jeton et relancer le minion (même identité, même nom d'hôte). **Montée de version d'un relay** : une indisponibilité inférieure à `TTL − intervalle` ne demande aucune action sur les minions ; le premier démarrage en v3.0.5 passe le TTL des JWT *émis* de 1 h à 24 h (les JWT déjà émis gardent leur échéance et sont renouvelés dès la connexion suivante)

7. **Après validation** seulement : révoquer/oublier les anciens jetons HS256, supprimer les sauvegardes selon la politique de rétention.

### Rotation de la clé de signature des liens (racine)

```bash
srv keys rotate-link      # courante → précédente, nouvelle courante ; link_keys poussé
srv keys link-status      # TOUS les relays doivent être "confirmed"
# AVANT le retrait, pour CHAQUE lien : un NOUVEAU jeton, signé par la nouvelle clé (affiché une seule fois)
srv tokens create --role relay-child --sub <enfant> --aud <parent>
# Sur CHAQUE relay non racine, AVANT le retrait : remplacer le fichier épinglé par la NOUVELLE clé publique
srv keys link-pubkey > root_link.pub   # puis le déposer à l'emplacement de REPEATER_ROOT_LINK_KEY_FILE
# Remplacer le jeton (REPEATER_UPSTREAM_TOKEN ou son _FILE) et redémarrer le relay (ces valeurs sont lues au démarrage) ; vérifier le lien
srv keys retire-link-previous
```

- **Séquence exacte** : `keys rotate-link` → confirmation de **tous** les relays (`keys link-status`) → **nouveau jeton de lien** par lien (`tokens create --role relay-child …`) → sur chaque relay non racine, remplacer **`REPEATER_UPSTREAM_TOKEN[_FILE]` ET `REPEATER_ROOT_LINK_KEY_FILE`**, redémarrer le relay, vérifier que le lien est `connected` → seulement alors `keys retire-link-previous`. C'est la séquence du scénario `link-rotation` de `DEPLOYMENT/qualif/chain-test.sh` (`link_anchor_prepare`, `link_mint_child`, redémarrage de l'enfant, puis retrait). Pour un lien **push**, le jeton `relay-parent` (`--sub <parent> --aud <enfant>`) est à re-minter de la même façon et à redonner au parent ; ce cas n'est pas couvert par le scénario de qualif.
- **Pourquoi le nouveau jeton est obligatoire** : un jeton de lien porte dans son en-tête le `kid` de la clé qui l'a signé et le relay qui le vérifie (la racine pour un enfant direct) n'accepte que les `kid` `current` et `previous` (`auth/linkjwt.go:251-258`) : un jeton émis AVANT la rotation est signé par l'ancienne clé et est refusé (`jwt_unknown_kid`) dès `retire-link-previous`. Sans lui, le lien déjà établi survit jusqu'à sa prochaine reconnexion, puis l'enfant est refusé : le défaut est masqué jusque-là (constaté par la QA avec un test dédié et exécuté). **Symptôme différé** : si le nouveau jeton est oublié, le lien déjà établi tient encore juste après `retire-link-previous` ; l'enfant ne se reconnecte plus qu'à son redémarrage suivant et la racine journalise `jwt_unknown_kid`. **L'absence de coupure immédiate ne prouve pas que la rotation est correcte** : vérifier chaque lien après redémarrage du relay avant de considérer la rotation terminée.
- **Mettre à jour `REPEATER_ROOT_LINK_KEY_FILE` de chaque relay non racine AVANT `retire-link-previous`.** Tant que la clé précédente existe, l'ancien fichier égale `previous` et reste accepté ; **après le retrait il n'est plus ni la clé courante ni la précédente**, et le **prochain démarrage** du relay (redémarrage du conteneur, mise à jour d'image) est refusé en boucle : `link trust anchor: pinned root link key disagrees with the persisted link_trust (outside a valid rotation chain)`. C'est voulu (fail closed) ; le lien déjà établi survit jusqu'à ce redémarrage, ce qui masque le défaut. Remède si le retrait a déjà eu lieu : remplacer le fichier par la clé courante (`keys link-pubkey`) et redémarrer le relay ; si l'ancre persistée est elle-même obsolète, `state link-trust reset --yes` (relay arrêté), nouveau fichier, redémarrage.

- **Ne jamais `retire-link-previous` avant la confirmation de tous les relays** : la racine répond `409 rotation_unconfirmed` (avec la liste `unconfirmed` et, depuis v3.0.5, `never_seen` : les relais déclarés ou appris mais jamais connectés) tant qu'un relay connu n'a pas confirmé la rotation. Un relais déclaré **jamais connecté** bloque donc la clôture : le connecter, ou le retirer avec `secagent-server relays remove --revoke <relay_id>` s'il ne doit plus exister (un relais déclaré par `relays add` sans jamais s'être connecté n'a aucun JTI de jeton suivi : `relays remove` seul répond `409 relay_not_revoked`, #153 ; `--revoke` le révoque d'abord). Un descendant `never_seen` seulement appris de la topologie (aucune ligne `relay_nodes` sur la racine) répond `404 relay_not_found` à `remove` : il disparaît du statut quand son ancêtre cesse de le déclarer (ou au redémarrage de la racine). `keys link-status` affiche la colonne `STATE` (`confirmed` / `unconfirmed` / `never_seen`). `--force` passe outre avec un `[SECURITY WARNING]` listant les relays concernés : à n'utiliser que pour un relay définitivement perdu.
- Une seule rotation à la fois (`409 previous_key_not_retired` tant que la précédente n'est pas fermée).
- Pendant la fenêtre, les jetons signés par l'ancienne **et** la nouvelle clé sont acceptés ; après `retire-link-previous`, plus que la nouvelle.
- Les jetons de lien déjà distribués restent valables **jusqu'à `retire-link-previous`** (leur clé reste `previous` pendant la fenêtre), puis ils sont refusés : voir la séquence ci-dessus. **Confirmé** signifie que le relay rapporte (`link_state`) le `kid` de la clé **courante** (`keys link-status`, colonne `CONFIRMED`) ; le `seq` rapporté n'est qu'informatif (non signé). Un relay déployé **après** la rotation, ancré sur la nouvelle clé, se confirme à son premier `link_state`.
- **Ordre à respecter — d'abord les relays existants, ensuite les nouveaux** : un relay ancré sur la **nouvelle** clé ne peut pas vérifier la rotation signée par l'ancienne ; il **ignore** la trame `link_keys` rejouée et **ne la retransmet plus** à ses enfants. Un enfant resté sur l'**ancienne** ancre sous un tel relay ne recevrait donc jamais la rotation. Lancer la rotation et vérifier la confirmation de **tous les relays existants** (`keys link-status`) **avant** de déployer de nouveaux relays épinglés sur la nouvelle clé. Un enfant déjà laissé sur l'ancienne ancre sous un relay ancré sur la nouvelle clé doit être **ré-épinglé** (arrêt, `state link-trust reset --yes`, nouveau `REPEATER_ROOT_LINK_KEY_FILE`, redémarrage).
- Un relay qui rate une rotation **et** le `retire-link-previous`, ou deux rotations, ne peut plus vérifier la chaîne : le **ré-épingler** (relay arrêté) : `docker compose run --rm --no-deps secagent-server state link-trust reset --yes` (sauvegarde `relay.state.linktrust-reset.<UTC ns>.bak`, n'efface que l'ancre ; refuse une racine et un verrou actif), remplacer `REPEATER_ROOT_LINK_KEY_FILE` / `REPEATER_ROOT_ID` par `keys link-pubkey` de la racine, redémarrer ; ses agents sont conservés. La sauvegarde `relay.state.linktrust-reset.<UTC ns>.bak` est une **copie complète de l'état** (secrets chiffrés `enc:` compris, mode `0600`) : la protéger comme `relay.state` (accès à `STATE_DIR`) et la **supprimer ou la déplacer hors du volume** une fois le relay re-validé : elle n'est jamais purgée automatiquement. Si un nœud démarre pendant la commande, celle-ci s'abandonne (code 8, état intact, sauvegarde conservée) : arrêter **toutes** les instances avant.
- **Refus de démarrage d'un relay non racine (v3.0.5, #218)** : si le fichier `REPEATER_ROOT_LINK_KEY_FILE` n'est ni la clé courante ni la précédente persistée (fichier d'avant une rotation déjà clôturée) ou si `REPEATER_ROOT_ID` change, le relay refuse de démarrer (`ErrAnchorMismatch`, aucune tolérance) et le message donne le `kid` du fichier épinglé, les `kid` courant et précédent persistés, la cause probable et les deux remèdes : `secagent-server keys link-pubkey` sur la racine puis remplacement du fichier, et `secagent-server state link-trust reset --yes` (relay arrêté) pour ré-épingler. Le message ne contient aucune clé.

### Re-racine (perte de `RSA_MASTER_KEY` ou de la clé privée de la racine)

Coût équivalent à une montée de version complète : à répéter en qualification. (1) arrêter toute la hiérarchie ; (2) sur la racine, nouvelle `RSA_MASTER_KEY` et état à réinitialiser si les secrets sont perdus (`state init`, ré-enrôlement de tous les agents) ; la clé de signature est regénérée à la demande ; (3) `keys link-pubkey` ; (4) sur **chaque** relay non racine : `state link-trust reset --yes` (relay arrêté ; l'ancienne ancre ferait sinon refuser le démarrage, `ErrAnchorMismatch`), nouvelle ancre (`REPEATER_ROOT_ID` + `REPEATER_ROOT_LINK_KEY_FILE`) ; (5) re-minter **tous** les jetons de lien ; (6) redémarrer les parents d'abord.

### Note : réponses d'`exec` de plus de 15 s (corrigé en v3.0.4)

Jusqu'à la v3.0.3 incluse (et depuis v1.0.0), le serveur API coupait la réponse de tout `exec`, `upload` ou `fetch` bloquant plus de 15 s (`WriteTimeout`) : la tâche s'exécutait sur l'agent mais le plugin voyait une connexion rompue (`bad record MAC` en TLS). La v3.0.4 étend la deadline d'écriture à `timeout + 35 s` pour ces trois routes ; aucune configuration n'est nécessaire. Si vous restez en v3.0.3, un contournement partiel consiste à garder les tâches sous 15 s.

## Montée de version v3.0.4 → v3.0.5 (JWT d'agent renouvelés, clé maître contrôlée)

Aucune rupture de lien ni d'agent. Trois précautions **avant** de démarrer le binaire v3.0.5 :

1. **Qualité de `RSA_MASTER_KEY` (#214)** : v3.0.5 refuse de démarrer avec une clé de moins de 32 octets ou prévisible (caractère/motif répété, moins de 12 caractères distincts). Vérifier la clé avant la montée (longueur : `wc -c` du fichier `RSA_MASTER_KEY_FILE`, newline final non compté) ; si elle est trop courte, exécuter d'abord `secagent-server state rekey` avec le binaire **v3.0.4** (nœuds arrêtés, nouvelle clé `openssl rand -base64 48` en `NEW_RSA_MASTER_KEY_FILE`, voir 6 bis ci-dessus) puis déployer la nouvelle clé sur tous les nœuds.
2. **Sauvegarde de `STATE_DIR` (nœuds arrêtés ou non : `relay.state` est remplacé atomiquement)** : `install -m 0600 "$STATE_DIR/relay.state" /chemin/hors-STATE_DIR/relay.state.pre-v305.$(date -u +%Y%m%dT%H%M%SZ)` sur chaque relais (avec `RSA_MASTER_KEY_FILE`, `secagent-server state verify <copie>` doit répondre `verdict: OK`). La sauvegarde est lisible avec la clé maître : même protection que `relay.state`.
3. **Variables** : `AGENT_JWT_TTL` (défaut 24 h) et `AGENT_JWT_RENEW_INTERVAL` (défaut TTL/3) ne demandent rien ; créer un jeton d'enrôlement réutilisable (voir « Agents après un redémarrage de relay »).

**Retour arrière vers v3.0.4** : à partir du premier renouvellement ou de la première rotation, l'état contient `prev_token_jti` et un binaire v3.0.4 ne sait plus le lire (il peut même basculer en silence sur `relay.state.prev`, plus ancien : `STATE_SPEC.md`). Procédure : arrêter **tous** les nœuds du relais, `secagent-server state restore --from <sauvegarde pre-v305> --state-dir "$STATE_DIR"` (vérifie le HMAC, sauvegarde l'état courant, écriture atomique), démarrer les binaires v3.0.4 avec la **même** clé maître (ou celle de la sauvegarde si `state rekey` a eu lieu entre-temps). **Perte** : tout ce que l'état contenait de plus récent que la sauvegarde — agents enrôlés, révocations, jetons créés, clés de signature de lien. Les agents dont le JWT a été renouvelé depuis ont un JTI inconnu de l'état restauré : ils reçoivent 401 et se ré-enrôlent (jeton réutilisable indispensable, sinon code 78). Noter avant le retour arrière les révocations à ré-appliquer.

## Gestion des Tokens Relay (v3.0.4)

### Créer un jeton de lien (sur la racine uniquement)

```bash
srv tokens create --role relay-child  --sub dmz1    --aud central   # lien pull
srv tokens create --role relay-parent --sub central --aud dmz1      # lien push

# Sortie : JWT Ed25519 signé par la racine, affiché UNE SEULE FOIS (id, sub, aud, kid, expires_at)
# Sur un relay qui a un parent : 409 not_root. Sans RSA_MASTER_KEY : 503 master_key_required.
```

### Lister les jetons de lien

```bash
srv tokens list --role relay-child     # ou relay-parent, ou all
# Sortie : id, role, sub -> aud, expires_at, revoked (jamais le jeton ni son hash)
```

### Révoquer un jeton de lien

```bash
srv tokens revoke <token-id>

# Effets (une seule mutation d'état sur la racine) :
# - revoked_at posé, JTI blacklisté jusqu'à l'expiration du jeton, compteur seq incrémenté
# - link_revocations poussé aux enfants, de proche en proche ; chaque relay ferme le lien
#   authentifié par ce jeton (close 4010 permanent) et blackliste le JTI
# - racine injoignable : les liens établis continuent, la révocation descend au retour du lien
```

### Identifiant d'un relay : `relay_id` ou UUID (v3.0.5, #233)

`relays revoke` et `relays remove` acceptent le nom `relay_id` (celui de `relays list`, ex. `dmz1`) **ou** l'UUID de la ligne (champ `id`). Le nom est résolu par `GET /api/admin/relays` ; un nom inconnu, ou porté par plusieurs lignes, est refusé avec un message (utiliser alors l'UUID, lisible dans `relays list --format json`). Les routes REST `/api/admin/relays/{id}/revoke` et `DELETE /api/admin/relays/{id}` attendent, elles, l'UUID (avec le nom : `404 relay_not_found`).

### Révoquer un relay enfant (mode pull)

```bash
# Destructif : confirmation (taper le relay_id) ; sans terminal, refus (code 9) sauf --yes
srvt relays revoke dmz1
# non interactif : relays revoke dmz1 --yes

# Effets :
# - JTI du token enfant blacklisté
# - Lien enfant fermé (close 4010 permanent)
# - Enfant ne peut plus se reconnecter
```

### Supprimer un relay (legacy ou post-révocation)

⚠️ Un relais dont le nœud ne suit pas le jeton de lien (typiquement déclaré par `relays add` et **jamais connecté**, `never_seen`) doit être révoqué AVANT d'être supprimé, sinon `409 relay_not_revoked`.

```bash
# En une commande : révoque puis supprime (même confirmation que relays revoke)
srvt relays remove --revoke dmz1
# ou en deux : relays revoke dmz1 ; relays remove dmz1 (chacune demande la confirmation, ou --yes en non interactif)
```

Un descendant `never_seen` seulement appris de la topologie (aucune ligne `relay_nodes` sur la racine) répond `404` : il disparaît quand son ancêtre cesse de le déclarer.

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
| `JWT_SECRET_KEY`, `ADMIN_TOKEN`, `RSA_MASTER_KEY` | — | Secrets requis (`RSA_MASTER_KEY` : secret HMAC/AES-GCM de l'état, pas une clef RSA ; **32 octets minimum**, `openssl rand -base64 48` — plus court : `state init` et le démarrage sont refusés, remède `state rekey` avant la montée de version, v3.0.5 #214) |
| `AGENT_JWT_TTL` | `24h` | Durée de vie du JWT des agents (7 jours au plus). Renouvelé tant que la WebSocket est ouverte (#217) |
| `AGENT_JWT_RENEW_INTERVAL` | `AGENT_JWT_TTL`/3 | Période de renouvellement du JWT (au plus TTL/2) |
| `TLS_CERT` | — | Certificat TLS (PEM, obligatoire en production ; `TLS_DISABLE=true` = tests/CI uniquement, jamais en production) |
| `TLS_KEY` | — | Clef privée TLS (PEM, obligatoire en production) |
| `ADMIN_ADDR` | `:7771` | Adresse admin (toutes interfaces par défaut ; `127.0.0.1:7771` pour la boucle locale) |
| `ADMIN_TLS` | `false` | TLS sur admin ; **obligatoire** si `ADMIN_ADDR` n'est pas loopback (sinon refus de démarrer, ou dérogation `ADMIN_INSECURE_HTTP` + ACK) |

#### Rechargement à chaud du certificat TLS

Le serveur relit la paire `TLS_CERT` / `TLS_KEY` au sondage suivant (60 s par défaut, `DefaultTLSReloadInterval`, `server/tls.go:49-50`) ou sur `SIGHUP`, sans coupure. Remplacer le certificat et la clé ensemble (répertoire versionné + bascule d'un lien symbolique par un seul `rename`) ; sinon un `[SECURITY WARNING] TLS certificate reload refused, keeping the previous pair` transitoire est attendu (`server/tls.go:153`), l'ancien certificat reste servi et le rechargement réussit au sondage suivant.

#### Secrets par fichier (`*_FILE`, #196)

Chaque secret peut être donné par une variable **ou** par un fichier : `JWT_SECRET_KEY` / `JWT_SECRET_KEY_FILE`, `ADMIN_TOKEN` / `ADMIN_TOKEN_FILE`, `RSA_MASTER_KEY` / `RSA_MASTER_KEY_FILE`, `REPEATER_UPSTREAM_TOKEN` / `REPEATER_UPSTREAM_TOKEN_FILE` (serveur seulement : la CLI ne lit que `ADMIN_TOKEN[_FILE]` et `RSA_MASTER_KEY[_FILE]`, `cli/client.go`), `RELAY_ENROLLMENT_TOKEN` / `RELAY_ENROLLMENT_TOKEN_FILE` (minion). Avantage : le secret n'apparaît plus dans `docker inspect` ni dans l'environnement du processus.

- Les deux définies ensemble : **refus de démarrer**. Une variable vide compte comme non définie.
- Le fichier doit être un fichier **régulier** (ni lien symbolique, ni périphérique), **non vide**, de 64 Kio au plus, avec des permissions `0600` ou plus strictes (aucun droit pour le groupe ni les autres). Les espaces et fins de ligne finaux sont retirés. Sinon : refus de démarrer, le message cite la variable et le chemin, jamais la valeur.
- Les variables directes restent acceptées (rétrocompatible).
- **Docker Compose (hors Swarm) : `uid`, `gid` et `mode` de `secrets:` sont IGNORÉS** (Compose affiche `secrets uid, gid and mode are not supported, they will be ignored`). Un `secrets: file:` est un **bind mount du fichier de l'hôte** qui garde son propriétaire et son mode d'hôte. Comme le conteneur tourne en **UID 10001** et que le serveur exige `0600` ou plus strict, le fichier doit **appartenir à l'UID 10001 avec le mode `0400`** (ou `0600`) : `chown 10001:10001` + `chmod 0400`. Un fichier root `0600` est illisible (`secret file cannot be read: permission denied`), un `0444`/`0644` est refusé (`permissions too open`) : dans les deux cas le serveur sort et redémarre en boucle. En production, `DEPLOYMENT/prod/preflight-secrets.sh` (à lancer **avant** `docker compose up`, `--child` pour un enfant) vérifie propriétaire, mode, type et taille de chaque fichier ; `--fix` corrige, `--write NOM` crée un secret depuis stdin. Contre un démon Docker **distant** un `secrets: file:` est inutilisable (le chemin est résolu sur l'hôte distant) : la qualif distante dépose les secrets de lien dans un volume nommé (`chain-test.sh`).
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
REPEATER_UPSTREAM_TOKEN=<jwt-relay-child>     # Jeton de lien relay-child, minté sur la RACINE (tokens create --role relay-child --sub dmz1 --aud <parent>)
REPEATER_ROOT_ID=central                       # (v3.0.4) REPEATER_ID de la racine : l'iss attendu des jetons de lien
REPEATER_ROOT_LINK_KEY_FILE=/run/secagent/root_link.pub  # (v3.0.4) clé PUBLIQUE de la racine (keys link-pubkey) ; sans ancre le relay refuse tout lien entrant
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
#   "token": "<jwt-relay-parent>",     # minté sur la RACINE : --role relay-parent --sub central --aud dmz1
#   "mode": "push"
# }
# L'enfant dmz1 n'a pas d'UPSTREAM_URL mais il a un parent : il a besoin de l'ancre
# (REPEATER_ROOT_ID + REPEATER_ROOT_LINK_KEY_FILE), sinon il refuse le lien (close 4010).
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
│  Host 1 (192.0.2.10)         │
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
