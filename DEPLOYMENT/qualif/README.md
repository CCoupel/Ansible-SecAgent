# Déploiement Qualif — relay actif/passif (192.168.1.218)

Topologie qualif v3.0.3 : **un relay en actif/passif**, deux instances (`secagent-server-a`, `secagent-server-b`) sur **un même volume d'état** `secagent_state`, définies dans `docker-compose.server.yml`. Exactement une instance est maître (ports 7770/7771/7772 ouverts) ; l'autre est secondaire et **n'ouvre aucun port** tant qu'elle n'a pas pris le verrou. Les ports d'hôte du service b sont décalés (8770/8771/8772) parce que les deux conteneurs tournent sur la même machine.

> La topologie « relay-proxy + relay-dmz1 + relay-dmz2 » (ports 7780-7784, `.env.proxy`, `/api/agents` agrégés), ses Compose (`proxy`, `minion`, `ansible`), les smoke-tests associés, `deploy.sh`/`deploy.bat` et `bootstrap-qualif.sh` ont été **supprimés** (#188) : ils sont remplacés par la chaîne ci-dessous.

## Topologie en chaîne (#188) : `docker-compose.chain.yml`

Racine actif/passif (`secagent-server-a/-b`, incluse depuis `docker-compose.server.yml`), **un relay enfant pull** (`secagent-child`, `REPEATER_ID=dmz1`, `REPEATER_UPSTREAM_URL` = liste des 2 adresses de la racine, `REPEATER_CA_FILE`), **deux minions** (`minion-root`, `minion-child`) avec listes d'adresses et `RELAY_CA_BUNDLE`. TLS de bout en bout avec une CA privée de test (`pki/gen.sh`), jamais `RELAY_INSECURE_TLS`. L'enfant push (optionnel) n'est pas déployé ; l'enfant pull est une seule instance (l'actif/passif testé est celui de la racine).
Le poste de contrôle Ansible (plugin `SECAGENT-PYTHON`, `secagent-inventory`, `ansible-core`) est le poste qui lance les scripts : il joint la racine par `127.0.0.1:7770` et `:8770` (jeton plugin en **fichier 0600**, jamais en variable d'environnement partagée).

```bash
export SECAGENT_IMAGE=ghcr.io/ccoupel/secagent-server:sha-<commit>@sha256:<digest>
export SECAGENT_MINION_IMAGE=ghcr.io/ccoupel/secagent-minion:sha-<commit>@sha256:<digest>
export INVENTORY_BIN=/chemin/secagent-inventory     # binaire du poste de controle
bash chain-test.sh ci-prepare   # CI/essai : PKI de test (pki/out) + qualif.env jetable ; en qualif : vos propres secrets
bash chain-test.sh bootstrap    # state init, relays add, jetons d'enrolement et plugin (./chain/, 0600), demarrage
bash chain-test.sh smoke        # relais, minions, inventaire hierarchique, ansible -m ping
bash chain-test.sh failover     # arret propre du maitre de la racine puis smoke ; kill : failover-test.sh run kill
bash chain-test.sh down
```
Les secrets (`qualif.env`, `chain/`, `pki/out/`) sont ignorés par git. En CI, le job « Chaîne en conteneurs » rejoue ce scénario à chaque push.

### Hôte Docker distant (qualif réelle 192.168.1.218), sans tunnel ni copie de certificats par scp

Projet dédié **`secagent-qualif`** (seul projet autorisé pour `down -v`, `teardown` et `backup-restore` quand `DOCKER_HOST` est distant ; refus sinon, et refus si `COMPOSE_PROJECT_NAME` diffère). Noms et ports sur l'hôte :

| Élément | Valeur |
|---|---|
| Conteneurs | `secagent-qualif-a`, `secagent-qualif-b` (racine), `secagent-qualif-child`, `secagent-qualif-minion-root-1`, `secagent-qualif-minion-child-1` |
| Ports publiés | 7770 et 7772 (racine a, `0.0.0.0`) ; 8770 et 8772 (racine b, `0.0.0.0`) ; admin **127.0.0.1** uniquement : 7771 (a), 8771 (b), 9771 (enfant) |
| Volumes | `secagent-qualif_secagent_state`, `…_child_state`, `…_minion_*_data`, `secagent-qualif_tls` (mode volume) |

**Libérer ces ports avant** (ancienne qualif v2 : 7770-7772) : le script ne s'en occupe pas.

```bash
export DOCKER_HOST=tcp://192.168.1.218:2375      # API Docker sans authentification : réseau de confiance uniquement
export TLS_MODE=volume                            # certificats dans un volume nommé, alimenté par un conteneur éphémère
export SECAGENT_ENDPOINT_HOST=192.168.1.218       # adresse que le poste de contrôle utilise pour 7770 / 8770
export PKI_EXTRA_SAN="IP:192.168.1.218"           # SAN supplémentaire dans le certificat de test
export SECAGENT_IMAGE=… SECAGENT_MINION_IMAGE=… INVENTORY_BIN=…
bash chain-test.sh ci-prepare                     # PKI + qualif.env jetables, en LOCAL (jamais ceux de prod)
bash chain-test.sh push-tls                       # copie tls.crt/tls.key/ca.crt dans le volume secagent-qualif_tls de l'hôte
bash chain-test.sh bootstrap && bash chain-test.sh smoke
```
`qualif.env` et `chain/*.env` sont lus côté client (`env_file`) ; seul `/certs` est un montage résolu sur l'hôte, d'où le volume. La clé de test (0644) est jetable et ne quitte jamais le poste que par ce flux.

### Images sans registre : artefact de run CI + `docker load`

Aucun pull GHCR n'est nécessaire : chaque push construit les images du commit et les publie comme **artefact du run** (7 jours : `secagent-server-ci-<sha12>.tar.gz`, `secagent-minion-ci-<sha12>.tar.gz`, binaire `secagent-inventory` linux/amd64 pour le poste de contrôle, `images.env`, `SHA256SUMS`).

```bash
gh run download <id-du-run> -n secagent-images-<sha-complet> -D images
export DOCKER_HOST=tcp://192.168.1.218:2375
bash chain-test.sh load-images images           # sha256sum -c, puis docker load des 2 archives
set -a; . images/images.env; set +a              # SECAGENT_IMAGE, SECAGENT_MINION_IMAGE (tags locaux ci-<sha12>), SECAGENT_PULL_POLICY=never
export INVENTORY_BIN="$PWD/images/secagent-inventory"
```
`load-images` enregistre l'empreinte stable des images (sha256 des couches `RootFS.Layers`, `chain/image-ids`, non secrets ; l'ID `.Id` varie selon le magasin containerd) et `bootstrap`/`failover`/`backup-restore` **refusent** de démarrer si l'empreinte réelle d'une image du démon diffère (tag local préexistant) ou si `load-images` n'a pas été lancé.
**Exception à « sans registre »** : « sans registre » vaut pour les **images secagent**. Deux commandes (`chain-test.sh push-tls` et `backup-restore`) utilisent aussi `alpine:3.20@sha256:d9e853e8…` (épinglée par digest, identique à celle du `GO/Dockerfile`), **tirée de Docker Hub** par l'hôte au premier usage ; sur un hôte sans accès au Hub, charger cette image au préalable (`docker pull` ailleurs puis `docker save | docker load`).
`SECAGENT_PULL_POLICY=never` empêche Compose de chercher ces tags locaux dans un registre. La production, elle, exige `tag@sha256` (archive de release, `check_compose.py --require-digest`).

**Procédure « qualification sans registre »** (le job `images-artifact` ne tourne que sur un **push**, après `docker-compose-checks`) :

1. Récupérer l'artefact du run du commit à qualifier : `gh run download <id> -n secagent-images-<sha-complet> -D images` (expire après 7 jours).
2. Pointer le client Docker vers l'hôte de qualif : `export DOCKER_HOST=tcp://192.168.1.218:2375` (équivalent de `docker -H tcp://192.168.1.218:2375` à chaque commande ; `docker compose` et les scripts utilisent `DOCKER_HOST`).
3. `bash chain-test.sh load-images images` : `sha256sum -c SHA256SUMS` puis `docker load` des deux archives, directement sur l'hôte distant. Charger ensuite `images/images.env` (tags locaux `secagent-*:ci-<sha12>`, `SECAGENT_PULL_POLICY=never`) et `INVENTORY_BIN` comme ci-dessus.
4. Déployer le projet `secagent-qualif` avec les étapes de la section « Hôte Docker distant » : `TLS_MODE=volume`, `SECAGENT_ENDPOINT_HOST`, `PKI_EXTRA_SAN`, `ci-prepare`, `push-tls`, `bootstrap`, `smoke`.

Les opérations destructives (`down`, `teardown`, `backup-restore`) sont refusées par `guard_project` sur un hôte distant pour tout projet autre que `secagent-qualif`.

**Un seul projet `secagent-qualif`** pour la chaîne ET les tests de basculement (mêmes noms de conteneurs `secagent-qualif-a/-b`) : lancer `chain-test.sh` et `failover-test.sh` **l'un après l'autre**, jamais en parallèle. `backup-restore` passe par des volumes nommés (`<projet>_backup`), donc fonctionne avec un démon distant ; `CONTROL_HOST` (alias de `SECAGENT_ENDPOINT_HOST`) désigne l'hôte joint par le poste de contrôle.

### Pièges du mode distant (incident E2) et du poste WSL

- **Ne jamais lancer `failover-test.sh` isolément contre un démon distant** : sans les variables du mode volume (`COMPOSE_FILE`, `COMPOSE_OVERRIDES`, `SECAGENT_TLS_VOLUME`) que `chain-test.sh` exporte, Compose recréait les conteneurs avec un bind mount d'un chemin **du poste**, créant des répertoires vides sur l'hôte distant. Le script **refuse** désormais en mode distant (`DOCKER_HOST` non local ou `SECAGENT_ENDPOINT_HOST`/`CONTROL_HOST` non local) sans `TLS_MODE=volume`, reprend lui-même le mode volume sinon, et refuse tout bind mount dans le rendu. Point d'entrée : `chain-test.sh failover`.
- **`chmod 600` n'est pas honoré sur `/mnt/c` (NTFS)** : le plugin refuse un fichier de jeton qui n'est pas 0600. Lancer les scripts depuis une copie **hors `/mnt/c`** : `git archive HEAD | tar -x -C ~/qualif-run` (puis `cd ~/qualif-run/DEPLOYMENT/qualif`), jamais depuis le dépôt monté.

## Compléments de qualif v3.0.4 (#197) : hooks, CA négative, jeton plugin frais, CLI Docker épinglé

- **Hooks en réel** : `hooks.json` (même répertoire) est livré par un **volume nommé** `${PROJECT}_hooks` (`chain-test.sh push-hooks`, appelé par `bootstrap` ; surcharge `docker-compose.hooks.yml`, `RELAY_HOOKS_CONFIG=/etc/secagent-hooks/hooks.json`) sur `secagent-server-a/-b` et `secagent-child`. **Jamais `configs: file:` ni `secrets: file:`** : hors Swarm Compose les monte en bind mount du chemin du client, introuvable sur un démon distant (échec constaté sur 192.168.1.218 le 2026-10-08) ; `scripts/ci/check_no_binds.py` (rendu distant, en CI) refuse tout chemin du client. Il écrit chaque `host.up` / `host.down` dans `/run/secagent/events.log` (tmpfs) du conteneur. `bash chain-test.sh hooks` vérifie `host.up` de `minion-root` (maître de la racine) et `minion-child` (enfant) ; `bash chain-test.sh failover` vérifie ensuite que le **nouveau maître** journalise `host.up` de `minion-root` après la bascule.
- **Essai CA négatif** : service `minion-negca` (profil Compose `negative`, jamais démarré par un `up` ordinaire), minion **sans** `RELAY_CA_BUNDLE` (store système seul) face à la CA privée. `bash chain-test.sh negative-ca` exige une erreur de certificat dans ses logs et son absence de `minions list`, puis le supprime. Le jeton d'enrôlement du service est factice (forme valide, 64 zéros) : le refus doit précéder toute authentification.
- **Jeton plugin frais** : `chain-test.sh` crée un jeton plugin neuf (fichier 0600) à chaque `smoke`, `failover` et `hooks` ; plus de dépendance au jeton du bootstrap qui expire (`TOKEN_TTL`).
- **Jetons de lien v3.0.4** (comportement par défaut du bootstrap) : `relays add` ne mint plus de jeton ; `chain-test.sh bootstrap` exporte la clé publique racine (`keys link-pubkey`, PEM sur stdout, `root_id=` sur stderr), la pousse dans le volume `${PROJECT}_link` (`push-link-key`, aucun bind mount), mint sur la racine le jeton `relay-child` de `dmz1` (`tokens create --role relay-child --sub dmz1 --aud <root_id>`, TTL `LINK_TTL`) et le dépose, par un conteneur éphémère, dans le même volume `${PROJECT}_link` (fichier `upstream-token`, propriétaire UID 10001, mode 0400, `REPEATER_UPSTREAM_TOKEN_FILE=/run/secagent-link/upstream-token`) ; la copie locale `chain/upstream-token` est supprimée après le dépôt. **Pas de `secrets:` Compose** : hors Swarm il monte le fichier de l'hôte (uid/gid/mode ignorés, illisible par l'UID 10001 — échec CI « permission denied ») et serait résolu sur l'hôte distant. `down` supprime ce volume. `REPEATER_ROOT_ID` (non secret) est écrit dans `chain/child.env`. L'enfant n'a plus aucun secret de lien en variable d'environnement.
- **Scénario `link-rotation`** : `keys rotate-link`, attente de la confirmation de `dmz1` (`keys link-status`), nouveau jeton signé par la nouvelle clé et remplacement du conteneur de l'enfant, `keys retire-link-previous` (sans `--force`), reconnexion de l'enfant puis `smoke`. **Scénario `link-revoke`** : `tokens revoke <id>` du jeton de lien, `dmz1` déconnecté (fermeture 4010, refus permanent) et **non reconnecté** pendant 40 s, puis remise en état avec un nouveau jeton et `smoke`.
- **Montée v3.0.3 → v3.0.4** : plan de répétition dans `REHEARSAL_v3.0.4.md`.

### CLI Docker statique épinglé

Pour un poste sans Docker (WSL sans intégration Docker Desktop, runner), le CLI statique officiel est épinglé :

| Élément | Valeur |
|---|---|
| Version | `docker-29.8.2.tgz` |
| URL | `https://download.docker.com/linux/static/stable/x86_64/docker-29.8.2.tgz` |
| sha256 | `995d1ef289677f74fd58d8d2c35727b6a4ee389c69db8638a3e42d0487aa5b0f` |

Origine du sha256 : calculé le 2026-10-07 sur le fichier téléchargé en HTTPS depuis `download.docker.com` ; Docker ne publie pas de fichier de sommes pour ces archives (le `.sha256` voisin répond 404), l'empreinte n'est donc pas recoupée par une source indépendante. Vérification avant extraction, **dans un répertoire dédié, vide** (jamais dans le dépôt) :

```bash
d=$(mktemp -d) && cd "$d" && curl -fsSLO https://download.docker.com/linux/static/stable/x86_64/docker-29.8.2.tgz \
  && echo "995d1ef289677f74fd58d8d2c35727b6a4ee389c69db8638a3e42d0487aa5b0f  docker-29.8.2.tgz" | sha256sum -c - \
  && tar -xzf docker-29.8.2.tgz docker/docker && ./docker/docker --version
```

Le CLI statique n'inclut pas `docker compose` (plugin séparé) : les scripts de qualif l'exigent. Rien n'est installé par les agents hors scratchpad ; l'installation sur le poste reste une décision de l'utilisateur.

## Prérequis

- Docker remote access actif sur `192.168.1.218:2375`
- Un répertoire de certificats TLS (`tls.crt`, `tls.key`) : `QUALIF_TLS_DIR`
- Une image candidate publiée par la CI (voir « Promotion » plus bas) : `SECAGENT_IMAGE`
- `qualif.env` créé depuis `qualif.env.example` (`JWT_SECRET_KEY`, `ADMIN_TOKEN`, `RSA_MASTER_KEY` : secrets de qualification, jamais ceux de PROD ; ignoré par git)

## Lancer

```bash
export SECAGENT_IMAGE=ghcr.io/ccoupel/secagent-server:sha-<commit>@sha256:<digest>
export QUALIF_TLS_DIR=/chemin/vers/certs
cp qualif.env.example qualif.env     # puis renseigner les secrets

# L'état n'est jamais créé implicitement : `secagent-server state init` une fois (voir DOC/project/DEPLOYMENT.md, étape 1)
DOCKER_HOST=tcp://192.168.1.218:2375 docker compose -p secagent-qualif -f docker-compose.server.yml up -d
DOCKER_HOST=tcp://192.168.1.218:2375 docker compose -p secagent-qualif -f docker-compose.server.yml ps
```

Le healthcheck est `secagent-server status --local` (aucun port). Les jetons d'enrôlement et les minions se gèrent comme dans `DOC/project/DEPLOYMENT.md` (étape 3) : `tokens create --role enrollment …`, puis `RELAY_ENROLLMENT_TOKEN` côté minion.

## Test de basculement

`failover-test.sh` (voir son en-tête) vérifie sur ces Compose le comportement actif/passif : `run stop` (arrêt propre du maître, reprise rapide), `run kill` (reprise après péremption du verrou, plusieurs minutes), `run freeze` (SIGSTOP), `teardown`.

## Ports (service a ; le service b est décalé de +1000 sur l'hôte)

| Port | Usage |
|------|-------|
| 7770 | API REST + WebSocket (TLS natif) |
| 7771 | Admin, publié sur `127.0.0.1` de l'hôte, `ADMIN_TLS=true` |
| 7772 | WebSocket dédié (TLS natif) |

## Promotion QUALIF des images serveur et minion (sans rebuild)

Un push ne fait que des tests : **aucune image n'est publiée par `ci.yml`**. La publication sur GHCR est réservée
(1) à la promotion QUALIF, lancée **manuellement** : GitHub → Actions → *Candidate images (QUALIF promotion)* →
*Run workflow* (`ref` = branche ou commit, `publish` = `true`) ; (2) au tag `vX.Y.Z` (`release.yml`, PROD).
Le résumé du run donne `ghcr.io/ccoupel/<image>:sha-<commit>@sha256:<digest>` : c'est la valeur de `SECAGENT_IMAGE`
de `docker-compose.server.yml`.

## Note de confiance : `ansible_secagent_server`

Le plugin de connexion lit l'adresse du serveur (`ansible_secagent_server`) et le fichier de jeton dans l'environnement **et** dans les variables d'hôte de l'inventaire ; une variable d'hôte **prime** sur l'environnement. L'inventaire est donc un élément **de confiance** : ne jamais utiliser un inventaire non maîtrisé avec un jeton plugin valide (il pourrait rediriger le jeton vers un autre serveur).
