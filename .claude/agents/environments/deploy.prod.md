# Deploy PROD — adaptations projet Ansible-SecAgent

> Compagnon de `deploy.prod.template.md` (mécanisme `docker-compose`) — à lire après le template.
> Ne contient que le spécifique projet. Le CODE fait foi : `DEPLOYMENT/prod/` et `DEPLOYMENT/prod/README.md`.

Installation de l'artefact déjà publié par PUBLISH PROD (tag `vX.Y.Z`, images buildées par la CI : `release.yml`) via
Docker Compose. Pas de Kubernetes/Helm, pas de Swarm, pas de NATS, pas de Caddy, pas de SQLite.

## Cible de déploiement
- Hôtes : N hôtes de prod (actif/passif), le MÊME Compose et le MÊME stockage partagé (`STATE_HOST_DIR` → `STATE_DIR`) sur chacun. Si un hôte de prod héberge aussi la QUALIF, vérifier avant `up` l'absence de collision de ports publiés (`docker ps --format '{{.Names}} {{.Ports}}'`) et alerter le teamleader sans arrêter la QUALIF.
- Méthode : Docker distant, hôte de prod = 192.168.1.218 (le même que la QUALIF, `DOCKER_HOST=tcp://192.168.1.218:2375`) ; d'autres hôtes actif/passif sont fournis par le teamleader / l'utilisateur. Projet compose `secagent-prod-*` uniquement, vérifier les collisions de ports avec `secagent-qualif-*` avant `up`, ne jamais arrêter la QUALIF. MooseFS (projet `chunks`, `/opt/MFS`) tourne aussi sur cet hôte : **ne JAMAIS y toucher**.
- Fichier Compose : `DEPLOYMENT/prod/docker-compose.server.yml` (service `secagent-server`) ; relay enfant : ajouter `-f DEPLOYMENT/prod/docker-compose.child.yml` (`REPEATER_*` obligatoires).
- **Ports d'hôte (D-P1, v3.0.5)** : `API_PUBLISH_PORT` / `WS_PUBLISH_PORT` / `ADMIN_PUBLISH_PORT` (défauts 7770/7772/7771, ports du conteneur inchangés). **Sur 192.168.1.218 (hôte partagé avec la QUALIF, qui tient 7770-7772, 8770-8772, 9771) : 17770 / 17772 / 17771** dans `DEPLOYMENT/prod/.env` (modèle `.env.example`), admin toujours sur `ADMIN_PUBLISH_ADDR=127.0.0.1`. Les clients PROD visent ces ports : minions `RELAY_SERVER_URL=https://192.168.1.218:17770` et `RELAY_WS_URL=wss://192.168.1.218:17772/ws/agent`, plugin Ansible sur `:17770`, relays enfants `REPEATER_UPSTREAM_URL=wss://192.168.1.218:17772`, admin `https://127.0.0.1:17771` sur l'hôte. Avant `up` : `docker ps --format '{{.Names}} {{.Ports}}'` ne montre aucun de ces ports ; contrôle du rendu : `docker compose config --format json | python3 tools/check_compose.py --require-memory-limit --require-digest --require-secret-files -` (refuse aussi deux publications du même port d'hôte).
- Projet compose dédié : `docker compose -p secagent-prod-<relay_id> ...` — jamais un projet de QUALIF.
- Variables non secrètes : `.env` à côté du Compose (copie publique : `PRIVATE/PROD/.env` ; modèle `.env.example` : `SECAGENT_VERSION`, `STATE_HOST_DIR`, `TLS_CERT_DIR`, `ADMIN_PUBLISH_ADDR`, `SECAGENT_MEM_LIMIT`, `GOMEMLIMIT`).
- Secrets (v3.0.4, #196) : FICHIERS dans `./secrets/` à côté du Compose sur l'hôte (référence des secrets et de la PKI PROD sur le poste : **`PRIVATE/PROD/`** (décision utilisateur du 2026-11-09 ; gitignoré, jamais commité ; `pki/` : `ca.key`, `ca.crt`, `tls.key`, `tls.crt` ; `secrets/` : fichiers ci-dessous ; fichiers **0600**, dossiers **0700**, propriétaire = utilisateur du poste ; `ca.key` ne sort **jamais** de `PRIVATE/PROD/pki/` ; sauvegarde chiffrée hors poste et hors partage par l'utilisateur ; risque résiduel accepté : le dépôt est sur MooseFS, lisible en root depuis tout client du partage). L'ancienne référence `~/secagent-private/prod/` (ext4 WSL) est abandonnée. Avant tout dépôt : `stat -c '%a %U %n'` sur `PRIVATE/PROD/{pki,secrets}` et leurs fichiers (0700 / 0600, utilisateur du poste), sinon `BLOQUE` ; ne jamais afficher ni copier le contenu ailleurs que vers l'hôte. `PRIVATE/` ne va jamais sur l'hôte ni dans l'archive) (`jwt_secret_key`, `admin_token`, `rsa_master_key`, + `repeater_upstream_token` pour un enfant ; mode d'emploi `prod.env.example`, hors dépôt, montés en `secrets:` et lus par `*_FILE` ; Compose hors Swarm ignore uid/gid/mode : les fichiers doivent appartenir à l'UID 10001 en mode 0400, à vérifier par `DEPLOYMENT/prod/preflight-secrets.sh` AVANT chaque `up`) : `JWT_SECRET_KEY`, `ADMIN_TOKEN`, `RSA_MASTER_KEY` IDENTIQUES sur tous les nœuds d'un relay, propres à PROD, jamais les valeurs de qualification. `RSA_MASTER_KEY` se sauvegarde HORS hôte et hors du partage.
- `.claude/agents/environments/prod.env` (jamais commité, modèle `prod.env.example` de ce dossier) ne porte que les accès registre/SSH de l'agent.

## Artefact
- Images `linux/amd64`, `ghcr.io/ccoupel/secagent-server:vX.Y.Z@sha256:<digest>`. Paquets GHCR **publics** (D-P4) : pull anonyme, sans `docker login`. **Attestation OBLIGATOIRE avant `pull`** : `gh attestation verify oci://ghcr.io/ccoupel/secagent-server@sha256:<digest> --repo CCoupel/Ansible-SecAgent --signer-workflow CCoupel/Ansible-SecAgent/.github/workflows/release.yml` (`gh` ≥ 2.49, voir `deploy.qualif.md`) ; code ≠ 0 = `BLOQUE`, jamais de pull. Pull **par digest** uniquement (archive de release : `image:` déjà réécrite en `tag@sha256`). L'archive de release `secagent-compose-<version>.tar.gz` contient les Compose avec `image:` réécrite en `tag@sha256` (jamais `latest`, jamais `build:`) ; vérifier `SHA256SUMS` avant usage.
- Sans archive : `SECAGENT_VERSION` dans `.env` fixe le tag.

## Références
- `DEPLOYMENT/prod/README.md` (stockage partagé, vérification, sauvegarde/restauration), `DEPLOYMENT/README.md`
- SERVER_SPEC.md : DOC/server/SERVER_SPEC.md §2 — 7770 (API), 7771 (admin), 7772 (WS) ; ARCHITECTURE.md §19 ; HLD.md §4

## Spécificités PROD
- 7771 n'est publié que sur `ADMIN_PUBLISH_ADDR` (boucle locale par défaut, jamais 0.0.0.0) ; `ADMIN_TLS=true` ; `TLS_DISABLE` et `RELAY_INSECURE_TLS` jamais définis.
- `tls.key` sur l'hôte : `10001:10001` mode `0600` (0640 déclenche `[SECURITY WARNING]`, constaté au déploiement v3.0.5) ; à reposer à chaque dépôt/rotation de la feuille, puis redémarrer et vérifier les logs.
- Administration PROD (CLI `tokens`, `status`…) : `RELAY_API_URL=https://srv8.local:17771` (ou l'IP du SAN), conteneur éphémère de la même image (digest) en `--network host --add-host srv8.local:127.0.0.1` avec `ADMIN_TOKEN_FILE` ; **jamais `localhost`** (hors SAN : échec TLS), jamais `RELAY_INSECURE_TLS`.
- Stockage partagé non testé avec `DEPLOYMENT/prod/tools/test_shared_storage.py` = non supporté.
- Ne jamais lancer `docker compose down -v` ni supprimer un volume ou le stockage d'état sans ordre explicite.

## Processus (sur demande du teamleader)
1. Vérifier que `DEPLOYMENT/prod/docker-compose.server.yml` existe, que `.env` et le répertoire `./secrets/` (déposés depuis `PRIVATE/PROD/` par flux vers l'hôte) sont en place sur l'hôte et que `./preflight-secrets.sh` (enfant : `--child`) retourne 0 (enfant : aussi `REPEATER_ROOT_ID` et `ROOT_LINK_KEY_FILE`) et que l'image/tag publié est présent. Sinon `BLOQUE` au teamleader (le scaffold est du ressort de l'agent `infra`).
2. Première installation uniquement, depuis UN seul hôte : `docker compose -p secagent-prod-<relay_id> -f docker-compose.server.yml run --rm --no-deps secagent-server state init`.
3. Sur chaque hôte : attestation vérifiée (voir « Artefact »), puis `docker compose -p secagent-prod-<relay_id> -f docker-compose.server.yml pull` (image en `tag@sha256`) puis `up -d`.
4. Vérifier `ps` et `logs --tail=50` : une instance maître (ports ouverts), les autres secondaires (aucun port) ; `exec secagent-server /app/secagent-server status --local` code 0 sur chaque hôte (healthy).
5. Smoke : `/health` du maître (`https://<hôte>:<API_PUBLISH_PORT>/health`, `:17770` sur 192.168.1.218 → `"role":"master"`, TLS natif, sans proxy) et `/api/inventory` avec un jeton plugin (le jeton admin est refusé).
6. Rapport : services + statut (maître / secondaires), URL accessible oui/non, logs d'erreur, `RÉSULTAT : OK / ÉCHEC`.

## Outils
Poste (depuis 2026-11-09) : Linux natif, dépôt sur le partage MooseFS ; **aucun client Docker installé**, pas de démon local (n'en installer ni n'en démarrer aucun) : CLI Linux + plugin Compose extraits des paquets signés dans le scratchpad (`DEPLOYMENT/qualif/README.md`, « CLI Docker : paquet signé »), `DOCKER_HOST=tcp://192.168.1.218:2375` exporté (honoré par le client Linux) ; avant tout `up`, `docker info --format '{{.Name}}'` doit renvoyer l'hôte attendu. `gh` du poste en 2.46 : `gh` ≥ 2.49 du scratchpad pour l'attestation (`deploy.qualif.md`). Pas de `ssh` sur le poste. Les modes POSIX sont conservés sur le dépôt : plus de copie `git archive` nécessaire.

## Règles absolues
- Ne jamais modifier le code source ni rebuilder : déployer l'artefact publié (principe BORE).
- En cas d'échec, fournir les logs complets et proposer le rollback au tag précédent sans l'exécuter sans accord. Un retour arrière de version ne dispense pas de la restauration d'état (`state verify` / `state restore`, voir le README prod).

## Plateforme Podman rootless (LOT-4, v3.0.6) — remplace .218 après T51

> L'hôte `192.168.1.218` (ci-dessus) reste la PROD jusqu'à la recréation sur la nouvelle plateforme (T51, GATE 4).
> Nouvelle cible : **srv1 `192.168.1.211` (racine a)** et **srv2 `192.168.1.212` (racine b)**, même Compose
> (`docker-compose.server.yml` + `DEPLOYMENT/podman/docker-compose.podman.yml`, `userns_mode: keep-id:uid=10001,gid=10001`),
> projet `secagent-prod`, état partagé `PRIVATE/PROD/state/root` (seul emplacement de l'état PROD, jamais copié),
> secrets `PRIVATE/PROD/secrets`, TLS `PRIVATE/PROD/pki`. **T43 (install-node.sh) non fait sur srv1/srv2** : attendre
> l'ordre du teamleader.

### Interdits (nœuds colocalisés avec RKE2 et des chunkservers MooseFS)
- Jamais `docker`, `kubectl`, `k3s`/`rke2`, `crictl`, ni rien sous `/opt/MFS` ; jamais arrêter/redémarrer un service système ni un conteneur qui n'est pas `secagent-*` ; aucune installation de paquet (Podman est installé par l'utilisateur). Le conteneur `mfschunk-S` arrêté sur srv3/srv4 l'était avant le LOT-4 : hors périmètre, ne pas y toucher.
- Ne jamais lire `PRIVATE/<ENV>/{state,secrets,pki,pki-ca}/` (`stat -c '%a %u'` seulement) ; jamais `down -v` sous Podman (état et secrets sont des volumes liés au partage) ; jamais copier un fichier sur un nœud : tout passe par `PRIVATE/<ENV>/<srvX>/cyril/secagent/` sur le partage.

### Accès
- `ssh -i PRIVATE/<ENV>/poste-cyril/id_ed25519 -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=PRIVATE/<ENV>/poste-cyril/known_hosts cyril@<ip>` (empreintes ed25519 confirmées par l'utilisateur ; `StrictHostKeyChecking=no` interdit). `CONTAINER_HOST=ssh://cyril@<ip>/run/user/1000/podman/podman.sock`, `CONTAINER_SSHKEY=PRIVATE/<ENV>/poste-cyril/id_ed25519`. Pas de client Podman sur le poste : les commandes `podman` / `podman-compose` s'exécutent **sur le nœud** par SSH.
- `PRIVATE/<ENV>` est vu par le nœud au **même chemin** que le poste (`/share/MFS/ROOT/CLAUDE_PROJETS/PROJETS/PRO/Ansible_SecAgent/PRIVATE/<ENV>`, autofs root existant) ; cloisonnement QUALIF/PROD non garanti par l'autofs (risque accepté).
- Secrets : propriétaire **`SECRET_OWNER_UID=1000`** (cyril ; uid 10001 du conteneur par `keep-id:uid=10001,gid=10001`), mode 0400 : `SECRET_OWNER_UID=1000 DEPLOYMENT/prod/preflight-secrets.sh` (sur le poste, même partage). `ca.key` dans `PRIVATE/<ENV>/pki-ca/` (jamais montée) ; `pki/` ne contient que `ca.crt`, `tls.crt`, `tls.key`.

### Déploiement d'un nœud (ordre imposé)
1. Nœud préparé une fois par `infra` (`install-node.sh`, `prepare-node-files.sh`).
2. **Dépôt** (poste) : `SECAGENT_IMAGE=… [SECAGENT_MINION_IMAGE=… SECAGENT_VERSION=…] DEPLOYMENT/podman/stage-node-files.sh <env> <srvX>` (`NODE_SOURCE_DIR=<archive de release extraite>` en PROD).
3. **Intégrité + épinglage, AVANT tout `daemon-reload` / démarrage** : `DEPLOYMENT/podman/verify-node-files.sh --pin <env> <srvX>` avec les mêmes variables : attendu recalculé depuis le dépôt (ou l'archive), réel lu sur le nœud (`bin/check-private.sh`, `release/`, `systemd/`, liste exacte) ; si conforme, écrit sur le nœud **hors partage** (home de `cyril`, 0600) la **copie** de l'unité `~/.config/systemd/user/secagent-<env>-<srvX>.service` et le manifeste épinglé `~/.config/secagent/<env>-<srvX>.sha256`. Code ≠ 0 ⇒ **BLOQUE**, ne rien recharger. À rejouer avant **tout** (re)démarrage décidé par `deployer` (nouvelle release, `restart` manuel) ; les démarrages automatiques (boot, `Restart=`) sont couverts par l'unité elle-même (étape 4).
4. Sur le nœud, en `cyril`, sans sudo : `systemctl --user enable --now podman.socket` (une fois) ; **jamais** `systemctl --user link` (unité lue depuis le partage : l'ancien lien, s'il existe, est remplacé par la copie de l'étape 3) ; `systemctl --user daemon-reload` ; `systemctl --user start secagent-<env>-<srvX>.service` ; `systemctl --user enable` pour le démarrage au boot (linger actif). À **chaque** démarrage, `ExecStartPre` vérifie 1) les empreintes du partage contre le manifeste épinglé (`sha256sum -c`), 2) la garde `check-private.sh <env> <srvX> <manifeste>` : partage accessible/FUSE/0700, `pki/` limité à `ca.crt`/`tls.crt`/`tls.key`, liste exacte des fichiers (un `release/.env` ajouté = refus). Une release déposée (`stage`) sans `--pin` ne démarre pas.
5. Contrôles : `podman ps` (sur le nœud), `podman inspect -f '{{.HostConfig.Memory}}' <conteneur>` ≠ 0 (limite mémoire effective), un seul maître, `/health`.

### Démarrage refusé après une indisponibilité du partage
Au boot, si l'autofs n'est pas joignable, l'unité (copie locale) est chargée mais `ExecStartPre` échoue (fichiers introuvables) : aucun conteneur ne démarre (fail-closed) ; `Restart=on-failure` réessaie 3 fois en 600 s. Partage revenu plus tard : `ssh … cyril@<ip> 'systemctl --user reset-failed secagent-<env>-<srvX>.service; systemctl --user start secagent-<env>-<srvX>.service'` (aucune ré-vérification depuis le poste nécessaire : le manifeste épinglé fait foi), puis `systemctl --user status` ; un échec d'empreinte (`sha256sum`) ou de liste (`check-private.sh`) ⇒ **BLOQUE** (partage modifié depuis la vérification), jamais de `--pin` pour « débloquer » sans comprendre l'écart ; un conteneur démarré avant un remontage de l'autofs garde l'ancien montage : `systemctl --user restart secagent-<env>-<srvX>.service`.
