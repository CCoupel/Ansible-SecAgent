<!--
SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Plateforme Podman rootless (LOT-4, v3.0.6, #267)

Déploiement de secagent sur des nœuds **Podman rootless** (compte `cyril`, uid 1000), sans démon Docker et sans
connexion entrante autre que SSH. Remplace à terme l'hôte Docker `192.168.1.218` (API `tcp:2375`).

| Env | Nœud | IP | Rôle |
|-----|------|----|------|
| QUALIF | srv3 | 192.168.1.213 | racine `secagent-server-a` |
| QUALIF | srv4 | 192.168.1.214 | racine `secagent-server-b`, enfant `secagent-child` (dmz1), `minion-root`, `minion-child` |
| PROD | srv1 | 192.168.1.211 | racine a (`secagent-server`) |
| PROD | srv2 | 192.168.1.212 | racine b (`secagent-server`) |

Les nœuds portent **aussi** le cluster RKE2 et des chunkservers MooseFS : rien n'est jamais fait côté Kubernetes,
MooseFS ou Docker (interdits codés dans `install-node.sh`) ; les limites mémoire de tous les conteneurs sont
obligatoires (contrôle CI `--require-memory-limit`, délégation cgroup `memory` vérifiée sur le nœud).

## Principes

- **Rien sur les nœuds** hormis le linger de `cyril` et `~/.config/systemd/user` (liens d'unités). Tous les fichiers de
  déploiement d'un nœud vivent sur le partage, dans `PRIVATE/<ENV>/<srvX>/cyril/secagent/` :
  `bin/check-private.sh` (garde), `release/` (Compose + `release.env` + `SHA256SUMS`), `systemd/` (unité + `SHA256SUMS`),
  `run/` (fichiers volatils de la qualif : jetons, `env_file`).
- **Partage** : les nœuds voient `PRIVATE/` par l'autofs root existant `/share/MFS/ROOT/...`, au **même chemin** que le
  poste. Pas de montage utilisateur, aucun paquet installé. Le cloisonnement QUALIF/PROD n'est pas garanti par l'autofs
  (risque accepté) : seuls les modes 0700 et l'uid 1000 commun protègent.
- **Mapping uid** : `userns_mode: keep-id:uid=10001,gid=10001` sur les services serveur (uid 10001 du conteneur = uid
  1000 de l'hôte = propriétaire des fichiers du partage). Secrets : propriétaire **1000**, 0400 (`SECRET_OWNER_UID=1000`).
- **TLS** : `pki/` ne contient que `ca.crt`, `tls.crt`, `tls.key` (monté sur `/certs`) ; `ca.key` est dans `pki-ca/`,
  jamais monté (`check_no_binds.py` et `check-private.sh` le refusent).
  Modes exigés par la garde : `tls.key` 0600 au plus ; QUALIF : `pki/` en **0711** (traversable, non listable) et
  `ca.crt`/`tls.crt` en 0644, car les minions colocalisés gardent le mapping rootless par défaut (uid `relay` ≠ propriétaire)
  et doivent lire `ca.crt` sans jamais pouvoir lire `tls.key` ; seuls les serveurs sont en keep-id (rendu contrôlé en CI :
  `scripts/ci/check_podman_certs.py`). PROD : `pki/` en 0700 (aucun minion sur les nœuds).
- **Intégrité** : `verify-node-files.sh --pin` recalcule le contenu attendu **depuis le dépôt** (garde `bin/`,
  `release/`, `systemd/`), le compare à ce que lit le nœud, puis écrit **hors partage** (home de `cyril`, 0600) la
  **copie** de l'unité (`~/.config/systemd/user/`, jamais un lien : systemd relirait une unité modifiable au boot) et le
  manifeste épinglé `~/.config/secagent/<env>-<srvX>.sha256`. À lancer avant tout `daemon-reload` / (re)démarrage décidé.
- **Fail-closed, à chaque démarrage** (boot, `Restart=`, relance) : `ExecStartPre` vérifie les empreintes du partage
  contre le manifeste épinglé, puis exécute la garde (ainsi vérifiée) `check-private.sh <env> <srvX> <manifeste>`, qui
  refuse un partage inaccessible, hors FUSE, mal possédé, incomplet, un `pki/` contenant autre chose que
  `ca.crt`/`tls.crt`/`tls.key`, ou un fichier en trop dans `bin/`, `release/`, `systemd/` (ex. `release/.env`).

## Fichiers

| Fichier | Où | Rôle |
|---------|----|------|
| `install-node.sh <env> <srvX>` | nœud (root, une fois) | contrôles (versions, subuid, disque, cgroup `memory`), linger, `~/.config/systemd/user`, exécution de la garde |
| `prepare-node-files.sh <env> <srvX>` | poste | arborescence `PRIVATE/<ENV>/<srvX>/cyril/secagent/` (0700) + copie de la garde |
| `check-private.sh <env> <srvX> [<manifeste>]` | nœud (cyril) | garde fail-closed (copiée dans `bin/`) ; avec le manifeste épinglé : liste exacte des fichiers |
| `stage-node-files.sh <env> <srvX>` | poste | dépôt de `bin/`, `release/` et `systemd/` + `SHA256SUMS` |
| `verify-node-files.sh [--pin] <env> <srvX>` | poste → nœud (SSH) | vérification d'intégrité contre le dépôt ; `--pin` : copie de l'unité + manifeste épinglé hors partage |
| `node-lib.sh` | — | topologie, `release.env`, génération de l'unité (sourcé) |
| `docker-compose.podman.yml` | — | surcharge PROD (`secagent-server`) |
| `docker-compose.podman.qualif.yml` | — | surcharge de la chaîne QUALIF répartie (état/secrets liés au partage, adresses inter-nœuds) |

## Séquence

```bash
# 1. une fois par nœud (root, depuis le poste)
DEPLOYMENT/podman/prepare-node-files.sh qualif srv3
ssh -i PRIVATE/QUALIF/poste-cyril/id_ed25519 -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes \
    -o UserKnownHostsFile=PRIVATE/QUALIF/poste-cyril/known_hosts cyril@192.168.1.213 \
    sudo -n bash -s -- qualif srv3 < DEPLOYMENT/podman/install-node.sh

# 2. à chaque release (poste) : dépôt puis vérification
SECAGENT_IMAGE=ghcr.io/ccoupel/secagent-server:sha-<c>@sha256:<d> SECAGENT_MINION_IMAGE=… \
  DEPLOYMENT/podman/stage-node-files.sh qualif srv3
SECAGENT_IMAGE=… SECAGENT_MINION_IMAGE=… DEPLOYMENT/podman/verify-node-files.sh --pin qualif srv3   # code 0 exigé

# 3. sur le nœud, en cyril (sans sudo) ; jamais `systemctl --user link` (unité copiée par --pin)
systemctl --user enable --now podman.socket
systemctl --user daemon-reload && systemctl --user enable --now secagent-qualif-srv3.service
```

QUALIF : la recette (`chain-test.sh bootstrap|smoke|failover|…`) se lance avec `CONTAINER_CLI=podman` (voir
`DEPLOYMENT/qualif/README.md`) ; `push-tls` et `backup-restore` ne s'appliquent pas sous Podman.

**Partage indisponible au démarrage** : l'unité est chargée mais `ExecStartPre` échoue (aucun conteneur) ;
`Restart=on-failure` réessaie 3 fois en 600 s. Après retour : `systemctl --user reset-failed … ; systemctl --user start
secagent-<env>-<srvX>.service`. Un
conteneur démarré avant un remontage de l'autofs garde l'ancien montage : `systemctl --user restart …`.

## Réseau

Chaque nœud a son propre réseau Compose. Depuis srv4, la racine a se joint par l'IP de srv3 (`QUALIF_NODE_A_ADDR`,
ports d'hôte 7770/7772) et b par son nom de service ; l'IP de srv4 elle-même n'est pas utilisée depuis un conteneur de
srv4 (pasta recopie l'adresse de l'hôte dans le conteneur). La PKI QUALIF doit contenir `IP:192.168.1.213` et
`IP:192.168.1.214` (T47). Poste de contrôle Ansible : `https://192.168.1.213:7770,https://192.168.1.214:8770`.
