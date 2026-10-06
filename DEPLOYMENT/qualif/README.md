# Déploiement Qualif — relay actif/passif (192.168.1.218)

Topologie qualif v3.0.3 : **un relay en actif/passif**, deux instances (`secagent-server-a`, `secagent-server-b`) sur **un même volume d'état** `secagent_state`, définies dans `docker-compose.server.yml`. Exactement une instance est maître (ports 7770/7771/7772 ouverts) ; l'autre est secondaire et **n'ouvre aucun port** tant qu'elle n'a pas pris le verrou. Les ports d'hôte du service b sont décalés (8770/8771/8772) parce que les deux conteneurs tournent sur la même machine.

> **Obsolète** : la topologie « relay-proxy + relay-dmz1 + relay-dmz2 » (ports 7780-7784, `.env.proxy`, `/api/agents` agrégés) n'existe plus. Les Compose `docker-compose.minion.yml`, `docker-compose.proxy.yml` et `docker-compose.ansible.yml` portent un bandeau **OBSOLETE v3.0.3** : non fonctionnels avec le serveur actuel (état sur fichier, TLS natif), conservés comme outillage de référence, **à ne pas utiliser** (la chaîne de relais sera reconstruite par une issue dédiée). `scripts/bootstrap-qualif.sh` appartient à cette ancienne topologie.

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
