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
