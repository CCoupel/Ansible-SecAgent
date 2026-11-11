# Déploiement Qualif — relay actif/passif (192.168.1.218)

Topologie qualif v3.0.3 : **un relay en actif/passif**, deux instances (`secagent-server-a`, `secagent-server-b`) sur **un même volume d'état** `secagent_state`, définies dans `docker-compose.server.yml`. Exactement une instance est maître (ports 7770/7771/7772 ouverts) ; l'autre est secondaire et **n'ouvre aucun port** tant qu'elle n'a pas pris le verrou. Les ports d'hôte du service b sont décalés (8770/8771/8772) parce que les deux conteneurs tournent sur la même machine.

> La topologie « relay-proxy + relay-dmz1 + relay-dmz2 » (ports 7780-7784, `.env.proxy`, `/api/agents` agrégés), ses Compose (`proxy`, `minion`, `ansible`), les smoke-tests associés, `deploy.sh`/`deploy.bat` et `bootstrap-qualif.sh` ont été **supprimés** (#188) : ils sont remplacés par la chaîne ci-dessous.

## Topologie en chaîne (#188) : `docker-compose.chain.yml`

Racine actif/passif (`secagent-server-a/-b`, incluse depuis `docker-compose.server.yml`), **un relay enfant pull** (`secagent-child`, `REPEATER_ID=dmz1`, `REPEATER_UPSTREAM_URL` = liste des 2 adresses de la racine, `REPEATER_CA_FILE`), **deux minions** (`minion-root`, `minion-child`) avec listes d'adresses et `RELAY_CA_BUNDLE`. TLS de bout en bout avec une CA privée de test (`pki/gen.sh`), jamais `RELAY_INSECURE_TLS`. Extensions X.509 explicites (RFC 5280, indépendantes de l'`openssl.cnf` du système) : CA `basicConstraints=critical,CA:TRUE,pathlen:0`, `keyUsage=critical,keyCertSign,cRLSign`, SKI/AKI ; feuille `basicConstraints=critical,CA:FALSE`, `keyUsage=critical,digitalSignature,keyEncipherment`, `extendedKeyUsage=serverAuth`, AKI = SKI de la CA, SAN inchangés. Python ≥ 3.13 (plugin Ansible du poste) vérifie en `VERIFY_X509_STRICT` et refuse une CA sans `keyUsage` (« CA cert does not include key usage extension ») : une PKI générée avant v3.0.6 est à **régénérer** (`pki/gen.sh`). Autotest : `scripts/ci/qualif_pki_selftest.sh` (poignée de main stricte contre `openssl s_server`). Le certificat jetable de `failover-test.sh setup-ci` (`gen_ci_tls`) suit les mêmes règles (feuille auto-signée). L'enfant push (optionnel) n'est pas déployé ; l'enfant pull est une seule instance (l'actif/passif testé est celui de la racine).
Le poste de contrôle Ansible (plugin `SECAGENT-PYTHON`, `secagent-inventory`, `ansible-core`) est le poste qui lance les scripts : il joint la racine par `127.0.0.1:7770` et `:8770` (jeton plugin en **fichier 0600**, jamais en variable d'environnement partagée).

```bash
export SECAGENT_IMAGE=ghcr.io/ccoupel/secagent-server:sha-<commit>@sha256:<digest>
export SECAGENT_MINION_IMAGE=ghcr.io/ccoupel/secagent-minion:sha-<commit>@sha256:<digest>
export INVENTORY_BIN=/chemin/secagent-inventory     # binaire du poste de controle
bash chain-test.sh ci-prepare   # CI/essai : PKI de test (`PRIVATE/QUALIF/pki/`) + secrets jetables (`PRIVATE/QUALIF/secrets/`, 3 fichiers 0400) ; en qualif : vos propres secrets
bash chain-test.sh bootstrap    # state init, relays add, jetons d'enrolement et plugin (`CHAIN_DIR`, hors `PRIVATE/` : `${TMPDIR:-/tmp}/secagent-qualif-chain-<uid>`, 0700, fichiers 0600), demarrage
bash chain-test.sh smoke        # relais, minions, inventaire hierarchique, ansible -m ping
bash chain-test.sh failover     # arret propre du maitre de la racine puis smoke ; kill : failover-test.sh run kill
bash chain-test.sh down
```
Les données privées de la qualif (`secrets/`, `pki/`, `ci-tls/`) vivent sous `PRIVATE/QUALIF/` (dossier gitignoré ; racine = `SECAGENT_PRIVATE_DIR`, défaut `<dépôt>/PRIVATE`), jamais à côté des scripts : voir « Données privées du poste » dans `DEPLOYMENT/README.md`. Les scripts refusent de générer des secrets si cette racine n'existe pas. Chemins par défaut : `SECRETS_DIR`, `QUALIF_TLS_DIR` (PKI) ; une valeur explicite prime. **`CHAIN_DIR` fait exception** : les jetons de chaîne sont volatils et vont par défaut dans `${TMPDIR:-/tmp}/secagent-qualif-chain-<uid>` (système de fichiers local du poste, hors partage réseau : le plugin refuse un répertoire plus large que 0700). `chain-test.sh` refuse (fail-closed) un `CHAIN_DIR` non absolu, lien symbolique, non répertoire, appartenant à un autre uid ou plus large que 0700 ; il le crée en 0700. Les trois secrets du serveur (`jwt_secret_key`, `admin_token`, `rsa_master_key`) sont des **fichiers** déposés dans le volume `${PROJECT}_secrets` (propriétaire 10001, mode 0400) et lus via `JWT_SECRET_KEY_FILE`, `ADMIN_TOKEN_FILE`, `RSA_MASTER_KEY_FILE` : `docker inspect` n'en montre aucun (#197 item 6, v3.0.5 ; `qualif.env` et `qualif.env.example` sont supprimés). En CI, le job « Chaîne en conteneurs » rejoue ce scénario à chaque push.

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
bash chain-test.sh ci-prepare                     # PKI + secrets jetables sous PRIVATE/QUALIF/, en LOCAL (jamais ceux de prod) ; `bootstrap` les depose dans le volume de l'hote
bash chain-test.sh push-tls                       # copie tls.crt/tls.key/ca.crt dans le volume secagent-qualif_tls de l'hôte (tls.key 10001 0600)
bash chain-test.sh bootstrap && bash chain-test.sh smoke
```
`$CHAIN_DIR/*.env` (`CHAIN_DIR`, volatil sous `/tmp`, hors `qualif.env` supprimé) est lu côté client (`env_file`) ; `/certs` et `/run/secagent-secrets` sont des montages résolus sur l'hôte, d'où des **volumes** alimentés par un conteneur éphémère (`push-tls`, `push_secrets` appelé par `bootstrap`). La clé de test (0644) est jetable et ne quitte jamais le poste que par ce flux.

### Images sans registre : artefact de run CI + `docker load`

Aucun pull GHCR n'est nécessaire : chaque push construit les images du commit et les publie comme **artefact du run** (7 jours : `secagent-server-ci-<sha12>.tar.gz`, `secagent-minion-ci-<sha12>.tar.gz`, binaire `secagent-inventory` linux/amd64 pour le poste de contrôle, `images.env`, `SHA256SUMS`).

```bash
gh run download <id-du-run> -n secagent-images-<sha-complet> -D images
export DOCKER_HOST=tcp://192.168.1.218:2375
bash chain-test.sh load-images images           # sha256sum -c, puis docker load des 2 archives
set -a; . images/images.env; set +a              # SECAGENT_IMAGE, SECAGENT_MINION_IMAGE (tags locaux ci-<sha12>), SECAGENT_PULL_POLICY=never
export INVENTORY_BIN="$PWD/images/secagent-inventory"
```
`load-images` enregistre l'empreinte stable des images (sha256 des couches `RootFS.Layers`, `$CHAIN_DIR/image-ids`, non secrets ; l'ID `.Id` varie selon le magasin containerd) et `bootstrap`/`failover`/`backup-restore` **refusent** de démarrer si l'empreinte réelle d'une image du démon diffère (tag local préexistant) ou si `load-images` n'a pas été lancé.
**Exception à « sans registre »** : « sans registre » vaut pour les **images secagent**. Deux commandes (`chain-test.sh push-tls` et `backup-restore`) utilisent aussi `alpine:3.24@sha256:be265606…` (épinglée par digest, identique à celle du `GO/Dockerfile`), **tirée de Docker Hub** par l'hôte au premier usage ; sur un hôte sans accès au Hub, charger cette image au préalable (`docker pull` ailleurs puis `docker save | docker load`).
`SECAGENT_PULL_POLICY=never` empêche Compose de chercher ces tags locaux dans un registre. La production, elle, exige `tag@sha256` (archive de release, `check_compose.py --require-digest`).

**Procédure « qualification sans registre »** (le job `images-artifact` ne tourne que sur un **push**, après `docker-compose-checks`) :

1. Récupérer l'artefact du run du commit à qualifier : `gh run download <id> -n secagent-images-<sha-complet> -D images` (expire après 7 jours).
2. Pointer le client Docker vers l'hôte de qualif : `export DOCKER_HOST=tcp://192.168.1.218:2375` (équivalent de `docker -H tcp://192.168.1.218:2375` à chaque commande ; `docker compose` et les scripts utilisent `DOCKER_HOST`).
3. `bash chain-test.sh load-images images` : `sha256sum -c SHA256SUMS` puis `docker load` des deux archives, directement sur l'hôte distant. Charger ensuite `images/images.env` (tags locaux `secagent-*:ci-<sha12>`, `SECAGENT_PULL_POLICY=never`) et `INVENTORY_BIN` comme ci-dessus.
4. Déployer le projet `secagent-qualif` avec les étapes de la section « Hôte Docker distant » : `TLS_MODE=volume`, `SECAGENT_ENDPOINT_HOST`, `PKI_EXTRA_SAN`, `ci-prepare`, `push-tls`, `bootstrap`, `smoke`.

Les opérations destructives (`down`, `teardown`, `backup-restore`) sont refusées par `guard_project` sur un hôte distant pour tout projet autre que `secagent-qualif`.

**Un seul projet `secagent-qualif`** pour la chaîne ET les tests de basculement (mêmes noms de conteneurs `secagent-qualif-a/-b`) : lancer `chain-test.sh` et `failover-test.sh` **l'un après l'autre**, jamais en parallèle. `backup-restore` passe par des volumes nommés (`<projet>_backup`), donc fonctionne avec un démon distant ; `CONTROL_HOST` (alias de `SECAGENT_ENDPOINT_HOST`) désigne l'hôte joint par le poste de contrôle.

### Pièges du mode distant (incident E2) et du poste

- **Ne jamais lancer `failover-test.sh` isolément contre un démon distant** : sans les variables du mode volume (`COMPOSE_FILE`, `COMPOSE_OVERRIDES`, `SECAGENT_TLS_VOLUME`) que `chain-test.sh` exporte, Compose recréait les conteneurs avec un bind mount d'un chemin **du poste**, créant des répertoires vides sur l'hôte distant. Le script **refuse** désormais en mode distant (`DOCKER_HOST` non local ou `SECAGENT_ENDPOINT_HOST`/`CONTROL_HOST` non local) sans `TLS_MODE=volume`, reprend lui-même le mode volume sinon, et refuse tout bind mount dans le rendu. Point d'entrée : `chain-test.sh failover`.
- **Système de fichiers du dépôt** (poste Linux depuis 2026-11-09) : le dépôt est sur le partage réseau MooseFS, qui conserve les modes POSIX (`chmod 600`/`700` constatés) : les scripts se lancent directement depuis le checkout (`cd DEPLOYMENT/qualif`). Le plugin refuse toujours un fichier de jeton qui n'est pas 0600 : un autre emplacement (montage qui n'honore pas les modes, comme l'ancien `/mnt/c` NTFS du poste WSL) impose une copie `git archive HEAD | tar -x -C <répertoire local>` avec `SECAGENT_PRIVATE_DIR` absolu vers le checkout.

## Compléments de qualif v3.0.4 (#197) : hooks, CA négative, jeton plugin frais, CLI Docker épinglé

- **Hooks en réel** : `hooks.json` (même répertoire) est livré par un **volume nommé** `${PROJECT}_hooks` (`chain-test.sh push-hooks`, appelé par `bootstrap` ; surcharge `docker-compose.hooks.yml`, `RELAY_HOOKS_CONFIG=/etc/secagent-hooks/hooks.json`) sur `secagent-server-a/-b` et `secagent-child`. **Jamais `configs: file:` ni `secrets: file:`** : hors Swarm Compose les monte en bind mount du chemin du client, introuvable sur un démon distant (échec constaté sur 192.168.1.218 le 2026-10-08) ; `scripts/ci/check_no_binds.py` (rendu distant, en CI) refuse tout chemin du client. Il écrit une ligne par événement — `host.up` / `host.reconnect` / `host.down` (`<ts> UP|RECONNECT|DOWN <hôte>`), `relay.failover` (`<ts> FAILOVER <relay_id> <cause> instance=… previous=…`, `previous={{previous_instance_id}}` littéral quand la cause est `start`), `relay.up` / `relay.reconnect` (`<ts> RELAY_UP|RELAY_RECONNECT <relay_id> conn_seq=… mode=… hosts_routed=…`), `relay.down` (`<ts> RELAY_DOWN <relay_id> <reason> hosts_routed=…`) — dans `/var/log/secagent-events/events.log`, sur un **volume externe par instance** `${PROJECT}_events-a/-b/-child` (`chain-test.sh push-events`, appelé par `bootstrap`, 10001 0700 ; retiré par `down`) : le journal **survit à l'arrêt et à la recréation** du conteneur (preuves de l'ancien maître après une bascule) et n'est pas partagé entre a et b. Un hook par événement : seul le premier hook correspondant s'exécute. Les contrôles après une action comptent les lignes (une de plus), jamais la seule présence. `bash chain-test.sh hooks` (après `bootstrap`) vérifie au maître `relay.failover` (cause `start`), `relay.up` de `dmz1` et `host.up` de `minion-root`, à l'enfant `host.up` de `minion-child`. `bash chain-test.sh failover` (arrêt propre) vérifie au **nouveau maître** `relay.failover` cause `start` (#225), puis une nouvelle ligne `host.reconnect` de `minion-root` (et non `host.up`, #265) et `relay.reconnect` de `dmz1` (et non `relay.up`, #245) ; `bash chain-test.sh failover-kill` fait de même après un `kill` du maître (cause `takeover`, `previous=` = instance tuée ; reprise à la péremption du verrou, **5 min** sans battement, `MasterStale`, `lock/params.go`). `bash chain-test.sh relay-down` arrête l'enfant, attend `relay.down` de `dmz1` au maître (raison `peer_closed:<code>` ou `read_error`), le redémarre, attend `relay.up` (nouveau processus, `conn_seq` 1) puis `smoke`. `failover-test.sh run stop|kill` vérifie lui-même `relay.failover` puis `relay.converged` (≤ `CONVERGED_MAX_S`, défaut 45 s) quand la surcharge des hooks est active (`COMPOSE_OVERRIDES`, toujours le cas via `chain-test.sh`).
- **LOT-3.2 (v3.0.6, #244 #246 #247)** : `hooks.json` compte **10 hooks** — en plus, `host.rerouted` (`<ts> REROUTED <hôte> <cause> old=<relay> new=<relay> old_chain=… new_chain=…`), `relay.rerouted` (`<ts> RELAY_REROUTED <relay_id> old_chain=… new_chain=… hosts_routed=…`), `relay.converged` (`<ts> CONVERGED <relay_id> relays_connected=… relays_missing=… hosts_direct=… hosts_routed=… dropped=…`). La racine et l'enfant ont `RELAY_CONVERGENCE_TIMEOUT=30s` ; la file amont de l'enfant vaut `CHILD_UPSTREAM_QUEUE_SIZE` (défaut 10 000). `hooks`/`failover`/`failover-kill` vérifient en plus **un seul** `CONVERGED` (après `FAILOVER`), aucun `REROUTED`/`RELAY_REROUTED` après une bascule et les compteurs `upstream_*` de l'enfant (`server status`). Nouveaux scénarios : `converged-timeout`, `rerouted` (`MINION_CHILD_SERVER_URL`/`MINION_CHILD_WS_URL` : minion-child re-pointé vers la racine, Docker), `upstream-queue` (`pause` du maître ≤ `UPSTREAM_PAUSE_MAX_S` = 150 s, `UPSTREAM_CYCLES` = 20, variante `UPSTREAM_QUEUE_SIZE=256`), `lost-during-failover` (kill du maître + `minion-root` arrêté pendant la fenêtre : aucun `DOWN`), et, avec **`CHAIN_LEVEL3=1`** dès le `bootstrap` (Docker seulement), un **3e niveau** : `secagent-grandchild` (`dmz2`, enfant pull de `dmz1`, admin `127.0.0.1:9772`, volume de lien `${PROJECT}_link_grand`, jeton de lien **minté sur la racine** `--sub dmz2 --aud dmz1` : seule la racine signe les liens) et `minion-grand`, scénarios `relay-rerouted` (`GRANDCHILD_UPSTREAM_URL` : dmz2 re-pointé vers la racine puis retour) et `failover-3-levels` (redémarrage de dmz2 : `FAILOVER dmz2 start` journalisé par la racine). `relay-down` attend désormais `RELAY_DOWN dmz1 peer_closed:1001` (T22 ; `RELAY_DOWN_REASON` pour un autre code). Séquence complète : `.claude/agents/environments/deploy.qualif.md` (étape 6).
- **Essai CA négatif** : service `minion-negca` (profil Compose `negative`, jamais démarré par un `up` ordinaire), minion **sans** `RELAY_CA_BUNDLE` (store système seul) face à la CA privée. `bash chain-test.sh negative-ca` exige une erreur de certificat dans ses logs et son absence de `minions list`, puis le supprime. Le jeton d'enrôlement du service est factice (forme valide, 64 zéros) : le refus doit précéder toute authentification.
- **Jeton plugin frais** : `chain-test.sh` crée un jeton plugin neuf (fichier 0600) à chaque `smoke`, `failover` et `hooks` ; plus de dépendance au jeton du bootstrap qui expire (`TOKEN_TTL`).
- **Jetons de lien v3.0.4** (comportement par défaut du bootstrap) : `relays add` ne mint plus de jeton ; `chain-test.sh bootstrap` exporte la clé publique racine (`keys link-pubkey`, PEM sur stdout, `root_id=` sur stderr), la pousse dans le volume `${PROJECT}_link` (`push-link-key`, aucun bind mount), mint sur la racine le jeton `relay-child` de `dmz1` (`tokens create --role relay-child --sub dmz1 --aud <root_id>`, TTL `LINK_TTL`) et le dépose, par un conteneur éphémère, dans le même volume `${PROJECT}_link` (fichier `upstream-token`, propriétaire UID 10001, mode 0400, `REPEATER_UPSTREAM_TOKEN_FILE=/run/secagent-link/upstream-token`) ; la copie locale `$CHAIN_DIR/upstream-token` est supprimée après le dépôt. **Pas de `secrets:` Compose** : hors Swarm il monte le fichier de l'hôte (uid/gid/mode ignorés, illisible par l'UID 10001 — échec CI « permission denied ») et serait résolu sur l'hôte distant. `down` supprime ce volume. `REPEATER_ROOT_ID` (non secret) est écrit dans `$CHAIN_DIR/child.env`. L'enfant n'a plus aucun secret de lien en variable d'environnement.
- **Scénario `link-rotation`** : `keys rotate-link`, attente de la confirmation de `dmz1` (`keys link-status`), **mise à jour du fichier épinglé de l'enfant avec la nouvelle clé publique AVANT le retrait** (sinon le redémarrage suivant de l'enfant est refusé : `pinned root link key disagrees with the persisted link_trust`), nouveau jeton signé par la nouvelle clé et remplacement du conteneur de l'enfant, `keys retire-link-previous` (sans `--force`), **redémarrage** de l'enfant puis `smoke`. **Scénario `link-revoke`** : `tokens revoke <id>` du jeton de lien, `dmz1` déconnecté (fermeture 4010, refus permanent) et **non reconnecté** pendant 40 s, puis remise en état avec un nouveau jeton et `smoke`.
- **Montée v3.0.3 → v3.0.4** : plan de répétition dans `REHEARSAL_v3.0.4.md`.

### CLI Docker : paquet signé `docker-ce-cli`, extrait sans installation (#240)

Pour un poste sans client Docker (poste Linux de l'équipe depuis 2026-11-09, runner), le CLI Linux et le plugin Compose v2 viennent des **paquets signés du dépôt APT Docker**, extraits dans un répertoire de travail : **aucune installation système** (ni `apt install`, ni `sudo`). La chaîne de confiance est celle d'APT : clé GPG Docker → `InRelease` signé → `Packages` (empreinte listée dans `InRelease`) → `.deb` (empreinte listée dans `Packages`).

| Élément | Valeur épinglée (Ubuntu `noble`, amd64, relevé le 2026-11-03) |
|---|---|
| Clé de signature Docker (`https://download.docker.com/linux/ubuntu/gpg`) | empreinte `9DC8 5822 9FC7 DD38 854A E2D8 8D81 803C 0EBF CD88` |
| `docker-ce-cli` | `5:29.8.2-1~ubuntu.24.04~noble`, sha256 du `.deb` `008b3b49b474136063fe0fbe8999b0e77c3e8556d7f7de21f98f05715e2f76ba` |
| `docker-compose-plugin` | `5.7.0-1~ubuntu.24.04~noble`, sha256 du `.deb` `61dd23ec4d0f6e4a99ef841f2ea2c0dc9cbada2c6ad99ffbd4f980ae957cc691` |

```bash
set -euo pipefail
FPR=9DC858229FC7DD38854AE2D88D81803C0EBFCD88                       # empreinte epinglee de la cle de signature Docker
B=https://download.docker.com/linux/ubuntu
cu() { curl --proto '=https' --tlsv1.2 -fsSLO "$@"; }              # HTTPS impose, jamais de repli vers http
d=$(mktemp -d) && cd "$d" && export GNUPGHOME="$d/gnupg" && mkdir -m700 "$GNUPGHOME"      # trousseau jetable : ni ~/.gnupg ni installation
cu "$B/gpg"
# 1. Fail-closed sur la cle : la cle telechargee doit avoir EXACTEMENT l'empreinte epinglee AVANT tout import
[ "$(gpg --with-colons --show-keys gpg | awk -F: '$1=="fpr"{print $10; exit}')" = "$FPR" ] || { echo "ECHEC : empreinte de la cle Docker inattendue" >&2; exit 1; }
gpg --import gpg
cu "$B/dists/noble/InRelease"
# 2. Fail-closed sur la signature : VALIDSIG obligatoire, et la cle PRIMAIRE (dernier champ) doit etre l'empreinte epinglee
gpg --status-fd 1 --verify InRelease 2>/dev/null | awk -v f="$FPR" '$2=="VALIDSIG" && $NF==f {ok=1} END{exit !ok}' \
  || { echo "ECHEC : InRelease n'est pas signe par la cle epinglee" >&2; exit 1; }
gpg --decrypt InRelease 2>/dev/null > Release
cu "$B/dists/noble/stable/binary-amd64/Packages"
want=$(awk '$3=="stable/binary-amd64/Packages" && length($1)==64 {print $1}' Release | head -1)
echo "$want  Packages" | sha256sum -c -                                                        # Packages conforme a InRelease signe
for f in docker-ce-cli_29.8.2-1~ubuntu.24.04~noble_amd64.deb docker-compose-plugin_5.7.0-1~ubuntu.24.04~noble_amd64.deb; do
  cu "$B/dists/noble/pool/stable/amd64/$f"
done
echo "008b3b49b474136063fe0fbe8999b0e77c3e8556d7f7de21f98f05715e2f76ba  docker-ce-cli_29.8.2-1~ubuntu.24.04~noble_amd64.deb" | sha256sum -c -
echo "61dd23ec4d0f6e4a99ef841f2ea2c0dc9cbada2c6ad99ffbd4f980ae957cc691  docker-compose-plugin_5.7.0-1~ubuntu.24.04~noble_amd64.deb" | sha256sum -c -
grep -c "008b3b49b474136063fe0fbe8999b0e77c3e8556d7f7de21f98f05715e2f76ba" Packages           # empreinte du .deb aussi dans Packages signe (>= 1)
# Extraction sans installation (dpkg-deb -x, ou `ar x` puis `tar -xJf data.tar.xz`) :
dpkg-deb -x docker-ce-cli_*.deb x && dpkg-deb -x docker-compose-plugin_*.deb x
mkdir -p "$HOME/qualif-cli/cfg" && cp x/usr/bin/docker "$HOME/qualif-cli/docker" && cp -r x/usr/libexec/docker/cli-plugins "$HOME/qualif-cli/plugins"
printf '{"cliPluginsExtraDirs":["%s"]}\n' "$HOME/qualif-cli/plugins" > "$HOME/qualif-cli/cfg/config.json"
export DOCKER_CONFIG="$HOME/qualif-cli/cfg" PATH="$HOME/qualif-cli:$PATH"      # dans le shell qui lance chain-test.sh
docker --version && docker compose version
```

Recoupement (2026-11-03) : le binaire `docker` du paquet signé et celui de l'ancienne archive statique diffèrent (builds distincts), mais annoncent la **même version et le même commit de build** (`29.8.2, build 7fc2dff`), qui est le commit du tag `v29.8.2` de `docker/cli`. **L'archive statique `docker-29.8.2.tgz` n'est plus utilisée** : Docker ne publie ni somme de contrôle, ni release GitHub, ni attestation pour elle (le `.sha256` voisin répond 404). Son empreinte `995d1ef289677f74fd58d8d2c35727b6a4ee389c69db8638a3e42d0487aa5b0f` (relevée en HTTPS le 2026-10-07, retrouvée identique le 2026-11-03) n'est **pas** une empreinte « officielle » : elle ne protège que contre une altération postérieure du téléchargement, jamais contre un fichier déjà compromis. **Risque accepté, daté du 2026-11-03**, pour qui l'emploierait quand même ; préférer le paquet signé ci-dessus.

### CLI Docker supporté par les scripts de qualif (#224)

`chain-test.sh` et `failover-test.sh` appellent `docker` (premier trouvé dans le `PATH`) et **`docker compose`** (plugin Compose v2 ; l'ancien binaire `docker-compose` v1 n'est pas utilisé). Le démon visé est **toujours** celui de `DOCKER_HOST`.

| Client | Supporté | Remarque |
|---|---|---|
| CLI **Linux** (paquet signé extrait ci-dessus, ou paquet de la distribution) + plugin Compose v2 | **oui** (seul cas utilisé en qualif v3.0.4) | `docker version` et `docker compose version` doivent répondre ; `DOCKER_HOST=tcp://192.168.1.218:2375` exporté dans le shell qui lance le script |
| `docker.exe` (Docker Desktop Windows) appelé depuis WSL (ancien poste) | **non** pour les scripts | voir ci-dessous |

**Contrôle avant tout lancement** : `command -v docker` doit désigner le CLI Linux voulu (celui du scratchpad sur le poste, qui n'a aucun client Docker installé ni démon local) et `docker info --format '{{.Name}}'` doit renvoyer le nom de l'hôte de qualif. Historique (ancien poste WSL) : `docker.exe` ignorait `DOCKER_HOST` exporté dans WSL et visait le démon local de Docker Desktop ; il n'était utilisable qu'en commande ponctuelle avec `-H` explicite, jamais pour les scripts.

## Prérequis

- Docker remote access actif sur `192.168.1.218:2375`
- Un répertoire de certificats TLS (`tls.crt`, `tls.key`) : `QUALIF_TLS_DIR` (défaut `PRIVATE/QUALIF/pki/`)
- **ansible-core à la version exacte épinglée par la CI** (`ansible-core==2.21.4` dans `.github/ci/requirements-ansible.txt`, #249) sur le poste de contrôle : `smoke`, `failover` et `admission-503` lisent `${ANSIBLE_BIN:-ansible} --version` (`ansible [core X.Y.Z]`) et **refusent** (`REFUS:`, code 2, avant toute action) toute autre version, une version illisible ou un binaire introuvable. Installation : `python3 -m venv ~/.venv-secagent && ~/.venv-secagent/bin/pip install -r .github/ci/requirements-ansible.txt`, puis `export ANSIBLE_BIN=~/.venv-secagent/bin/ansible`. Pourquoi : avec ansible-core **2.17**, l'étape 5 d'`admission-503` donne `FAILED | rc=-1` au lieu de `UNREACHABLE` et le plugin laisse le tmpdir distant non nettoyé (nettoyage refusé) — un faux échec qui ressemblait à une régression du plugin.
- Une image candidate publiée par la CI (voir « Promotion » plus bas) : `SECAGENT_IMAGE`
- Un répertoire `PRIVATE/QUALIF/secrets/` (`SECRETS_DIR`, gitignoré) avec `jwt_secret_key`, `admin_token`, `rsa_master_key` (secrets de qualification, jamais ceux de PROD ; `rsa_master_key` ≥ 32 octets) ; `bash failover-test.sh setup-ci` / `chain-test.sh ci-prepare` les génèrent aléatoirement, puis `push_secrets` les dépose dans le volume `${PROJECT}_secrets`

## Lancer

```bash
export SECAGENT_IMAGE=ghcr.io/ccoupel/secagent-server:sha-<commit>@sha256:<digest>
export QUALIF_TLS_DIR=/chemin/vers/certs        # facultatif : défaut PRIVATE/QUALIF/pki
bash chain-test.sh ci-prepare        # ou deposer PRIVATE/QUALIF/secrets/{jwt_secret_key,admin_token,rsa_master_key} (0400), puis : bash failover-test.sh setup-ci

# L'état n'est jamais créé implicitement : `secagent-server state init` une fois (voir DOC/project/DEPLOYMENT.md, étape 1)
DOCKER_HOST=tcp://192.168.1.218:2375 docker compose -p secagent-qualif -f docker-compose.server.yml up -d
DOCKER_HOST=tcp://192.168.1.218:2375 docker compose -p secagent-qualif -f docker-compose.server.yml ps
```

Le healthcheck est `secagent-server status --local` (aucun port). Les jetons d'enrôlement et les minions se gèrent comme dans `DOC/project/DEPLOYMENT.md` (étape 3) : `tokens create --role enrollment …`, puis `RELAY_ENROLLMENT_TOKEN` côté minion.

## Test de basculement

`failover-test.sh` (voir son en-tête) vérifie sur ces Compose le comportement actif/passif : `run stop` (arrêt propre du maître, reprise rapide), `run kill` (reprise après péremption du verrou, plusieurs minutes), `run freeze` (SIGSTOP), `teardown`.

**Codes de sortie des scripts de qualif (#256)** : `0` = OK ; `1` = échec d'exécution (`ECHEC: …`, suivi de `== DIAGNOSTIC ==` sous `chain-test.sh`) ; `2` = refus d'une garde **avant toute action** (`REFUS: …`, jamais de DIAGNOSTIC) : certificat absent, chemin privé, `CHAIN_DIR`, projet, bind mount distant, variable obligatoire, images, version d'ansible-core. `run` exige le certificat avant toute commande `docker` : `tls.crt` et `tls.key` dans `${QUALIF_TLS_DIR:-PRIVATE/QUALIF/ci-tls}` (`ca.crt` non exigé), ou, avec `TLS_MODE=volume`, le volume `SECAGENT_TLS_VOLUME` existant (`chain-test.sh push-tls`).

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

## Compléments de qualif v3.0.5 (#197 item 6, #238, #229, #241)

- **Secrets du serveur en fichiers (#197 item 6)** : `docker-compose.server.yml` et `docker-compose.chain.yml` ne lisent plus `qualif.env` ; les trois secrets sont des fichiers du volume **externe** `${PROJECT}_secrets` (modèle des volumes `tls`/`hooks`/`link` : un `secrets: file:` serait un bind mount du poste, irréalisable contre un démon distant), montés en lecture seule sur `/run/secagent-secrets` et lus via `*_FILE`. `push_secrets` (appelé par `bootstrap` et `failover-test.sh setup-ci`) les dépose par un conteneur éphémère : propriétaire 10001, mode 0400. `scripts/ci/check_compose.py --require-secret-files` refuse tout service serveur avec un secret en variable d'environnement ou un `env_file` autre que `child.env` (`$CHAIN_DIR`) (qui ne porte que `REPEATER_ROOT_ID`). Contrôle : `docker inspect` d'un conteneur serveur ne montre aucune des trois valeurs. `down` / `teardown` retirent le volume. `backup-restore` simule la perte de la clé avec `RSA_MASTER_KEY_FILE` vide (clé non définie : code 6 attendu) puis un volume de secrets portant une autre clé (code 2), au lieu de retirer la variable ; un fichier de secret inexistant donne le code 1 (lecture impossible).
- **Durcissement des minions (#238)** : `minion-root`, `minion-child` et `minion-negca` tournent avec `cap_drop: [ALL]`, `cap_add: [CHOWN, SETUID, SETGID]` et `no-new-privileges:true`. L'entrypoint de l'image démarre en root (création des répertoires, clé RSA, `chown`) puis passe à `relay` par `su-exec` : **mesuré sur 192.168.1.218** (image minion, volume neuf puis redémarrage sur volume existant) : ces trois capacités suffisent, le minion tourne en `relay` ; `DAC_OVERRIDE` n'est pas nécessaire. `check_compose.py` refuse un minion de qualif sans `cap_drop: ALL` ou sans `no-new-privileges`.
- **`minion-negca` avec les deux adresses (#229)** : `RELAY_SERVER_URL` / `RELAY_WS_URL` listent `secagent-server-a` **et** `-b`. Le refus TLS est donc constaté quel que soit le maître, y compris après `failover` (où `a` est secondaire et n'écoute pas). Séquence rejouée : `failover` puis `negative-ca`. **Dépendance au maître par scénario** : `smoke`, `hooks`, `negative-ca`, `link-rotation`, `link-revoke` et `admission-503` interrogent le **maître courant** (`master()`), quel qu'il soit ; `failover` change de maître ; `backup-restore` redémarre a et b sur un état restauré (le maître peut changer).
- **`admission-503` (#241)** : `bash chain-test.sh admission-503` abaisse `MAX_STDOUT_BUFFER_TOTAL` des deux nœuds de la racine à `52428800` (surcharge Compose écrite dans `$CHAIN_DIR`, rien dans le dépôt) : 10 tâches simultanées admises (5 Mio réservés par tâche), la 11ᵉ reçoit `503 memory_budget_exhausted` avec `Retry-After`, rien n'atteint le minion, `[SECURITY WARNING] task refused at admission` est journalisé par le maître ; libération, puis le plugin réel (12 forks) remonte un `UNREACHABLE` explicite sans rejeu (critère de l'étape 5 : au moins un `UNREACHABLE` avec `memory_budget_exhausted` et `Retry-After`, **inchangé** depuis #249 : la version d'ansible-core est imposée par la garde ci-dessus, un `FAILED` n'est pas accepté car il masquerait une régression du plugin) ; retour au plafond par défaut. Variables : `ADM503_BUDGET` (défaut `52428800`), `ADM503_HOLD` (durée des `sleep`, défaut 45 s). Durée ≈ 4-5 minutes.

## Qualif sur Podman rootless (v3.0.6, LOT-4, #267)

`CONTAINER_CLI=podman bash chain-test.sh <étape>` exécute chaque commande **sur le nœud** (`ssh cyril@<ip> podman …`,
clé et `known_hosts` de `PRIVATE/QUALIF/poste-cyril/`, `StrictHostKeyChecking=yes`) : racine a sur srv3
(`CONTAINER_HOST_A`, défaut `ssh://cyril@192.168.1.213/…`), b, enfant et minions sur srv4 (`CONTAINER_HOST_B`).
`podman-compose` est lancé sur le nœud depuis `PRIVATE/QUALIF/<srvX>/cyril/secagent/release/` (déposé par
`DEPLOYMENT/podman/stage-node-files.sh`, vérifié par `verify-node-files.sh`, appelé aussi par `guard_remote_binds`), avec la
surcharge `DEPLOYMENT/podman/docker-compose.podman.qualif.yml` (état `PRIVATE/QUALIF/state/{root,child}` et secrets
`PRIVATE/QUALIF/secrets` liés au partage, `keep-id:uid=10001,gid=10001`). Différences avec Docker :
`SECRET_OWNER_UID=1000` ; jetons volatils dans `PRIVATE/QUALIF/srv4/cyril/secagent/run/` ; poste de contrôle sur
`https://192.168.1.213:7770,https://192.168.1.214:8770` ; `push-tls` et `backup-restore` refusés (TLS et état sont sur le
partage) ; `down` sans `-v`. PKI : `pki/gen.sh` écrit `ca.key` dans `pki-ca/` (jamais monté) ; SAN à ajouter pour la
chaîne répartie : `PKI_EXTRA_SAN=IP:192.168.1.213,IP:192.168.1.214`. Procédure de la plateforme :
`DEPLOYMENT/podman/README.md`.
