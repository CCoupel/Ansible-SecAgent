#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
# SPDX-License-Identifier: AGPL-3.0-or-later

# Topologie de qualif EN CHAINE (#188) : amorcage, smoke et bascule de la racine.
#
#   chain-test.sh ci-prepare   # PKI de test + secrets aleatoires et jetables (SECRETS_DIR, fichiers 0400) ; ne regenere que l'absent
#   chain-test.sh bootstrap    # state init (racine, enfant), relays add, jetons enrolement/plugin, demarrage
#   chain-test.sh smoke        # relais connectes, minions connectes, inventaire hierarchique, ansible -m ping
#   chain-test.sh failover     # arret propre du maitre de la racine (failover-test.sh) puis smoke ; hooks : relay.failover,
#                              # host.reconnect minion-root et relay.reconnect dmz1 au nouveau maitre
#   chain-test.sh failover-kill  # idem apres un KILL du maitre (reprise a la peremption du verrou, 5 min) ; relay.failover takeover
#   chain-test.sh backup-restore  # sauvegarde de l etat + de RSA_MASTER_KEY (a part), perte du volume, restauration
#   chain-test.sh load-images <dir>  # docker load des images d'un artefact CI (sans registre), SECAGENT_PULL_POLICY=never
#   chain-test.sh push-tls     # TLS_MODE=volume : copie les certificats dans le volume Docker (hote distant)
#   chain-test.sh push-hooks    # hooks.json -> volume ${PROJECT}_hooks (fait par bootstrap)
#   chain-test.sh push-events   # volumes du journal des hooks ${PROJECT}_events-{a,b,child} (10001, 0700 ; fait par bootstrap)
#   chain-test.sh push-secrets  # SECRETS_DIR -> volume ${PROJECT}_secrets, 10001 0400 (fait par bootstrap)
#   chain-test.sh push-link-key  # cle publique racine (+ jeton de lien s'il existe) -> volume ${PROJECT}_link
#   chain-test.sh link-rotation  # rotation de la cle de lien, confirmation, nouveau jeton, retire-link-previous (v3.0.4)
#   chain-test.sh link-revoke    # revocation du lien d'un enfant : fermeture 4010, pas de reconnexion, puis remise en etat
#   chain-test.sh hooks        # journal des hooks apres bootstrap : relay.failover, relay.up dmz1, host.up (#197, #225, #245, hooks.json)
#   chain-test.sh relay-down   # arret puis redemarrage de l'enfant : relay.down peer_closed:1001 puis relay.up de dmz1 (#245, T22)
#   chain-test.sh converged-timeout   # enfant arrete puis bascule : relay.converged au delai (relays_missing=1), un seul (#246)
#   chain-test.sh rerouted     # minion-child re-pointe vers la racine puis retour : host.rerouted direct puis indirect (#244)
#   chain-test.sh upstream-queue  # lien amont gele (<= 120 s) puis vu coupe, 6 (de)connexions rejouees sans perte ; UPSTREAM_QUEUE_SIZE=256 : variante (#246)
#   chain-test.sh relay-rerouted  # CHAIN_LEVEL3=1 : dmz2 re-pointe vers la racine puis retour : relay.rerouted (#244)
#   chain-test.sh failover-3-levels  # CHAIN_LEVEL3=1 : redemarrage de dmz2, relay.failover dmz2 journalise par la racine (#225)
#   chain-test.sh lost-during-failover  # kill du maitre + minion-root arrete pendant la fenetre : aucun host.down (#247)
#   chain-test.sh removed      # suppression de minion-root : host.removed + host.deleted (deprecie), reenrolement : discover (#266)
#   chain-test.sh removed-indirect  # suppression chez dmz1 : removed propage au maitre, deleted local, reenrolement (#266)
#   chain-test.sh revoke-no-removed  # revocations (minion-root ; dmz2 a 3 niveaux) : aucun removed, puis remise en etat (#266)
#   chain-test.sh relay-removed  # CHAIN_LEVEL3=1 : dmz2 revoque puis supprime chez dmz1 : relay.removed, pas de cascade (#266)
#   chain-test.sh rollback-refused  # ROLLBACK_IMAGE (v3.0.5 par digest) : state verify refuse l'etat v3.0.6 (first_seen_at)
#   chain-test.sh negative-ca  # essai CA negatif (profil Compose `negative`) : un minion sans la CA est refuse (#197)
#   chain-test.sh admission-503  # refus 503 memory_budget_exhausted en reel (#241) : plafond abaisse, voir admission-503.sh
#   chain-test.sh paths        # chemins prives resolus (sans docker) ; echec si la racine PRIVATE/ manque
#   chain-test.sh logs | down  # down : conteneurs, volumes externes ET $CHAIN_DIR (jetons volatils, apres la garde)
#
# Variables : SECAGENT_IMAGE, SECAGENT_MINION_IMAGE (obligatoires, references promues ou locales),
#   SECAGENT_PRIVATE_DIR (racine des donnees privees, defaut <depot>/PRIVATE, jamais creee : chemin ABSOLU du
#   checkout depuis une copie), SECRETS_DIR (defaut $SECAGENT_PRIVATE_DIR/QUALIF/secrets),
#   QUALIF_TLS_DIR (defaut $SECAGENT_PRIVATE_DIR/QUALIF/pki),
#   CHAIN_DIR (jetons VOLATILS, defaut ${TMPDIR:-/tmp}/secagent-qualif-chain-<uid> : hors PRIVATE/, sur un systeme de fichiers
#   qui honore chmod ; repertoire 0700 de l'utilisateur, refuse s'il est un lien, d'un autre proprietaire ou plus ouvert),
#   INVENTORY_BIN (binaire secagent-inventory du poste de controle),
#   ANSIBLE_BIN (defaut `ansible`, version EXACTE de ansible-core epinglee dans .github/ci/requirements-ansible.txt,
#   sinon smoke/failover/admission-503 refusent : #249), PROJECT (defaut secagent-chain), TOKEN_TTL (defaut 2h).
#   LINK_TTL (defaut = TOKEN_TTL) : duree du jeton de lien relay-child de l'enfant.
#   LOT-3.2 : CHAIN_LEVEL3 (0|1, 3e niveau dmz2, Docker), UPSTREAM_CYCLES / UPSTREAM_QUEUE_SIZE / UPSTREAM_PAUSE_MAX_S, RELAY_DOWN_REASON.
#   LOT-3.3 : ROLLBACK_IMAGE (rollback-refused : image serveur v3.0.5 epinglee par digest).
# Les jetons sont ecrits UNIQUEMENT dans $CHAIN_DIR (0700, fichiers 0600, hors du depot) : jamais affiches.
# Le poste de controle Ansible (plugin SECAGENT-PYTHON + secagent-inventory) est ici le poste qui lance ce script,
# il joint la racine par les ports d'hote 7770 (a) et 8770 (b) avec la CA de test.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
# Racine des donnees privees (#250) : meme resolution que failover-test.sh (source plus bas, garde require_private_dir).
PRIVATE_DIR="${SECAGENT_PRIVATE_DIR:-$REPO/PRIVATE}"
PRIVATE_DIR="${PRIVATE_DIR%/}"
# Projet dedie `secagent-qualif` (conteneurs secagent-qualif-a/-b/-child, ports d'hote 7770/7772 + 8770/8772 pour b,
# admin 127.0.0.1:7771/8771/9771). Deployer sur un hote qui heberge deja une ancienne qualif : liberer ces ports avant.
export COMPOSE_FILE="$HERE/docker-compose.chain.yml" PROJECT="${PROJECT:-${COMPOSE_PROJECT_NAME:-secagent-qualif}}"
# TLS_MODE=volume : certificats dans un VOLUME Docker nomme (hote Docker distant) au lieu d'un bind mount.
# Les hooks de qualif sont TOUJOURS livres par un volume nomme (docker-compose.hooks.yml), jamais par un fichier du client.
export SECAGENT_HOOKS_VOLUME="${SECAGENT_HOOKS_VOLUME:-${PROJECT}_hooks}"
# Prefixe des volumes du journal des hooks (un par instance : -a, -b, -child ; docker-compose.hooks.yml, push-events).
export SECAGENT_EVENTS_VOLUME="${SECAGENT_EVENTS_VOLUME:-${PROJECT}_events}"
export COMPOSE_OVERRIDES="$HERE/docker-compose.hooks.yml"
if [ "${TLS_MODE:-bind}" = volume ] && [ "${CONTAINER_CLI:-docker}" = docker ]; then
  export SECAGENT_TLS_VOLUME="${SECAGENT_TLS_VOLUME:-${PROJECT}_tls}"
  export COMPOSE_OVERRIDES="$HERE/docker-compose.remote-tls.yml $COMPOSE_OVERRIDES"
fi
# Hote sur lequel le poste de controle joint la racine (ports d'hote 7770 et 8770) ; defaut : poste local / runner.
# Hote distant : SECAGENT_ENDPOINT_HOST=192.168.1.218 (doit figurer dans les SAN : PKI_EXTRA_SAN=IP:192.168.1.218).
ENDPOINT_HOST="${CONTROL_HOST:-${SECAGENT_ENDPOINT_HOST:-127.0.0.1}}"   # CONTROL_HOST = alias
export QUALIF_TLS_DIR="${QUALIF_TLS_DIR:-$PRIVATE_DIR/QUALIF/pki}"
export SECAGENT_LINK_VOLUME="${SECAGENT_LINK_VOLUME:-${PROJECT}_link}"   # volume de l'ancre (cle publique racine)
export SECAGENT_LINK_GRAND_VOLUME="${SECAGENT_LINK_GRAND_VOLUME:-${PROJECT}_link_grand}"   # lien du 3e niveau (dmz2)
C_A="secagent-qualif-a"; C_B="secagent-qualif-b"; C_CHILD="secagent-qualif-child"; C_GRAND="secagent-qualif-grandchild"
# 3e niveau (LOT-3.2 : dmz2 enfant pull de dmz1 + minion-grand, profil Compose `level3`) : CHAIN_LEVEL3=1, Docker seulement
# (sous Podman : T47). Defaut 0 : la CI et les qualifs a deux niveaux sont inchangees.
CHAIN_LEVEL3="${CHAIN_LEVEL3:-0}"
case "$CHAIN_LEVEL3" in 0|1) ;; *) echo "REFUS: CHAIN_LEVEL3='$CHAIN_LEVEL3' : 0 ou 1 attendu" >&2; exit 2 ;; esac
if [ "$CHAIN_LEVEL3" = 1 ]; then
  [ "${CONTAINER_CLI:-docker}" = docker ] || { echo "REFUS: CHAIN_LEVEL3=1 : 3e niveau sous Docker seulement (Podman : T47)" >&2; exit 2; }
  export COMPOSE_PROFILES="level3"
fi
level3() { [ "$CHAIN_LEVEL3" = 1 ]; }
need_level3() { level3 || refuse "$1 : 3e niveau requis (CHAIN_LEVEL3=1 depuis le bootstrap)"; }
docker_only() { [ "$CONTAINER_CLI" = docker ] || refuse "$1 : sous Docker seulement (adresses de la chaine Podman repartie : T47)"; }
export C_A C_B
TOKEN_TTL="${TOKEN_TTL:-2h}"
LINK_TTL="${LINK_TTL:-$TOKEN_TTL}"
# Jetons de la chaine : VOLATILS (regeneres par bootstrap), donc hors PRIVATE/ ; defaut sur /tmp (systeme de fichiers local
# du poste, hors partage reseau : les modes 0700/0600 exiges par le plugin y sont honores). Exporte : docker-compose.chain.yml lit les env_file
# des minions et de l'enfant dans ${CHAIN_DIR:-./chain}.
# Podman (#267) : les env_file de l'enfant et des minions sont lus par podman-compose SUR le noeud b : les jetons volatils
# vont par defaut dans PRIVATE/QUALIF/<noeud b>/cyril/secagent/run/ (meme chemin absolu sur le poste et le noeud ; partage
# MooseFS qui honore 0700/0600), jamais dans release/ ni systemd/ (verifies par SHA256SUMS).
if [ "${CONTAINER_CLI:-docker}" = podman ]; then
  CHAIN_DIR="${CHAIN_DIR:-$PRIVATE_DIR/QUALIF/${QUALIF_NODE_B:-srv4}/cyril/secagent/run}"
else
  _tmp="${TMPDIR:-/tmp}"; CHAIN_DIR="${CHAIN_DIR:-${_tmp%/}/secagent-qualif-chain-$(id -u)}"; unset _tmp
fi
case "$CHAIN_DIR" in ?*/) CHAIN_DIR="${CHAIN_DIR%/}" ;; esac   # slash final retire, sauf `/` (refuse tel quel par la garde)
export CHAIN_DIR
# shellcheck source=failover-test.sh
source "$HERE/failover-test.sh"   # fonctions : listening, is_master, wait_for, health, fail, DC...
# shellcheck source=admission-503.sh
source "$HERE/admission-503.sh"   # etape admission-503 (#241)

adm() { # $1 conteneur, puis la commande secagent-server : CLI admin en TLS (CA de test), ADMIN_TOKEN du conteneur
  local c="$1"; shift
  ctr exec -e RELAY_API_URL=https://localhost:7771 -e REPEATER_CA_FILE=/certs/ca.crt "$c" /app/secagent-server "$@"
}
master() { is_master "$C_A" && echo "$C_A" || { is_master "$C_B" && echo "$C_B"; }; }
# Garde de $CHAIN_DIR (repertoire potentiellement partage comme /tmp) : refus FAIL-CLOSED (refuse : REFUS:, code 2) d'un lien symbolique, d'un non
# repertoire, d'un autre proprietaire que l'utilisateur courant ou de droits plus larges que 0700. Jamais de chmod correctif
# sur un repertoire existant (il a pu etre lu entre-temps) : le supprimer et relancer.
chain_dir_check() {
  local d="$CHAIN_DIR" uid mode
  # chemin ABSOLU exige : un chemin relatif serait resolu par Compose depuis le repertoire du fichier compose, pas d'ici
  case "$d" in /?*) ;; *) refuse "CHAIN_DIR='$d' n'est pas un chemin absolu (ni la racine) : refus" ;; esac
  [ ! -L "$d" ] || refuse "CHAIN_DIR=$d est un lien symbolique : refus (jetons de la chaine)"
  [ -e "$d" ] || return 0
  [ -d "$d" ] || refuse "CHAIN_DIR=$d existe et n'est pas un repertoire : refus"
  uid="$(stat -c %u -- "$d")"
  [ "$uid" = "$(id -u)" ] || refuse "CHAIN_DIR=$d appartient a l'uid $uid (utilisateur courant : $(id -u)) : refus"
  mode="$(stat -c %a -- "$d")"
  [ $(( 8#$mode & 8#077 )) -eq 0 ] || refuse "CHAIN_DIR=$d a les droits $mode, plus larges que 0700 : refus (supprimer le repertoire puis relancer)"
}
# Suppression des jetons volatils (down) : UNIQUEMENT apres chain_dir_check (jamais de rm -rf sur un chemin relatif, `/`,
# un lien, un non repertoire, un repertoire d'un autre uid ou trop ouvert : refus fail-closed, rien n'est supprime).
chain_dir_clean() {
  case "$CHAIN_DIR" in /?*) ;; *) chain_dir_check ;; esac   # vide, `/` ou relatif : refus explicite (jamais un no-op muet)
  [ -e "$CHAIN_DIR" ] || [ -L "$CHAIN_DIR" ] || return 0
  chain_dir_check
  rm -rf -- "$CHAIN_DIR"
  echo "jetons de la chaine supprimes ($CHAIN_DIR)"
}
chain_dir() { # cree $CHAIN_DIR en 0700 (sans course : mkdir echoue si un tiers l'a cree entre-temps) puis le reverifie
  chain_dir_check
  if [ ! -e "$CHAIN_DIR" ]; then
    mkdir -p -- "$(dirname -- "$CHAIN_DIR")"
    mkdir -m 700 -- "$CHAIN_DIR" || fail "CHAIN_DIR=$CHAIN_DIR : creation impossible"
  fi
  chain_dir_check
}
write_secret() { # $1 fichier relatif a chain/, valeur lue sur stdin : jamais affichee
  ( umask 077; cat > "$CHAIN_DIR/$1" )
  chmod 600 "$CHAIN_DIR/$1"
}
# extract (derniere occurrence d'un motif, vide si aucune : sur sous pipefail) : failover-test.sh (source).
need() { [ -n "${!1:-}" ] || refuse "variable $1 obligatoire"; }
# Garde de version ansible-core (#249) : le poste de controle doit avoir EXACTEMENT la version epinglee par la CI
# (`ansible-core==X` de .github/ci/requirements-ansible.txt). Avec une autre version (ex. 2.17), le plugin se comporte
# differemment (admission-503 etape 5 : `FAILED | rc=-1` au lieu de UNREACHABLE, nettoyage du tmpdir refuse) et
# l'echec ressemblait a une regression. Lit la premiere ligne de `${ANSIBLE_BIN:-ansible} --version`
# (`ansible [core X.Y.Z]`) ; comparaison stricte de chaine. Refus (REFUS:, code 2) avant toute action.
ANSIBLE_REQUIREMENTS="${ANSIBLE_REQUIREMENTS:-$REPO/.github/ci/requirements-ansible.txt}"
require_ansible_version() {
  local bin="${ANSIBLE_BIN:-ansible}" want got
  [ -f "$ANSIBLE_REQUIREMENTS" ] || refuse "ansible-core : $ANSIBLE_REQUIREMENTS absent (version epinglee introuvable)"
  want="$(sed -n 's/^[[:space:]]*ansible-core[[:space:]]*==[[:space:]]*\([^[:space:];#]*\).*/\1/p' "$ANSIBLE_REQUIREMENTS" | head -n 1)"
  [ -n "$want" ] || refuse "ansible-core : aucune ligne 'ansible-core==X' dans $ANSIBLE_REQUIREMENTS"
  command -v "$bin" >/dev/null 2>&1 \
    || refuse "ansible-core : ANSIBLE_BIN=$bin introuvable ; attendu ansible-core $want. Installer : python3 -m venv ~/.venv-secagent && ~/.venv-secagent/bin/pip install -r $ANSIBLE_REQUIREMENTS, puis ANSIBLE_BIN=~/.venv-secagent/bin/ansible"
  got="$("$bin" --version 2>/dev/null | sed -n '1s/.*\[core \([^]]*\)\].*/\1/p')" || true
  [ "$got" = "$want" ] \
    || refuse "ansible-core ${got:-illisible} trouve ($bin), $want attendu ($ANSIBLE_REQUIREMENTS). Installer : python3 -m venv ~/.venv-secagent && ~/.venv-secagent/bin/pip install -r $ANSIBLE_REQUIREMENTS, puis ANSIBLE_BIN=~/.venv-secagent/bin/ansible"
  echo "ansible-core $got ($bin) conforme"
}

# Diagnostic des conteneurs du projet qui ne sont pas sains (appele par fail() : la CI montre la vraie cause d'un
# healthcheck qui ne passe jamais). UNIQUEMENT l'etat (jamais `docker inspect` complet : Config.Env contient
# JWT_SECRET_KEY / ADMIN_TOKEN / RSA_MASTER_KEY : plus en variable depuis v3.0.5, #197) et la fin des logs (les valeurs de secrets n'y figurent pas).
diag_unhealthy() {
  local c st
  echo "== DIAGNOSTIC (projet $PROJECT) ==" >&2
  local CTR_NODE; for CTR_NODE in $(nodes); do
  for c in $(ctr ps -a --filter "label=com.docker.compose.project=$PROJECT" --format '{{.Names}}' 2>/dev/null); do
    st="$(ctr inspect -f '{{.State.Status}} exit={{.State.ExitCode}} oom={{.State.OOMKilled}} restarts={{.RestartCount}} health={{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}} err={{.State.Error}}' "$c" 2>/dev/null)" || continue
    echo "-- $c : $st" >&2
    case "$st" in *"health=healthy"*) ;; *) ctr logs --tail=40 "$c" 2>&1 | sed 's/^/   | /' >&2 ;; esac
  done
  done
}
# Sourcer failover-test.sh a defini fail() et refuse() ; on enrichit fail() sans changer son contrat (message + exit 1).
# refuse() (gardes : REFUS:, exit 2) n'est PAS enrichi : une garde refuse avant toute action, sans DIAGNOSTIC (#256).
fail() { echo "ECHEC: $*" >&2; diag_unhealthy || true; exit 1; }

# Pousse tls.crt/tls.key/ca.crt de QUALIF_TLS_DIR dans le volume `$SECAGENT_TLS_VOLUME` de l'hote Docker (distant ou
# non) via un conteneur ephemere (flux tar sur stdin, image alpine epinglee) : TLS_MODE=volume requis.
push_tls() {
  [ "$CONTAINER_CLI" = docker ] || refuse "push-tls : sans objet sous Podman (TLS lie depuis $QUALIF_TLS_DIR, partage PRIVATE)"
  [ "${TLS_MODE:-bind}" = volume ] || fail "push-tls exige TLS_MODE=volume"
  local f; for f in tls.crt tls.key ca.crt; do [ -f "$QUALIF_TLS_DIR/$f" ] || fail "$QUALIF_TLS_DIR/$f absent (lancer ci-prepare)"; done
  ctr volume create "$SECAGENT_TLS_VOLUME" >/dev/null
  tar -C "$QUALIF_TLS_DIR" -cf - tls.crt tls.key ca.crt | ctr run --rm -i -v "$SECAGENT_TLS_VOLUME:/certs" \
    alpine:3.24@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a \
    sh -c 'set -e; tar -xf - -C /certs; chown 0:0 /certs /certs/tls.crt /certs/ca.crt; chmod 755 /certs; chmod 644 /certs/tls.crt /certs/ca.crt
           chown 10001:10001 /certs/tls.key; chmod 0600 /certs/tls.key'
  echo "certificats de test pousses dans le volume $SECAGENT_TLS_VOLUME (tls.key 10001 0600, tls.crt/ca.crt 0644)"
}

# Depose hooks.json dans le volume `$SECAGENT_HOOKS_VOLUME` (hote Docker distant ou non) par un conteneur ephemere
# (flux tar sur stdin, image alpine epinglee) : aucun bind mount, aucun fichier du client reference par Compose.
# Conteneurs ephemeres de depot sous Podman : meme mapping que les serveurs (uid 10001 du conteneur = cyril de l'hote),
# en root du conteneur pour chown ; sous Docker : rien.
RUN_USERNS=()
if [ "$CONTAINER_CLI" != docker ]; then
  # shellcheck disable=SC2054   # la virgule fait partie de l'option keep-id:uid=...,gid=...
  RUN_USERNS=(--userns=keep-id:uid=10001,gid=10001 --user 0:0)
fi
push_hooks() {
  [ -f "$HERE/hooks.json" ] || fail "$HERE/hooks.json absent"
  local CTR_NODE; for CTR_NODE in $(nodes); do   # Podman : racine a (A) et b + enfant (B)
  ctr volume create "$SECAGENT_HOOKS_VOLUME" >/dev/null
  tar -C "$HERE" -cf - hooks.json | ctr run --rm -i "${RUN_USERNS[@]}" -v "$SECAGENT_HOOKS_VOLUME:/hooks" \
    alpine:3.24@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a \
    sh -c 'set -e; tar -xf - -C /hooks; chown 0:0 /hooks /hooks/hooks.json; chmod 755 /hooks; chmod 644 /hooks/hooks.json'
  echo "hooks.json depose dans le volume $SECAGENT_HOOKS_VOLUME${CTR_NODE:+ (noeud $CTR_NODE)}"
  done
}

# Volumes du journal des hooks, un PAR INSTANCE (docker-compose.hooks.yml) : crees s'ils manquent et rendus a l'uid 10001
# (0700) par un conteneur ephemere, comme push-hooks ; un journal existant est CONSERVE (preuves), seul `down` le retire.
EVENTS_SUFFIXES="a b child grandchild"   # grandchild : profil level3 (volume cree dans tous les cas, vide sinon)
push_events() {
  local CTR_NODE sfx; for CTR_NODE in $(nodes); do   # Podman : les trois volumes sur chaque noeud (seuls ceux du noeud servent)
    for sfx in $EVENTS_SUFFIXES; do
      ctr volume create "$SECAGENT_EVENTS_VOLUME-$sfx" >/dev/null
      ctr run --rm "${RUN_USERNS[@]}" -v "$SECAGENT_EVENTS_VOLUME-$sfx:/events" \
        alpine:3.24@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a \
        sh -c 'set -e; chown 10001:10001 /events; chmod 0700 /events; [ ! -e /events/events.log ] || chown 10001:10001 /events/events.log'
    done
    echo "volumes du journal des hooks prets : $SECAGENT_EVENTS_VOLUME-{a,b,child,grandchild}${CTR_NODE:+ (noeud $CTR_NODE)}"
  done
}
events_volumes() { local sfx; for sfx in $EVENTS_SUFFIXES; do printf '%s ' "$SECAGENT_EVENTS_VOLUME-$sfx"; done; }

# Empreinte STABLE d'une image : sha256 de la liste des couches (RootFS.Layers). L'ID `.Id` varie selon le magasin
# (overlay2 / containerd, Docker >= 29, Desktop) ; les couches (diff ids) sont identiques apres save/load.
# Meme calcul dans le job `images-artifact` de ci.yml (images.ids = "<ref> <empreinte>").
image_fp() { ctr image inspect --format '{{json .RootFS.Layers}}' "$1" 2>/dev/null | sha256sum | cut -d' ' -f1; }

# Garde (BAS-3) : avec SECAGENT_PULL_POLICY=never, Docker reutiliserait SILENCIEUSEMENT un tag local preexistant. Avant
# tout demarrage, l'ID reel des images du demon doit etre celui enregistre par `load-images` (non secret).
verify_images() {
  [ "${SECAGENT_PULL_POLICY:-missing}" = never ] || return 0
  local f="$CHAIN_DIR/image-ids" var ref want id CTR_NODE
  [ -f "$f" ] || refuse "SECAGENT_PULL_POLICY=never mais $f est absent : lancer d'abord 'chain-test.sh load-images <repertoire-de-l-artefact>'"
  for CTR_NODE in $(nodes); do   # Podman : chaque noeud a son propre magasin d'images
  for var in SECAGENT_IMAGE SECAGENT_MINION_IMAGE; do
    ref="${!var:-}"; [ -n "$ref" ] || refuse "$var non defini"
    want="$(awk -v r="$ref" '$1==r {print $2}' "$f")"
    [ -n "$want" ] || refuse "$ref ne figure pas dans $f (images non chargees par load-images)"
    ctr image inspect "$ref" >/dev/null 2>&1 || refuse "image $ref absente du demon Docker"
    id="$(image_fp "$ref")"
    [ "$id" = "$want" ] || refuse "empreinte des couches de $ref differente de l'artefact charge (demon: $id, attendu: $want) : un tag local preexistant ? relancer load-images"
  done
  done
}

# Charge sur l'hote Docker (distant ou non) les images d'un ARTEFACT de run CI (docker save), sans registre :
#   gh run download <id> -n secagent-images-<sha> -D images && chain-test.sh load-images images
# Verifie SHA256SUMS, `docker load` des deux archives, puis affiche les variables a exporter (images.env).
load_images() {
  local d="${1:?repertoire de l artefact (images.env SHA256SUMS archives)}"
  [ -f "$d/images.env" ] && [ -f "$d/SHA256SUMS" ] || fail "$d : images.env ou SHA256SUMS absent"
  ( cd "$d" && sha256sum -c SHA256SUMS ) || fail "empreintes de l'artefact invalides"
  [ -f "$d/images.ids" ] || fail "$d/images.ids absent (artefact trop ancien)"
  # upload-artifact perd le bit d'execution : il est restaure ici (et le binaire est obligatoire).
  [ -f "$d/secagent-inventory" ] || fail "$d/secagent-inventory absent de l'artefact (binaire du poste de controle)"
  chmod +x "$d/secagent-inventory"
  local a ref want id CTR_NODE; chain_dir
  for CTR_NODE in $(nodes); do   # Podman : chargement sur chaque noeud
  for a in "$d"/secagent-server-ci-*.tar.gz "$d"/secagent-minion-ci-*.tar.gz; do
    [ -f "$a" ] || fail "archive d'image absente ($a)"
    gunzip -c "$a" | ctr load
  done
  # Empreintes reelles apres chargement == celles de l'artefact ; ils sont enregistres dans l'etat local (verify_images).
  while read -r ref want; do
    [ -n "$ref" ] || continue
    ctr image inspect "$ref" >/dev/null 2>&1 < /dev/null || fail "image $ref absente apres docker load"
    id="$(image_fp "$ref" < /dev/null)"
    [ "$id" = "$want" ] || fail "empreinte de $ref apres chargement ($id) != artefact ($want)"
  done < "$d/images.ids"
  done
  cp "$d/images.ids" "$CHAIN_DIR/image-ids"; chmod 600 "$CHAIN_DIR/image-ids"
  echo "images chargees. A exporter :"; cat "$d/images.env"
  echo "(binaire du poste de controle : $d/secagent-inventory -> INVENTORY_BIN)"
}

ci_prepare() {
  require_private_dir "$QUALIF_TLS_DIR" "$SECRETS_DIR"   # fail-closed (#250) avant toute generation
  # tls.key en 0600 (Podman keep-id, volume push-tls), 0644 seulement pour le bind mount Docker local/CI (TLS_MODE=bind)
  local km=0600; [ "$CONTAINER_CLI" = docker ] && [ "${TLS_MODE:-bind}" = bind ] && km=0644
  PKI_MODE="$km" bash "$HERE/pki/gen.sh" "$QUALIF_TLS_DIR"
  gen_secrets   # $SECRETS_DIR (defaut PRIVATE/QUALIF/secrets) : jwt_secret_key, admin_token, rsa_master_key en fichiers 0400
}

# Chemins prives resolus (support de scripts/ci/private_paths_selftest.sh) : aucun appel docker, rien n'est cree.
chain_paths() {
  require_private_dir "$SECRETS_DIR" "$QUALIF_TLS_DIR"
  chain_dir_check   # CHAIN_DIR verifie s'il existe (lien, proprietaire, droits), jamais cree ici
  printf 'PRIVATE_DIR=%s\nSECRETS_DIR=%s\nQUALIF_TLS_DIR=%s\nCHAIN_DIR=%s\n' "$PRIVATE_DIR" "$SECRETS_DIR" "$QUALIF_TLS_DIR" "$CHAIN_DIR"
}

bootstrap() {
  need SECAGENT_IMAGE; need SECAGENT_MINION_IMAGE
  verify_images
  chain_dir
  push_hooks
  push_events    # journal des hooks persistant, un volume par instance (10001, 0700)
  push_secrets   # secrets serveur -> volume ${PROJECT}_secrets (10001, 0400) ; lus via *_FILE
  echo "== etat initial (racine)"
  dc run --rm --no-deps secagent-server-a state init
  echo "== racine : demarrage et identification du maitre"
  dc up -d secagent-server-a secagent-server-b
  wait_for "racine healthy" 120 all_health healthy "$C_A" "$C_B" >/dev/null
  sleep 3
  local m; m="$(master)" || fail "pas de maitre sur la racine"
  echo "maitre de la racine : $m"
  echo "== lien de l'enfant dmz1 (v3.0.4) : declaration, ancre (cle publique racine), jeton de lien relay-child"
  # `relays add` en mode pull ne mint plus aucun jeton (BREAKING v3.0.4) : il declare seulement l'enfant attendu.
  adm "$m" relays add --id dmz1 --description "chain child" >/dev/null || fail "relays add dmz1 refuse"
  link_anchor_prepare "$m"
  link_mint_child "$m"
  dc run --rm --no-deps secagent-child state init
  dc up -d secagent-child
  wait_for "enfant healthy" 120 all_health healthy "$C_CHILD" >/dev/null
  echo "== jetons d'enrolement (un par minion, hostname exact) et jeton plugin (FICHIER 0600)"
  adm "$m" tokens create --role enrollment --hostname-pattern '^minion-root$' --expires "$TOKEN_TTL" 2>&1 \
    | extract 'secagent_enr_[0-9a-f]{64}' | { read -r t || true; [ -n "$t" ] || fail "jeton minion-root non extrait"; printf 'RELAY_ENROLLMENT_TOKEN=%s\n' "$t" | write_secret minion-root.env; }
  adm "$C_CHILD" tokens create --role enrollment --hostname-pattern '^minion-child$' --expires "$TOKEN_TTL" 2>&1 \
    | extract 'secagent_enr_[0-9a-f]{64}' | { read -r t || true; [ -n "$t" ] || fail "jeton minion-child non extrait"; printf 'RELAY_ENROLLMENT_TOKEN=%s\n' "$t" | write_secret minion-child.env; }
  if level3; then
    echo "== 3e niveau : dmz2 (enfant pull de dmz1) declare sur dmz1, jeton de lien mine sur la racine (--aud dmz1)"
    adm "$C_CHILD" relays add --id dmz2 --description "chain grandchild" >/dev/null || fail "relays add dmz2 (sur dmz1) refuse"
    link_mint_grand "$m" dmz1
    dc run --rm --no-deps secagent-grandchild state init
    dc up -d secagent-grandchild
    wait_for "petit-enfant dmz2 healthy" 120 all_health healthy "$C_GRAND" >/dev/null
    adm "$C_GRAND" tokens create --role enrollment --hostname-pattern '^minion-grand$' --expires "$TOKEN_TTL" 2>&1 \
      | extract 'secagent_enr_[0-9a-f]{64}' | { read -r t || true; [ -n "$t" ] || fail "jeton minion-grand non extrait"; printf 'RELAY_ENROLLMENT_TOKEN=%s\n' "$t" | write_secret minion-grand.env; }
  fi
  plugin_token
  echo "== minions"
  dc up -d minion-root minion-child
  if level3; then dc up -d minion-grand; fi
  echo "bootstrap OK (jetons dans $CHAIN_DIR, non affiches)"
}

connected() { # $1 conteneur CLI, $2 commande (relays|minions), $3 nom, $4 colonne du statut
  # Attend (150 s max : backoff de reconnexion du minion jusqu'a 60 s) que $3 soit `connected` sur 3 releves
  # CONSECUTIFS espaces de 2 s : un statut perime (« connected » herite de l'ancien maitre) ne suffit pas.
  local ok=0 t0; t0=$(now)
  while [ "$ok" -lt 3 ]; do
    if ctr exec -e RELAY_API_URL=https://localhost:7771 -e REPEATER_CA_FILE=/certs/ca.crt "$1" /app/secagent-server "$2" list 2>/dev/null \
       | awk -v n="$3" -v c="$4" '$1==n && $c=="connected" {f=1} END{exit !f}'; then ok=$((ok+1)); else ok=0; fi
    awk -v a="$t0" -v b="$(now)" 'BEGIN{exit !(b-a>150)}' && fail "$3 n'est pas connected (150 s) sur $1"
    sleep 2
  done
}

# Attend (120 s max) que les DEUX minions apparaissent dans l'inventaire de la racine (propagation des hotes de
# l'enfant) avant tout `ansible -m ping`.
wait_inventory() {
  local t0 inv; t0=$(now)
  while :; do
    inv="$(RELAY_TOKEN="$(cat "$RELAY_TOKEN_FILE")" "$INVENTORY_BIN" --list 2>/dev/null || true)"
    if printf '%s' "$inv" | grep -q minion-root && printf '%s' "$inv" | grep -q minion-child \
       && { ! level3 || printf '%s' "$inv" | grep -q minion-grand; }; then return 0; fi
    awk -v a="$t0" -v b="$(now)" 'BEGIN{exit !(b-a>120)}' && fail "minion-root et minion-child absents de l'inventaire de la racine apres 120 s"
    sleep 3
  done
}

# Jeton plugin FRAIS a chaque appel (#197) : plus de dependance a un jeton cree au bootstrap qui expire (TOKEN_TTL).
# Cree sur le maitre courant (l'etat est partage par a/b), ecrit en FICHIER 0600, jamais affiche. Un ancien jeton
# non revoque expire de lui-meme (TTL) ; description horodatee pour les reperer dans `tokens list`.
plugin_token() {
  local m; m="$(master)" || fail "pas de maitre sur la racine (jeton plugin)"
  chain_dir
  adm "$m" tokens create --role plugin --description "chain-smoke-$(date +%s)" --expires "$TOKEN_TTL" 2>&1 \
    | extract 'secagent_plg_[0-9a-f]{64}' | { read -r t || true; [ -n "$t" ] || fail "jeton plugin non extrait"; printf '%s' "$t" | write_secret plugin.token; }
}

control_env() { # variables du poste de controle Ansible : listes d'adresses, CA de test, jeton en FICHIER
  plugin_token   # jeton frais a chaque appel (smoke, failover, hooks)
  if [ "$CONTAINER_CLI" = podman ]; then   # a sur le noeud A (7770), b sur le noeud B (8770)
    local ea eb; ea="$(node_addr A)"; eb="$(node_addr B)"
    export RELAY_SERVER_URL="https://$ea:7770,https://$eb:8770" RELAY_CA_BUNDLE="$QUALIF_TLS_DIR/ca.crt"
  else
    export RELAY_SERVER_URL="https://${ENDPOINT_HOST}:7770,https://${ENDPOINT_HOST}:8770" RELAY_CA_BUNDLE="$QUALIF_TLS_DIR/ca.crt"
  fi
  export RELAY_TOKEN_FILE="$CHAIN_DIR/plugin.token"
}

smoke() {
  require_ansible_version   # #249 : avant tout appel docker / ansible
  local m; m="$(master)" || fail "pas de maitre sur la racine"
  echo "== relais et minions connectes"
  connected "$m" relays dmz1 4
  connected "$m" minions minion-root 2
  connected "$C_CHILD" minions minion-child 2
  if level3; then connected "$C_CHILD" relays dmz2 4; connected "$C_GRAND" minions minion-grand 2; fi
  echo "== inventaire hierarchique (liste d'adresses de la racine)"
  control_env
  need INVENTORY_BIN
  wait_inventory
  echo "== ansible -m ping sur tous les hotes (plugin de connexion, CA de test)"
  local inv_script="$CHAIN_DIR/inventory.sh"
  printf '#!/bin/sh\nRELAY_TOKEN="$(cat "%s")" exec "%s" "$@"\n' "$RELAY_TOKEN_FILE" "$INVENTORY_BIN" | write_secret inventory.sh
  chmod 700 "$inv_script"
  ANSIBLE_CONNECTION_PLUGINS="$REPO/SECAGENT-PYTHON/ansible_plugins/connection_plugins" ANSIBLE_HOST_KEY_CHECKING=False \
    "${ANSIBLE_BIN:-ansible}" all -i "$inv_script" -m ping | ( umask 077; tee "$CHAIN_DIR/ping.log" )
  chmod 600 "$CHAIN_DIR/ping.log"   # un ancien fichier garderait son mode (tee tronque sans le changer)
  local want=2; level3 && want=3
  [ "$(count_lines SUCCESS < "$CHAIN_DIR/ping.log")" -ge "$want" ] || fail "ansible -m ping : moins de $want hotes SUCCESS"
  echo "smoke OK"
}

# Sauvegarde / restauration en conteneurs (#170) : l'etat (relay.state) et RSA_MASTER_KEY sont sauvegardes SEPAREMENT
# (repertoires distincts, hors du volume). Perte totale du volume d'etat, puis restauration sur un volume vierge :
# sans la cle, `state verify` refuse (code 6) ; avec une MAUVAISE cle il refuse (code 2) ; avec la bonne cle l'etat
# est restaure, la racine redemarre et le minion DEJA enrole se reconnecte SANS re-enrolement (meme identite).
backup_restore() {
  [ "$CONTAINER_CLI" = docker ] || refuse "backup-restore : non supporte sous Podman (l'etat EST le partage PRIVATE/QUALIF/state/root : la perte simulee du volume l'effacerait)"
  guard_project
  verify_images
  local m bk key; m="$(master)" || fail "pas de maitre sur la racine"
  bk="$CHAIN_DIR/backup-state"; key="$CHAIN_DIR/backup-key"
  local bkvol="${PROJECT}_backup"   # volume NOMME (pas de bind mount local : le demon peut etre distant)
  rm -rf "$bk" "$key"; mkdir -p "$bk" "$key"; chmod 700 "$key"
  connected "$m" minions minion-root 2    # le minion doit etre enrole et connecte avant la sauvegarde
  echo "== sauvegarde (etat) et sauvegarde distincte de RSA_MASTER_KEY"
  ctr exec "$m" /app/secagent-server state verify /data/relay.state >/dev/null || fail "etat source invalide"
  ctr cp "$m:/data/relay.state" "$bk/relay.state"; chmod 755 "$bk"; chmod 644 "$bk/relay.state"
  ctr volume create "$bkvol" >/dev/null
  tar -C "$bk" -cf - relay.state | ctr run --rm -i -v "$bkvol:/backup" \
    alpine:3.24@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a \
    sh -c 'tar -xf - -C /backup && chmod 755 /backup && chmod 644 /backup/relay.state'

  # La cle est sauvegardee a part (jamais dans le volume d'etat ni dans la sauvegarde de l'etat) : copie du fichier de secret.
  [ -s "$SECRETS_DIR/rsa_master_key" ] || fail "$SECRETS_DIR/rsa_master_key absent (secrets du poste de controle)"
  ( umask 077; cp "$SECRETS_DIR/rsa_master_key" "$key/rsa_master_key" ); chmod 400 "$key/rsa_master_key"
  echo "== sinistre : arret de la racine, perte du volume d'etat, puis cle absente et cle erronee"
  dc rm -sf secagent-server-a secagent-server-b >/dev/null
  ctr volume rm "${PROJECT}_secagent_state" >/dev/null
  # Les secrets sont des fichiers d'un volume : « sans la cle » = RSA_MASTER_KEY_FILE vide (cle non definie, code 6) ;
  # « mauvaise cle » = volume portant une autre valeur (code 2). Les variables directes RSA_MASTER_KEY + *_FILE ensemble
  # seraient refusees au demarrage (ambiguite), et un fichier inexistant donne un code 1 (lecture impossible), d'ou ce choix.
  local badkey="${PROJECT}_badkey" bkd; bkd="$(mktemp -d -p "$CHAIN_DIR")"
  ( umask 077; openssl rand -hex 32 | tr -d '\n' > "$bkd/rsa_master_key" ); chmod 400 "$bkd/rsa_master_key"
  # Nettoyage garanti meme en cas d'echec (fail() quitte le script) : volume de la mauvaise cle et repertoire temporaire.
  # shellcheck disable=SC2064
  trap "ctr volume rm '$badkey' >/dev/null 2>&1 || true; rm -rf '$bkd'" EXIT
  push_secrets "$bkd" "$badkey"
  local rc=0
  dc run --rm --no-deps -e RSA_MASTER_KEY_FILE= -v "$bkvol:/backup:ro" secagent-server-a state verify /backup/relay.state >/dev/null 2>&1 || rc=$?
  [ "$rc" = 6 ] || fail "sans RSA_MASTER_KEY : code 6 attendu, obtenu $rc"
  echo "sans la cle : refus (code 6) comme attendu"
  rc=0
  dc run --rm --no-deps -v "$badkey:/run/secagent-secrets:ro" -v "$bkvol:/backup:ro" secagent-server-a state verify /backup/relay.state >/dev/null 2>&1 || rc=$?
  [ "$rc" = 2 ] || fail "avec une mauvaise cle : code 2 attendu, obtenu $rc"
  echo "mauvaise cle : refus (code 2) comme attendu"
  ctr volume rm "$badkey" >/dev/null || true
  rm -rf "$bkd"; trap - EXIT
  echo "== restauration de la cle (depuis la sauvegarde distincte) puis de l'etat sur un volume vierge"
  push_secrets "$key"   # remet la cle sauvegardee a part dans le volume de secrets (jwt/admin conserves : push partiel)
  dc run --rm --no-deps -v "$bkvol:/backup:ro" secagent-server-a state verify /backup/relay.state >/dev/null || fail "etat sauvegarde refuse avec la cle restauree"
  dc run --rm --no-deps -v "$bkvol:/backup:ro" secagent-server-a state restore --from /backup/relay.state
  dc up -d secagent-server-a secagent-server-b
  wait_for "racine healthy apres restauration" 120 all_health healthy "$C_A" "$C_B" >/dev/null
  sleep 3
  m="$(master)" || fail "pas de maitre apres restauration"
  echo "== le minion DEJA enrole se reconnecte sans re-enrolement (aucun nouveau jeton cree)"
  connected "$m" minions minion-root 2
  ctr volume rm "$bkvol" >/dev/null || true
  echo "backup-restore OK (meme identite : le minion, authentifie par l'etat restaure, est reconnecte)"
}

# --- Jetons de lien v3.0.4 (#141/#146) -----------------------------------------------------------------------------
# La RACINE mint un jeton par lien (Ed25519) ; la cle publique racine est epinglee sur chaque relay non racine.
#   pull : racine `tokens create --role relay-child --sub dmz1 --aud <root_id>` -> fichier `upstream-token` du volume
#          ${PROJECT}_link (proprietaire 10001, mode 0400) = REPEATER_UPSTREAM_TOKEN_FILE de l'enfant ; REPEATER_ROOT_ID
#          dans chain/child.env (non secret). PAS de `secrets:` Compose : hors Swarm il monte le fichier de l'HOTE
#          (uid/gid/mode ignores), illisible par l'uid 10001 du conteneur et irrealisable contre un demon distant.
#   ancre : `keys link-pubkey` (PEM sur stdout, `root_id=... kid=...` sur stderr) -> meme volume (0644)
# L'enfant n'a PLUS de jeton en variable d'environnement (docker inspect ne montre aucun secret).

# Pousse dans le volume `$SECAGENT_LINK_VOLUME` (hote Docker distant ou non) la cle publique racine
# (chain/root-link.pub, NON secrete, 0644) et, s'il existe, le jeton de lien (chain/upstream-token, SECRET, 0400,
# proprietaire 10001 = uid du conteneur), par un conteneur ephemere (flux tar sur stdin, image alpine epinglee) : aucun
# bind mount, aucun droit requis sur l'hote. Le jeton local est supprime apres la copie (il vit alors dans le volume).
push_link_key() { # $1 volume (defaut $SECAGENT_LINK_VOLUME, lien de dmz1 ; $SECAGENT_LINK_GRAND_VOLUME pour dmz2)
  local vol="${1:-$SECAGENT_LINK_VOLUME}"
  [ -f "$CHAIN_DIR/root-link.pub" ] || fail "$CHAIN_DIR/root-link.pub absent (lancer bootstrap)"
  local files="root-link.pub" CTR_NODE=B   # Podman : volume de l'enfant, noeud B
  [ -f "$CHAIN_DIR/upstream-token" ] && files="root-link.pub upstream-token"
  ctr volume create "$vol" >/dev/null
  # shellcheck disable=SC2086
  tar -C "$CHAIN_DIR" -cf - $files | ctr run --rm -i "${RUN_USERNS[@]}" -v "$vol:/link" \
    alpine:3.24@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a \
    sh -c 'set -e; tar -xf - -C /link; chmod 755 /link; chown 0:0 /link/root-link.pub; chmod 644 /link/root-link.pub
           if [ -f /link/upstream-token ]; then chown 10001:10001 /link/upstream-token; chmod 0400 /link/upstream-token; fi'
  rm -f "$CHAIN_DIR/upstream-token"
  echo "ancre (et jeton de lien) deposes dans le volume $vol"
}

# $1 conteneur maitre : exporte la cle publique racine, releve root_id, ecrit chain/root-link.pub, chain/root-id et
# chain/child.env (REPEATER_ROOT_ID, non secret).
link_anchor_prepare() {
  local m="$1" rid
  # stdout = PEM (fichier) ; stderr = "root_id=<id> kid=<kid>" (capture), jamais de cle privee.
  # cree directement en 0600 (umask 077) : fichier local du poste, lu seulement par push_link_key (meme uid) ; c'est le
  # depot dans le volume qui le rend 0644 (lu par l'uid 10001 du conteneur)
  rid="$(umask 077; { adm "$m" keys link-pubkey 2>&1 >"$CHAIN_DIR/root-link.pub" || true; } | sed -n 's/^root_id=\([^ ]*\) .*/\1/p')"
  [ -n "$rid" ] || fail "root_id non releve (keys link-pubkey)"
  grep -q 'BEGIN PUBLIC KEY' "$CHAIN_DIR/root-link.pub" || fail "keys link-pubkey n'a pas produit de PEM public"
  chmod 600 "$CHAIN_DIR/root-link.pub"
  printf '%s' "$rid" | write_secret root-id
  printf 'REPEATER_ROOT_ID=%s\n' "$rid" | write_secret child.env
  # le depot dans le volume est fait par link_mint_child (cle publique et jeton ensemble)
}

# $1 conteneur maitre : mint (sur la racine) du jeton relay-child de dmz1 -> chain/upstream-token puis DEPOT dans le
# volume (push_link_key : 0400, proprietaire 10001, fichier local supprime) et chain/upstream-token.id (identifiant du
# registre, non secret, pour `tokens revoke`). Jamais affiche.
link_mint_child() { # $1 maitre ; $2 sub (defaut dmz1) ; $3 aud (defaut racine) ; $4 volume ; $5 fichier d'id (non secret)
  local m="$1" sub="${2:-dmz1}" aud="${3:-}" vol="${4:-$SECAGENT_LINK_VOLUME}" idf="${5:-upstream-token.id}" out t id rid
  rid="$(cat "$CHAIN_DIR/root-id")" || fail "chain/root-id absent (link_anchor_prepare)"
  [ -n "$aud" ] || aud="$rid"
  # Mint TOUJOURS sur la racine (seule a signer les liens : 409 not_root ailleurs), quel que soit le parent (aud).
  out="$(adm "$m" tokens create --role relay-child --sub "$sub" --aud "$aud" --expires "$LINK_TTL" 2>&1)" \
    || fail "mint du jeton de lien $sub -> $aud refuse (tokens create --role relay-child)"
  t="$(printf '%s\n' "$out" | extract 'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+')"
  id="$(printf '%s\n' "$out" | sed -n 's/^ *ID: *//p' | head -1)"
  [ -n "$t" ] || fail "jeton de lien non extrait"
  [ -n "$id" ] || fail "identifiant du jeton de lien non extrait"
  printf '%s' "$t" | write_secret upstream-token
  printf '%s' "$id" | write_secret "$idf"
  push_link_key "$vol"
}
# Lien du 3e niveau : dmz2 vers $2 (dmz1 par defaut ; la racine pour relay-rerouted), volume $SECAGENT_LINK_GRAND_VOLUME.
link_mint_grand() { link_mint_child "$1" dmz2 "${2:-dmz1}" "$SECAGENT_LINK_GRAND_VOLUME" upstream-token-grand.id; }
recreate_grand() {
  dc up -d --force-recreate --no-deps secagent-grandchild
  wait_for "petit-enfant dmz2 healthy" 120 all_health healthy "$C_GRAND" >/dev/null
}

relay_connected() { # $1 conteneur CLI, $2 relay_id
  adm "$1" relays list 2>/dev/null | awk -v n="$2" '$1==n && $4=="connected" {f=1} END{exit !f}'
}
relay_gone() { ! relay_connected "$1" "$2"; }
link_confirmed() { # $1 conteneur CLI, $2 relay_id : la rotation est confirmee par ce relay (keys link-status)
  adm "$1" keys link-status 2>/dev/null | awk -v n="$2" '$1==n && $4=="true" {f=1} END{exit !f}'
}
link_field() { # $1 conteneur CLI, $2 champ de la 1re ligne de keys link-status (current|previous|seq)
  adm "$1" keys link-status 2>/dev/null | head -1 | sed -n "s/.* $2=\([^ ]*\).*/\1/p"
}
recreate_child() { # remplace le conteneur de l'enfant (le jeton n'est lu qu'au demarrage) et attend healthy
  dc up -d --force-recreate --no-deps secagent-child
  wait_for "enfant healthy" 120 all_health healthy "$C_CHILD" >/dev/null
}

# Scenario link-rotation : rotation de la cle de signature -> confirmation par dmz1 (link_state) -> MISE A JOUR DU FICHIER
# EPINGLE de chaque relay non racine avec la nouvelle cle publique -> nouveau jeton signe par la nouvelle cle ->
# retire-link-previous (sans --force : refuse tant que non confirme) -> le lien survit a un REDEMARRAGE de l'enfant (c'est
# ce redemarrage qui revele un fichier epingle perime). Termine par un smoke (inventaire, ping).
link_rotation() {
  verify_images; need INVENTORY_BIN
  local m kid0 kid1 prev; m="$(master)" || fail "pas de maitre sur la racine"
  connected "$m" relays dmz1 4
  kid0="$(link_field "$m" current)"; [ -n "$kid0" ] || fail "kid courant illisible (keys link-status)"
  echo "== rotation de la cle de lien (kid courant $kid0)"
  adm "$m" keys rotate-link || fail "rotate-link refuse"
  kid1="$(link_field "$m" current)"
  [ -n "$kid1" ] && [ "$kid1" != "$kid0" ] || fail "le kid courant n'a pas change apres la rotation"
  [ "$(link_field "$m" previous)" = "$kid0" ] || fail "previous != ancien kid (fenetre de double acceptation absente)"
  wait_for "dmz1 confirme la rotation (keys link-status)" 90 link_confirmed "$m" dmz1 >/dev/null
  echo "== ANCRE : fichier epingle de l'enfant <- NOUVELLE cle publique (AVANT le retrait), puis nouveau jeton et enfant recree"
  # Apres retire-link-previous, un fichier epingle qui n'est ni la cle courante ni la precedente fait REFUSER le demarrage
  # de l'enfant (« pinned root link key disagrees with the persisted link_trust », fail closed voulu) : constate sur 192.168.1.218.
  link_anchor_prepare "$m"
  link_mint_child "$m"   # depose aussi la cle publique courante dans le volume
  recreate_child
  connected "$m" relays dmz1 4
  if level3; then
    # 3e niveau : le jeton de dmz2 (minte au bootstrap) est signe par l'ANCIENNE cle et son ancre l'est aussi ; la rotation
    # se propage bien jusqu'a dmz2 (link_keys), mais apres retire-link-previous sa reconnexion serait refusee (« bad
    # handshake », fail-closed voulu : SECURITY.md, jeton a re-minter). Re-mint (--aud dmz1) + nouvelle ancre (meme volume)
    # + recreation de dmz2 AVANT le retrait (_work/reports/dev-relay-qualif-link-rotation-3levels-20261112.md).
    echo "== 3e niveau : nouveau jeton et nouvelle ancre de dmz2, petit-enfant recree"
    link_mint_grand "$m" dmz1
    recreate_grand
    connected "$C_CHILD" relays dmz2 4
  fi
  echo "== retire-link-previous (refus attendu tant que non confirme : ici confirme)"
  adm "$m" keys retire-link-previous || fail "retire-link-previous refuse (rotation non confirmee ?)"
  prev="$(link_field "$m" previous)"
  case "$prev" in ""|"<nil>"|"-") ;; *) fail "previous encore present apres retire ($prev)" ;; esac
  echo "== le lien survit a une reconnexion de l'enfant apres le retrait"
  dc restart secagent-child >/dev/null
  connected "$m" relays dmz1 4
  if level3; then
    echo "== 3e niveau : dmz2 se reconnecte a dmz1 apres le retrait, puis survit a son propre redemarrage (ancre courante)"
    connected "$C_CHILD" relays dmz2 4
    dc restart secagent-grandchild >/dev/null
    wait_for "petit-enfant dmz2 healthy" 120 all_health healthy "$C_GRAND" >/dev/null
    connected "$C_CHILD" relays dmz2 4
  fi
  smoke
  echo "link-rotation OK (kid $kid0 -> $kid1, previous retire, lien reconnecte$(level3 && echo ', dmz2 re-minte et reconnecte'))"
}

# Scenario link-revoke : revocation du jeton de lien de dmz1 sur la racine -> lien ferme (4010, refus PERMANENT),
# l'enfant ne se reconnecte pas avec ce jeton ; remise en etat avec un nouveau jeton.
link_revoke() {
  verify_images; need INVENTORY_BIN
  local m id; m="$(master)" || fail "pas de maitre sur la racine"
  connected "$m" relays dmz1 4
  id="$(cat "$CHAIN_DIR/upstream-token.id")" || fail "chain/upstream-token.id absent"
  echo "== revocation du jeton de lien de dmz1 ($id)"
  adm "$m" tokens revoke "$id" || fail "tokens revoke refuse"
  wait_for "dmz1 deconnecte de la racine (fermeture 4010)" 60 relay_gone "$m" dmz1 >/dev/null
  echo "== pas de reconnexion avec le jeton revoque (40 s)"
  sleep 40
  ! relay_connected "$m" dmz1 || fail "dmz1 s'est reconnecte avec un jeton revoque"
  ctr logs "$C_CHILD" 2>&1 | grep -Eiq '4010|permanent|revoked' \
    && echo "journal de l'enfant : refus permanent constate" \
    || echo "info : aucune mention de refus permanent dans les logs de l'enfant (a analyser a l'execution)"
  echo "== remise en etat : nouveau jeton de lien"
  link_mint_child "$m"; recreate_child
  connected "$m" relays dmz1 4
  smoke
  echo "link-revoke OK (lien ferme et non retabli avec le jeton revoque ; retabli avec un nouveau jeton)"
}

# --- Hooks en reel (#197 item 1) -----------------------------------------------------------------------------------
# hooks.json (DEPLOYMENT/qualif/hooks.json, livre par le volume `${PROJECT}_hooks`, push-hooks) ecrit une ligne par
# evenement (10 hooks, un par evenement : seul le premier hook correspondant s'execute, c9ae9e7/#271) dans
# /var/log/secagent-events/events.log, volume externe PAR INSTANCE (push-events) : le journal survit a l'arret du conteneur.
# Seul le MAITRE de la racine execute ses hooks. Depuis #265 (v3.0.6) : 1re connexion d'un processus (conn_seq 1) =
# host.up / relay.up ; reconnexion du meme processus (conn_seq > 1, ex. apres une bascule) = host.reconnect /
# relay.reconnect, jamais les deux. LOT-3.2 : host.rerouted (REROUTED <hote> <cause>), relay.rerouted (RELAY_REROUTED),
# relay.converged (CONVERGED <self> relays_connected= relays_missing= ...). Fonctions events_log, hook_seen, hook_count,
# hook_more, kind_count, hook_last_kv, hook_last : failover-test.sh (source).
# Les journaux persistent jusqu'a `down` : les controles APRES une action comptent les lignes (une de plus), jamais la
# simple presence.
EVENTS_LOG_HINT="docker exec <conteneur> cat /var/log/secagent-events/events.log"

# Relais attendus par la racine apres une promotion (#246, server/convergence.go:139-147) : TOUS ses relay_nodes valides,
# y compris les DESCENDANTS appris par snapshot (relay_handler.go:1707-1712) : dmz1, et dmz2 avec CHAIN_LEVEL3=1.
expected_relays() { if level3; then echo 2; else echo 1; fi; }

# Entrees `upstream_dropped` du journal des actions de $1 (hooks log) : 0 si aucune ou si la commande echoue.
upstream_dropped_entries() { { adm "$1" hooks log --event '*' --limit 200 --format json 2>/dev/null || true; } | count_matches '"action_type": *"upstream_dropped"'; }

# Compteurs de la file amont de $1 (`server status`) : "<depth> <capacity> <dropped>" (vides si absents).
upstream_counters() {
  adm "$1" server status 2>/dev/null | awk '$1=="upstream_queue_depth" {d=$2; c=$4} $1=="upstream_dropped_events" {x=$2} END{print d, c, x}'
}
# $1 conteneur, $2 cle, $3 valeur attendue : la DERNIERE ligne CONVERGED de la racine porte cle=valeur.
converged_is() { [ "$(hook_last_kv "$1" "$ROOT_RELAY_ID" CONVERGED "$2")" = "$3" ]; }
# Ordre dans le journal : la derniere ligne $2 (genre) precede la derniere ligne $3 (genre), sujet = la racine.
in_order() { events_log "$1" | awk -v a="$2" -v b="$3" -v h="$ROOT_RELAY_ID" '$2==a && $3==h {ia=NR} $2==b && $3==h {ib=NR} END{exit !(ia && ib && ia<ib)}'; }

check_hooks() {
  local m n; m="$(master)" || fail "pas de maitre sur la racine"
  echo "== hooks : maitre $m (relay.failover, relay.converged, relay.up dmz1, host.up minion-root), enfant $C_CHILD (host.up minion-child)"
  wait_for "relay.failover (start) du maitre $m" 60 hook_seen "$m" "$ROOT_RELAY_ID" FAILOVER start >/dev/null
  # relay.converged (#246) : au 1er demarrage la racine n'attend encore aucun enfant (dmz1 est declare APRES) : emission
  # immediate, relays_missing=0 ; UN seul (jamais reemis).
  wait_for "relay.converged du maitre $m" 60 hook_seen "$m" "$ROOT_RELAY_ID" CONVERGED >/dev/null
  n="$(hook_count "$m" "$ROOT_RELAY_ID" CONVERGED)"; [ "$n" = 1 ] || fail "relay.converged : $n lignes au maitre $m (une seule attendue)"
  converged_is "$m" relays_missing 0 || fail "relay.converged du demarrage : relays_missing != 0 ($(hook_last "$m" "$ROOT_RELAY_ID" CONVERGED))"
  in_order "$m" FAILOVER CONVERGED || fail "relay.converged journalise avant relay.failover au maitre $m"
  echo "relay.converged : $(hook_last "$m" "$ROOT_RELAY_ID" CONVERGED)"
  wait_for "relay.up dmz1 dans le journal du maitre $m" 90 hook_seen "$m" dmz1 RELAY_UP >/dev/null
  wait_for "host.up minion-root dans le journal du maitre $m" 60 hook_seen "$m" minion-root UP >/dev/null
  wait_for "host.up minion-child dans le journal de l'enfant" 60 hook_seen "$C_CHILD" minion-child UP >/dev/null
  # LOT-3.3 (#266) : discover = premier handshake reussi (cycle de vie d'inventaire), AVANT up, jamais reemis
  first_before "$m" dmz1 RELAY_DISCOVER RELAY_UP || fail "relay.discover dmz1 absent ou apres relay.up au maitre $m (#266)"
  first_before "$m" minion-root DISCOVER UP || fail "host.discover minion-root absent ou apres host.up au maitre $m (#266)"
  first_before "$C_CHILD" minion-child DISCOVER UP || fail "host.discover minion-child absent ou apres host.up a l'enfant (#266)"
  wait_for "host.discover minion-child propage au maitre $m" 60 hook_seen "$m" minion-child DISCOVER >/dev/null
  [ "$(hook_last_kv "$m" minion-child DISCOVER chain)" = dmz1 ] || fail "host.discover minion-child au maitre : chain=dmz1 attendu ($(hook_last "$m" minion-child DISCOVER))"
  [ "$(hook_last_kv "$m" dmz1 RELAY_DISCOVER first_seen)" != "" ] || fail "relay.discover dmz1 sans first_seen"
  [ "$(count_matches '"first_seen_at"' < <({ adm "$m" minions list --format json 2>/dev/null || true; }))" -ge 1 ] \
    || fail "minions list --format json du maitre : first_seen_at absent (#266)"
  echo "discover : $(hook_last "$m" minion-root DISCOVER) | $(hook_last "$m" dmz1 RELAY_DISCOVER)"
  if level3; then
    wait_for "relay.up dmz2 dans le journal de l'enfant dmz1" 90 hook_seen "$C_CHILD" dmz2 RELAY_UP >/dev/null
    wait_for "host.up minion-grand dans le journal de dmz2" 60 hook_seen "$C_GRAND" minion-grand UP >/dev/null
    first_before "$C_CHILD" dmz2 RELAY_DISCOVER RELAY_UP || fail "relay.discover dmz2 absent ou apres relay.up chez dmz1 (#266)"
    wait_for "relay.discover dmz2 propage au maitre $m" 60 hook_seen "$m" dmz2 RELAY_DISCOVER >/dev/null
  fi
  echo "hooks OK (journaux : $EVENTS_LOG_HINT)"
}

# Releve des compteurs AVANT la bascule (les deux instances : le futur maitre n'est pas encore connu).
declare -A HOOKS_BEFORE=()
hooks_snapshot() {
  local c e; for c in "$C_A" "$C_B"; do
    for e in "minion-root RECONNECT" "minion-root UP" "minion-root DOWN" "dmz1 RELAY_RECONNECT" "dmz1 RELAY_UP" \
             "$ROOT_RELAY_ID CONVERGED" "$ROOT_RELAY_ID FAILOVER"; do
      # shellcheck disable=SC2086   # e = "<sujet> <genre>"
      HOOKS_BEFORE["$c $e"]="$(hook_count "$c" $e)"
    done
    HOOKS_BEFORE["$c *REROUTED"]="$(kind_count "$c" REROUTED)"
    HOOKS_BEFORE["$c *DISCOVER"]="$(kind_count "$c" DISCOVER)"
    HOOKS_BEFORE["$c *RELAY_DISCOVER"]="$(kind_count "$c" RELAY_DISCOVER)"
    HOOKS_BEFORE["$c *RELAY_REROUTED"]="$(kind_count "$c" RELAY_REROUTED)"
  done
}
before() { echo "${HOOKS_BEFORE["$1"]:-0}"; }

# Compteurs de la file amont de l'enfant apres une bascule (#246) : aucune perte, capacite par defaut (ou $1).
check_child_upstream() { # $1 capacite attendue (defaut 10000)
  local d c x; read -r d c x < <(upstream_counters "$C_CHILD")
  [ -n "$c" ] || fail "server status de l'enfant : compteurs upstream_* absents (serveur < LOT-3.2 ?)"
  echo "file amont de l'enfant : profondeur=$d capacite=$c perdus=$x"
  [ "$c" = "${1:-10000}" ] || fail "upstream_queue_capacity de l'enfant = $c (attendu ${1:-10000})"
  [ "$x" = 0 ] || fail "upstream_dropped_events de l'enfant = $x (aucune perte attendue)"
}

# Bascule avec hooks (failover-test.sh run stop|kill) : le NOUVEAU maitre doit journaliser relay.failover (cause start
# apres un arret propre, takeover apres un kill ; controle fait aussi par failover-test.sh), puis une NOUVELLE ligne
# host.reconnect de minion-root et relay.reconnect de dmz1 (memes processus qui se reconnectent : conn_seq > 1, #265,
# #245 ; ni host.up ni relay.up), puis UN SEUL relay.converged (#246 : relays_connected=1, relays_missing=0, ou au delai
# relays_connected=0 relays_missing=1 si $2=missing), et AUCUN host.rerouted / relay.rerouted (#244 : routes volatiles).
# minion-child : informatif (il reste connecte a l'enfant, qui ne redemarre pas).
check_hooks_after_failover() { # $1 cause attendue (start | takeover) ; $2 connected (defaut) | missing
  local m cause="${1:-start}" conv="${2:-connected}" n; m="$(master)" || fail "pas de maitre apres la bascule"
  echo "== hooks apres bascule : nouveau maitre $m"
  hook_seen "$m" "$ROOT_RELAY_ID" FAILOVER "$cause" || fail "relay.failover ($cause) absent du journal de $m"
  wait_for "host.reconnect minion-root journalise par le nouveau maitre $m" 150 hook_more "$m" minion-root RECONNECT "$(before "$m minion-root RECONNECT")" >/dev/null
  if [ "$conv" = connected ]; then
    wait_for "relay.reconnect dmz1 journalise par le nouveau maitre $m" 150 hook_more "$m" dmz1 RELAY_RECONNECT "$(before "$m dmz1 RELAY_RECONNECT")" >/dev/null
  fi
  wait_for "relay.converged journalise par le nouveau maitre $m" 60 hook_more "$m" "$ROOT_RELAY_ID" CONVERGED "$(before "$m $ROOT_RELAY_ID CONVERGED")" >/dev/null
  sleep 5   # un second relay.converged serait un defaut (jamais reemis)
  n=$(( $(hook_count "$m" "$ROOT_RELAY_ID" CONVERGED) - $(before "$m $ROOT_RELAY_ID CONVERGED") ))
  [ "$n" = 1 ] || fail "relay.converged : $n nouvelle(s) ligne(s) au nouveau maitre $m (une seule attendue)"
  echo "relay.converged : $(hook_last "$m" "$ROOT_RELAY_ID" CONVERGED)"
  local want; want="$(expected_relays)"
  if [ "$conv" = connected ]; then
    converged_is "$m" relays_connected "$want" && converged_is "$m" relays_missing 0 \
      || fail "relay.converged : relays_connected=$want relays_missing=0 attendus (dmz1$(level3 && echo ' + dmz2'))"
  else
    # dmz1 arrete : dmz2 (derriere lui) manque aussi
    converged_is "$m" relays_connected 0 && converged_is "$m" relays_missing "$want" \
      || fail "relay.converged au delai : relays_connected=0 relays_missing=$want attendus (dmz1$(level3 && echo ' + dmz2') absents)"
  fi
  in_order "$m" FAILOVER CONVERGED || fail "relay.converged journalise avant relay.failover au maitre $m"
  kind_more "$m" REROUTED "$(before "$m *REROUTED")" && fail "host.rerouted journalise par $m apres la bascule (aucun attendu, #244)"
  kind_more "$m" RELAY_REROUTED "$(before "$m *RELAY_REROUTED")" && fail "relay.rerouted journalise par $m apres la bascule (aucun attendu, #244)"
  # #266 : first_seen_at est dans l'etat PARTAGE : le nouveau maitre ne redecouvre rien
  kind_more "$m" DISCOVER "$(before "$m *DISCOVER")" && fail "host.discover journalise par $m apres la bascule (aucun attendu, #266)"
  kind_more "$m" RELAY_DISCOVER "$(before "$m *RELAY_DISCOVER")" && fail "relay.discover journalise par $m apres la bascule (aucun attendu, #266)"
  if hook_more "$m" minion-root UP "$(before "$m minion-root UP")"; then echo "info : host.up minion-root AUSSI journalise par $m (attendu : host.reconnect seul, #265 ; minion < v3.0.6 ?)"; fi
  if hook_more "$m" dmz1 RELAY_UP "$(before "$m dmz1 RELAY_UP")" && [ "$conv" = connected ]; then fail "relay.up dmz1 journalise par $m apres la bascule (attendu : relay.reconnect seul, #245)"; fi
  local k; for k in RECONNECT UP; do
    if hook_seen "$m" minion-child "$k"; then echo "info : $k minion-child aussi journalise par $m"; fi
  done
  [ "$conv" = connected ] && check_child_upstream
  echo "hooks apres bascule OK"
}

# Scenario relay-down (#245, T22) : l'enfant s'arrete (conteneur stoppe, PAS le maitre) -> le maitre journalise
# relay.down de dmz1 avec la raison `peer_closed:1001` (fermeture ordonnee « going away » de l'enfant, T22 : avant T22
# `peer_closed:1006`) ; puis l'enfant redemarre (nouveau processus, conn_seq 1) -> relay.up dmz1, smoke. Idempotent :
# compte les lignes avant l'action, ne depend d'aucun etat anterieur.
relay_down() {
  verify_images; need INVENTORY_BIN
  local m down0 up0 why; m="$(master)" || fail "pas de maitre sur la racine"
  connected "$m" relays dmz1 4
  down0="$(hook_count "$m" dmz1 RELAY_DOWN)"; up0="$(hook_count "$m" dmz1 RELAY_UP)"
  local rd0 hd0; rd0="$(hook_count "$m" dmz1 RELAY_DISCOVER)"; hd0="$(hook_count "$C_CHILD" minion-child DISCOVER)"
  echo "== arret de l'enfant ($C_CHILD) : relay.down dmz1 (peer_closed:1001) attendu au maitre $m"
  dc stop secagent-child >/dev/null
  wait_for "relay.down dmz1 journalise par le maitre $m" 60 hook_more "$m" dmz1 RELAY_DOWN "$down0" >/dev/null
  echo "relay.down : $(hook_last "$m" dmz1 RELAY_DOWN)"
  why="$(events_log "$m" | awk '$2=="RELAY_DOWN" && $3=="dmz1" {r=$4} END{print r}')"
  [ "$why" = "${RELAY_DOWN_REASON:-peer_closed:1001}" ] || fail "relay.down dmz1 : raison '$why' (attendu ${RELAY_DOWN_REASON:-peer_closed:1001}, T22)"
  echo "== redemarrage de l'enfant : relay.up dmz1 (nouveau processus, conn_seq 1)"
  dc start secagent-child >/dev/null
  wait_for "enfant healthy" 120 all_health healthy "$C_CHILD" >/dev/null
  connected "$m" relays dmz1 4
  wait_for "relay.up dmz1 journalise par le maitre $m" 90 hook_more "$m" dmz1 RELAY_UP "$up0" >/dev/null
  connected "$C_CHILD" minions minion-child 2
  [ "$(hook_count "$m" dmz1 RELAY_DISCOVER)" = "$rd0" ] || fail "relay.discover dmz1 au redemarrage de l'enfant (deja decouvert, #266)"
  [ "$(hook_count "$C_CHILD" minion-child DISCOVER)" = "$hd0" ] || fail "host.discover minion-child a l'enfant apres son redemarrage (etat persistant, #266)"
  smoke
  echo "relay-down OK (relay.down peer_closed:1001 puis relay.up de dmz1 au maitre $m)"
}

# Scenario converged-timeout (#246) : l'enfant est ARRETE, puis bascule a->b (arret propre) : le nouveau maitre attend dmz1
# (declare) qui ne vient pas -> UN relay.converged au delai RELAY_CONVERGENCE_TIMEOUT (qualif 30 s) avec
# relays_connected=0 relays_missing=1 (2 avec CHAIN_LEVEL3=1 : dmz2 est derriere dmz1) ; l'enfant redemarre -> relay.up
# dmz1 (nouveau processus), PAS de second converged. La bascule ne (re)demarre QUE la racine (FAILOVER_UP_SERVICES) :
# sans cela `up -d` de failover-test.sh relancait l'enfant arrete (QUALIF 2026-11-12, 09:18:11 -> 09:18:14).
converged_timeout() {
  require_ansible_version; verify_images; need INVENTORY_BIN; control_env
  local m up0 cv; m="$(master)" || fail "pas de maitre sur la racine"
  connected "$m" relays dmz1 4
  echo "== arret de l'enfant, puis bascule de la racine (dmz1 attendu mais absent)"
  dc stop secagent-child >/dev/null
  hooks_snapshot
  # attend relay.failover puis relay.converged (<= 45 s) sur le nouveau maitre ; l'enfant reste ARRETE
  FAILOVER_UP_SERVICES="secagent-server-a secagent-server-b" bash "$HERE/failover-test.sh" run stop
  ctr inspect -f '{{.State.Running}}' "$C_CHILD" 2>/dev/null | grep -qx false || fail "l'enfant a redemarre pendant la bascule (scenario invalide)"
  check_hooks_after_failover start missing
  m="$(master)" || fail "pas de maitre apres la bascule"
  up0="$(hook_count "$m" dmz1 RELAY_UP)"; cv="$(hook_count "$m" "$ROOT_RELAY_ID" CONVERGED)"
  echo "== redemarrage de l'enfant : relay.up dmz1, aucun nouveau relay.converged"
  dc start secagent-child >/dev/null
  wait_for "enfant healthy" 120 all_health healthy "$C_CHILD" >/dev/null
  connected "$m" relays dmz1 4
  wait_for "relay.up dmz1 journalise par le maitre $m" 90 hook_more "$m" dmz1 RELAY_UP "$up0" >/dev/null
  sleep 10
  [ "$(hook_count "$m" "$ROOT_RELAY_ID" CONVERGED)" = "$cv" ] || fail "second relay.converged apres le retour de dmz1 (jamais reemis, #246)"
  smoke
  echo "converged-timeout OK"
}

# Scenario rerouted (#244, cause direct puis indirect) : minion-child (enrole derriere dmz1) est re-pointe vers la racine
# (MINION_CHILD_*_URL) : le maitre journalise `REROUTED minion-child direct` (route relais -> connexion locale) ; puis retour
# derriere dmz1 : `REROUTED minion-child indirect`. L'enfant ne journalise aucun REROUTED. Docker seulement.
# Identifiants : chaque noeud signe les JWT de SES agents avec son propre secret (`state init` en tire un au hasard :
# state/init.go:89-93,114) : le JWT emis par dmz1 est refuse par la racine (401 « signature is invalid », QUALIF
# 2026-11-12) et l'inverse. A chaque re-pointage le minion est donc REENROLE aupres du noeud vise : jeton d'enrolement mine
# sur CE noeud (minion-child.env), ancien JWT retire du volume du minion (sa cle id_rsa est conservee). Le maitre doit
# avoir vu passer minion-child par dmz1 DEPUIS sa promotion (memoire des routes en RAM, relay_reroute.go:84-118) : le
# minion est d'abord redemarre derriere dmz1.
# Reenrolement d'un minion (Docker) : $1 service (minion-root|minion-child|minion-grand), $2 conteneur qui mint le jeton
# d'enrolement (le noeud qui l'accueillera ; chaque noeud signe les JWT de SES agents). Jeton ecrit dans <service>.env
# (0600, jamais affiche), JWT retire du volume <projet>_<service>_data (cle id_rsa conservee), conteneur recree.
# Les variables d'URL eventuelles (MINION_CHILD_*_URL) sont heritees de l'appelant.
minion_reenroll() {
  local svc="$1" issuer="$2" vol="${PROJECT}_${1//-/_}_data"
  adm "$issuer" tokens create --role enrollment --hostname-pattern "^$svc\$" --expires "$TOKEN_TTL" 2>&1 \
    | extract 'secagent_enr_[0-9a-f]{64}' | { read -r t || true; [ -n "$t" ] || fail "jeton $svc ($issuer) non extrait"; printf 'RELAY_ENROLLMENT_TOKEN=%s\n' "$t" | write_secret "$svc.env"; }
  dc stop "$svc" >/dev/null
  ctr run --rm -v "$vol:/d" \
    alpine:3.24@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a \
    sh -c 'rm -f /d/token.jwt' || fail "retrait du JWT de $svc impossible (volume $vol)"
  dc up -d --force-recreate --no-deps "$svc"
}
minion_child_retarget() { minion_reenroll minion-child "$1"; }   # $1 conteneur qui mint le jeton (noeud vise)
minion_child_seen_more() { [ $(( $(hook_count "$1" minion-child UP) + $(hook_count "$1" minion-child RECONNECT) )) -gt "$2" ]; }
rerouted() {
  docker_only rerouted; verify_images; need INVENTORY_BIN
  local m d0 c0 s0; m="$(master)" || fail "pas de maitre sur la racine"
  connected "$C_CHILD" minions minion-child 2
  echo "== minion-child redemarre derriere dmz1 : le maitre $m apprend sa route (memoire des routes)"
  s0=$(( $(hook_count "$m" minion-child UP) + $(hook_count "$m" minion-child RECONNECT) ))
  dc restart minion-child >/dev/null
  connected "$C_CHILD" minions minion-child 2
  wait_for "host.up/reconnect minion-child via dmz1 au maitre $m" 90 minion_child_seen_more "$m" "$s0" >/dev/null
  d0="$(hook_count "$m" minion-child REROUTED)"; c0="$(kind_count "$C_CHILD" REROUTED)"
  echo "== minion-child re-pointe vers la racine (reenrole aupres de $m) : host.rerouted direct attendu au maitre $m"
  MINION_CHILD_SERVER_URL="https://secagent-server-a:7770,https://secagent-server-b:7770" \
  MINION_CHILD_WS_URL="wss://secagent-server-a:7772/ws/agent,wss://secagent-server-b:7772/ws/agent" \
    minion_child_retarget "$m"
  connected "$m" minions minion-child 2
  wait_for "host.rerouted minion-child (direct) au maitre $m" 90 hook_more "$m" minion-child REROUTED "$d0" >/dev/null
  echo "rerouted : $(hook_last "$m" minion-child REROUTED)"
  [ "$(events_log "$m" | awk '$2=="REROUTED" && $3=="minion-child" {c=$4} END{print c}')" = direct ] || fail "host.rerouted minion-child : cause direct attendue"
  d0="$(hook_count "$m" minion-child REROUTED)"
  echo "== retour derriere dmz1 (reenrole aupres de dmz1) : host.rerouted indirect attendu au maitre $m"
  minion_child_retarget "$C_CHILD"
  connected "$C_CHILD" minions minion-child 2
  wait_for "host.rerouted minion-child (indirect) au maitre $m" 90 hook_more "$m" minion-child REROUTED "$d0" >/dev/null
  echo "rerouted : $(hook_last "$m" minion-child REROUTED)"
  [ "$(events_log "$m" | awk '$2=="REROUTED" && $3=="minion-child" {c=$4} END{print c}')" = indirect ] || fail "host.rerouted minion-child : cause indirect attendue"
  [ "$(kind_count "$C_CHILD" REROUTED)" = "$c0" ] || fail "l'enfant dmz1 a journalise un host.rerouted (aucun attendu : il n'est pas l'ancetre commun)"
  smoke
  echo "rerouted OK"
}

# Scenario upstream-queue (#246) : le lien amont de l'enfant est GELE (`pause` du maitre de la racine). Tant que l'enfant
# croit ce lien vivant (jusqu'a l'expiration du delai de lecture, 3 x PingInterval = 90 s : repeater/client.go:52,54,
# uplink.go:158), ce qu'il produit part sur la socket et est PERDU EN VOL a la fermeture (« au plus une fois »,
# documente, correction v3.0.7 : _work/reports/dev-relay-qualif-upstream-queue-20261112.md). Le scenario attend donc
# que l'enfant voie son lien amont NON connecte (`server status` : LINK upstream, STATE != connected) AVANT les cycles :
# tout ce qui suit passe par la file amont. Puis UPSTREAM_CYCLES (defaut 6) (de)connexions de minion-child, `unpause` :
# STRICT : la file a servi (profondeur > 0), le maitre journalise toutes les UP/DOWN, 0 perte (upstream_dropped_events).
# Duree du gel bornee par UPSTREAM_PAUSE_MAX_S (defaut 120 s, plafond 130 s) : le maitre gele ne bat plus et se retire
# (SelfRetire, 180 s apres son DERNIER battement reussi, lock/params.go:54) ; ce battement peut dater de 30 s (Beat) avant
# le gel : la marge reelle est donc 180 - 30 = 150 s, moins un cycle (~7 s) et une marge. La borne est testee AVANT
# chaque cycle avec la duree estimee du cycle (la plus longue observee, 10 s au depart) : aucun cycle ne la depasse
# (QA r3 : 141 s observes, jusqu'a ~147 s possibles avec l'ancien test). Detection mesuree : 71-78 s.
# Variante UPSTREAM_QUEUE_SIZE=<n> (>= 256) : enfant recree avec une file de n (capacite verifiee). Une perte n'est
# OBSERVABLE que si 2 x cycles faits > n ; dans la fenetre du gel (~8 cycles apres la detection) ce n'est PAS atteignable
# pour n=256 (il faudrait > 128 cycles) : la variante verifie alors capacite = n et 0 perte, et la preuve du debordement
# reste le test d'integration (6) de T19. Meme regle de detection du lien coupe que le cas nominal.
upstream_link_state() { # $1 conteneur : etat du lien amont (connected | retrying | refused_permanent ; vide si absent)
  { adm "$1" server status 2>/dev/null || true; } | upstream_state_from_status
}
upstream_link_down() { local st; st="$(upstream_link_state "$1")"; [ -n "$st" ] && [ "$st" != connected ]; }
upstream_queue() {
  verify_images; need INVENTORY_BIN
  local m cycles="${UPSTREAM_CYCLES:-6}" qs="${UPSTREAM_QUEUE_SIZE:-}" pmax="${UPSTREAM_PAUSE_MAX_S:-120}" i ndone=0 t0 td tc dc_max=10 d c x x0 dmax=0 up0 dn0 e0 st
  [[ $cycles =~ ^[1-9][0-9]{0,3}$ ]] || refuse "UPSTREAM_CYCLES='$cycles' invalide"
  [[ $pmax =~ ^[1-9][0-9]{1,2}$ ]] && [ "$pmax" -le 130 ] || refuse "UPSTREAM_PAUSE_MAX_S='$pmax' invalide (10..130 s : retrait du maitre gele possible des 150 s)"
  m="$(master)" || fail "pas de maitre sur la racine"
  if [ -n "$qs" ]; then
    [[ $qs =~ ^[0-9]{3,6}$ ]] && [ "$qs" -ge 256 ] || refuse "UPSTREAM_QUEUE_SIZE='$qs' invalide (>= 256)"
    echo "== variante : file amont de l'enfant a $qs"
    CHILD_UPSTREAM_QUEUE_SIZE="$qs" recreate_child
  fi
  connected "$m" relays dmz1 4; connected "$C_CHILD" minions minion-child 2
  st="$(upstream_link_state "$C_CHILD")"; [ "$st" = connected ] || fail "lien amont de l'enfant '$st' avant le gel (connected attendu)"
  read -r d c x0 < <(upstream_counters "$C_CHILD"); [ -n "$c" ] || fail "compteurs upstream_* absents de l'enfant"
  echo "file amont avant : profondeur=$d capacite=$c perdus=$x0"
  [ -z "$qs" ] || [ "$c" = "$qs" ] || fail "capacite de la file amont de l'enfant = $c (attendu $qs)"
  e0="$(upstream_dropped_entries "$C_CHILD")"
  echo "== gel du lien amont (pause de $m) ; attente que l'enfant voie le lien coupe (<= 90 s + marge)"
  ctr pause "$m" >/dev/null; t0=$(now)
  trap 'ctr unpause "'"$m"'" >/dev/null 2>&1 || true' EXIT   # jamais un maitre laisse gele sur un echec
  while ! upstream_link_down "$C_CHILD"; do
    if awk -v a="$t0" -v b="$(now)" -v m="$pmax" 'BEGIN{exit !(b-a>m)}'; then
      ctr unpause "$m" >/dev/null; trap - EXIT
      fail "l'enfant voit toujours son lien amont connected apres ${pmax}s de gel (detection attendue vers 90 s)"
    fi
    sleep 2
  done
  td=$(now)
  echo "lien amont vu coupe par l'enfant apres $(awk -v a="$t0" -v b="$td" 'BEGIN{printf "%.0f", b-a}') s (etat $(upstream_link_state "$C_CHILD")) : $cycles (de)connexions de minion-child"
  # compteurs du maitre RELEVES MAINTENANT : ce qui a ete produit avant la detection peut etre perdu en vol (documente)
  up0="$(hook_count "$m" minion-child UP)"; dn0="$(hook_count "$m" minion-child DOWN)"
  for i in $(seq 1 "$cycles"); do
    # le cycle ne commence que s'il FINIT avant la borne (duree estimee = la plus longue observee)
    cycle_fits "$(awk -v a="$t0" -v b="$(now)" 'BEGIN{print b-a}')" "$dc_max" "$pmax" \
      || { echo "info : gel borne a ${pmax}s, arret apres $((i - 1)) cycle(s) (cycle estime ${dc_max}s)"; break; }
    tc=$(now)
    dc stop minion-child >/dev/null; dc start minion-child >/dev/null
    connected "$C_CHILD" minions minion-child 2
    dc_max="$(awk -v a="$tc" -v b="$(now)" -v m="$dc_max" 'BEGIN{d=b-a; printf "%.0f", (d>m ? d+0.5 : m)}')"
    ndone=$i
    read -r d _ _ < <(upstream_counters "$C_CHILD"); [ "${d:-0}" -gt "$dmax" ] && dmax="${d:-0}"
  done
  ctr unpause "$m" >/dev/null; trap - EXIT
  echo "file amont pendant le gel : profondeur max observee $dmax (cycles faits : $ndone, gel $(awk -v a="$t0" -v b="$(now)" 'BEGIN{printf "%.0f", b-a}') s)"
  [ "$ndone" -gt 0 ] || fail "aucun cycle dans la fenetre du gel (detection trop tardive) : scenario non concluant"
  [ "$dmax" -gt 0 ] || fail "file amont restee vide alors que le lien etait vu coupe (les evenements devaient y entrer)"
  if [ -z "$qs" ] || [ $((2 * ndone)) -le "$qs" ]; then
    wait_for "UP minion-child rejoues au maitre $m" 180 hook_more "$m" minion-child UP $((up0 + ndone - 1)) >/dev/null
    wait_for "DOWN minion-child rejoues au maitre $m" 180 hook_more "$m" minion-child DOWN $((dn0 + ndone - 1)) >/dev/null
    for i in $(seq 1 60); do [ "$(upstream_counters "$C_CHILD" | awk '{print $1}')" = 0 ] && break; sleep 2; done
    read -r d c x < <(upstream_counters "$C_CHILD")
    [ "$d" = 0 ] || fail "file amont de l'enfant non videe apres le degel (profondeur $d)"
    [ "$x" = "$x0" ] || fail "upstream_dropped_events de l'enfant : $x0 -> $x (aucune perte attendue)"
    [ -z "$qs" ] || echo "info : variante $qs : $((2 * ndone)) evenements <= $qs, debordement non atteignable dans le gel (preuve : test d'integration (6))"
    echo "file amont apres : profondeur=$d capacite=$c perdus=$x ; maitre : +$(( $(hook_count "$m" minion-child UP) - up0 )) UP, +$(( $(hook_count "$m" minion-child DOWN) - dn0 )) DOWN"
  else
    sleep 30
    read -r d c x < <(upstream_counters "$C_CHILD")
    [ "$x" -gt "$x0" ] || fail "file a $qs, $((2 * ndone)) evenements : aucune perte comptee (upstream_dropped_events $x0 -> $x)"
    local e1; e1="$(upstream_dropped_entries "$C_CHILD")"
    [ $((e1 - e0)) -ge 1 ] || fail "aucune entree upstream_dropped dans hooks log de l'enfant"
    echo "pertes comptees : $x0 -> $x ; entrees upstream_dropped : +$((e1 - e0))"
  fi
  if [ -n "$qs" ]; then echo "== retour a la file par defaut"; recreate_child; connected "$m" relays dmz1 4; fi
  smoke
  echo "upstream-queue OK"
}

# Scenario relay-rerouted (#244, 3e niveau) : dmz2 (derriere dmz1) est re-pointe directement vers la racine (declaration
# sur la racine + jeton --aud <racine>) -> le maitre journalise `RELAY_REROUTED dmz2 old_chain=dmz1,dmz2 new_chain=dmz2`
# (et aucun host.rerouted de minion-grand) ; puis retour derriere dmz1 (nouveau RELAY_REROUTED).
relay_rerouted() {
  need_level3 relay-rerouted; verify_images; need INVENTORY_BIN
  local m r0 h0 rid; m="$(master)" || fail "pas de maitre sur la racine"
  rid="$(cat "$CHAIN_DIR/root-id")" || fail "chain/root-id absent"
  connected "$C_CHILD" relays dmz2 4
  r0="$(hook_count "$m" dmz2 RELAY_REROUTED)"; h0="$(hook_count "$m" minion-grand REROUTED)"
  echo "== dmz2 re-pointe vers la racine : declaration sur la racine, jeton --aud $rid"
  adm "$m" relays add --id dmz2 --description "grandchild rerouted" >/dev/null 2>&1 || true   # deja declare : sans effet
  link_mint_grand "$m" "$rid"
  GRANDCHILD_UPSTREAM_URL="wss://secagent-server-a:7772,wss://secagent-server-b:7772" recreate_grand
  connected "$m" relays dmz2 4
  wait_for "relay.rerouted dmz2 au maitre $m" 90 hook_more "$m" dmz2 RELAY_REROUTED "$r0" >/dev/null
  echo "relay-rerouted : $(hook_last "$m" dmz2 RELAY_REROUTED)"
  [ "$(hook_last_kv "$m" dmz2 RELAY_REROUTED old_chain)" = "dmz1,dmz2" ] && [ "$(hook_last_kv "$m" dmz2 RELAY_REROUTED new_chain)" = dmz2 ] \
    || fail "relay.rerouted dmz2 : old_chain=dmz1,dmz2 new_chain=dmz2 attendus"
  [ "$(hook_count "$m" minion-grand REROUTED)" = "$h0" ] || fail "host.rerouted minion-grand journalise (reparent => relay.rerouted seul, #244)"
  r0="$(hook_count "$m" dmz2 RELAY_REROUTED)"
  echo "== retour de dmz2 derriere dmz1 (jeton --aud dmz1)"
  link_mint_grand "$m" dmz1
  recreate_grand
  connected "$C_CHILD" relays dmz2 4
  wait_for "relay.rerouted dmz2 (retour) au maitre $m" 90 hook_more "$m" dmz2 RELAY_REROUTED "$r0" >/dev/null
  echo "relay-rerouted : $(hook_last "$m" dmz2 RELAY_REROUTED)"
  [ "$(hook_count "$m" minion-grand REROUTED)" = "$h0" ] || fail "host.rerouted minion-grand journalise au retour"
  # Pas de `relays remove dmz2` : la racine reenregistre dmz2 a chaque snapshot de dmz1 (relay_handler.go:1707-1712) et
  # les relay.converged a 3 niveaux le comptent deja (expected_relays) ; le retrait serait sans effet, voire refuse.
  smoke
  echo "relay-rerouted OK"
}

# Scenario failover-3-levels (#225, 3e niveau) : redemarrage de dmz2 -> son relay.failover (cause start) est propage
# dmz2 -> dmz1 -> racine et journalise par le MAITRE de la racine ; dmz1 journalise relay.up dmz2 (nouveau processus).
failover_3_levels() {
  need_level3 failover-3-levels; verify_images; need INVENTORY_BIN
  local m f0 u0; m="$(master)" || fail "pas de maitre sur la racine"
  connected "$C_CHILD" relays dmz2 4
  f0="$(hook_count "$m" dmz2 FAILOVER)"; u0="$(hook_count "$C_CHILD" dmz2 RELAY_UP)"
  local rd0; rd0="$(hook_count "$C_CHILD" dmz2 RELAY_DISCOVER)"
  echo "== redemarrage de dmz2 : relay.failover dmz2 attendu au maitre de la racine $m (via dmz1)"
  dc restart secagent-grandchild >/dev/null
  wait_for "petit-enfant dmz2 healthy" 120 all_health healthy "$C_GRAND" >/dev/null
  wait_for "relay.failover dmz2 journalise par la racine ($m)" 90 hook_more "$m" dmz2 FAILOVER "$f0" >/dev/null
  echo "failover-3-levels : $(hook_last "$m" dmz2 FAILOVER)"
  [ "$(events_log "$m" | awk '$2=="FAILOVER" && $3=="dmz2" {c=$4} END{print c}')" = start ] || fail "relay.failover dmz2 : cause start attendue"
  wait_for "relay.up dmz2 journalise par dmz1" 90 hook_more "$C_CHILD" dmz2 RELAY_UP "$u0" >/dev/null
  connected "$C_CHILD" relays dmz2 4
  [ "$(hook_count "$C_CHILD" dmz2 RELAY_DISCOVER)" = "$rd0" ] || fail "relay.discover dmz2 au redemarrage de dmz2 (deja decouvert, #266)"
  smoke
  echo "failover-3-levels OK"
}

# Scenario lost-during-failover (#247, option A) : kill du maitre, puis minion-root ARRETE pendant la fenetre de reprise
# (peremption du verrou, 5 min) : le nouveau maitre ne journalise AUCUN host.down de minion-root (agent direct tombe
# pendant la fenetre : perte documentee, HOOKS_SPEC §9b) ; au redemarrage du minion : host.up (nouveau processus).
lost_during_failover() {
  require_ansible_version; verify_images; need INVENTORY_BIN; control_env
  local m s dn0 up0 t
  m="$(master)" || fail "pas de maitre sur la racine"
  if [ "$m" = "$C_A" ]; then s="$C_B"; else s="$C_A"; fi
  connected "$m" minions minion-root 2
  dn0="$(hook_count "$s" minion-root DOWN)"; up0="$(hook_count "$s" minion-root UP)"
  local di0; di0="$(kind_count "$s" DISCOVER)"
  echo "== kill du maitre $m, puis arret de minion-root pendant la fenetre de reprise"
  ctr kill "$m" >/dev/null
  dc stop minion-root >/dev/null
  t=$(wait_for "reprise par $s" "$KILL_MAX_S" is_master "$s")
  echo "reprise par $s en ${t}s"
  wait_for "relay.failover (takeover) de $s" 60 hook_seen "$s" "$ROOT_RELAY_ID" FAILOVER takeover >/dev/null
  wait_for "relay.converged de $s" 60 hook_seen "$s" "$ROOT_RELAY_ID" CONVERGED >/dev/null
  sleep 15
  [ "$(hook_count "$s" minion-root DOWN)" = "$dn0" ] || fail "host.down minion-root journalise par $s (aucun attendu : agent tombe pendant la fenetre, #247 option A)"
  echo "aucun host.down minion-root au nouveau maitre (conforme a #247 option A)"
  dc start minion-root >/dev/null
  wait_for "host.up minion-root (nouveau processus) au nouveau maitre $s" 150 hook_more "$s" minion-root UP "$up0" >/dev/null
  [ "$(kind_count "$s" DISCOVER)" = "$di0" ] || fail "host.discover au nouveau maitre $s (aucun attendu : deja decouvert, #266)"
  ctr start "$m" >/dev/null
  wait_for "ancien maitre healthy" 120 all_health healthy "$m" >/dev/null
  is_silent "$m" || fail "l'ancien maitre ecoute alors qu'il y a un maitre"
  smoke
  echo "lost-during-failover OK"
}

# --- Cycle de vie d'inventaire LOT-3.3 (#266) : host.removed / relay.removed, aucun sur une revocation -------------------
# Les compteurs sont releves AVANT chaque action (journaux persistants). host.deleted est DEPRECIE (v3.0.6, retire en
# v3.0.7) : hooks.json s'y abonne expres, ce qui doit produire au chargement le [WARN] « deprecated since v3.0.6 » ;
# il reste LOCAL (non propage).

# Scenario removed : suppression de minion-root (agent direct) au maitre -> REMOVED minion-root deleted + DELETED (local) ;
# puis reenrolement -> DISCOVER minion-root (nouveau first_seen) AVANT UP. Docker seulement (reenrolement).
removed() {
  docker_only removed; verify_images; need INVENTORY_BIN
  local m r0 x0 d0 u0 fs0; m="$(master)" || fail "pas de maitre sur la racine"
  connected "$m" minions minion-root 2
  r0="$(hook_count "$m" minion-root REMOVED)"; x0="$(hook_count "$m" minion-root DELETED)"
  d0="$(hook_count "$m" minion-root DISCOVER)"; u0="$(hook_count "$m" minion-root UP)"
  fs0="$(hook_last_kv "$m" minion-root DISCOVER first_seen)"
  echo "== suppression de minion-root au maitre $m : host.removed (deleted) + host.deleted (deprecie, local)"
  adm "$m" minions delete minion-root --yes >/dev/null || fail "minions delete minion-root refuse"
  wait_for "host.removed minion-root au maitre $m" 30 hook_more "$m" minion-root REMOVED "$r0" >/dev/null
  echo "removed : $(hook_last "$m" minion-root REMOVED)"
  [ "$(events_log "$m" | awk '$2=="REMOVED" && $3=="minion-root" {c=$4} END{print c}')" = deleted ] || fail "host.removed minion-root : cause deleted attendue"
  wait_for "host.deleted minion-root (deprecie) au maitre $m" 30 hook_more "$m" minion-root DELETED "$x0" >/dev/null
  { adm "$m" minions list 2>/dev/null || true; } | awk '$1=="minion-root" {f=1} END{exit f}' || fail "minion-root encore dans minions list apres la suppression"
  echo "== reenrolement de minion-root : host.discover (nouveau first_seen) puis host.up"
  minion_reenroll minion-root "$m"
  connected "$m" minions minion-root 2
  wait_for "host.discover minion-root (reenrole) au maitre $m" 90 hook_more "$m" minion-root DISCOVER "$d0" >/dev/null
  wait_for "host.up minion-root (reenrole) au maitre $m" 90 hook_more "$m" minion-root UP "$u0" >/dev/null
  events_log "$m" | awk -v d="$d0" -v u="$u0" '$3=="minion-root" && $2=="DISCOVER" {nd++; if (nd==d+1) id=NR} $3=="minion-root" && $2=="UP" {nu++; if (nu==u+1) iu=NR} END{exit !(id && iu && id<iu)}' \
    || fail "host.discover du reenrolement apres son host.up au maitre $m"
  [ "$(hook_last_kv "$m" minion-root DISCOVER first_seen)" != "$fs0" ] || fail "first_seen de minion-root inchange apres suppression et reenrolement (nouveau noeud attendu)"
  smoke
  echo "removed OK"
}

# Scenario removed-indirect : suppression de minion-child chez l'enfant dmz1 -> enfant : REMOVED + DELETED ; maitre :
# REMOVED minion-child deleted chain=dmz1 (propage) et AUCUN DELETED (local) ; reenrolement -> DISCOVER a l'enfant ET au
# maitre. Docker seulement.
removed_indirect() {
  docker_only removed-indirect; verify_images; need INVENTORY_BIN
  local m cr0 cx0 mr0 mx0 cd0 md0; m="$(master)" || fail "pas de maitre sur la racine"
  connected "$C_CHILD" minions minion-child 2
  cr0="$(hook_count "$C_CHILD" minion-child REMOVED)"; cx0="$(hook_count "$C_CHILD" minion-child DELETED)"
  mr0="$(hook_count "$m" minion-child REMOVED)"; mx0="$(hook_count "$m" minion-child DELETED)"
  cd0="$(hook_count "$C_CHILD" minion-child DISCOVER)"; md0="$(hook_count "$m" minion-child DISCOVER)"
  echo "== suppression de minion-child chez dmz1 : removed a l'enfant et au maitre (propage), deleted a l'enfant seulement"
  adm "$C_CHILD" minions delete minion-child --yes >/dev/null || fail "minions delete minion-child (dmz1) refuse"
  wait_for "host.removed minion-child chez dmz1" 30 hook_more "$C_CHILD" minion-child REMOVED "$cr0" >/dev/null
  wait_for "host.deleted minion-child chez dmz1" 30 hook_more "$C_CHILD" minion-child DELETED "$cx0" >/dev/null
  wait_for "host.removed minion-child propage au maitre $m" 60 hook_more "$m" minion-child REMOVED "$mr0" >/dev/null
  echo "removed-indirect : $(hook_last "$m" minion-child REMOVED)"
  [ "$(hook_last_kv "$m" minion-child REMOVED chain)" = dmz1 ] || fail "host.removed minion-child au maitre : chain=dmz1 attendu"
  sleep 5
  [ "$(hook_count "$m" minion-child DELETED)" = "$mx0" ] || fail "host.deleted minion-child au maitre (local a dmz1, jamais propage)"
  echo "== reenrolement de minion-child chez dmz1 : host.discover a l'enfant et au maitre"
  minion_reenroll minion-child "$C_CHILD"
  connected "$C_CHILD" minions minion-child 2
  wait_for "host.discover minion-child (reenrole) chez dmz1" 90 hook_more "$C_CHILD" minion-child DISCOVER "$cd0" >/dev/null
  wait_for "host.discover minion-child (reenrole) au maitre $m" 90 hook_more "$m" minion-child DISCOVER "$md0" >/dev/null
  smoke
  echo "removed-indirect OK"
}

# Scenario revoke-no-removed : une REVOCATION n'est pas une suppression : `minions revoke minion-root` au maitre puis
# `relays revoke dmz2` chez dmz1 (3 niveaux) -> AUCUN REMOVED ni RELAY_REMOVED (relay.down reason=revoked chez dmz1).
# Remise en etat ensuite (suppression + reenrolement de minion-root ; dmz2 retire, re-declare, nouveau jeton, recree) :
# ces suppressions-la emettent bien removed, releve APRES la verification.
revoke_no_removed() {
  docker_only revoke-no-removed; verify_images; need INVENTORY_BIN
  local m c rm0 rr0 cr0 crr0 dd0; m="$(master)" || fail "pas de maitre sur la racine"
  connected "$m" minions minion-root 2
  rm0="$(kind_count "$m" REMOVED)"; rr0="$(kind_count "$m" RELAY_REMOVED)"
  cr0="$(kind_count "$C_CHILD" REMOVED)"; crr0="$(kind_count "$C_CHILD" RELAY_REMOVED)"
  dd0="$(hook_count "$C_CHILD" dmz2 RELAY_DOWN)"
  echo "== revocation de minion-root au maitre $m"
  adm "$m" minions revoke minion-root >/dev/null || fail "minions revoke minion-root refuse"
  if level3; then
    echo "== revocation de dmz2 chez dmz1 : relay.down revoked attendu chez dmz1"
    connected "$C_CHILD" relays dmz2 4
    adm "$C_CHILD" relays revoke dmz2 --yes >/dev/null || fail "relays revoke dmz2 (dmz1) refuse"
    wait_for "relay.down dmz2 chez dmz1" 60 hook_more "$C_CHILD" dmz2 RELAY_DOWN "$dd0" >/dev/null
    echo "relay.down : $(hook_last "$C_CHILD" dmz2 RELAY_DOWN)"
    [ "$(events_log "$C_CHILD" | awk '$2=="RELAY_DOWN" && $3=="dmz2" {r=$4} END{print r}')" = revoked ] || fail "relay.down dmz2 : raison revoked attendue"
  fi
  sleep 10
  for c in "$m" "$C_CHILD"; do
    [ "$(kind_count "$c" REMOVED)" = "$([ "$c" = "$m" ] && echo "$rm0" || echo "$cr0")" ] || fail "host.removed apres une revocation sur $c (aucun attendu, #266)"
    [ "$(kind_count "$c" RELAY_REMOVED)" = "$([ "$c" = "$m" ] && echo "$rr0" || echo "$crr0")" ] || fail "relay.removed apres une revocation sur $c (aucun attendu, #266)"
  done
  echo "aucun removed apres les revocations (conforme a #266)"
  echo "== remise en etat"
  adm "$m" minions delete minion-root --yes >/dev/null || fail "minions delete minion-root (remise en etat) refuse"
  minion_reenroll minion-root "$m"
  connected "$m" minions minion-root 2
  if level3; then grand_redeclare; fi
  smoke
  echo "revoke-no-removed OK"
}
# dmz2 revoque ou supprime chez dmz1 : retire (si encore declare), re-declare, nouveau jeton (racine, --aud dmz1), recree.
grand_redeclare() {
  local m; m="$(master)" || fail "pas de maitre sur la racine"
  adm "$C_CHILD" relays remove dmz2 --yes >/dev/null 2>&1 || true
  adm "$C_CHILD" relays add --id dmz2 --description "chain grandchild" >/dev/null || fail "relays add dmz2 (sur dmz1) refuse"
  link_mint_grand "$m" dmz1
  recreate_grand
  connected "$C_CHILD" relays dmz2 4
}

# Scenario relay-removed (3 niveaux) : chez dmz1, `relays revoke dmz2` puis `relays remove dmz2` -> dmz1 : RELAY_REMOVED
# dmz2 deleted mode=pull et RELAY_DOWN dmz2 revoked ; maitre : RELAY_REMOVED dmz2 propage ; AUCUN REMOVED minion-grand
# (pas de cascade, Q4). Puis re-declaration + recreation : RELAY_DISCOVER dmz2 a nouveau chez dmz1 (nouveau noeud) puis
# RELAY_UP.
relay_removed() {
  need_level3 relay-removed; verify_images; need INVENTORY_BIN
  local m crr0 mrr0 dd0 g0 mg0 rd0 ru0; m="$(master)" || fail "pas de maitre sur la racine"
  connected "$C_CHILD" relays dmz2 4
  crr0="$(hook_count "$C_CHILD" dmz2 RELAY_REMOVED)"; mrr0="$(hook_count "$m" dmz2 RELAY_REMOVED)"
  dd0="$(hook_count "$C_CHILD" dmz2 RELAY_DOWN)"
  g0="$(hook_count "$C_CHILD" minion-grand REMOVED)"; mg0="$(hook_count "$m" minion-grand REMOVED)"
  rd0="$(hook_count "$C_CHILD" dmz2 RELAY_DISCOVER)"; ru0="$(hook_count "$C_CHILD" dmz2 RELAY_UP)"
  echo "== chez dmz1 : revocation puis suppression de dmz2"
  adm "$C_CHILD" relays revoke dmz2 --yes >/dev/null || fail "relays revoke dmz2 (dmz1) refuse"
  adm "$C_CHILD" relays remove dmz2 --yes >/dev/null || fail "relays remove dmz2 (dmz1) refuse"
  wait_for "relay.removed dmz2 chez dmz1" 30 hook_more "$C_CHILD" dmz2 RELAY_REMOVED "$crr0" >/dev/null
  echo "relay-removed : $(hook_last "$C_CHILD" dmz2 RELAY_REMOVED)"
  [ "$(events_log "$C_CHILD" | awk '$2=="RELAY_REMOVED" && $3=="dmz2" {c=$4} END{print c}')" = deleted ] || fail "relay.removed dmz2 : cause deleted attendue"
  [ "$(hook_last_kv "$C_CHILD" dmz2 RELAY_REMOVED mode)" = pull ] || fail "relay.removed dmz2 : mode=pull attendu"
  wait_for "relay.down dmz2 (revoked) chez dmz1" 60 hook_more "$C_CHILD" dmz2 RELAY_DOWN "$dd0" >/dev/null
  wait_for "relay.removed dmz2 propage au maitre $m" 60 hook_more "$m" dmz2 RELAY_REMOVED "$mrr0" >/dev/null
  sleep 5
  [ "$(hook_count "$C_CHILD" minion-grand REMOVED)" = "$g0" ] && [ "$(hook_count "$m" minion-grand REMOVED)" = "$mg0" ] \
    || fail "host.removed minion-grand apres relay.removed dmz2 (pas de cascade, #266 Q4)"
  echo "== re-declaration de dmz2 : relay.discover (nouveau noeud) puis relay.up chez dmz1"
  grand_redeclare
  wait_for "relay.discover dmz2 (re-declare) chez dmz1" 90 hook_more "$C_CHILD" dmz2 RELAY_DISCOVER "$rd0" >/dev/null
  wait_for "relay.up dmz2 (re-declare) chez dmz1" 90 hook_more "$C_CHILD" dmz2 RELAY_UP "$ru0" >/dev/null
  smoke
  echo "relay-removed OK"
}

# Scenario rollback-refused (optionnel) : l'etat v3.0.6 du maitre (avec first_seen_at) est REFUSE par `state verify` d'un
# serveur v3.0.5 (decodeur strict) : prouve la regle de retour arriere de DEPLOYMENT.md (restaurer la sauvegarde d'avant
# montee). ROLLBACK_IMAGE obligatoire (image serveur v3.0.5 epinglee par digest, jamais devinee ici). Copie de l'etat dans
# un volume jetable (10001, 0400), jamais sur le poste ; rien n'est ecrit dans l'etat vivant. Docker seulement.
rollback_refused() {
  docker_only rollback-refused; need ROLLBACK_IMAGE
  [[ $ROLLBACK_IMAGE =~ @sha256:[0-9a-f]{64}$ ]] || refuse "ROLLBACK_IMAGE='$ROLLBACK_IMAGE' : reference epinglee par digest attendue (<image>:v3.0.5@sha256:<64 hex>)"
  local vol="${PROJECT}_rollback_probe" out rc=0
  ctr volume create "$vol" >/dev/null
  # shellcheck disable=SC2064   # vol fixe ici
  trap "ctr volume rm '$vol' >/dev/null 2>&1 || true" EXIT
  ctr run --rm -v "${PROJECT}_secagent_state:/data:ro" -v "$vol:/b" \
    alpine:3.24@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a \
    sh -c 'set -e; cp /data/relay.state /b/relay.state; chown 10001:10001 /b/relay.state; chmod 0400 /b/relay.state' \
    || fail "copie de relay.state impossible"
  out="$(ctr run --rm --user 10001:10001 -v "${SECAGENT_SECRETS_VOLUME:-${PROJECT}_secrets}:/run/secagent-secrets:ro" -v "$vol:/b:ro" \
    -e RSA_MASTER_KEY_FILE=/run/secagent-secrets/rsa_master_key "$ROLLBACK_IMAGE" state verify /b/relay.state 2>&1)" || rc=$?
  ctr volume rm "$vol" >/dev/null 2>&1 || true; trap - EXIT
  printf '%s\n' "$out" | tail -5
  [ "$rc" != 0 ] || fail "state verify v3.0.5 a ACCEPTE un etat v3.0.6 avec first_seen_at (retour arriere non bloque)"
  printf '%s' "$out" | grep -q first_seen_at || fail "state verify v3.0.5 refuse (code $rc) sans citer first_seen_at"
  echo "rollback-refused OK (v3.0.5 refuse l'etat v3.0.6 : code $rc, first_seen_at cite)"
}

# --- Essai CA negatif (#197 item 2) : service Compose `minion-negca`, profil `negative` -----------------------------
negative_ca() {
  verify_images
  local m; m="$(master)" || fail "pas de maitre sur la racine"
  echo "== minion sans la CA privee (store systeme seul) : doit etre REFUSE"
  dc --profile negative up -d --no-deps minion-negca
  local ok=0
  for _ in $(seq 1 30); do
    if dc --profile negative logs minion-negca 2>&1 | grep -Eiq 'x509|certificate|unknown authority'; then ok=1; break; fi
    sleep 2
  done
  local listed=0
  adm "$m" minions list 2>/dev/null | awk '$1=="minion-negca" {f=1} END{exit !f}' && listed=1
  dc --profile negative rm -sf minion-negca >/dev/null
  [ "$ok" = 1 ] || fail "negative-ca : aucune erreur de certificat dans les logs de minion-negca (60 s)"
  [ "$listed" = 0 ] || fail "negative-ca : minion-negca figure dans minions list malgre l'absence de CA"
  echo "negative-ca OK (erreur de certificat, minion absent de la liste)"
}

failover() { # $1 stop (defaut : arret propre) | kill (crash : reprise apres peremption du verrou, MasterStale 5 min)
  local mode="${1:-stop}"
  require_ansible_version   # #249 : avant l'arret du maitre (smoke le reverifie)
  verify_images
  need INVENTORY_BIN
  control_env
  # L'enfant et les minions doivent se reconnecter par leurs listes, ping OK ensuite.
  hooks_snapshot   # compteurs du journal des hooks AVANT la bascule (journaux persistants)
  # failover-test.sh herite de COMPOSE_FILE / COMPOSE_OVERRIDES (hooks) : il verifie aussi relay.failover sur le nouveau
  # maitre (cause start apres stop, takeover apres kill)
  bash "$HERE/failover-test.sh" run "$mode"
  smoke
  check_hooks_after_failover "$([ "$mode" = kill ] && echo takeover || echo start)"
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  case "${1:-}" in
    ci-prepare) ci_prepare ;;
    paths) chain_paths ;;
    bootstrap) bootstrap ;;
    smoke) smoke ;;
    failover) failover stop ;;
    failover-kill) failover kill ;;
    backup-restore) backup_restore ;;
    logs) dc logs --tail=100 ;;
    load-images) load_images "${2:-}" ;;
    push-tls) push_tls ;;
    push-hooks) push_hooks ;;
    push-events) push_events ;;
    push-secrets) push_secrets ;;
    push-link-key) push_link_key ;;
    link-rotation) link_rotation ;;
    link-revoke) link_revoke ;;
    hooks) check_hooks ;;
    relay-down) relay_down ;;
    converged-timeout) converged_timeout ;;
    rerouted) rerouted ;;
    upstream-queue) upstream_queue ;;
    relay-rerouted) relay_rerouted ;;
    failover-3-levels) failover_3_levels ;;
    lost-during-failover) lost_during_failover ;;
    removed) removed ;;
    removed-indirect) removed_indirect ;;
    revoke-no-removed) revoke_no_removed ;;
    relay-removed) relay_removed ;;
    rollback-refused) rollback_refused ;;
    negative-ca) negative_ca ;;
    admission-503) admission_503 ;;
    down) guard_project
          if [ "$CONTAINER_CLI" = podman ]; then
            # JAMAIS `down -v` sous Podman : etat et secrets sont des volumes lies au partage PRIVATE (#267)
            dc down
            # shellcheck disable=SC2046   # events_volumes : noms sans espace
            for CTR_NODE in A B; do ctr volume rm "$SECAGENT_LINK_VOLUME" "$SECAGENT_HOOKS_VOLUME" $(events_volumes) >/dev/null 2>&1 || true; done
          else
            export COMPOSE_PROFILES=level3   # retire aussi dmz2 et minion-grand, meme sans CHAIN_LEVEL3=1
            dc down -v
            # le volume du jeton de lien est EXTERNE (non supprime par down -v) et contient un secret : retrait explicite
            # shellcheck disable=SC2046   # events_volumes : noms sans espace
            ctr volume rm "$SECAGENT_LINK_VOLUME" "$SECAGENT_LINK_GRAND_VOLUME" "$SECAGENT_HOOKS_VOLUME" "$SECAGENT_SECRETS_VOLUME" $(events_volumes) >/dev/null 2>&1 || true
          fi
          chain_dir_clean ;;   # jetons volatils du poste (garde chain_dir_check avant tout rm)
    *) sed -n '2,53p' "$0"; exit 2 ;;
  esac
fi
