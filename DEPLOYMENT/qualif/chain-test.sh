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
#   chain-test.sh relay-down   # arret puis redemarrage de l'enfant : relay.down puis relay.up de dmz1 au maitre (#245), smoke
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
C_A="secagent-qualif-a"; C_B="secagent-qualif-b"; C_CHILD="secagent-qualif-child"
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
extract() { grep -oE "$1" | tail -1; }   # extrait un jeton de la sortie du CLI sans l'afficher
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
EVENTS_SUFFIXES="a b child"
push_events() {
  local CTR_NODE sfx; for CTR_NODE in $(nodes); do   # Podman : les trois volumes sur chaque noeud (seuls ceux du noeud servent)
    for sfx in $EVENTS_SUFFIXES; do
      ctr volume create "$SECAGENT_EVENTS_VOLUME-$sfx" >/dev/null
      ctr run --rm "${RUN_USERNS[@]}" -v "$SECAGENT_EVENTS_VOLUME-$sfx:/events" \
        alpine:3.24@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a \
        sh -c 'set -e; chown 10001:10001 /events; chmod 0700 /events; [ ! -e /events/events.log ] || chown 10001:10001 /events/events.log'
    done
    echo "volumes du journal des hooks prets : $SECAGENT_EVENTS_VOLUME-{a,b,child}${CTR_NODE:+ (noeud $CTR_NODE)}"
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
  bash "$HERE/pki/gen.sh" "$QUALIF_TLS_DIR"
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
    | extract 'secagent_enr_[0-9a-f]{64}' | { read -r t; [ -n "$t" ] || fail "jeton minion-root non extrait"; printf 'RELAY_ENROLLMENT_TOKEN=%s\n' "$t" | write_secret minion-root.env; }
  adm "$C_CHILD" tokens create --role enrollment --hostname-pattern '^minion-child$' --expires "$TOKEN_TTL" 2>&1 \
    | extract 'secagent_enr_[0-9a-f]{64}' | { read -r t; [ -n "$t" ] || fail "jeton minion-child non extrait"; printf 'RELAY_ENROLLMENT_TOKEN=%s\n' "$t" | write_secret minion-child.env; }
  plugin_token
  echo "== minions"
  dc up -d minion-root minion-child
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
    if printf '%s' "$inv" | grep -q minion-root && printf '%s' "$inv" | grep -q minion-child; then return 0; fi
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
    | extract 'secagent_plg_[0-9a-f]{64}' | { read -r t; [ -n "$t" ] || fail "jeton plugin non extrait"; printf '%s' "$t" | write_secret plugin.token; }
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
  echo "== inventaire hierarchique (liste d'adresses de la racine)"
  control_env
  need INVENTORY_BIN
  wait_inventory
  echo "== ansible -m ping sur tous les hotes (plugin de connexion, CA de test)"
  local inv_script="$CHAIN_DIR/inventory.sh"
  printf '#!/bin/sh\nRELAY_TOKEN="$(cat "%s")" exec "%s" "$@"\n' "$RELAY_TOKEN_FILE" "$INVENTORY_BIN" | write_secret inventory.sh
  chmod 700 "$inv_script"
  ANSIBLE_CONNECTION_PLUGINS="$REPO/SECAGENT-PYTHON/ansible_plugins/connection_plugins" ANSIBLE_HOST_KEY_CHECKING=False \
    "${ANSIBLE_BIN:-ansible}" all -i "$inv_script" -m ping | tee "$CHAIN_DIR/ping.log"
  [ "$(grep -c SUCCESS "$CHAIN_DIR/ping.log")" -ge 2 ] || fail "ansible -m ping : moins de 2 hotes SUCCESS"
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
push_link_key() {
  [ -f "$CHAIN_DIR/root-link.pub" ] || fail "$CHAIN_DIR/root-link.pub absent (lancer bootstrap)"
  local files="root-link.pub" CTR_NODE=B   # Podman : volume de l'enfant, noeud B
  [ -f "$CHAIN_DIR/upstream-token" ] && files="root-link.pub upstream-token"
  ctr volume create "$SECAGENT_LINK_VOLUME" >/dev/null
  # shellcheck disable=SC2086
  tar -C "$CHAIN_DIR" -cf - $files | ctr run --rm -i "${RUN_USERNS[@]}" -v "$SECAGENT_LINK_VOLUME:/link" \
    alpine:3.24@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a \
    sh -c 'set -e; tar -xf - -C /link; chmod 755 /link; chown 0:0 /link/root-link.pub; chmod 644 /link/root-link.pub
           if [ -f /link/upstream-token ]; then chown 10001:10001 /link/upstream-token; chmod 0400 /link/upstream-token; fi'
  rm -f "$CHAIN_DIR/upstream-token"
  echo "ancre (et jeton de lien) deposes dans le volume $SECAGENT_LINK_VOLUME"
}

# $1 conteneur maitre : exporte la cle publique racine, releve root_id, ecrit chain/root-link.pub, chain/root-id et
# chain/child.env (REPEATER_ROOT_ID, non secret).
link_anchor_prepare() {
  local m="$1" rid
  # stdout = PEM (fichier) ; stderr = "root_id=<id> kid=<kid>" (capture), jamais de cle privee.
  rid="$(adm "$m" keys link-pubkey 2>&1 >"$CHAIN_DIR/root-link.pub" | sed -n 's/^root_id=\([^ ]*\) .*/\1/p')"
  [ -n "$rid" ] || fail "root_id non releve (keys link-pubkey)"
  grep -q 'BEGIN PUBLIC KEY' "$CHAIN_DIR/root-link.pub" || fail "keys link-pubkey n'a pas produit de PEM public"
  chmod 644 "$CHAIN_DIR/root-link.pub"
  printf '%s' "$rid" | write_secret root-id
  printf 'REPEATER_ROOT_ID=%s\n' "$rid" | write_secret child.env
  # le depot dans le volume est fait par link_mint_child (cle publique et jeton ensemble)
}

# $1 conteneur maitre : mint (sur la racine) du jeton relay-child de dmz1 -> chain/upstream-token puis DEPOT dans le
# volume (push_link_key : 0400, proprietaire 10001, fichier local supprime) et chain/upstream-token.id (identifiant du
# registre, non secret, pour `tokens revoke`). Jamais affiche.
link_mint_child() {
  local m="$1" out t id rid
  rid="$(cat "$CHAIN_DIR/root-id")" || fail "chain/root-id absent (link_anchor_prepare)"
  out="$(adm "$m" tokens create --role relay-child --sub dmz1 --aud "$rid" --expires "$LINK_TTL" 2>&1)" \
    || fail "mint du jeton de lien dmz1 -> $rid refuse (tokens create --role relay-child)"
  t="$(printf '%s\n' "$out" | extract 'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+')"
  id="$(printf '%s\n' "$out" | sed -n 's/^ *ID: *//p' | head -1)"
  [ -n "$t" ] || fail "jeton de lien non extrait"
  [ -n "$id" ] || fail "identifiant du jeton de lien non extrait"
  printf '%s' "$t" | write_secret upstream-token
  printf '%s' "$id" | write_secret upstream-token.id
  push_link_key
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
  echo "== retire-link-previous (refus attendu tant que non confirme : ici confirme)"
  adm "$m" keys retire-link-previous || fail "retire-link-previous refuse (rotation non confirmee ?)"
  prev="$(link_field "$m" previous)"
  case "$prev" in ""|"<nil>"|"-") ;; *) fail "previous encore present apres retire ($prev)" ;; esac
  echo "== le lien survit a une reconnexion de l'enfant apres le retrait"
  dc restart secagent-child >/dev/null
  connected "$m" relays dmz1 4
  smoke
  echo "link-rotation OK (kid $kid0 -> $kid1, previous retire, lien reconnecte)"
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
# evenement (host.up, host.reconnect, host.down, relay.failover, relay.up, relay.reconnect, relay.down ; un hook distinct
# par evenement : seul le premier hook correspondant s'execute, c9ae9e7/#271) dans /var/log/secagent-events/events.log,
# volume externe PAR INSTANCE (push-events) : le journal survit a l'arret du conteneur (preuves de l'ancien maitre).
# Seul le MAITRE de la racine execute ses hooks. Depuis #265 (v3.0.6) : 1re connexion d'un processus (conn_seq 1) =
# host.up / relay.up ; reconnexion du meme processus (conn_seq > 1, ex. apres une bascule) = host.reconnect /
# relay.reconnect, jamais les deux. Fonctions events_log, hook_seen, hook_count, hook_more : failover-test.sh (source).
# Les journaux persistent jusqu'a `down` : les controles APRES une action comptent les lignes (une de plus), jamais la
# simple presence.
EVENTS_LOG_HINT="docker exec <conteneur> cat /var/log/secagent-events/events.log"

check_hooks() {
  local m; m="$(master)" || fail "pas de maitre sur la racine"
  echo "== hooks : maitre $m (relay.failover, relay.up dmz1, host.up minion-root), enfant $C_CHILD (host.up minion-child)"
  wait_for "relay.failover (start) du maitre $m" 60 hook_seen "$m" "$ROOT_RELAY_ID" FAILOVER start >/dev/null
  wait_for "relay.up dmz1 dans le journal du maitre $m" 90 hook_seen "$m" dmz1 RELAY_UP >/dev/null
  wait_for "host.up minion-root dans le journal du maitre $m" 60 hook_seen "$m" minion-root UP >/dev/null
  wait_for "host.up minion-child dans le journal de l'enfant" 60 hook_seen "$C_CHILD" minion-child UP >/dev/null
  echo "hooks OK (journaux : $EVENTS_LOG_HINT)"
}

# Releve des compteurs AVANT la bascule (les deux instances : le futur maitre n'est pas encore connu).
declare -A HOOKS_BEFORE=()
hooks_snapshot() {
  local c e; for c in "$C_A" "$C_B"; do
    for e in "minion-root RECONNECT" "minion-root UP" "dmz1 RELAY_RECONNECT" "dmz1 RELAY_UP"; do
      # shellcheck disable=SC2086   # e = "<sujet> <genre>"
      HOOKS_BEFORE["$c $e"]="$(hook_count "$c" $e)"
    done
  done
}

# Bascule avec hooks (failover-test.sh run stop|kill) : le NOUVEAU maitre doit journaliser relay.failover (cause start
# apres un arret propre, takeover apres un kill ; controle fait aussi par failover-test.sh), puis une NOUVELLE ligne
# host.reconnect de minion-root et relay.reconnect de dmz1 (memes processus qui se reconnectent : conn_seq > 1, #265,
# #245 ; ni host.up ni relay.up). minion-child : informatif (il reste connecte a l'enfant, qui ne redemarre pas).
check_hooks_after_failover() { # $1 cause attendue de relay.failover (start | takeover)
  local m cause="${1:-start}"; m="$(master)" || fail "pas de maitre apres la bascule"
  echo "== hooks apres bascule : nouveau maitre $m"
  hook_seen "$m" "$ROOT_RELAY_ID" FAILOVER "$cause" || fail "relay.failover ($cause) absent du journal de $m"
  wait_for "host.reconnect minion-root journalise par le nouveau maitre $m" 150 hook_more "$m" minion-root RECONNECT "${HOOKS_BEFORE["$m minion-root RECONNECT"]:-0}" >/dev/null
  wait_for "relay.reconnect dmz1 journalise par le nouveau maitre $m" 150 hook_more "$m" dmz1 RELAY_RECONNECT "${HOOKS_BEFORE["$m dmz1 RELAY_RECONNECT"]:-0}" >/dev/null
  if hook_more "$m" minion-root UP "${HOOKS_BEFORE["$m minion-root UP"]:-0}"; then echo "info : host.up minion-root AUSSI journalise par $m (attendu : host.reconnect seul, #265 ; minion < v3.0.6 ?)"; fi
  if hook_more "$m" dmz1 RELAY_UP "${HOOKS_BEFORE["$m dmz1 RELAY_UP"]:-0}"; then fail "relay.up dmz1 journalise par $m apres la bascule (attendu : relay.reconnect seul, #245)"; fi
  local k; for k in RECONNECT UP; do
    if hook_seen "$m" minion-child "$k"; then echo "info : $k minion-child aussi journalise par $m"; fi
  done
  hook_seen "$m" minion-child RECONNECT || hook_seen "$m" minion-child UP || echo "info : aucun evenement minion-child dans le journal de $m (a analyser a l'execution)"
  echo "hooks apres bascule OK"
}

# Scenario relay-down (#245) : l'enfant s'arrete (conteneur stoppe, PAS le maitre) -> le maitre journalise relay.down
# de dmz1 (raison = fermeture par le pair ou erreur de lecture) ; puis l'enfant redemarre (nouveau processus,
# conn_seq 1) -> relay.up dmz1, smoke. Idempotent : compte les lignes avant l'action, ne depend d'aucun etat anterieur.
relay_down() {
  verify_images; need INVENTORY_BIN
  local m down0 up0; m="$(master)" || fail "pas de maitre sur la racine"
  connected "$m" relays dmz1 4
  down0="$(hook_count "$m" dmz1 RELAY_DOWN)"; up0="$(hook_count "$m" dmz1 RELAY_UP)"
  echo "== arret de l'enfant ($C_CHILD) : relay.down dmz1 attendu au maitre $m"
  dc stop secagent-child >/dev/null
  wait_for "relay.down dmz1 journalise par le maitre $m" 60 hook_more "$m" dmz1 RELAY_DOWN "$down0" >/dev/null
  echo "relay.down : $(events_log "$m" | awk '$2=="RELAY_DOWN" && $3=="dmz1" {l=$0} END{print l}')"
  echo "== redemarrage de l'enfant : relay.up dmz1 (nouveau processus, conn_seq 1)"
  dc start secagent-child >/dev/null
  wait_for "enfant healthy" 120 all_health healthy "$C_CHILD" >/dev/null
  connected "$m" relays dmz1 4
  wait_for "relay.up dmz1 journalise par le maitre $m" 90 hook_more "$m" dmz1 RELAY_UP "$up0" >/dev/null
  smoke
  echo "relay-down OK (relay.down puis relay.up de dmz1 au maitre $m)"
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
    negative-ca) negative_ca ;;
    admission-503) admission_503 ;;
    down) guard_project
          if [ "$CONTAINER_CLI" = podman ]; then
            # JAMAIS `down -v` sous Podman : etat et secrets sont des volumes lies au partage PRIVATE (#267)
            dc down
            # shellcheck disable=SC2046   # events_volumes : noms sans espace
            for CTR_NODE in A B; do ctr volume rm "$SECAGENT_LINK_VOLUME" "$SECAGENT_HOOKS_VOLUME" $(events_volumes) >/dev/null 2>&1 || true; done
          else
            dc down -v
            # le volume du jeton de lien est EXTERNE (non supprime par down -v) et contient un secret : retrait explicite
            # shellcheck disable=SC2046   # events_volumes : noms sans espace
            ctr volume rm "$SECAGENT_LINK_VOLUME" "$SECAGENT_HOOKS_VOLUME" "$SECAGENT_SECRETS_VOLUME" $(events_volumes) >/dev/null 2>&1 || true
          fi
          chain_dir_clean ;;   # jetons volatils du poste (garde chain_dir_check avant tout rm)
    *) sed -n '2,40p' "$0"; exit 2 ;;
  esac
fi
