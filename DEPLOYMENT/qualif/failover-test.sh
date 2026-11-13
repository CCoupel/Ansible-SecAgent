#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
# SPDX-License-Identifier: AGPL-3.0-or-later

# Test de basculement actif/passif EN CONTENEURS (#174 M6, partage avec #171 B).
# Verifie que les images et Compose LIVRES se comportent comme prevu : 2 instances sur un meme volume d'etat.
#
#   failover-test.sh setup-ci            # CI uniquement : certificats auto-signes, secrets en fichiers (volume), `state init`
#   failover-test.sh run stop            # arret propre du maitre : reprise rapide
#   failover-test.sh run kill            # docker kill : reprise apres la peremption du verrou (~5-6 min)
#   failover-test.sh run freeze          # SIGSTOP du maitre : doit passer `unhealthy`, puis SIGCONT : un seul maitre
#   failover-test.sh teardown            # docker compose down -v
#   failover-test.sh paths               # chemins prives resolus (sans docker) ; echec si la racine PRIVATE/ manque
#
# Variables : COMPOSE_FILE (defaut docker-compose.server.yml de ce repertoire), PROJECT (secagent-qualif),
#   C_A / C_B (noms de conteneurs, defaut secagent-qualif-a / -b), STOP_MAX_S (defaut 10), KILL_MAX_S (defaut 600),
#   INSPECT_MINION_CMD / INVENTORY_CMD : commandes optionnelles (code 0 = OK) lancees apres chaque bascule
#   (minion reconnecte sans re-enrolement ; secagent-inventory avec la liste des 2 adresses).
#   Donnees privees (#250) : racine SECAGENT_PRIVATE_DIR (defaut <depot>/PRIVATE, jamais creee par ce script) ;
#   SECRETS_DIR (defaut $SECAGENT_PRIVATE_DIR/QUALIF/secrets), QUALIF_TLS_DIR (defaut .../QUALIF/ci-tls, CI).
# Ne demarre rien a l'import ; exige docker et docker compose. Exit 0 = OK, 1 = echec d'execution (ECHEC:),
#   2 = refus d'une garde avant toute action (REFUS:, sans diagnostic : certificat absent, chemin prive, projet...).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
fail() { echo "ECHEC: $*" >&2; exit 1; }
# Refus d'une GARDE (#256) : precondition non remplie (chemin, projet, variable, image, certificat...), constatee AVANT
# toute action. Message `REFUS: ...`, code 2, et JAMAIS de diagnostic des conteneurs (chain-test.sh enrichit fail()
# avec diag_unhealthy, pas refuse()) : rien n'a ete lance, il n'y a rien a diagnostiquer. fail() reste reserve aux
# echecs d'execution (code 1).
refuse() { echo "REFUS: $*" >&2; exit 2; }
# Racine UNIQUE des donnees privees du poste (#250) : secrets, PKI de test, jetons de la chaine. Depuis une copie du
# depot (worktree, scratchpad), exporter SECAGENT_PRIVATE_DIR=<checkout>/PRIVATE (chemin absolu).
PRIVATE_DIR="${SECAGENT_PRIVATE_DIR:-$REPO/PRIVATE}"
PRIVATE_DIR="${PRIVATE_DIR%/}"
# --- CLI de conteneurs (#267, LOT-4) ---------------------------------------------------------------------------------
# CONTAINER_CLI=docker (defaut : CI, ancienne qualif .218 par DOCKER_HOST) | podman (noeuds rootless srv3/srv4 : chaque
# commande est executee SUR LE NOEUD par `ssh cyril@<ip> podman ...`, podman-compose lance sur le noeud depuis
# PRIVATE/QUALIF/<srvX>/cyril/secagent/release/ ; aucun demon ni client Podman sur le poste).
#   CONTAINER_HOST_A / CONTAINER_HOST_B : ssh://cyril@<ip>/run/user/1000/podman/podman.sock (racine a / noeud b+enfant+minions)
#   QUALIF_NODE_A / QUALIF_NODE_B (srv3 / srv4), CONTAINER_SSHKEY, CONTAINER_KNOWN_HOSTS (PRIVATE/QUALIF/poste-cyril/)
#   SECRET_OWNER_UID : proprietaire des fichiers de secrets (10001 sous Docker, 1000 = cyril sous Podman keep-id)
CONTAINER_CLI="${CONTAINER_CLI:-docker}"
case "$CONTAINER_CLI" in docker|podman) ;; *) refuse "CONTAINER_CLI='$CONTAINER_CLI' : attendu docker ou podman" ;; esac
if [ "$CONTAINER_CLI" = podman ]; then
  QUALIF_NODE_A="${QUALIF_NODE_A:-srv3}"; QUALIF_NODE_B="${QUALIF_NODE_B:-srv4}"
  CONTAINER_HOST_A="${CONTAINER_HOST_A:-ssh://cyril@192.168.1.213/run/user/1000/podman/podman.sock}"
  CONTAINER_HOST_B="${CONTAINER_HOST_B:-ssh://cyril@192.168.1.214/run/user/1000/podman/podman.sock}"
  CONTAINER_SSHKEY="${CONTAINER_SSHKEY:-$PRIVATE_DIR/QUALIF/poste-cyril/id_ed25519}"
  CONTAINER_KNOWN_HOSTS="${CONTAINER_KNOWN_HOSTS:-$PRIVATE_DIR/QUALIF/poste-cyril/known_hosts}"
  SECRET_OWNER_UID="${SECRET_OWNER_UID:-1000}"
  # Les noeuds voient PRIVATE/ au MEME chemin absolu que le poste (autofs /share/MFS/ROOT) : sinon les chemins passes a
  # podman-compose (CHAIN_DIR, QUALIF_TLS_DIR, etat) designeraient autre chose sur le noeud.
  # PODMAN_SHARE_ROOT : racine du partage vue par les noeuds (defaut /share/MFS/ROOT ; autre valeur : essais locaux seulement,
  # scripts/ci/podman_compose_replay.sh). Chemin absolu sans `..`.
  SHARE_ROOT="${PODMAN_SHARE_ROOT:-/share/MFS/ROOT}"
  [[ $SHARE_ROOT =~ ^/[A-Za-z0-9_./-]+$ && ! /$SHARE_ROOT/ =~ /\.\./ ]] || refuse "PODMAN_SHARE_ROOT='$SHARE_ROOT' invalide"
  case "$PRIVATE_DIR" in "${SHARE_ROOT%/}"/*) ;; *) refuse "CONTAINER_CLI=podman : SECAGENT_PRIVATE_DIR=$PRIVATE_DIR hors de $SHARE_ROOT (chemin vu par les noeuds)" ;; esac
  [[ $PRIVATE_DIR =~ ^/[A-Za-z0-9_./-]+$ && ! /$PRIVATE_DIR/ =~ /\.\./ ]] || refuse "CONTAINER_CLI=podman : SECAGENT_PRIVATE_DIR='$PRIVATE_DIR' : caracteres [A-Za-z0-9_./-] sans .. attendus (transmis aux noeuds)"
  # tmpfs des serveurs : `U` (podman 5.7 refuse uid=/gid= ; docker-compose.server.yml), comme release.env des unites
  SECAGENT_TMPFS_OPTS=U
  export SECAGENT_TMPFS_OPTS QUALIF_NODE_A QUALIF_NODE_B CONTAINER_HOST_A CONTAINER_HOST_B CONTAINER_SSHKEY CONTAINER_KNOWN_HOSTS SECRET_OWNER_UID
else
  SECRET_OWNER_UID="${SECRET_OWNER_UID:-10001}"
fi
export CONTAINER_CLI SECRET_OWNER_UID

ssh_target() { # $1 ssh://user@hote[:port]/socket -> "user@hote" (port ignore : 22) ; refus si la forme est inattendue
  local u="${1#ssh://}"; u="${u%%/*}"; u="${u%%:*}"
  [[ $1 == ssh://* && $u =~ ^[a-z_][a-z0-9_-]*@[A-Za-z0-9.-]+$ ]] || refuse "CONTAINER_HOST='$1' : attendu ssh://<user>@<hote>/run/user/<uid>/podman/podman.sock"
  printf '%s' "$u"
}
node_addr() { local t; t="$(ssh_target "$(node_url "$1")")"; printf '%s' "${t#*@}"; }   # $1 A|B -> adresse IP/nom
node_url() { case "$1" in A) printf '%s' "$CONTAINER_HOST_A" ;; B) printf '%s' "$CONTAINER_HOST_B" ;; *) refuse "noeud '$1' : attendu A|B" ;; esac; }
node_name() { case "$1" in A) printf '%s' "$QUALIF_NODE_A" ;; B) printf '%s' "$QUALIF_NODE_B" ;; esac; }
nodes() { if [ "$CONTAINER_CLI" = podman ]; then echo A B; else echo local; fi; }
# SSH vers un noeud : cle et known_hosts de l'environnement, verification STRICTE de l'hote, connexion multiplexee
# (les attentes de sante interrogent le noeud toutes les 0,2 s). $1 A|B, $2 stdin|nostdin, puis la commande distante,
# passee mot a mot (printf %q : aucun mot n'est reinterprete par le shell distant).
node_ssh() {
  local n="$1" in="$2" t cp; shift 2
  t="$(ssh_target "$(node_url "$n")")"
  [ -f "$CONTAINER_SSHKEY" ] && [ -f "$CONTAINER_KNOWN_HOSTS" ] || refuse "cle SSH ($CONTAINER_SSHKEY) ou known_hosts ($CONTAINER_KNOWN_HOSTS) absents"
  cp="${TMPDIR:-/tmp}"; cp="${cp%/}/secagent-ssh-$(id -u)"
  [ -e "$cp" ] || [ -L "$cp" ] || ( umask 077; mkdir -p "$cp" )
  # repertoire des sockets maitres SSH : a soi, 0700, pas un lien (un tiers local y poserait un faux maitre)
  [ -d "$cp" ] && [ ! -L "$cp" ] && [ "$(stat -c '%u %a' "$cp")" = "$(id -u) 700" ] \
    || refuse "$cp : repertoire des sockets SSH attendu a l'uid $(id -u) en 0700 (non lien) ; le supprimer puis relancer"
  local opts=(-i "$CONTAINER_SSHKEY" -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes
              -o UserKnownHostsFile="$CONTAINER_KNOWN_HOSTS" -o ConnectTimeout=10
              -o ControlMaster=auto -o ControlPath="$cp/%C" -o ControlPersist=120)
  [ "$in" = stdin ] || opts+=(-n)
  ssh "${opts[@]}" "$t" "$(printf '%q ' "$@")"
}
node_of() { # $1 nom de conteneur ou de service -> A|B (vide si inconnu)
  case "$1" in
    "$C_A"|secagent-server-a) echo A ;;
    "$C_B"|secagent-server-b|"${C_CHILD:-secagent-qualif-child}"|secagent-child|secagent-qualif-grandchild|secagent-grandchild|minion-*|*_minion-*|*-minion-*) echo B ;;
  esac
}
# Remplace `docker` : docker local/DOCKER_HOST, ou `podman` SUR le noeud du conteneur vise (sinon $CTR_NODE, defaut B).
ctr() {
  if [ "$CONTAINER_CLI" = docker ]; then docker "$@"; return; fi
  local a n="" in=nostdin
  for a in "$@"; do [ -n "$n" ] || n="$(node_of "$a")"; [ "$a" = -i ] && in=stdin; done
  [ "${1:-}" = load ] && in=stdin
  node_ssh "${n:-${CTR_NODE:-B}}" "$in" podman "$@"
}
# Cree un volume nomme s'il manque (idempotent) : `podman volume create` refuse un volume existant (« already exists »),
# a l'inverse de `docker volume create` ; un bootstrap rejoue (apres un echec, push-hooks seul...) ne doit pas echouer.
vol_ensure() { ctr volume inspect "$1" >/dev/null 2>&1 || ctr volume create "$1" >/dev/null; }
# Variables transmises a podman-compose sur le noeud (Compose interpole cote noeud) : liste FERMEE, valeurs non secretes.
DC_ENV_VARS="SECAGENT_TMPFS_OPTS SECAGENT_IMAGE SECAGENT_MINION_IMAGE SECAGENT_PULL_POLICY SECAGENT_MEM_LIMIT LOG_LEVEL GOMEMLIMIT QUALIF_TLS_DIR CHAIN_DIR SECAGENT_HOOKS_VOLUME SECAGENT_EVENTS_VOLUME SECAGENT_LINK_VOLUME SECAGENT_LINK_GRAND_VOLUME CHILD_UPSTREAM_QUEUE_SIZE MINION_CHILD_SERVER_URL MINION_CHILD_WS_URL GRANDCHILD_UPSTREAM_URL SECAGENT_SECRETS_VOLUME SECAGENT_TLS_VOLUME QUALIF_PRIVATE_DIR QUALIF_NODE_A_ADDR"
release_dir() { printf '%s' "$PRIVATE_DIR/QUALIF/$(node_name "$1")/cyril/secagent/release"; }
dc_on() { # $1 A|B, puis les arguments podman-compose
  local n="$1" v env=(); shift
  # shellcheck disable=SC2034   # lues par indirection (${!v}) ci-dessous
  QUALIF_PRIVATE_DIR="$PRIVATE_DIR/QUALIF"
  # shellcheck disable=SC2034
  QUALIF_NODE_A_ADDR="$(node_addr A)"
  for v in $DC_ENV_VARS; do [ -z "${!v:-}" ] || env+=("$v=${!v}"); done
  node_ssh "$n" nostdin env -C "$(release_dir "$n")" "${env[@]}" podman-compose -p "$PROJECT" \
    -f docker-compose.chain.yml -f docker-compose.hooks.yml -f docker-compose.podman.qualif.yml "$@"
}
# Remplace "${DC[@]}" : sous Podman, les services sont repartis par noeud (a -> A ; b, enfant, minions -> B).
#   run/exec : sur le noeud du premier service ; avec services : chaque noeud recoit les siens ; sans service : `up`
#   demarre la racine de chaque noeud (a sur A, b sur B), les autres commandes (down, logs, ps...) visent les deux noeuds.
dc() {
  if [ "$CONTAINER_CLI" = docker ]; then "${DC[@]}" "$@"; return; fi
  local pre=() sub="" rest=() a i=0
  local args=("$@")
  while [ $i -lt ${#args[@]} ]; do
    a="${args[$i]}"
    if [ -z "$sub" ]; then
      case "$a" in -f|-p|--profile|--env-file) pre+=("$a" "${args[$((i+1))]}"); i=$((i+2)); continue ;; -*) pre+=("$a") ;; *) sub="$a" ;; esac
    else rest+=("$a"); fi
    i=$((i+1))
  done
  [ -n "$sub" ] || refuse "dc : sous-commande absente"
  # Sous-commandes de podman-compose 1.5.0 (ordre n°21) : `rm` n'existe pas (emule ci-dessous), toute autre absente est
  # refusee ici plutot que par un message d'usage au milieu d'un scenario ; options sans equivalent traduites ou refusees.
  case "$sub" in
    up|run|exec|start|stop|restart|logs|down|ps|kill|pause|unpause|pull|images|port|config) ;;
    rm) dc_rm "${rest[@]}"; return ;;   # -f/--profile de tete sans objet : selection par etiquettes
    *) refuse "dc $sub : sous-commande absente de podman-compose 1.5 (Podman) : a emuler dans dc() avant usage" ;;
  esac
  if [ "$sub" = logs ]; then   # podman-compose logs : pas de --no-color (sortie sans couleur de toute facon)
    local kept=(); for a in "${rest[@]}"; do [ "$a" = --no-color ] || kept+=("$a"); done; rest=("${kept[@]}")
  fi
  [ "$sub" != config ] || [[ " ${rest[*]} " != *" --format "* ]] || refuse "dc config --format : absent de podman-compose 1.5"
  local n
  case "$sub" in
    run|exec)
      for a in "${rest[@]}"; do n="$(node_of "$a")"; [ -z "$n" ] || break; done
      [ -n "$n" ] || refuse "dc $sub : service inconnu (${rest[*]})"
      dc_on "$n" "${pre[@]}" "$sub" "${rest[@]}"; return ;;
  esac
  local svcA=() svcB=() opts=()
  for a in "${rest[@]}"; do
    case "$(node_of "$a")" in A) svcA+=("$a") ;; B) svcB+=("$a") ;; *) opts+=("$a") ;; esac
  done
  if [ ${#svcA[@]} -eq 0 ] && [ ${#svcB[@]} -eq 0 ]; then
    if [ "$sub" = up ]; then svcA=(secagent-server-a); svcB=(secagent-server-b); fi
    if [ "$sub" != up ]; then dc_on A "${pre[@]}" "$sub" "${opts[@]}"; dc_on B "${pre[@]}" "$sub" "${opts[@]}"; return; fi
  fi
  [ ${#svcA[@]} -eq 0 ] || dc_on A "${pre[@]}" "$sub" "${opts[@]}" "${svcA[@]}"
  [ ${#svcB[@]} -eq 0 ] || dc_on B "${pre[@]}" "$sub" "${opts[@]}" "${svcB[@]}"
  # podman-compose up/start/restart rend 0 MEME si la creation ou le demarrage d'un conteneur echoue (T48) : etat verifie.
  # DC_NOCHECK=1 : service dont l'echec est attendu (negative-ca).
  case "$sub" in up|start|restart) [ "${DC_NOCHECK:-0}" = 1 ] || require_running "${svcA[@]}" "${svcB[@]}" ;; esac
}
# `docker compose rm [-s] [-f] [-v] <services>` sous Podman (absent de podman-compose 1.5, ordre n°21) : `podman rm -f` des
# conteneurs du projet portant l'etiquette du service, sur le noeud du service ; idempotent (aucun conteneur = rien a faire),
# puis verification qu'il n'en reste aucun. Options -s/-f/-v/--stop/--force acceptees (rm -f arrete et force toujours) ;
# `-v` (volumes anonymes) : aucun dans nos Compose. Sans service : refus (jamais tout le projet par megarde).
dc_rm() { # $@ options de `compose rm` (ignorees) puis services
  local a svcs=() s n ids
  for a in "$@"; do case "$a" in -*) ;; *) svcs+=("$a") ;; esac; done
  [ ${#svcs[@]} -gt 0 ] || refuse "dc rm : service(s) obligatoire(s) sous Podman"
  for s in "${svcs[@]}"; do
    n="$(node_of "$s")"; n="${n:-B}"
    ids="$(CTR_NODE="$n" ctr ps -aq --filter "label=com.docker.compose.project=$PROJECT" --filter "label=com.docker.compose.service=$s")"
    # shellcheck disable=SC2086   # identifiants sans espace
    [ -z "$ids" ] || CTR_NODE="$n" ctr rm -f $ids >/dev/null
    [ -z "$(CTR_NODE="$n" ctr ps -aq --filter "label=com.docker.compose.project=$PROJECT" --filter "label=com.docker.compose.service=$s")" ] \
      || fail "dc rm $s : conteneur(s) encore present(s) sur le noeud $n"
  done
}
# Echoue si un service Compose n'a pas de conteneur EN COURS (etiquettes Compose, posees par docker compose et
# podman-compose) sur son noeud : jamais se fier au code retour de podman-compose (T48).
require_running() { # $@ services Compose
  local s n
  for s in "$@"; do
    n="$(node_of "$s")"
    [ -n "$(CTR_NODE="${n:-B}" ctr ps -q --filter "label=com.docker.compose.project=$PROJECT" \
            --filter "label=com.docker.compose.service=$s" --filter status=running 2>/dev/null)" ] \
      || fail "service $s : aucun conteneur en cours sur le noeud ${n:-B} apres le demarrage (podman-compose rend 0 meme en cas d'echec)"
  done
}
# Garde FAIL-CLOSED (incident du 2026-11-03 : secrets generes dans une copie ephemere puis perdus) : un chemin situe
# sous $PRIVATE_DIR n'est jamais ecrit si la racine n'existe pas ; la racine n'est JAMAIS creee par les scripts.
# Un chemin explicite hors de $PRIVATE_DIR (ex. SECRETS_DIR=/autre) n'est pas concerne ; une racine relative est refusee.
require_private_dir() { # $@ chemins qui vont etre ecrits
  local p
  # Racine RELATIVE refusee : elle dependrait du repertoire courant et contournerait la comparaison des chemins.
  case "$PRIVATE_DIR" in /*) ;; *) refuse "SECAGENT_PRIVATE_DIR=$PRIVATE_DIR n'est pas un chemin absolu : refus (exporter SECAGENT_PRIVATE_DIR=<checkout>/PRIVATE en chemin absolu)" ;; esac
  for p in "$@"; do
    case "$p" in
      "$PRIVATE_DIR"|"$PRIVATE_DIR"/*)
        [ -d "$PRIVATE_DIR" ] || refuse "racine des donnees privees introuvable (SECAGENT_PRIVATE_DIR=$PRIVATE_DIR) : refus d'ecrire $p dans un emplacement ephemere. Creer la racine ou exporter SECAGENT_PRIVATE_DIR=<checkout>/PRIVATE (chemin absolu)" ;;
    esac
  done
}
# Mode HOTE DISTANT : DOCKER_HOST non local, ou point d'acces (SECAGENT_ENDPOINT_HOST / CONTROL_HOST) non local.
is_remote() {
  case "${DOCKER_HOST:-}" in ""|unix://*|npipe://*) ;; *) return 0 ;; esac
  case "${CONTROL_HOST:-${SECAGENT_ENDPOINT_HOST:-}}" in ""|127.0.0.1|localhost|::1) ;; *) return 0 ;; esac
  return 1
}
# Garde (incident E2) : lance ISOLEMENT contre un demon distant, sans les variables que chain-test.sh exporte, ce script
# recreait les conteneurs avec un BIND MOUNT d'un chemin du POSTE (repertoires vides crees sur l'hote distant) au lieu du
# volume TLS. En mode distant : TLS_MODE=volume est OBLIGATOIRE (sinon refus) et le script reprend lui-meme le mode volume
# (Compose de chaine + surcharge remote-tls + volume) ; le point d'entree normal est `chain-test.sh failover`.
if [ "$CONTAINER_CLI" = docker ] && is_remote; then
  [ "${TLS_MODE:-}" = volume ] || refuse "hote Docker distant (DOCKER_HOST=${DOCKER_HOST:-} / point d'acces=${CONTROL_HOST:-${SECAGENT_ENDPOINT_HOST:-}}) : TLS_MODE=volume est obligatoire. Lancer 'chain-test.sh failover' (point d'entree, il prepare le mode volume) ; jamais ce script isole sans le mode volume."
  case "${COMPOSE_FILE:-}" in ""|*/docker-compose.chain.yml) ;; *) refuse "hote distant : COMPOSE_FILE=${COMPOSE_FILE} incompatible avec le mode volume (attendu docker-compose.chain.yml) : lancer 'chain-test.sh failover'" ;; esac
  COMPOSE_FILE="${COMPOSE_FILE:-$HERE/docker-compose.chain.yml}"
  COMPOSE_OVERRIDES="${COMPOSE_OVERRIDES:-$HERE/docker-compose.remote-tls.yml}"
  SECAGENT_TLS_VOLUME="${SECAGENT_TLS_VOLUME:-${PROJECT:-${COMPOSE_PROJECT_NAME:-secagent-qualif}}_tls}"
  export COMPOSE_FILE COMPOSE_OVERRIDES SECAGENT_TLS_VOLUME
fi
COMPOSE_FILE="${COMPOSE_FILE:-$HERE/docker-compose.server.yml}"
PROJECT="${PROJECT:-${COMPOSE_PROJECT_NAME:-secagent-qualif}}"   # un SEUL projet (qualif reelle) : memes noms de conteneurs que la chaine, scripts lances SEQUENTIELLEMENT
C_A="${C_A:-secagent-qualif-a}"; C_B="${C_B:-secagent-qualif-b}"
# Volume EXTERNE des secrets serveur (#197 item 6, v3.0.5) : trois fichiers (jwt_secret_key, admin_token, rsa_master_key)
# lus via JWT_SECRET_KEY_FILE / ADMIN_TOKEN_FILE / RSA_MASTER_KEY_FILE ; plus aucun secret en variable d'environnement.
export SECAGENT_SECRETS_VOLUME="${SECAGENT_SECRETS_VOLUME:-${PROJECT}_secrets}"
SECRETS_DIR="${SECRETS_DIR:-$PRIVATE_DIR/QUALIF/secrets}"   # cote client, sous PRIVATE/ (ignore par git), fichiers 0400
CI_TLS_DIR="$PRIVATE_DIR/QUALIF/ci-tls"   # certificat jetable de setup-ci (defaut de QUALIF_TLS_DIR dans ce script)
# Podman : TLS lie depuis le partage (pki/ ne contient que ca.crt, tls.crt, tls.key ; ca.key est dans pki-ca/), et la
# chaine de qualif (a sur A, b sur B) est le seul Compose supporte.
if [ "$CONTAINER_CLI" = podman ]; then
  export QUALIF_TLS_DIR="${QUALIF_TLS_DIR:-$PRIVATE_DIR/QUALIF/pki}"
  [ "$SECRETS_DIR" = "$PRIVATE_DIR/QUALIF/secrets" ] || refuse "CONTAINER_CLI=podman : SECRETS_DIR doit etre $PRIVATE_DIR/QUALIF/secrets (lie dans les conteneurs par docker-compose.podman.qualif.yml)"
fi
STOP_MAX_S="${STOP_MAX_S:-10}"; KILL_MAX_S="${KILL_MAX_S:-600}"
DC=(docker compose -p "$PROJECT" -f "$COMPOSE_FILE")
# Fichiers de surcharge optionnels (ex. docker-compose.remote-tls.yml pour un hote Docker distant) : liste separee par des espaces.
for f in ${COMPOSE_OVERRIDES:-}; do DC+=(-f "$f"); done
now() { date +%s.%N; }

listening() { # $1 conteneur, $2 port : 0 si le conteneur ecoute sur le port (lecture de /proc/net/tcp{,6} :
  # aucune dependance a netstat/ss ; etat 0A = LISTEN, port en hexadecimal sur 4 chiffres)
  local hex; hex=$(printf '%04X' "$2")
  ctr exec "$1" sh -c "cat /proc/net/tcp /proc/net/tcp6 2>/dev/null | awk -v p=':$hex' '\$4==\"0A\" && index(\$2,p) && substr(\$2,length(\$2)-3)==substr(p,2) {f=1} END{exit !f}'"
}
is_master() { listening "$1" 7770 && listening "$1" 7772; }
is_silent() { ! listening "$1" 7770 && ! listening "$1" 7772 && ! listening "$1" 7771; }
lock_count() { ctr exec "$1" sh -c 'ls /data | grep -c "^relay\.lock" || true'; }
health() { ctr inspect -f '{{.State.Health.Status}}' "$1" 2>/dev/null || echo none; }
all_health() { # $1 etat attendu (healthy|unhealthy), puis les conteneurs : 0 si TOUS sont dans cet etat
  local want="$1" c; shift
  for c in "$@"; do [ "$(health "$c")" = "$want" ] || return 1; done
}

# Garde-fou des operations DESTRUCTIVES (down -v, teardown, backup-restore) : jamais hors des projets de test.
# Hote Docker DISTANT (DOCKER_HOST non local) : uniquement le projet `secagent-qualif`. Local/CI : les projets de
# test des scripts (ALLOWED_PROJECTS, defaut secagent-qualif secagent-chain secagent-failover). Tout autre projet
# (ex. l'ancienne qualif v2) est refuse.
guard_project() {
  local remote=0
  case "${DOCKER_HOST:-}" in ""|unix://*|npipe://*) ;; *) remote=1 ;; esac
  [ "$CONTAINER_CLI" = docker ] || remote=1   # noeuds Podman = hotes reels : projet secagent-qualif seulement
  if [ "$remote" = 1 ]; then
    [ "$PROJECT" = secagent-qualif ] || refuse "operation destructive refusee : hote distant (${DOCKER_HOST:-noeuds $CONTAINER_CLI}) et projet '$PROJECT' != secagent-qualif"
  else
    case " ${ALLOWED_PROJECTS:-secagent-qualif secagent-chain secagent-failover} " in
      *" $PROJECT "*) ;;
      *) refuse "operation destructive refusee : projet '$PROJECT' hors de la liste (${ALLOWED_PROJECTS:-secagent-qualif secagent-chain secagent-failover})" ;;
    esac
  fi
  if [ -n "${COMPOSE_PROJECT_NAME:-}" ] && [ "$COMPOSE_PROJECT_NAME" != "$PROJECT" ]; then
    refuse "COMPOSE_PROJECT_NAME ($COMPOSE_PROJECT_NAME) differe de PROJECT ($PROJECT) : refus"
  fi
}

# Mode distant : AUCUN bind mount (resolu sur l'hote distant, pas sur le poste) dans le rendu Compose ; refuse sinon.
guard_remote_binds() {
  if [ "$CONTAINER_CLI" = podman ]; then
    # Les Compose lus par les noeuds sont ceux du depot, deposes avec leurs empreintes : verification d'integrite (le rendu
    # Podman des binds sous PRIVATE/QUALIF est controle en CI par check_no_binds.py --allow-prefix).
    local n; for n in A B; do
      bash "$REPO/DEPLOYMENT/podman/verify-node-files.sh" qualif "$(node_name "$n")" \
        || refuse "fichiers de deploiement de $(node_name "$n") non conformes au depot : verify-node-files.sh"
    done
    return 0
  fi
  is_remote || return 0
  local json; json="$(dc config --format json 2>/dev/null)" || refuse "rendu Compose impossible (variables obligatoires ?) : verification des bind mounts refusee"
  printf '%s' "$json" | python3 "$HERE/../../scripts/ci/check_no_binds.py" \
    || refuse "mode distant : bind mount d'un chemin du poste vers le demon distant refuse (utiliser TLS_MODE=volume + chain-test.sh push-tls)"
}

# --- Journal des hooks (#197, v3.0.6) ---------------------------------------------------------------------------------
# Present seulement avec la surcharge docker-compose.hooks.yml (chain-test.sh l'ajoute toujours) : hooks.json ecrit une
# ligne par evenement dans /var/log/secagent-events/events.log, volume externe PAR INSTANCE (survit a l'arret du conteneur).
# Formats (champ 2 = genre, champ 3 = sujet) : "<ts> UP|RECONNECT|DOWN <hote>", "<ts> FAILOVER <relay_id> <cause> ...",
# "<ts> RELAY_UP|RELAY_RECONNECT <relay_id> conn_seq=.. ...", "<ts> RELAY_DOWN <relay_id> <reason> ...".
hooks_enabled() { case " ${COMPOSE_OVERRIDES:-} " in *docker-compose.hooks.yml*) return 0 ;; esac; return 1; }
events_log() { ctr exec "$1" cat /var/log/secagent-events/events.log 2>/dev/null || true; }
# $1 conteneur, $2 sujet, $3 genre, $4 (optionnel) champ 4 exact (cause de FAILOVER, raison de RELAY_DOWN) : la ligne existe.
hook_seen() { events_log "$1" | awk -v h="$2" -v k="$3" -v c="${4:-}" '$2==k && $3==h && (c=="" || $4==c) {f=1} END{exit !f}'; }
# $1 conteneur, $2 sujet, $3 genre : nombre de lignes (scenarios idempotents : on attend une ligne DE PLUS).
hook_count() { events_log "$1" | awk -v h="$2" -v k="$3" '$2==k && $3==h {n++} END{print n+0}'; }
hook_more() { [ "$(hook_count "$1" "$2" "$3")" -gt "$4" ]; }   # $4 compte avant l'action
# $1 conteneur, $2 genre : nombre de lignes de ce genre, TOUS sujets (ex. aucun REROUTED, quel que soit l'hote).
kind_count() { events_log "$1" | awk -v k="$2" '$2==k {n++} END{print n+0}'; }
kind_more() { [ "$(kind_count "$1" "$2")" -gt "$3" ]; }
# $1 conteneur, $2 sujet, $3 genre, $4 cle : valeur de `cle=` sur la DERNIERE ligne (vide si absente).
hook_last_kv() { events_log "$1" | awk -v h="$2" -v k="$3" -v key="$4" '$2==k && $3==h {v=""; for (i=4; i<=NF; i++) if (index($i, key "=")==1) v=substr($i, length(key)+2)} END{print v}'; }
# $1 conteneur, $2 sujet : la PREMIERE ligne de genre $3 precede la premiere de genre $4 (ex. DISCOVER avant UP, #266).
first_before() { events_log "$1" | awk -v h="$2" -v a="$3" -v b="$4" '$3==h && $2==a && !ia {ia=NR} $3==h && $2==b && !ib {ib=NR} END{exit !(ia && ib && ia<ib)}'; }
# $1 conteneur, $2 sujet, $3 genre : derniere ligne (affichage).
hook_last() { events_log "$1" | awk -v h="$2" -v k="$3" '$2==k && $3==h {l=$0} END{print l}'; }
# Comptages et extractions SURS sous `set -euo pipefail` : grep sort en 1 sans correspondance, ce qui faisait echouer
# SANS MESSAGE l'affectation `x="$(... | grep ... | wc -l)"` (upstream-queue, QUALIF 2026-11-12). Lisent stdin.
count_matches() { { grep -Eo -- "$1" || true; } | wc -l | tr -d ' '; }   # nombre d'occurrences du motif ERE $1 (0 si aucune)
count_lines() { { grep -c -- "$1" || true; }; }                          # nombre de lignes contenant $1 (0 si aucune)
extract() { { grep -oE -- "$1" || true; } | tail -1; }                   # derniere occurrence de $1 (vide si aucune), jamais affichee
# Gel borne (chain-test.sh upstream-queue) : un cycle de duree estimee $2 s, commence a $1 s du debut du gel, finit-il
# avant la borne $3 s ? (nombres entiers ou decimaux ; 0 = oui). La borne n'est JAMAIS depassee par un cycle commence.
cycle_fits() { awk -v e="$1" -v d="$2" -v m="$3" 'BEGIN{exit !(e + d <= m)}'; }
# Etat du lien amont dans la sortie de `secagent-server server status` (stdin) : ligne
# "upstream (<mode>)  <pair>  <etat>  <depuis>  <raison>" (cli/server.go:124-125) -> <etat> (vide si pas de lien amont).
upstream_state_from_status() { awk '$1=="upstream" {print $4; exit}'; }
# Sujet de relay.failover d'une racine : son relay_id local (REPEATER_ID absent = defaut du serveur).
ROOT_RELAY_ID="${ROOT_RELAY_ID:-secagent-server}"

wait_for() { # $1 description, $2 delai max, $3... commande
  local what="$1" max="$2"; shift 2; local t0; t0=$(now)
  while ! "$@" 2>/dev/null; do
    awk -v a="$t0" -v b="$(now)" -v m="$max" 'BEGIN{exit !(b-a>m)}' && fail "$what: delai de ${max}s depasse"
    sleep 0.2
  done
  awk -v a="$t0" -v b="$(now)" 'BEGIN{printf "%.1f", b-a}'
}

# Genere des secrets ALEATOIRES et JETABLES (jamais ceux de prod) dans $SECRETS_DIR (0700, fichiers 0400), sans les afficher.
# Un fichier DEJA present est conserve (RSA_MASTER_KEY ne doit pas changer apres `state init`) sauf FORCE=1.
gen_secrets() {
  require_private_dir "$SECRETS_DIR"
  ( umask 077; mkdir -p "$SECRETS_DIR"; chmod 700 "$SECRETS_DIR"
    local n; for n in jwt_secret_key admin_token rsa_master_key; do
      if [ "${FORCE:-0}" = 1 ] || [ ! -s "$SECRETS_DIR/$n" ]; then
        rm -f "$SECRETS_DIR/$n"; openssl rand -hex 32 | tr -d '\n' > "$SECRETS_DIR/$n"; chmod 400 "$SECRETS_DIR/$n"
      fi
    done )
}

# Podman (T48) : le volume nomme des secrets ($SECAGENT_SECRETS_VOLUME, declare EXTERNE par docker-compose.server.yml) est
# CREE sur chaque noeud en bind sur $SECRETS_DIR (= PRIVATE/QUALIF/secrets, partage vu au meme chemin) : rien n'est copie,
# les fichiers restent 0400 / uid 1000 sur le partage. Idempotent ; un volume existant qui pointe ailleurs est REFUSE.
# Etape faite par bootstrap (push-secrets) AVANT le state init et tout `up` (podman-compose exige qu'un volume externe existe).
podman_secrets_volume() {
  local CTR_NODE dev
  for CTR_NODE in A B; do
    if ctr volume inspect "$SECAGENT_SECRETS_VOLUME" >/dev/null 2>&1; then
      dev="$(ctr volume inspect --format '{{.Options.device}}' "$SECAGENT_SECRETS_VOLUME" 2>/dev/null || true)"
      [ "$dev" = "$SECRETS_DIR" ] || refuse "volume $SECAGENT_SECRETS_VOLUME (noeud $CTR_NODE) lie a '$dev' et non a $SECRETS_DIR : le retirer (podman volume rm) puis relancer"
    else
      ctr volume create --driver local --opt type=none --opt o=bind,uid=10001,gid=10001 --opt "device=$SECRETS_DIR" "$SECAGENT_SECRETS_VOLUME" >/dev/null \
        || fail "creation du volume $SECAGENT_SECRETS_VOLUME (noeud $CTR_NODE) impossible"
    fi
    echo "volume des secrets $SECAGENT_SECRETS_VOLUME -> $SECRETS_DIR (bind, noeud $CTR_NODE)"
  done
}

# Depose les fichiers de secret de $1 (repertoire, defaut $SECRETS_DIR) dans le volume $2 (defaut
# $SECAGENT_SECRETS_VOLUME) de l'hote Docker (distant ou non) par un conteneur ephemere (flux tar sur stdin, image alpine
# epinglee) : proprietaire 10001 (uid du conteneur), mode 0400, repertoire 0755. Aucun bind mount, aucune valeur affichee.
# Meme modele que les volumes tls / hooks / link : fonctionne contre un demon distant.
# shellcheck disable=SC2120   # arguments optionnels, passes par chain-test.sh (backup-restore)
push_secrets() {
  if [ "$CONTAINER_CLI" = podman ]; then podman_secrets_volume; return; fi
  local d="${1:-$SECRETS_DIR}" vol="${2:-$SECAGENT_SECRETS_VOLUME}" n files=""
  for n in jwt_secret_key admin_token rsa_master_key; do
    [ -f "$d/$n" ] && files="$files $n"
  done
  [ -n "$files" ] || fail "$d : aucun secret (jwt_secret_key, admin_token, rsa_master_key) ; lancer ci-prepare"
  vol_ensure "$vol"
  # shellcheck disable=SC2086
  tar -C "$d" -cf - $files | ctr run --rm -i -v "$vol:/secrets" \
    alpine:3.24@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a \
    sh -c 'set -e; tar -xf - -C /secrets; chown 0:0 /secrets; chmod 755 /secrets; for f in /secrets/*; do chown 10001:10001 "$f"; chmod 0400 "$f"; done'
  echo "secrets deposes dans le volume $vol (10001, 0400)"
}

# Certificat serveur JETABLE de CI (auto-signe, jamais une CA de confiance de la chaine) dans $1 : extensions X.509
# EXPLICITES (RFC 5280, independantes de l'openssl.cnf du systeme, qui ajoute sinon CA:TRUE sans keyUsage, refuse par
# Python >= 3.13 en VERIFY_X509_STRICT) : feuille serveur CA:FALSE, keyUsage critique, serverAuth, SAN localhost.
gen_ci_tls() {
  local d="$1"
  ( umask 077
    printf '%s\n' '[req]' 'distinguished_name = dn' 'x509_extensions = v3_leaf' 'prompt = no' '[dn]' 'CN = localhost' '[v3_leaf]' \
      'basicConstraints = critical,CA:FALSE' 'keyUsage = critical,digitalSignature,keyEncipherment' \
      'extendedKeyUsage = serverAuth' 'subjectKeyIdentifier = hash' 'subjectAltName = DNS:localhost,IP:127.0.0.1' > "$d/ci-tls.cnf"
    openssl req -x509 -newkey rsa:2048 -nodes -days 30 -config "$d/ci-tls.cnf" -keyout "$d/tls.key" -out "$d/tls.crt" 2>/dev/null )
  local rc=$?; rm -f "$d/ci-tls.cnf"; [ "$rc" = 0 ] || refuse "generation du certificat jetable de CI impossible ($d)"
  chmod 644 "$d/tls.key" "$d/tls.crt"   # lisible par l'UID 10001 du conteneur ; certificat jetable de CI
}

setup_ci() {
  [ "$CONTAINER_CLI" = docker ] || refuse "setup-ci : CI Docker uniquement"
  local d="${QUALIF_TLS_DIR:-$CI_TLS_DIR}"
  require_private_dir "$d" "$SECRETS_DIR"
  mkdir -p "$d"
  gen_ci_tls "$d"
  # Secrets ALEATOIRES et JETABLES de CI (jamais ceux de qualif/prod), en FICHIERS : 32 octets en hexadecimal (64 car.,
  # >= 32 octets exiges par #214), deposes dans le volume des secrets.
  gen_secrets   # conserve des secrets deja presents (la cle de l'etat ne doit pas changer apres `state init`)
  push_secrets
  QUALIF_TLS_DIR="$d" dc run --rm --no-deps secagent-server-a state init
  echo "QUALIF_TLS_DIR=$d"
}

# --- Racine (a, b) : UN SEUL chemin de creation/demarrage par plateforme (T48) ---------------------------------------
# Docker : Compose (`dc up -d`). Podman : les unites --user secagent-qualif-<srvX> (posees par verify-node-files.sh --pin,
# daemon-reload fait) : jamais podman-compose pour a/b. Un conteneur arrete par un scenario (ctr stop/kill) est relance
# tel quel (`ctr start`) : l'unite oneshot reste active et ne recree rien.
root_unit() { printf 'secagent-qualif-%s.service' "$(node_name "$1")"; }
root_up() {
  if [ "$CONTAINER_CLI" != podman ]; then
    # FAILOVER_UP_SERVICES (liste, optionnel) : ne (re)demarrer QUE ces services. Sans elle, `up -d` demarre TOUT le Compose,
    # y compris un service qu'un scenario vient d'arreter expres (chain-test.sh converged-timeout : l'enfant).
    # shellcheck disable=SC2086   # liste de services separes par des espaces
    QUALIF_TLS_DIR="${QUALIF_TLS_DIR:-$CI_TLS_DIR}" dc up -d ${FAILOVER_UP_SERVICES:-}
    return
  fi
  local n
  for n in A B; do
    node_ssh "$n" nostdin systemctl --user start "$(root_unit "$n")" \
      || fail "unite $(root_unit "$n") non demarree sur le noeud $n : deposee et epinglee ? (stage-node-files.sh + verify-node-files.sh --pin qualif $(node_name "$n"), puis daemon-reload)"
  done
  ctr start "$C_A" >/dev/null; ctr start "$C_B" >/dev/null
  require_running secagent-server-a secagent-server-b   # l'unite (oneshot) peut etre « active » sans conteneur
}
# Recree a et b avec la configuration PAR DEFAUT apres un scenario qui les a reconfigures (admission-503). Podman : arret des
# unites, suppression des conteneurs, redemarrage des unites (c'est l'unite qui recree). Docker : compose force-recreate.
root_reset() {
  if [ "$CONTAINER_CLI" != podman ]; then dc up -d --no-deps --force-recreate secagent-server-a secagent-server-b; return; fi
  local n
  for n in A B; do node_ssh "$n" nostdin systemctl --user stop "$(root_unit "$n")" || true; done
  ctr rm -f "$C_A" >/dev/null 2>&1 || true; ctr rm -f "$C_B" >/dev/null 2>&1 || true
  root_up
}

up_and_identify() {
  guard_remote_binds
  root_up
  wait_for "les deux conteneurs healthy" 120 all_health healthy "$C_A" "$C_B" >/dev/null
  sleep 3
  local ma=0 mb=0
  is_master "$C_A" && ma=1; is_master "$C_B" && mb=1
  [ $((ma+mb)) -eq 1 ] || fail "attendu exactement 1 maitre, trouve $((ma+mb))"
  if [ $ma -eq 1 ]; then MASTER=$C_A; SECOND=$C_B; else MASTER=$C_B; SECOND=$C_A; fi
  is_silent "$SECOND" || fail "le secondaire $SECOND ecoute sur un port"
  [ "$(lock_count "$MASTER")" = 1 ] || fail "plusieurs fichiers relay.lock"
  [ "$(health "$SECOND")" = healthy ] || fail "le secondaire n'est pas healthy"
  echo "maitre=$MASTER secondaire=$SECOND (1 seul relay.lock, secondaire sans port, healthy)"
}

hooks() {
  [ -z "${INVENTORY_CMD:-}" ] || bash -c "$INVENTORY_CMD" || fail "secagent-inventory ne repond pas"
  [ -z "${INSPECT_MINION_CMD:-}" ] || wait_for "minion reconnecte" 120 bash -c "$INSPECT_MINION_CMD" >/dev/null
}

# Garde (#256) : certificat serveur present AVANT tout `docker` de run(). Sans lui, `up -d` recreait les conteneurs sur
# un repertoire vide (bind mount) ou un volume absent : ils ne deviennent jamais healthy et l'echec ressemblait a une
# panne de bascule. Bind (defaut) : tls.crt et tls.key dans ${QUALIF_TLS_DIR:-$CI_TLS_DIR} (ca.crt non exige : setup-ci
# ne le produit pas). TLS_MODE=volume : le volume $SECAGENT_TLS_VOLUME doit exister (chain-test.sh push-tls).
require_run_tls() {
  local d="${QUALIF_TLS_DIR:-$CI_TLS_DIR}" f
  if [ "${TLS_MODE:-bind}" = volume ]; then
    [ -n "${SECAGENT_TLS_VOLUME:-}" ] || refuse "TLS_MODE=volume mais SECAGENT_TLS_VOLUME est vide : lancer 'chain-test.sh failover' (point d'entree du mode volume)"
    ctr volume inspect "$SECAGENT_TLS_VOLUME" >/dev/null 2>&1 \
      || refuse "TLS_MODE=volume : volume $SECAGENT_TLS_VOLUME absent du demon Docker (lancer 'chain-test.sh push-tls')"
    return 0
  fi
  for f in tls.crt tls.key; do
    [ -f "$d/$f" ] || refuse "certificat serveur absent : $d/$f (QUALIF_TLS_DIR=$d) ; lancer 'failover-test.sh setup-ci' (CI) ou 'chain-test.sh ci-prepare' (chaine) avant 'run'"
  done
}

run() {
  local mode="$1" t max
  case "$mode" in stop|kill|freeze) ;; *) refuse "mode inconnu: $mode (attendu stop|kill|freeze)" ;; esac
  require_run_tls   # avant toute commande docker (#256)
  up_and_identify
  hooks
  local fo_before=0 cv_before=0
  if hooks_enabled; then fo_before="$(hook_count "$SECOND" "$ROOT_RELAY_ID" FAILOVER)"; cv_before="$(hook_count "$SECOND" "$ROOT_RELAY_ID" CONVERGED)"; fi
  if [ "$mode" = freeze ]; then
    ctr kill -s STOP "$MASTER" >/dev/null
    t=$(wait_for "$MASTER unhealthy (process fige)" 180 all_health unhealthy "$MASTER")
    echo "$MASTER unhealthy apres ${t}s de gel"
    ctr kill -s CONT "$MASTER" >/dev/null
    wait_for "$MASTER de nouveau healthy" 180 all_health healthy "$MASTER" >/dev/null
    sleep 5
    local ma=0 mb=0
    is_master "$C_A" && ma=1; is_master "$C_B" && mb=1
    [ $((ma+mb)) -le 1 ] || fail "deux maitres apres le degel"
    echo "OK (freeze)"; return 0
  fi
  case "$mode" in
    stop) ctr stop -t 30 "$MASTER" >/dev/null; max=$STOP_MAX_S ;;
    kill) ctr kill "$MASTER" >/dev/null; max=$KILL_MAX_S ;;
  esac
  t=$(wait_for "reprise par $SECOND" "$max" is_master "$SECOND")
  echo "reprise par $SECOND en ${t}s (mode $mode, limite ${max}s)"
  [ "$(lock_count "$SECOND")" = 1 ] || fail "plusieurs fichiers relay.lock apres la bascule"
  if hooks_enabled; then
    # relay.failover (#225) emis par le NOUVEAU maitre : cause `start` apres un arret propre (verrou libere), `takeover`
    # apres un kill (verrou perime retire, previous_instance_id renseigne).
    local cause=start; [ "$mode" = kill ] && cause=takeover
    wait_for "relay.failover ($cause) journalise par le nouveau maitre $SECOND" 60 hook_more "$SECOND" "$ROOT_RELAY_ID" FAILOVER "$fo_before" >/dev/null
    events_log "$SECOND" | awk -v h="$ROOT_RELAY_ID" -v c="$cause" '$2=="FAILOVER" && $3==h {l=$0; k=$4} END{if (k!=c) {print "derniere ligne FAILOVER : " l > "/dev/stderr"; exit 1}}' \
      || fail "relay.failover de $SECOND : cause attendue $cause"
    echo "relay.failover journalise par $SECOND (cause $cause)"
    # relay.converged (#246, LOT-3.2) : UN seul, apres relay.failover, au plus tard au delai RELAY_CONVERGENCE_TIMEOUT
    # (qualif : 30 s) + marge ; ses comptes sont verifies par chain-test.sh.
    wait_for "relay.converged journalise par le nouveau maitre $SECOND" "${CONVERGED_MAX_S:-45}" hook_more "$SECOND" "$ROOT_RELAY_ID" CONVERGED "$cv_before" >/dev/null
    echo "relay.converged : $(hook_last "$SECOND" "$ROOT_RELAY_ID" CONVERGED)"
  fi
  hooks
  # L'ancien maitre revient en secondaire : aucun port, healthy, toujours un seul verrou.
  ctr start "$MASTER" >/dev/null
  wait_for "ancien maitre healthy" 120 all_health healthy "$MASTER" >/dev/null
  is_silent "$MASTER" || fail "l'ancien maitre ecoute alors qu'il y a un maitre"
  [ "$(lock_count "$SECOND")" = 1 ] || fail "plusieurs fichiers relay.lock apres le retour"
  echo "OK ($mode)"
}

# Chemins prives resolus (support de scripts/ci/private_paths_selftest.sh) : aucun appel docker, rien n'est cree.
paths() {
  local tls="${QUALIF_TLS_DIR:-$CI_TLS_DIR}"
  require_private_dir "$SECRETS_DIR" "$tls"
  printf 'PRIVATE_DIR=%s\nSECRETS_DIR=%s\nQUALIF_TLS_DIR=%s\n' "$PRIVATE_DIR" "$SECRETS_DIR" "$tls"
}

# Sourceable (chain-test.sh reutilise les fonctions) : le dispatch ne s'execute que lance directement.
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  case "${1:-}" in
    setup-ci) setup_ci ;;
    paths) paths ;;
    run) run "${2:?mode stop|kill}" ;;
    teardown) guard_project
              [ "$CONTAINER_CLI" = docker ] || refuse "teardown : utiliser 'chain-test.sh down' sous Podman (jamais down -v : etat et secrets sur le partage)"
              dc down -v
              # le volume des secrets est EXTERNE (non supprime par down -v) et contient des secrets : retrait explicite
              ctr volume rm "$SECAGENT_SECRETS_VOLUME" >/dev/null 2>&1 || true ;;
    *) sed -n '2,21p' "$0"; exit 2 ;;
  esac
fi
