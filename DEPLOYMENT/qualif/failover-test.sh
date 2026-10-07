#!/usr/bin/env bash
# Test de basculement actif/passif EN CONTENEURS (#174 M6, partage avec #171 B).
# Verifie que les images et Compose LIVRES se comportent comme prevu : 2 instances sur un meme volume d'etat.
#
#   failover-test.sh setup-ci            # CI uniquement : certificats auto-signes, qualif.env, `state init`
#   failover-test.sh run stop            # arret propre du maitre : reprise rapide
#   failover-test.sh run kill            # docker kill : reprise apres la peremption du verrou (~5-6 min)
#   failover-test.sh run freeze          # SIGSTOP du maitre : doit passer `unhealthy`, puis SIGCONT : un seul maitre
#   failover-test.sh teardown            # docker compose down -v
#
# Variables : COMPOSE_FILE (defaut docker-compose.server.yml de ce repertoire), PROJECT (secagent-qualif),
#   C_A / C_B (noms de conteneurs, defaut secagent-qualif-a / -b), STOP_MAX_S (defaut 10), KILL_MAX_S (defaut 600),
#   INSPECT_MINION_CMD / INVENTORY_CMD : commandes optionnelles (code 0 = OK) lancees apres chaque bascule
#   (minion reconnecte sans re-enrolement ; secagent-inventory avec la liste des 2 adresses).
# Ne demarre rien a l'import ; exige docker et docker compose. Exit 0 = OK, 1 = echec.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fail() { echo "ECHEC: $*" >&2; exit 1; }
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
if is_remote; then
  [ "${TLS_MODE:-}" = volume ] || fail "hote Docker distant (DOCKER_HOST=${DOCKER_HOST:-} / point d'acces=${CONTROL_HOST:-${SECAGENT_ENDPOINT_HOST:-}}) : TLS_MODE=volume est obligatoire. Lancer 'chain-test.sh failover' (point d'entree, il prepare le mode volume) ; jamais ce script isole sans le mode volume."
  case "${COMPOSE_FILE:-}" in ""|*/docker-compose.chain.yml) ;; *) fail "hote distant : COMPOSE_FILE=${COMPOSE_FILE} incompatible avec le mode volume (attendu docker-compose.chain.yml) : lancer 'chain-test.sh failover'" ;; esac
  COMPOSE_FILE="${COMPOSE_FILE:-$HERE/docker-compose.chain.yml}"
  COMPOSE_OVERRIDES="${COMPOSE_OVERRIDES:-$HERE/docker-compose.remote-tls.yml}"
  SECAGENT_TLS_VOLUME="${SECAGENT_TLS_VOLUME:-${PROJECT:-${COMPOSE_PROJECT_NAME:-secagent-qualif}}_tls}"
  export COMPOSE_FILE COMPOSE_OVERRIDES SECAGENT_TLS_VOLUME
fi
COMPOSE_FILE="${COMPOSE_FILE:-$HERE/docker-compose.server.yml}"
PROJECT="${PROJECT:-${COMPOSE_PROJECT_NAME:-secagent-qualif}}"   # un SEUL projet (qualif reelle) : memes noms de conteneurs que la chaine, scripts lances SEQUENTIELLEMENT
C_A="${C_A:-secagent-qualif-a}"; C_B="${C_B:-secagent-qualif-b}"
STOP_MAX_S="${STOP_MAX_S:-10}"; KILL_MAX_S="${KILL_MAX_S:-600}"
DC=(docker compose -p "$PROJECT" -f "$COMPOSE_FILE")
# Fichiers de surcharge optionnels (ex. docker-compose.remote-tls.yml pour un hote Docker distant) : liste separee par des espaces.
for f in ${COMPOSE_OVERRIDES:-}; do DC+=(-f "$f"); done
now() { date +%s.%N; }

listening() { # $1 conteneur, $2 port : 0 si le conteneur ecoute sur le port (lecture de /proc/net/tcp{,6} :
  # aucune dependance a netstat/ss ; etat 0A = LISTEN, port en hexadecimal sur 4 chiffres)
  local hex; hex=$(printf '%04X' "$2")
  docker exec "$1" sh -c "cat /proc/net/tcp /proc/net/tcp6 2>/dev/null | awk -v p=':$hex' '\$4==\"0A\" && index(\$2,p) && substr(\$2,length(\$2)-3)==substr(p,2) {f=1} END{exit !f}'"
}
is_master() { listening "$1" 7770 && listening "$1" 7772; }
is_silent() { ! listening "$1" 7770 && ! listening "$1" 7772 && ! listening "$1" 7771; }
lock_count() { docker exec "$1" sh -c 'ls /data | grep -c "^relay\.lock" || true'; }
health() { docker inspect -f '{{.State.Health.Status}}' "$1" 2>/dev/null || echo none; }

# Garde-fou des operations DESTRUCTIVES (down -v, teardown, backup-restore) : jamais hors des projets de test.
# Hote Docker DISTANT (DOCKER_HOST non local) : uniquement le projet `secagent-qualif`. Local/CI : les projets de
# test des scripts (ALLOWED_PROJECTS, defaut secagent-qualif secagent-chain secagent-failover). Tout autre projet
# (ex. l'ancienne qualif v2) est refuse.
guard_project() {
  local remote=0
  case "${DOCKER_HOST:-}" in ""|unix://*|npipe://*) ;; *) remote=1 ;; esac
  if [ "$remote" = 1 ]; then
    [ "$PROJECT" = secagent-qualif ] || fail "operation destructive refusee : hote Docker distant (${DOCKER_HOST}) et projet '$PROJECT' != secagent-qualif"
  else
    case " ${ALLOWED_PROJECTS:-secagent-qualif secagent-chain secagent-failover} " in
      *" $PROJECT "*) ;;
      *) fail "operation destructive refusee : projet '$PROJECT' hors de la liste (${ALLOWED_PROJECTS:-secagent-qualif secagent-chain secagent-failover})" ;;
    esac
  fi
  if [ -n "${COMPOSE_PROJECT_NAME:-}" ] && [ "$COMPOSE_PROJECT_NAME" != "$PROJECT" ]; then
    fail "COMPOSE_PROJECT_NAME ($COMPOSE_PROJECT_NAME) differe de PROJECT ($PROJECT) : refus"
  fi
}

# Mode distant : AUCUN bind mount (resolu sur l'hote distant, pas sur le poste) dans le rendu Compose ; refuse sinon.
guard_remote_binds() {
  is_remote || return 0
  local json; json="$("${DC[@]}" config --format json 2>/dev/null)" || fail "rendu Compose impossible (variables obligatoires ?) : verification des bind mounts refusee"
  printf '%s' "$json" | python3 "$HERE/../../scripts/ci/check_no_binds.py" \
    || fail "mode distant : bind mount d'un chemin du poste vers le demon distant refuse (utiliser TLS_MODE=volume + chain-test.sh push-tls)"
}

wait_for() { # $1 description, $2 delai max, $3... commande
  local what="$1" max="$2"; shift 2; local t0; t0=$(now)
  while ! "$@" 2>/dev/null; do
    awk -v a="$t0" -v b="$(now)" -v m="$max" 'BEGIN{exit !(b-a>m)}' && fail "$what: delai de ${max}s depasse"
    sleep 0.2
  done
  awk -v a="$t0" -v b="$(now)" 'BEGIN{printf "%.1f", b-a}'
}

setup_ci() {
  local d="${QUALIF_TLS_DIR:-$HERE/.ci-tls}"
  mkdir -p "$d"
  openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" -keyout "$d/tls.key" -out "$d/tls.crt" 2>/dev/null
  chmod 644 "$d/tls.key"   # lisible par l'UID 10001 du conteneur ; certificat jetable de CI
  # Secrets ALEATOIRES et JETABLES de CI (jamais ceux de qualif/prod). RSA_MASTER_KEY : toute chaine non vide
  # convient (SHA-256 / HKDF du texte, internal/crypto) ; 32 octets aleatoires en hexadecimal en CI.
  umask 077
  { echo "JWT_SECRET_KEY=$(openssl rand -hex 32)"; echo "ADMIN_TOKEN=$(openssl rand -hex 24)"
    echo "RSA_MASTER_KEY=$(openssl rand -hex 32)"; } > "$HERE/qualif.env"
  QUALIF_TLS_DIR="$d" "${DC[@]}" run --rm --no-deps secagent-server-a state init
  echo "QUALIF_TLS_DIR=$d"
}

up_and_identify() {
  guard_remote_binds
  QUALIF_TLS_DIR="${QUALIF_TLS_DIR:-$HERE/.ci-tls}" "${DC[@]}" up -d
  wait_for "les deux conteneurs healthy" 120 bash -c "[ \"\$(docker inspect -f '{{.State.Health.Status}}' $C_A)\" = healthy ] && [ \"\$(docker inspect -f '{{.State.Health.Status}}' $C_B)\" = healthy ]" >/dev/null
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

run() {
  local mode="$1" t max
  up_and_identify
  hooks
  if [ "$mode" = freeze ]; then
    docker kill -s STOP "$MASTER" >/dev/null
    t=$(wait_for "$MASTER unhealthy (process fige)" 180 bash -c "[ \"\$(docker inspect -f '{{.State.Health.Status}}' $MASTER)\" = unhealthy ]")
    echo "$MASTER unhealthy apres ${t}s de gel"
    docker kill -s CONT "$MASTER" >/dev/null
    wait_for "$MASTER de nouveau healthy" 180 bash -c "[ \"\$(docker inspect -f '{{.State.Health.Status}}' $MASTER)\" = healthy ]" >/dev/null
    sleep 5
    local ma=0 mb=0
    is_master "$C_A" && ma=1; is_master "$C_B" && mb=1
    [ $((ma+mb)) -le 1 ] || fail "deux maitres apres le degel"
    echo "OK (freeze)"; return 0
  fi
  case "$mode" in
    stop) docker stop -t 30 "$MASTER" >/dev/null; max=$STOP_MAX_S ;;
    kill) docker kill "$MASTER" >/dev/null; max=$KILL_MAX_S ;;
    *) fail "mode inconnu: $mode" ;;
  esac
  t=$(wait_for "reprise par $SECOND" "$max" is_master "$SECOND")
  echo "reprise par $SECOND en ${t}s (mode $mode, limite ${max}s)"
  [ "$(lock_count "$SECOND")" = 1 ] || fail "plusieurs fichiers relay.lock apres la bascule"
  hooks
  # L'ancien maitre revient en secondaire : aucun port, healthy, toujours un seul verrou.
  docker start "$MASTER" >/dev/null
  wait_for "ancien maitre healthy" 120 bash -c "[ \"\$(docker inspect -f '{{.State.Health.Status}}' $MASTER)\" = healthy ]" >/dev/null
  is_silent "$MASTER" || fail "l'ancien maitre ecoute alors qu'il y a un maitre"
  [ "$(lock_count "$SECOND")" = 1 ] || fail "plusieurs fichiers relay.lock apres le retour"
  echo "OK ($mode)"
}

# Sourceable (chain-test.sh reutilise les fonctions) : le dispatch ne s'execute que lance directement.
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  case "${1:-}" in
    setup-ci) setup_ci ;;
    run) run "${2:?mode stop|kill}" ;;
    teardown) guard_project; "${DC[@]}" down -v ;;
    *) sed -n '2,15p' "$0"; exit 2 ;;
  esac
fi
