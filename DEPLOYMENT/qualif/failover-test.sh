#!/usr/bin/env bash
# Test de basculement actif/passif EN CONTENEURS (#174 M6, partage avec #171 B).
# Verifie que les images et Compose LIVRES se comportent comme prevu : 2 instances sur un meme volume d'etat.
#
#   failover-test.sh setup-ci            # CI uniquement : certificats auto-signes, qualif.env, `state init`
#   failover-test.sh run stop            # arret propre du maitre : reprise rapide
#   failover-test.sh run kill            # docker kill : reprise apres la peremption du verrou (~5-6 min)
#   failover-test.sh teardown            # docker compose down -v
#
# Variables : COMPOSE_FILE (defaut docker-compose.server.yml de ce repertoire), PROJECT (secagent-failover),
#   C_A / C_B (noms de conteneurs, defaut secagent-qualif-a / -b), STOP_MAX_S (defaut 10), KILL_MAX_S (defaut 600),
#   INSPECT_MINION_CMD / INVENTORY_CMD : commandes optionnelles (code 0 = OK) lancees apres chaque bascule
#   (minion reconnecte sans re-enrolement ; secagent-inventory avec la liste des 2 adresses).
# Ne demarre rien a l'import ; exige docker et docker compose. Exit 0 = OK, 1 = echec.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="${COMPOSE_FILE:-$HERE/docker-compose.server.yml}"
PROJECT="${PROJECT:-secagent-failover}"
C_A="${C_A:-secagent-qualif-a}"; C_B="${C_B:-secagent-qualif-b}"
STOP_MAX_S="${STOP_MAX_S:-10}"; KILL_MAX_S="${KILL_MAX_S:-600}"
DC=(docker compose -p "$PROJECT" -f "$COMPOSE_FILE")
fail() { echo "ECHEC: $*" >&2; exit 1; }
now() { date +%s.%N; }

listening() { # $1 conteneur, $2 port : 0 si le conteneur ecoute sur le port
  docker exec "$1" sh -c "netstat -ltn 2>/dev/null | grep -q ':$2 '"
}
is_master() { listening "$1" 7770 && listening "$1" 7772; }
is_silent() { ! listening "$1" 7770 && ! listening "$1" 7772 && ! listening "$1" 7771; }
lock_count() { docker exec "$1" sh -c 'ls /data | grep -c "^relay\.lock" || true'; }
health() { docker inspect -f '{{.State.Health.Status}}' "$1" 2>/dev/null || echo none; }

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
  openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" -keyout "$d/tls.key" -out "$d/tls.crt" 2>/dev/null
  chmod 644 "$d/tls.key"   # lisible par l'UID 10001 du conteneur ; certificat jetable de CI
  # Secrets ALEATOIRES et JETABLES de CI (jamais ceux de qualif/prod). Format de RSA_MASTER_KEY : voir STATE_SPEC.
  umask 077
  { echo "JWT_SECRET_KEY=$(openssl rand -hex 32)"; echo "ADMIN_TOKEN=$(openssl rand -hex 24)"
    echo "RSA_MASTER_KEY=$(openssl rand -hex 32)"; } > "$HERE/qualif.env"
  QUALIF_TLS_DIR="$d" "${DC[@]}" run --rm --no-deps secagent-server-a state init
  echo "QUALIF_TLS_DIR=$d"
}

up_and_identify() {
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
  local mode="$1"
  up_and_identify
  hooks
  case "$mode" in
    stop) docker stop -t 30 "$MASTER" >/dev/null; max=$STOP_MAX_S ;;
    kill) docker kill "$MASTER" >/dev/null; max=$KILL_MAX_S ;;
    *) fail "mode inconnu: $mode" ;;
  esac
  local t
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

case "${1:-}" in
  setup-ci) setup_ci ;;
  run) run "${2:?mode stop|kill}" ;;
  teardown) "${DC[@]}" down -v ;;
  *) sed -n '2,15p' "$0"; exit 2 ;;
esac
