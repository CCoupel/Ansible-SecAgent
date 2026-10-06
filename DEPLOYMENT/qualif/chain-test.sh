#!/usr/bin/env bash
# Topologie de qualif EN CHAINE (#188) : amorcage, smoke et bascule de la racine.
#
#   chain-test.sh ci-prepare   # CI uniquement : PKI de test + qualif.env aleatoire et jetable
#   chain-test.sh bootstrap    # state init (racine, enfant), relays add, jetons enrolement/plugin, demarrage
#   chain-test.sh smoke        # relais connectes, minions connectes, inventaire hierarchique, ansible -m ping
#   chain-test.sh failover     # arret propre du maitre de la racine (failover-test.sh) puis smoke
#   chain-test.sh logs | down
#
# Variables : SECAGENT_IMAGE, SECAGENT_MINION_IMAGE (obligatoires, references promues ou locales),
#   QUALIF_TLS_DIR (defaut ./pki/out), INVENTORY_BIN (binaire secagent-inventory du poste de controle),
#   ANSIBLE_BIN (defaut `ansible`), PROJECT (defaut secagent-chain), TOKEN_TTL (defaut 2h).
# Les jetons sont ecrits UNIQUEMENT dans ./chain/ (0700, fichiers 0600, ignore par git) : jamais affiches.
# Le poste de controle Ansible (plugin SECAGENT-PYTHON + secagent-inventory) est ici le poste qui lance ce script,
# il joint la racine par les ports d'hote 7770 (a) et 8770 (b) avec la CA de test.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
export COMPOSE_FILE="$HERE/docker-compose.chain.yml" PROJECT="${PROJECT:-secagent-chain}"
export QUALIF_TLS_DIR="${QUALIF_TLS_DIR:-$HERE/pki/out}"
C_A="secagent-qualif-a"; C_B="secagent-qualif-b"; C_CHILD="secagent-qualif-child"
export C_A C_B
TOKEN_TTL="${TOKEN_TTL:-2h}"
CHAIN_DIR="$HERE/chain"
# shellcheck source=failover-test.sh
source "$HERE/failover-test.sh"   # fonctions : listening, is_master, wait_for, health, fail, DC...

adm() { # $1 conteneur, puis la commande secagent-server : CLI admin en TLS (CA de test), ADMIN_TOKEN du conteneur
  local c="$1"; shift
  docker exec -e RELAY_API_URL=https://localhost:7771 -e REPEATER_CA_FILE=/certs/ca.crt "$c" /app/secagent-server "$@"
}
master() { is_master "$C_A" && echo "$C_A" || { is_master "$C_B" && echo "$C_B"; }; }
write_secret() { # $1 fichier relatif a chain/, valeur lue sur stdin : jamais affichee
  ( umask 077; cat > "$CHAIN_DIR/$1" )
  chmod 600 "$CHAIN_DIR/$1"
}
extract() { grep -oE "$1" | tail -1; }   # extrait un jeton de la sortie du CLI sans l'afficher
need() { [ -n "${!1:-}" ] || fail "variable $1 obligatoire"; }

ci_prepare() {
  bash "$HERE/pki/gen.sh" "$QUALIF_TLS_DIR"
  ( umask 077
    { echo "JWT_SECRET_KEY=$(openssl rand -hex 32)"; echo "ADMIN_TOKEN=$(openssl rand -hex 24)"
      echo "RSA_MASTER_KEY=$(openssl rand -hex 32)"; } > "$HERE/qualif.env" )
}

bootstrap() {
  need SECAGENT_IMAGE; need SECAGENT_MINION_IMAGE
  mkdir -p "$CHAIN_DIR"; chmod 700 "$CHAIN_DIR"
  echo "== etat initial (racine, enfant)"
  "${DC[@]}" run --rm --no-deps secagent-server-a state init
  "${DC[@]}" run --rm --no-deps secagent-child state init
  echo "== racine : demarrage et identification du maitre"
  "${DC[@]}" up -d secagent-server-a secagent-server-b
  wait_for "racine healthy" 120 bash -c "[ \"\$(docker inspect -f '{{.State.Health.Status}}' $C_A)\" = healthy ] && [ \"\$(docker inspect -f '{{.State.Health.Status}}' $C_B)\" = healthy ]" >/dev/null
  sleep 3
  local m; m="$(master)" || fail "pas de maitre sur la racine"
  echo "maitre de la racine : $m"
  echo "== jeton de l'enfant pull (relays add)"
  adm "$m" relays add --id dmz1 --description "chain child" 2>&1 | extract 'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+' \
    | { read -r t; [ -n "$t" ] || fail "jeton d'enfant non extrait"; printf 'REPEATER_UPSTREAM_TOKEN=%s\n' "$t" | write_secret child.env; }
  "${DC[@]}" up -d secagent-child
  wait_for "enfant healthy" 120 bash -c "[ \"\$(docker inspect -f '{{.State.Health.Status}}' $C_CHILD)\" = healthy ]" >/dev/null
  echo "== jetons d'enrolement (un par minion, hostname exact) et jeton plugin (FICHIER 0600)"
  adm "$m" tokens create --role enrollment --hostname-pattern '^minion-root$' --expires "$TOKEN_TTL" 2>&1 \
    | extract 'secagent_enr_[0-9a-f]{64}' | { read -r t; [ -n "$t" ] || fail "jeton minion-root non extrait"; printf 'RELAY_ENROLLMENT_TOKEN=%s\n' "$t" | write_secret minion-root.env; }
  adm "$C_CHILD" tokens create --role enrollment --hostname-pattern '^minion-child$' --expires "$TOKEN_TTL" 2>&1 \
    | extract 'secagent_enr_[0-9a-f]{64}' | { read -r t; [ -n "$t" ] || fail "jeton minion-child non extrait"; printf 'RELAY_ENROLLMENT_TOKEN=%s\n' "$t" | write_secret minion-child.env; }
  adm "$m" tokens create --role plugin --description chain-smoke --expires "$TOKEN_TTL" 2>&1 \
    | extract 'secagent_plg_[0-9a-f]{64}' | { read -r t; [ -n "$t" ] || fail "jeton plugin non extrait"; printf '%s' "$t" | write_secret plugin.token; }
  echo "== minions"
  "${DC[@]}" up -d minion-root minion-child
  echo "bootstrap OK (jetons dans $CHAIN_DIR, non affiches)"
}

connected() { # $1 conteneur CLI, $2 commande (relays|minions), $3 nom, $4 colonne du statut : poll <= 90 s
  wait_for "$3 connected" 90 bash -c "docker exec -e RELAY_API_URL=https://localhost:7771 -e REPEATER_CA_FILE=/certs/ca.crt $1 /app/secagent-server $2 list | awk -v n='$3' -v c=$4 '\$1==n && \$c==\"connected\" {f=1} END{exit !f}'" >/dev/null
}

control_env() { # variables du poste de controle Ansible : listes d'adresses, CA de test, jeton en FICHIER
  export RELAY_SERVER_URL="https://127.0.0.1:7770,https://127.0.0.1:8770" RELAY_CA_BUNDLE="$QUALIF_TLS_DIR/ca.crt"
  export RELAY_TOKEN_FILE="$CHAIN_DIR/plugin.token"
}

smoke() {
  local m; m="$(master)" || fail "pas de maitre sur la racine"
  echo "== relais et minions connectes"
  connected "$m" relays dmz1 4
  connected "$m" minions minion-root 2
  connected "$C_CHILD" minions minion-child 2
  echo "== inventaire hierarchique (liste d'adresses de la racine)"
  control_env
  need INVENTORY_BIN
  local inv; inv="$(RELAY_TOKEN="$(cat "$RELAY_TOKEN_FILE")" "$INVENTORY_BIN" --list)"
  printf '%s' "$inv" | grep -q minion-root || fail "minion-root absent de l'inventaire"
  printf '%s' "$inv" | grep -q minion-child || fail "minion-child (sous l'enfant) absent de l'inventaire de la racine"
  echo "== ansible -m ping sur tous les hotes (plugin de connexion, CA de test)"
  local inv_script="$CHAIN_DIR/inventory.sh"
  printf '#!/bin/sh\nRELAY_TOKEN="$(cat "%s")" exec "%s" "$@"\n' "$RELAY_TOKEN_FILE" "$INVENTORY_BIN" | write_secret inventory.sh
  chmod 700 "$inv_script"
  ANSIBLE_CONNECTION_PLUGINS="$REPO/SECAGENT-PYTHON/ansible_plugins/connection_plugins" ANSIBLE_HOST_KEY_CHECKING=False \
    "${ANSIBLE_BIN:-ansible}" all -i "$inv_script" -m ping | tee "$CHAIN_DIR/ping.log"
  [ "$(grep -c SUCCESS "$CHAIN_DIR/ping.log")" -ge 2 ] || fail "ansible -m ping : moins de 2 hotes SUCCESS"
  echo "smoke OK"
}

failover() {
  need INVENTORY_BIN
  control_env
  # Arret propre du maitre : l'enfant et les minions doivent se reconnecter par leurs listes, ping OK ensuite.
  bash "$HERE/failover-test.sh" run stop
  smoke
}

case "${1:-}" in
  ci-prepare) ci_prepare ;;
  bootstrap) bootstrap ;;
  smoke) smoke ;;
  failover) failover ;;
  logs) "${DC[@]}" logs --tail=100 ;;
  down) "${DC[@]}" down -v ;;
  *) sed -n '2,16p' "$0"; exit 2 ;;
esac
