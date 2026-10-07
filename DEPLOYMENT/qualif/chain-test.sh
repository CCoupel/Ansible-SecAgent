#!/usr/bin/env bash
# Topologie de qualif EN CHAINE (#188) : amorcage, smoke et bascule de la racine.
#
#   chain-test.sh ci-prepare   # CI uniquement : PKI de test + qualif.env aleatoire et jetable
#   chain-test.sh bootstrap    # state init (racine, enfant), relays add, jetons enrolement/plugin, demarrage
#   chain-test.sh smoke        # relais connectes, minions connectes, inventaire hierarchique, ansible -m ping
#   chain-test.sh failover     # arret propre du maitre de la racine (failover-test.sh) puis smoke
#   chain-test.sh backup-restore  # sauvegarde de l etat + de RSA_MASTER_KEY (a part), perte du volume, restauration
#   chain-test.sh push-tls     # TLS_MODE=volume : copie les certificats dans le volume Docker (hote distant)
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
# Projet dedie `secagent-qualif` (conteneurs secagent-qualif-a/-b/-child, ports d'hote 7770/7772 + 8770/8772 pour b,
# admin 127.0.0.1:7771/8771/9771). Deployer sur un hote qui heberge deja une ancienne qualif : liberer ces ports avant.
export COMPOSE_FILE="$HERE/docker-compose.chain.yml" PROJECT="${PROJECT:-${COMPOSE_PROJECT_NAME:-secagent-qualif}}"
# TLS_MODE=volume : certificats dans un VOLUME Docker nomme (hote Docker distant) au lieu d'un bind mount.
if [ "${TLS_MODE:-bind}" = volume ]; then
  export SECAGENT_TLS_VOLUME="${SECAGENT_TLS_VOLUME:-${PROJECT}_tls}"
  export COMPOSE_OVERRIDES="$HERE/docker-compose.remote-tls.yml"
fi
# Hote sur lequel le poste de controle joint la racine (ports d'hote 7770 et 8770) ; defaut : poste local / runner.
# Hote distant : SECAGENT_ENDPOINT_HOST=192.168.1.218 (doit figurer dans les SAN : PKI_EXTRA_SAN=IP:192.168.1.218).
ENDPOINT_HOST="${SECAGENT_ENDPOINT_HOST:-127.0.0.1}"
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

# Pousse tls.crt/tls.key/ca.crt de QUALIF_TLS_DIR dans le volume `$SECAGENT_TLS_VOLUME` de l'hote Docker (distant ou
# non) via un conteneur ephemere (flux tar sur stdin, image alpine epinglee) : TLS_MODE=volume requis.
push_tls() {
  [ "${TLS_MODE:-bind}" = volume ] || fail "push-tls exige TLS_MODE=volume"
  local f; for f in tls.crt tls.key ca.crt; do [ -f "$QUALIF_TLS_DIR/$f" ] || fail "$QUALIF_TLS_DIR/$f absent (lancer ci-prepare)"; done
  docker volume create "$SECAGENT_TLS_VOLUME" >/dev/null
  tar -C "$QUALIF_TLS_DIR" -cf - tls.crt tls.key ca.crt | docker run --rm -i -v "$SECAGENT_TLS_VOLUME:/certs" \
    alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc \
    sh -c 'tar -xf - -C /certs && chmod 755 /certs && chmod 644 /certs/tls.crt /certs/tls.key /certs/ca.crt'
  echo "certificats de test pousses dans le volume $SECAGENT_TLS_VOLUME"
}

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

connected() { # $1 conteneur CLI, $2 commande (relays|minions), $3 nom, $4 colonne du statut
  # Attend (150 s max : backoff de reconnexion du minion jusqu'a 60 s) que $3 soit `connected` sur 3 releves
  # CONSECUTIFS espaces de 2 s : un statut perime (« connected » herite de l'ancien maitre) ne suffit pas.
  local ok=0 t0; t0=$(now)
  while [ "$ok" -lt 3 ]; do
    if docker exec -e RELAY_API_URL=https://localhost:7771 -e REPEATER_CA_FILE=/certs/ca.crt "$1" /app/secagent-server "$2" list 2>/dev/null \
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

control_env() { # variables du poste de controle Ansible : listes d'adresses, CA de test, jeton en FICHIER
  export RELAY_SERVER_URL="https://${ENDPOINT_HOST}:7770,https://${ENDPOINT_HOST}:8770" RELAY_CA_BUNDLE="$QUALIF_TLS_DIR/ca.crt"
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
  guard_project
  local m bk key; m="$(master)" || fail "pas de maitre sur la racine"
  bk="$CHAIN_DIR/backup-state"; key="$CHAIN_DIR/backup-key"
  rm -rf "$bk" "$key"; mkdir -p "$bk" "$key"; chmod 700 "$key"
  connected "$m" minions minion-root 2    # le minion doit etre enrole et connecte avant la sauvegarde
  echo "== sauvegarde (etat) et sauvegarde distincte de RSA_MASTER_KEY"
  docker exec "$m" /app/secagent-server state verify /data/relay.state >/dev/null || fail "etat source invalide"
  docker cp "$m:/data/relay.state" "$bk/relay.state"; chmod 755 "$bk"; chmod 644 "$bk/relay.state"
  grep '^RSA_MASTER_KEY=' "$HERE/qualif.env" | write_secret "backup-key/rsa_master_key"
  echo "== sinistre : arret de la racine, perte du volume d'etat, perte de la cle sur l'hote"
  "${DC[@]}" rm -sf secagent-server-a secagent-server-b >/dev/null
  docker volume rm "${PROJECT}_secagent_state" >/dev/null
  cp "$HERE/qualif.env" "$CHAIN_DIR/qualif.env.lost"; chmod 600 "$CHAIN_DIR/qualif.env.lost"
  sed -i '/^RSA_MASTER_KEY=/d' "$HERE/qualif.env"
  local rc=0
  "${DC[@]}" run --rm --no-deps -v "$bk:/backup:ro" secagent-server-a state verify /backup/relay.state >/dev/null 2>&1 || rc=$?
  [ "$rc" = 6 ] || fail "sans RSA_MASTER_KEY : code 6 attendu, obtenu $rc"
  echo "sans la cle : refus (code 6) comme attendu"
  rc=0
  "${DC[@]}" run --rm --no-deps -e RSA_MASTER_KEY=mauvaise-cle -v "$bk:/backup:ro" secagent-server-a state verify /backup/relay.state >/dev/null 2>&1 || rc=$?
  [ "$rc" = 2 ] || fail "avec une mauvaise cle : code 2 attendu, obtenu $rc"
  echo "mauvaise cle : refus (code 2) comme attendu"
  echo "== restauration de la cle (depuis la sauvegarde distincte) puis de l'etat sur un volume vierge"
  { cat "$key/rsa_master_key"; echo; } >> "$HERE/qualif.env"
  "${DC[@]}" run --rm --no-deps -v "$bk:/backup:ro" secagent-server-a state verify /backup/relay.state >/dev/null || fail "etat sauvegarde refuse avec la cle restauree"
  "${DC[@]}" run --rm --no-deps -v "$bk:/backup:ro" secagent-server-a state restore --from /backup/relay.state
  "${DC[@]}" up -d secagent-server-a secagent-server-b
  wait_for "racine healthy apres restauration" 120 bash -c "[ \"\$(docker inspect -f '{{.State.Health.Status}}' $C_A)\" = healthy ] && [ \"\$(docker inspect -f '{{.State.Health.Status}}' $C_B)\" = healthy ]" >/dev/null
  sleep 3
  m="$(master)" || fail "pas de maitre apres restauration"
  echo "== le minion DEJA enrole se reconnecte sans re-enrolement (aucun nouveau jeton cree)"
  connected "$m" minions minion-root 2
  echo "backup-restore OK (meme identite : le minion, authentifie par l'etat restaure, est reconnecte)"
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
  backup-restore) backup_restore ;;
  logs) "${DC[@]}" logs --tail=100 ;;
  push-tls) push_tls ;;
  down) guard_project; "${DC[@]}" down -v ;;
  *) sed -n '2,16p' "$0"; exit 2 ;;
esac
