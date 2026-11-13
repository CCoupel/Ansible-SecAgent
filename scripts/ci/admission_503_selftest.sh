#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
# SPDX-License-Identifier: AGPL-3.0-or-later

# Auto-test des fonctions HTTP de DEPLOYMENT/qualif/admission-503.sh (#241) avec un faux `curl` : sans docker ni reseau.
# Verifie les exec de fond (codes, PID), la lecture 503 + Retry-After, la detection d'un lot refuse et l'absence de fuite
# du jeton (l'en-tete d'autorisation n'est passe que par fichier). L'etape reelle est jouee par deployer sur la qualif.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
mkdir -p "$T/bin" "$T/chain"
cat > "$T/bin/curl" <<'STUB'
#!/usr/bin/env bash
# faux curl : "cmd":"true" => 503 memory_budget_exhausted + Retry-After ; "cmd":"deny" => 429 ; sinon 200 rc 0 apres 1 s
args="$*"; echo "$args" >> "$STUB_LOG"
while [ $# -gt 0 ]; do case "$1" in -D) H=$2; shift;; -o) O=$2; shift;; -d) D=$2; shift;; esac; shift; done
case "$D" in
  *'"cmd":"true"'*) printf 'HTTP/2 503\r\nRetry-After: 5\r\n\r\n' > "$H"; echo '{"error":"memory_budget_exhausted"}' > "$O"; printf 503 ;;
  *'"cmd":"sleep 300"'*) echo $$ >> "$STUB_PIDS"; exec sleep 300 ;;
  *'"cmd":"deny"'*) printf 'HTTP/2 429\r\nRetry-After: 1\r\n\r\n' > "$H"; echo '{"error":"agent_busy"}' > "$O"; printf 429 ;;
  *) sleep 1; printf 'HTTP/2 200\r\n\r\n' > "$H"; echo '{"rc":0,"stdout":""}' > "$O"; printf 200 ;;
esac
STUB
chmod +x "$T/bin/curl"
export STUB_LOG="$T/curl.log" STUB_PIDS="$T/curl.pids"; : > "$STUB_LOG"; : > "$STUB_PIDS"
bad=0
ko() { echo "KO  $*"; bad=1; }
ok() { echo "ok  $*"; }
check() { # $1 libelle, $2 "0" si la condition est tenue, $3 detail de l'echec
  if [ "$2" = 0 ]; then ok "$1"; else ko "$1 ${3:-}"; fi
}

# shellcheck disable=SC2016
out="$(PATH="$T/bin:$PATH" CHAIN_DIR="$T/chain" QUALIF_TLS_DIR=/ca ENDPOINT_HOST=h C_A=c-a bash -c '
  set -euo pipefail
  fail() { echo "FAIL $*"; exit 1; }
  master() { echo c-a; }
  source "'"$ROOT"'/DEPLOYMENT/qualif/admission-503.sh"
  ADM503_BASE="$(adm503_base_of c-a)"
  ADM503_DIR="$CHAIN_DIR/adm"; mkdir -p "$ADM503_DIR"; echo "Authorization: Bearer SECRET-VALUE" > "$CHAIN_DIR/plugin.header"
  adm503_fill fill 2 minion-child minion-child minion-root
  adm503_lot_alive && echo "alive"
  echo "probe=$(adm503_exec minion-root "$(adm503_uuid)" true 20 "$ADM503_DIR/p")"
  grep -i "^retry-after: 5" "$ADM503_DIR/p.hdr" >/dev/null && echo "retry-after"
  grep -q memory_budget_exhausted "$ADM503_DIR/p.body" && echo "body"
  adm503_lot_wait; adm503_lot_all_ok fill 3; echo "lot-ok"
  echo "denied=$(adm503_exec minion-root "$(adm503_uuid)" deny 20 "$ADM503_DIR/d")"
  echo "base=$(adm503_base_of c-a)"
' 2>&1)" || { ko "scenario : $out"; }
for want in alive probe=503 retry-after body lot-ok denied=429 base=https://h:7770; do
  case "$out" in *"$want"*) ok "faux curl : $want" ;; *) ko "faux curl : '$want' absent de : $out" ;; esac
done
check "jeton passe par fichier (-H @fichier)" "$(grep -q -- '-H @' "$STUB_LOG"; echo $?)"
check "le jeton ne figure pas dans la ligne de commande de curl" "$(if grep -q 'SECRET-VALUE' "$STUB_LOG"; then echo 1; else echo 0; fi)"
check "CA de test utilisee (--cacert)" "$(grep -q -- '--cacert /ca/ca.crt' "$STUB_LOG"; echo $?)"
check "verification TLS non desactivee (ni -k ni --insecure)" "$(if grep -q -- ' -k\| --insecure' "$STUB_LOG"; then echo 1; else echo 0; fi)"

# T48 (ordre n°22) : URL du maitre sous Podman (adresse du noeud, pas ENDPOINT_HOST), resolue une fois ; aucune
# session SSH (master/ctr) dans les requetes paralleles ; attente du maitre elu et de l'API apres recreation
# shellcheck disable=SC2016
res="$(PATH="$T/bin:$PATH" CHAIN_DIR="$T/chain" QUALIF_TLS_DIR=/ca ENDPOINT_HOST=127.0.0.1 C_A=c-a CONTAINER_CLI=podman bash -c '
  set -euo pipefail
  fail() { echo "FAIL $*"; exit 1; }
  node_addr() { case "$1" in A) echo 10.0.0.3 ;; B) echo 10.0.0.4 ;; esac; }
  source "'"$ROOT"'/DEPLOYMENT/qualif/admission-503.sh"
  echo "pa=$(adm503_base_of c-a) pb=$(adm503_base_of c-b)"
  echo "port=$(ADM503_PORT_A=17770 adm503_base_of c-a)"
  calls="'"$T"'/ssh-calls"; : > "$calls"
  master() { echo master >> "'"$T"'/ssh-calls"; echo c-b; }; ctr() { echo ctr >> "'"$T"'/ssh-calls"; }
  wait_for() { shift 2; "$@"; }
  adm503_set_base; : > "$calls"
  ADM503_DIR="$CHAIN_DIR/adm5"; mkdir -p "$ADM503_DIR"
  adm503_fill f 1 minion-root minion-child minion-root; adm503_lot_wait
  echo "ssh-dans-le-fond=$(wc -l < "$calls")"
' 2>&1)" || true
case "$res" in *"pa=https://10.0.0.3:7770 pb=https://10.0.0.4:8770"*) ok "Podman : a joint par l'adresse du noeud A:7770, b par B:8770 (pas ENDPOINT_HOST)" ;; *) ko "URL Podman : $res" ;; esac
case "$res" in *"port=https://10.0.0.3:17770"*) ok "ADM503_PORT_A : port d'hote parametrable (banc isole)" ;; *) ko "ADM503_PORT_A : $res" ;; esac
case "$res" in *"maitre c-b, API https://10.0.0.4:8770 joignable"*) ok "adm503_set_base : maitre elu (b) puis API joignable" ;; *) ko "adm503_set_base : $res" ;; esac
case "$res" in *"ssh-dans-le-fond=0"*) ok "requetes paralleles : aucune session SSH (master/ctr) dans les taches de fond" ;; *) ko "SSH dans les taches de fond : $res" ;; esac
grep -q 'adm503_set_base   # maitre elu' "$ROOT/DEPLOYMENT/qualif/admission-503.sh" && sed -n '/^adm503_recreate_root() {/,/^}/p' "$ROOT/DEPLOYMENT/qualif/admission-503.sh" | grep -q adm503_set_base \
  && ok "adm503_recreate_root : attente du maitre et de l'API apres chaque recreation" || ko "adm503_recreate_root sans adm503_set_base"

# un exec de fond refuse (429) fait echouer adm503_lot_all_ok avec le code observe
set +e
res="$(PATH="$T/bin:$PATH" CHAIN_DIR="$T/chain" QUALIF_TLS_DIR=/ca ENDPOINT_HOST=h C_A=c-a bash -c '
  set -euo pipefail
  fail() { echo "FAIL $*"; exit 1; }
  master() { echo c-a; }
  source "'"$ROOT"'/DEPLOYMENT/qualif/admission-503.sh"
  ADM503_BASE="$(adm503_base_of c-a)"
  ADM503_DIR="$CHAIN_DIR/adm2"; mkdir -p "$ADM503_DIR"
  printf minion-root > "$ADM503_DIR/x-1.host"; printf 429 > "$ADM503_DIR/x-1.code"; echo "{\"error\":\"agent_busy\"}" > "$ADM503_DIR/x-1.body"
  adm503_lot_all_ok x 1
' 2>&1)"; rc=$?
set -e
good=1; case "$res" in *"HTTP 429"*agent_busy*) [ "$rc" -ne 0 ] && good=0 ;; esac
check "lot refuse : echec avec HTTP 429 et le corps" "$good" "(rc=$rc) : $res"

# garde-fou du budget : plus de 20 taches (> 2 x MAX_TASKS_PER_AGENT) est refuse avant tout demarrage
set +e
res="$(ADM503_BUDGET=$((5242880 * 21)) bash -c '
  fail() { echo "FAIL $*"; exit 1; }
  verify_images() { :; }; need() { :; }; CHAIN_DIR='"$T"'/chain
  source "'"$ROOT"'/DEPLOYMENT/qualif/admission-503.sh"
  admission_503
' 2>&1)"; rc=$?
set -e
good=1; case "$res" in *"429"*) [ "$rc" -ne 0 ] && good=0 ;; esac
check "budget > 20 taches refuse (le refus serait un 429)" "$good" "(rc=$rc) : $res"
# nettoyage : tue les exec de fond ET leurs `curl` enfants (par PID parent), et seulement ceux de l'etape
res="$(PATH="$T/bin:$PATH" CHAIN_DIR="$T/chain" QUALIF_TLS_DIR=/ca ENDPOINT_HOST=h C_A=c-a bash -c '
  set -euo pipefail
  fail() { echo "FAIL $*"; exit 1; }
  master() { echo c-a; }
  source "'"$ROOT"'/DEPLOYMENT/qualif/admission-503.sh"
  ADM503_BASE="$(adm503_base_of c-a)"
  ADM503_DIR="$CHAIN_DIR/adm3"; mkdir -p "$ADM503_DIR"
  sleep 300 & other=$!      # processus etranger a l etape : ne doit pas etre touche
  adm503_fill hang 300 minion-root minion-child
  for _ in $(seq 1 50); do [ "$(wc -l < "$STUB_PIDS")" -ge 2 ] && break; sleep 0.1; done
  [ "$(wc -l < "$STUB_PIDS")" -ge 2 ] || { echo "no-curl-started"; kill "$other"; exit 0; }
  adm503_cleanup
  sleep 0.5
  for c in $(cat "$STUB_PIDS"); do if kill -0 "$c" 2>/dev/null; then echo "curl-survivant=$c"; fi; done
  kill -0 "$other" 2>/dev/null && echo "etranger-intact"
  kill "$other" 2>/dev/null || true
  echo "pids-vides=${#ADM503_PIDS[@]}"
' 2>&1)" || true
case "$res" in *no-curl-started*) ko "nettoyage : les faux curl n'ont pas demarre : $res" ;; *curl-survivant*) ko "nettoyage : un curl enfant survit : $res" ;; *) ok "nettoyage : les curl enfants sont tues" ;; esac
case "$res" in *etranger-intact*) ok "nettoyage : un processus etranger a l'etape n'est pas tue" ;; *) ko "nettoyage : processus etranger touche : $res" ;; esac
case "$res" in *pids-vides=0*) ok "nettoyage : liste des PID videe" ;; *) ko "nettoyage : liste non videe : $res" ;; esac

# adm503_lot_wait retire du suivi les PID deja attendus (un PID recycle ne doit pas etre vise plus tard)
res="$(PATH="$T/bin:$PATH" CHAIN_DIR="$T/chain" QUALIF_TLS_DIR=/ca ENDPOINT_HOST=h C_A=c-a bash -c '
  set -euo pipefail
  fail() { echo "FAIL $*"; exit 1; }
  master() { echo c-a; }
  source "'"$ROOT"'/DEPLOYMENT/qualif/admission-503.sh"
  ADM503_BASE="$(adm503_base_of c-a)"
  ADM503_DIR="$CHAIN_DIR/adm4"; mkdir -p "$ADM503_DIR"
  adm503_fill a 1 minion-root minion-root
  adm503_lot_wait
  echo "apres-wait=${#ADM503_PIDS[@]}:${ADM503_PIDS[*]:-}"
  adm503_fill b 1 minion-root
  echo "apres-fill=${#ADM503_PIDS[@]}"
  adm503_lot_wait
  echo "fin=${ADM503_PIDS[*]:-}"
' 2>&1)" || true
case "$res" in *"apres-wait=0:"*) ok "lot_wait : PID du lot retires du suivi" ;; *) ko "lot_wait : PID attendus encore suivis : $res" ;; esac
case "$res" in *apres-fill=1*) ok "lot_wait : un nouveau lot est suivi" ;; *) ko "lot_wait : nouveau lot non suivi : $res" ;; esac

# la desactivation de la verification des cles d'hote n'a rien a faire dans cette etape
check "ANSIBLE_HOST_KEY_CHECKING absent de admission-503.sh" "$(if grep -q 'HOST_KEY_CHECKING' "$ROOT/DEPLOYMENT/qualif/admission-503.sh"; then echo 1; else echo 0; fi)"
exit "$bad"
