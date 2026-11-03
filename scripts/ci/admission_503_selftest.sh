#!/usr/bin/env bash
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
  *'"cmd":"deny"'*) printf 'HTTP/2 429\r\nRetry-After: 1\r\n\r\n' > "$H"; echo '{"error":"agent_busy"}' > "$O"; printf 429 ;;
  *) sleep 1; printf 'HTTP/2 200\r\n\r\n' > "$H"; echo '{"rc":0,"stdout":""}' > "$O"; printf 200 ;;
esac
STUB
chmod +x "$T/bin/curl"
export STUB_LOG="$T/curl.log"; : > "$STUB_LOG"
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
  ADM503_DIR="$CHAIN_DIR/adm"; mkdir -p "$ADM503_DIR"; echo "Authorization: Bearer SECRET-VALUE" > "$CHAIN_DIR/plugin.header"
  adm503_fill fill 2 minion-child minion-child minion-root
  adm503_lot_alive && echo "alive"
  echo "probe=$(adm503_exec minion-root "$(adm503_uuid)" true 20 "$ADM503_DIR/p")"
  grep -i "^retry-after: 5" "$ADM503_DIR/p.hdr" >/dev/null && echo "retry-after"
  grep -q memory_budget_exhausted "$ADM503_DIR/p.body" && echo "body"
  adm503_lot_wait; adm503_lot_all_ok fill 3; echo "lot-ok"
  echo "denied=$(adm503_exec minion-root "$(adm503_uuid)" deny 20 "$ADM503_DIR/d")"
  echo "base=$(adm503_base)"
' 2>&1)" || { ko "scenario : $out"; }
for want in alive probe=503 retry-after body lot-ok denied=429 base=https://h:7770; do
  case "$out" in *"$want"*) ok "faux curl : $want" ;; *) ko "faux curl : '$want' absent de : $out" ;; esac
done
check "jeton passe par fichier (-H @fichier)" "$(grep -q -- '-H @' "$STUB_LOG"; echo $?)"
check "le jeton ne figure pas dans la ligne de commande de curl" "$(if grep -q 'SECRET-VALUE' "$STUB_LOG"; then echo 1; else echo 0; fi)"
check "CA de test utilisee (--cacert)" "$(grep -q -- '--cacert /ca/ca.crt' "$STUB_LOG"; echo $?)"
check "verification TLS non desactivee (ni -k ni --insecure)" "$(if grep -q -- ' -k\| --insecure' "$STUB_LOG"; then echo 1; else echo 0; fi)"

# un exec de fond refuse (429) fait echouer adm503_lot_all_ok avec le code observe
set +e
res="$(PATH="$T/bin:$PATH" CHAIN_DIR="$T/chain" QUALIF_TLS_DIR=/ca ENDPOINT_HOST=h C_A=c-a bash -c '
  set -euo pipefail
  fail() { echo "FAIL $*"; exit 1; }
  master() { echo c-a; }
  source "'"$ROOT"'/DEPLOYMENT/qualif/admission-503.sh"
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
exit "$bad"
