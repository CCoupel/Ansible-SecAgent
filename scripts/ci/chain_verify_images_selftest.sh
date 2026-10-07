#!/usr/bin/env bash
# Test de verify_images (chain-test.sh) avec un faux `docker` : couches identiques / differentes, image absente, politique `missing`.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
T="$(mktemp -d)"
export QUALIF_TLS_DIR="$T/tls" SECAGENT_IMAGE=secagent-server:ci-aaaaaaaaaaaa SECAGENT_MINION_IMAGE=secagent-minion:ci-aaaaaaaaaaaa
# shellcheck disable=SC1091
source "$HERE/../../DEPLOYMENT/qualif/chain-test.sh"
CHAIN_DIR="$T/chain"; mkdir -p "$CHAIN_DIR"
LAYERS="$T/layers"   # "<ref> <json des couches>" : ce que le demon connait (RootFS.Layers)
docker() {
  [ "$1 $2" = "image inspect" ] || return 1
  local ref="${@: -1}" l; l="$(awk -v r="$ref" '$1==r {print $2; f=1} END{exit !f}' "$LAYERS")" || return 1
  case "$*" in *RootFS.Layers*) printf '%s\n' "$l" ;; *) printf '[{"Id":"x"}]\n' ;; esac
}
set +e   # chain-test.sh active `set -e` : le test gere lui-meme les codes de retour
fail() { echo "ECHEC: $*" >&2; exit 1; }   # appele dans un sous-shell : ne quitte que lui
run() { ( verify_images ) >/dev/null 2>&1; }
bad=0; expect() { local want="$1" name="$2"; run; local rc=$?; if { [ "$want" = ok ] && [ $rc -eq 0 ]; } || { [ "$want" = ko ] && [ $rc -ne 0 ]; }; then echo "ok   $name"; else echo "KO   $name"; bad=1; fi; }
fp() { printf '%s\n' "$1" | sha256sum | cut -d' ' -f1; }
L1='["sha256:aaa","sha256:bbb"]'; L2='["sha256:ccc"]'
printf '%s %s\n%s %s\n' "$SECAGENT_IMAGE" "$(fp "$L1")" "$SECAGENT_MINION_IMAGE" "$(fp "$L2")" > "$CHAIN_DIR/image-ids"
printf '%s %s\n%s %s\n' "$SECAGENT_IMAGE" "$L1" "$SECAGENT_MINION_IMAGE" "$L2" > "$LAYERS"
export SECAGENT_PULL_POLICY=never
expect ok "memes couches (l'ID .Id n'intervient plus)"
printf '%s %s\n%s %s\n' "$SECAGENT_IMAGE" "$L1" "$SECAGENT_MINION_IMAGE" '["sha256:zzz"]' > "$LAYERS"
expect ko "couches differentes pour le minion (tag local preexistant)"
printf '%s %s\n' "$SECAGENT_IMAGE" "$L1" > "$LAYERS"
expect ko "image minion absente du demon"
printf '%s %s\n%s %s\n' "$SECAGENT_IMAGE" "$L1" "$SECAGENT_MINION_IMAGE" "$L2" > "$LAYERS"
rm "$CHAIN_DIR/image-ids"
expect ko "load-images jamais lance (fichier d'empreintes absent)"
printf '%s %s\n' "$SECAGENT_IMAGE" "$(fp "$L1")" > "$CHAIN_DIR/image-ids"
expect ko "image absente du fichier d'empreintes"
SECAGENT_PULL_POLICY=missing
expect ok "politique missing : pas de verification (CI, registre)"
exit $bad
