#!/usr/bin/env bash
# Test de verify_images (chain-test.sh) avec un faux `docker` : ID absent, different, correct, politique `missing`.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
T="$(mktemp -d)"
export QUALIF_TLS_DIR="$T/tls" SECAGENT_IMAGE=secagent-server:ci-aaaaaaaaaaaa SECAGENT_MINION_IMAGE=secagent-minion:ci-aaaaaaaaaaaa
# shellcheck disable=SC1091
source "$HERE/../../DEPLOYMENT/qualif/chain-test.sh"
CHAIN_DIR="$T/chain"; mkdir -p "$CHAIN_DIR"
FAKE_IDS="$T/fake"   # "<ref> <id>" par ligne : ce que le demon connait
docker() { [ "$1 $2" = "image inspect" ] || return 1; awk -v r="${@: -1}" '$1==r {print $2; f=1} END{exit !f}' "$FAKE_IDS"; }
set +e   # chain-test.sh active `set -e` : le test gere lui-meme les codes de retour
fail() { echo "ECHEC: $*" >&2; exit 1; }   # appele dans un sous-shell : ne quitte que lui
run() { ( verify_images ) >/dev/null 2>&1; }
bad=0; expect() { local want="$1" name="$2"; run; local rc=$?; if { [ "$want" = ok ] && [ $rc -eq 0 ]; } || { [ "$want" = ko ] && [ $rc -ne 0 ]; }; then echo "ok   $name"; else echo "KO   $name"; bad=1; fi; }
printf '%s sha256:111\n%s sha256:222\n' "$SECAGENT_IMAGE" "$SECAGENT_MINION_IMAGE" > "$CHAIN_DIR/image-ids"
printf '%s sha256:111\n%s sha256:222\n' "$SECAGENT_IMAGE" "$SECAGENT_MINION_IMAGE" > "$FAKE_IDS"
export SECAGENT_PULL_POLICY=never
expect ok "IDs identiques"
printf '%s sha256:111\n%s sha256:999\n' "$SECAGENT_IMAGE" "$SECAGENT_MINION_IMAGE" > "$FAKE_IDS"
expect ko "ID du minion different (tag local preexistant)"
printf '%s sha256:111\n' "$SECAGENT_IMAGE" > "$FAKE_IDS"
expect ko "image minion absente du demon"
printf '%s sha256:111\n%s sha256:222\n' "$SECAGENT_IMAGE" "$SECAGENT_MINION_IMAGE" > "$FAKE_IDS"
rm "$CHAIN_DIR/image-ids"
expect ko "load-images jamais lance (fichier d'ID absent)"
printf '%s sha256:111\n' "$SECAGENT_IMAGE" > "$CHAIN_DIR/image-ids"
expect ko "image absente du fichier d'ID"
SECAGENT_PULL_POLICY=missing
expect ok "politique missing : pas de verification (CI, registre)"
exit $bad
