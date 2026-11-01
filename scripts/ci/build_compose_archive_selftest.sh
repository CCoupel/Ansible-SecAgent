#!/usr/bin/env bash
# Autotest de build_compose_archive.sh : construit l'archive avec un digest FACTICE (rien n'est publie), puis verifie les
# modes dans l'archive (scripts executables, reste en 644), l'image epinglee et la reproductibilite (2 builds identiques).
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
FAKE="sha256:$(printf '0%.0s' $(seq 64))"
FAIL=0
chk() { if [ "$2" = 1 ]; then echo "ok   $1"; else echo "KO   $1"; FAIL=1; fi; }
for n in 1 2; do
  ( cd "$REPO" && STAGE_DIR="$T/stage$n" bash scripts/ci/build_compose_archive.sh v0.0.0 0.0.0 "$FAKE" "$T/out$n" ) >"$T/build$n.log" 2>&1 \
    || { echo "KO   build $n :"; tail -5 "$T/build$n.log"; exit 1; }
done
A="$T/out1/secagent-compose-0.0.0.tar.gz"
LIST="$(tar -tvzf "$A")"
mode_of() { printf '%s\n' "$LIST" | awk -v f="secagent-compose-0.0.0/$1" '$NF==f {print $1}'; }
chk "preflight-secrets.sh executable (-rwxr-xr-x)" $([ "$(mode_of preflight-secrets.sh)" = "-rwxr-xr-x" ] && echo 1 || echo 0)
chk "tools/check_compose.py executable" $([ "$(mode_of tools/check_compose.py)" = "-rwxr-xr-x" ] && echo 1 || echo 0)
chk "docker-compose.server.yml en 644" $([ "$(mode_of docker-compose.server.yml)" = "-rw-r--r--" ] && echo 1 || echo 0)
chk "prod.env.example en 644" $([ "$(mode_of prod.env.example)" = "-rw-r--r--" ] && echo 1 || echo 0)
# aucun .sh de l'archive ne doit etre non executable
BADSH="$(printf '%s\n' "$LIST" | awk '$NF ~ /\.sh$/ && $1 != "-rwxr-xr-x" {print $NF}')"
chk "tous les *.sh de l'archive sont executables" $([ -z "$BADSH" ] && echo 1 || echo 0)
tar -xzf "$A" -C "$T" && grep -q "image: ghcr.io/ccoupel/secagent-server:v0.0.0@$FAKE" "$T/secagent-compose-0.0.0/docker-compose.server.yml"
chk "image serveur epinglee en tag@digest" $([ $? -eq 0 ] && echo 1 || echo 0)
chk "archive reproductible (2 builds, meme sha256)" $([ "$(sha256sum < "$A")" = "$(sha256sum < "$T/out2/secagent-compose-0.0.0.tar.gz")" ] && echo 1 || echo 0)
exit $FAIL
