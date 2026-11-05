#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
# SPDX-License-Identifier: AGPL-3.0-or-later

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
for lic in LICENSE THIRD_PARTY_NOTICES.md; do
  chk "$lic dans l'archive (644)" $([ "$(mode_of "$lic")" = "-rw-r--r--" ] && echo 1 || echo 0)
  chk "$lic de l'archive identique a celle du depot" $(cmp -s "$REPO/$lic" "$T/secagent-compose-0.0.0/$lic" && echo 1 || echo 0)
done
# sans LICENSE dans le depot, la fabrication de l'archive doit echouer (copie minimale : scripts/ci seulement, pas de LICENSE)
mkdir -p "$T/nolic/scripts/ci" && cp "$REPO/scripts/ci/check_compose.py" "$T/nolic/scripts/ci/"
REAL="$REPO"   # (dans un prefixe d'affectation, $REPO designerait deja la copie minimale)
( cd "$T/nolic" && REPO="$T/nolic" SRC_DIR="$REAL/DEPLOYMENT/prod" STAGE_DIR="$T/stagenl" bash "$REAL/scripts/ci/build_compose_archive.sh" v0.0.0 0.0.0 "$FAKE" "$T/outnl" ) >"$T/nl.log" 2>&1
chk "sans LICENSE dans le depot, l'archive est refusee" $([ $? -ne 0 ] && grep -q "LICENSE absente" "$T/nl.log" && echo 1 || echo 0)
# avec LICENSE mais sans THIRD_PARTY_NOTICES.md, refus aussi (mentions tierces exigees avec les binaires par les licences des dependances)
cp "$REPO/LICENSE" "$T/nolic/LICENSE"
( cd "$T/nolic" && REPO="$T/nolic" SRC_DIR="$REAL/DEPLOYMENT/prod" STAGE_DIR="$T/stagent" bash "$REAL/scripts/ci/build_compose_archive.sh" v0.0.0 0.0.0 "$FAKE" "$T/outnt" ) >"$T/nt.log" 2>&1
chk "sans THIRD_PARTY_NOTICES.md dans le depot, l'archive est refusee" $([ $? -ne 0 ] && grep -q "THIRD_PARTY_NOTICES.md absente" "$T/nt.log" && echo 1 || echo 0)
chk "archive reproductible (2 builds, meme sha256)" $([ "$(sha256sum < "$A")" = "$(sha256sum < "$T/out2/secagent-compose-0.0.0.tar.gz")" ] && echo 1 || echo 0)
exit $FAIL
