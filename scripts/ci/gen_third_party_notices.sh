#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
# SPDX-License-Identifier: AGPL-3.0-or-later

# Genere THIRD_PARTY_NOTICES.md (#237 / LOT-7, D15) : licences des modules Go lies statiquement dans les trois binaires
# (go-licenses, template scripts/ci/third_party_notices.tpl) puis licence de la bibliotheque standard Go ($GOROOT/LICENSE).
#
# Usage : gen_third_party_notices.sh [--check]
#   sans option : (re)ecrit THIRD_PARTY_NOTICES.md a la racine du depot, puis les copies GO/LICENSE et
#                 GO/THIRD_PARTY_NOTICES.md ;
#   --check     : genere dans un fichier temporaire et echoue (exit 1) si THIRD_PARTY_NOTICES.md differe, ou si une copie
#                 de GO/ differe de son original a la racine.
# Copies dans GO/ : le contexte de build Docker est GO/ (ci.yml, release.yml, candidate-images.yml, builds locaux) ;
# les images y prennent /app/LICENSE et /app/THIRD_PARTY_NOTICES.md. Copies suivies par git (pas de lien symbolique :
# Docker ne suit pas un lien sortant du contexte, et git sous /mnt/c ne les restitue pas) et gardees identiques ici.
# Prerequis : `go` (version de GO/go.work) et `go-licenses` v2.0.1 dans le PATH
#   (CI : go install github.com/google/go-licenses/v2@v2.0.1 ; poste d'agent : .claude/outillage_go.md, GOBIN du scratchpad).
# GOOS/GOARCH sont fixes (linux/amd64, seule cible des releases) : la sortie ne depend pas du poste.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
OUT="$ROOT/THIRD_PARTY_NOTICES.md"
TPL="$ROOT/scripts/ci/third_party_notices.tpl"
WANT_VERSION="v2.0.1"

command -v go-licenses >/dev/null 2>&1 || { echo "::error::go-licenses introuvable (go install github.com/google/go-licenses/v2@${WANT_VERSION})" >&2; exit 2; }
have=$(go version -m "$(command -v go-licenses)" 2>/dev/null | awk '$1 == "mod" {print $3}')
if [ "$have" != "$WANT_VERSION" ]; then
  echo "::error::go-licenses ${have:-?} : ${WANT_VERSION} attendu (sortie epinglee)" >&2
  exit 2
fi

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
(
  cd "$ROOT/GO"
  # --ignore secagent-server : le module du depot lui-meme (AGPL, LICENSE) n'est pas une dependance tierce.
  GOOS=linux GOARCH=amd64 GOFLAGS="${GOFLAGS:-}" go-licenses report --ignore secagent-server \
    --template "$TPL" ./cmd/secagent-server ./cmd/secagent-minion ./cmd/secagent-inventory
  printf '\n---\n\n## Go standard library and runtime (%s)\n\n- License: BSD-3-Clause\n- Source: https://go.dev/LICENSE\n\n```\n' \
    "$(go env GOVERSION)"
  cat "$(go env GOROOT)/LICENSE"
  printf '```\n'
) > "$tmp"

if [ "${1:-}" = "--check" ]; then
  rc=0
  if ! cmp -s "$tmp" "$OUT"; then
    echo "::error::THIRD_PARTY_NOTICES.md n'est pas a jour : lancer scripts/ci/gen_third_party_notices.sh et commiter" >&2
    diff -u "$OUT" "$tmp" | head -40 >&2 || true
    rc=1
  fi
  for f in LICENSE THIRD_PARTY_NOTICES.md; do
    if ! cmp -s "$ROOT/$f" "$ROOT/GO/$f"; then
      echo "::error::GO/$f absent ou different de $f (contexte de build Docker) : lancer scripts/ci/gen_third_party_notices.sh" >&2
      rc=1
    fi
  done
  [ "$rc" -eq 0 ] && echo "OK THIRD_PARTY_NOTICES.md a jour, GO/LICENSE et GO/THIRD_PARTY_NOTICES.md identiques"
  exit "$rc"
else
  cp "$tmp" "$OUT"
  cp "$ROOT/LICENSE" "$ROOT/GO/LICENSE"
  cp "$OUT" "$ROOT/GO/THIRD_PARTY_NOTICES.md"
  echo "THIRD_PARTY_NOTICES.md, GO/LICENSE et GO/THIRD_PARTY_NOTICES.md ecrits"
fi
