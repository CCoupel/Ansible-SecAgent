#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
# SPDX-License-Identifier: AGPL-3.0-or-later

# Audit des vulnerabilites Go (commands.audit, LOT-8 #248) : govulncheck sur tout le module GO/, echec si une
# vulnerabilite est ATTEINTE par le code (rc 3 de govulncheck). Partage par ci.yml (job lint) et scripts/ci.sh (C11).
# Le binaire doit etre EXACTEMENT la version epinglee, module verifie par sa somme h1 (go version -m) : un autre
# govulncheck du PATH est refuse. Reseau requis (base vuln.go.dev).
set -euo pipefail
WANT_VERSION="v1.9.0"
WANT_H1="h1:12VaqnI9kJfqwRoPptxoqsUhQtdfrSbdksT7X/KY/sc="
ROOT=$(cd "$(dirname "$0")/../.." && pwd)

bin=$(command -v govulncheck) || { echo "::error::govulncheck introuvable (go install golang.org/x/vuln/cmd/govulncheck@${WANT_VERSION})" >&2; exit 2; }
read -r _ _ have have_h1 < <(go version -m "$bin" | awk '$1 == "mod" && $2 == "golang.org/x/vuln"') || true
if [ "${have:-}" != "$WANT_VERSION" ] || [ "${have_h1:-}" != "$WANT_H1" ]; then
  echo "::error::govulncheck ${have:-?} (${have_h1:-?}) : ${WANT_VERSION} ${WANT_H1} attendu" >&2
  exit 2
fi
cd "$ROOT/GO"
go version
if govulncheck ./...; then
  echo "govulncheck OK : aucune vulnerabilite atteinte"
else
  rc=$?
  [ "$rc" -eq 3 ] && echo "::error::govulncheck : vulnerabilite(s) atteinte(s) par le code (voir ci-dessus)" >&2
  exit "$rc"
fi
