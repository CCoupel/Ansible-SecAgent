#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
# SPDX-License-Identifier: AGPL-3.0-or-later

# Script CI unique (commands.ci, contrat C11) — miroir local des jobs « Build + tests Go » et « Lint Go »
# de .github/workflows/ci.yml. Les jobs Docker/Compose/Ansible/chaine restent dans ci.yml.
# Toute etape ajoutee ici doit l'etre aussi dans ci.yml (et inversement) tant que ci.yml ne l'appelle pas.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Etapes du job « Lint Go » sur l'arbre entier (LOT-7, #237) : en-tetes SPDX (garde auto-testee) et mentions tierces.
echo "==> En-tetes SPDX"
python3 -I "$ROOT/scripts/ci/check_spdx_selftest.py"
python3 -I "$ROOT/scripts/ci/check_spdx.py" --root "$ROOT"

echo "==> govulncheck (vulnerabilites atteintes)"
if command -v govulncheck >/dev/null 2>&1; then
  bash "$ROOT/scripts/ci/run_govulncheck.sh"
else
  echo "govulncheck absent du PATH (CI : go install golang.org/x/vuln/cmd/govulncheck@v1.9.0) — etape non jouee localement" >&2
  exit 1
fi

echo "==> Mentions tierces (go-licenses)"
if command -v go-licenses >/dev/null 2>&1; then
  bash "$ROOT/scripts/ci/gen_third_party_notices.sh" --check
else
  echo "go-licenses absent du PATH (CI : go install github.com/google/go-licenses/v2@v2.0.1) — etape non jouee localement" >&2
  exit 1
fi

cd "$ROOT/GO"

echo "==> Build"
go build ./...

echo "==> Build sans CGO"
CGO_ENABLED=0 go build ./...

echo "==> Tests (-race)"
JWT_SECRET_KEY=test ADMIN_TOKEN=test go test -race ./... -timeout 300s

echo "==> gofmt"
UNFORMATTED=$(gofmt -l .)
if [ -n "$UNFORMATTED" ]; then
  echo "Fichiers non conformes a gofmt :"
  echo "$UNFORMATTED"
  exit 1
fi

echo "==> golangci-lint"
if command -v golangci-lint >/dev/null 2>&1; then
  golangci-lint run --timeout=5m
else
  echo "golangci-lint absent du PATH (CI : golangci-lint v2.14.0) — etape non jouee localement" >&2
  exit 1
fi

echo "CI OK"
