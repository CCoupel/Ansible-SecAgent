#!/usr/bin/env bash
# Script CI unique (commands.ci, contrat C11) — miroir local des jobs « Build + tests Go » et « Lint Go »
# de .github/workflows/ci.yml. Les jobs Docker/Compose/Ansible/chaine restent dans ci.yml.
# Toute etape ajoutee ici doit l'etre aussi dans ci.yml (et inversement) tant que ci.yml ne l'appelle pas.
set -euo pipefail

cd "$(dirname "$0")/../GO"

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
