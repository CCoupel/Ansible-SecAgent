#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
# SPDX-License-Identifier: AGPL-3.0-or-later

# Fabrique secagent-compose-<version>.tar.gz : Compose de production avec l'image du serveur reecrite en
# tag@digest, controles bloquants (aucun `latest`/`build:`/NATS, image epinglee). Utilise a l'identique par
# release.yml (digest reel) et par la repetition a vide de ci.yml (digest factice, rien n'est publie).
#
#   build_compose_archive.sh <vX.Y.Z> <X.Y.Z> <sha256:digest> <repertoire_de_sortie>
# Variables : SRC_DIR (defaut DEPLOYMENT/prod), STAGE_DIR (defaut ./stage), REPO (racine du depot).
set -euo pipefail
umask 022   # modes de fichiers independants de l'umask de l'appelant (reproductibilite)
TAG="${1:?tag}"; VERSION="${2:?version}"; SRV="${3:?digest}"; OUT="${4:?sortie}"
REPO="${REPO:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
SRC_DIR="${SRC_DIR:-$REPO/DEPLOYMENT/prod}"; STAGE_DIR="${STAGE_DIR:-stage}"
case "$SRV" in sha256:????????????????????????????????????????????????????????????????) ;; *) echo "::error::digest invalide '$SRV'"; exit 1;; esac
D="$STAGE_DIR/secagent-compose-${VERSION}"
rm -rf "$D"; mkdir -p "$D" "$OUT"
cp -r "$SRC_DIR/." "$D/"
# LICENSE et mentions tierces du depot dans l'archive (#237) : l'archive est distribuee seule, sans le depot
for lic in LICENSE THIRD_PARTY_NOTICES.md; do
  [ -f "$REPO/$lic" ] || { echo "::error::$lic absente de $REPO : l'archive Compose doit la contenir"; exit 1; }
  cp "$REPO/$lic" "$D/$lic"
done
rm -f "$D"/prod.env "$D"/.env
# Surcharge Podman rootless de PROD (#267, LOT-4) : stage-node-files.sh prod la prend PAR SON NOM dans l'archive extraite
# (NODE_SOURCE_DIR, node-lib.sh). Sans `image:` (userns_mode seulement) : non touchee par la reecriture tag@digest.
PODMAN_OVERLAY="$REPO/DEPLOYMENT/podman/docker-compose.podman.yml"
[ -f "$PODMAN_OVERLAY" ] || { echo "::error::$PODMAN_OVERLAY absente : l'archive Compose doit la contenir (Podman PROD)"; exit 1; }
cp "$PODMAN_OVERLAY" "$D/docker-compose.podman.yml"
mkdir -p "$D/tools"; cp "$REPO/scripts/ci/check_compose.py" "$D/tools/check_compose.py"
for f in "$D"/docker-compose*.yml; do
  sed -i -E "s#^([[:space:]]*image:[[:space:]]*)ghcr\.io/ccoupel/secagent-server:.*#\1ghcr.io/ccoupel/secagent-server:${TAG}@${SRV}#" "$f"
done
sed -i -E "s#^SECAGENT_VERSION=.*#SECAGENT_VERSION=${TAG}#" "$D/.env.example"
# Controles bloquants
if grep -rnE '(^|[[:space:]])build:|:latest' "$D"/docker-compose*.yml; then
  echo "::error::'latest' ou 'build:' dans l'archive Compose"; exit 1
fi
if grep -rniE --exclude-dir=tools 'nats|jetstream' "$D"; then
  echo "::error::Reference NATS dans l'archive Compose"; exit 1
fi
grep -qE "image: ghcr.io/ccoupel/secagent-server:${TAG}@sha256:[0-9a-f]{64}\$" "$D/docker-compose.server.yml" \
  || { echo "::error::docker-compose.server.yml : image non epinglee en tag@digest"; exit 1; }
# la surcharge Podman ne doit jamais porter d'image (elle masquerait l'image epinglee du Compose de base)
if grep -qE '^[[:space:]]*image:' "$D/docker-compose.podman.yml"; then
  echo "::error::docker-compose.podman.yml porte une image : la surcharge ne doit fixer que userns_mode"; exit 1
fi
# Modes explicites (independants du systeme de fichiers source) : 755 pour les dossiers, tools/*.py et TOUS les scripts
# *.sh (ex. preflight-secrets.sh, documente comme `./preflight-secrets.sh` avant chaque `docker compose up`), 644 sinon
find "$D" -type d -exec chmod 755 {} +
find "$D" -type f -exec chmod 644 {} +
chmod 755 "$D"/tools/*.py
find "$D" -type f -name '*.sh' -exec chmod 755 {} +
[ -x "$D/preflight-secrets.sh" ] || { echo "::error::preflight-secrets.sh absent ou non executable dans l'archive"; exit 1; }
# Archive reproductible (ordre, dates, proprietaires fixes)
tar --sort=name --mtime='UTC 2020-01-01' --owner=0 --group=0 --numeric-owner \
  --exclude='__pycache__' --exclude='*.pyc' \
  -cf - -C "$STAGE_DIR" "secagent-compose-${VERSION}" | gzip -n > "$OUT/secagent-compose-${VERSION}.tar.gz"
echo "archive : $OUT/secagent-compose-${VERSION}.tar.gz"
