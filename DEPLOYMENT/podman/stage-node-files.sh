#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
# SPDX-License-Identifier: AGPL-3.0-or-later

# Depose DEPUIS LE POSTE, sur le partage, les fichiers de deploiement d'un noeud Podman (#267, LOT-4) :
#
#   stage-node-files.sh <qualif|prod> <srvX>
#
# bin/ : garde check-private.sh du depot (re-ecrite a chaque depot) ; release/ : Compose du depot (ou de NODE_SOURCE_DIR, archive de release extraite) + release.env (variables NON
# secretes : images, version, chemins du partage) ; systemd/ : unite --user secagent-<env>-<srvX>.service. Chaque
# dossier recoit son SHA256SUMS. Le contenu est REMPLACE en entier (fichiers en trop retires) : release/ et systemd/
# ne contiennent jamais que ce que le depot produit. Rien n'est ecrit sur le noeud ; deployer verifie ensuite le noeud
# avec verify-node-files.sh AVANT `systemctl --user daemon-reload` / demarrage.
# Prerequis : prepare-node-files.sh <env> <srvX> (arborescence 0700). Variables lues : SECAGENT_IMAGE,
# SECAGENT_MINION_IMAGE, SECAGENT_VERSION, SECAGENT_PULL_POLICY, SECAGENT_MEM_LIMIT, GOMEMLIMIT, LOG_LEVEL,
# NODE_SOURCE_DIR, SECAGENT_PRIVATE_DIR. Codes : 0 OK, 2 refus.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
refuse() { echo "REFUS: $*" >&2; exit 2; }
PRIVATE_DIR="${SECAGENT_PRIVATE_DIR:-$REPO/PRIVATE}"; PRIVATE_DIR="${PRIVATE_DIR%/}"
case "$PRIVATE_DIR" in /*) ;; *) refuse "SECAGENT_PRIVATE_DIR=$PRIVATE_DIR n'est pas un chemin absolu" ;; esac
case "${NODE_SOURCE_DIR:-/}" in /*) ;; *) refuse "NODE_SOURCE_DIR=$NODE_SOURCE_DIR n'est pas un chemin absolu" ;; esac
# shellcheck source=node-lib.sh
source "$HERE/node-lib.sh"
node_topology "${1:-}" "${2:-}"
[ -n "${SECAGENT_IMAGE:-}" ] || [ "$1" = prod ] || refuse "SECAGENT_IMAGE obligatoire"
[ "$1" = qualif ] || [ -n "${SECAGENT_VERSION:-}" ] || refuse "SECAGENT_VERSION obligatoire (prod)"
for d in "$NODE_BASE" "$NODE_BASE/bin" "$NODE_BASE/release" "$NODE_BASE/systemd"; do
  [ -d "$d" ] && [ ! -L "$d" ] || refuse "$d absent ou lien : lancer d'abord prepare-node-files.sh $1 $2"
done
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
expected_tree "$T" "$1" "$2"
for sub in bin release systemd; do
  find "$NODE_BASE/$sub" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
  ( umask 077; cp -- "$T/$sub"/* "$NODE_BASE/$sub/" )
  chmod 600 "$NODE_BASE/$sub"/*
done
chmod 700 "$NODE_BASE/bin/check-private.sh"   # garde executee par ExecStartPre
echo "fichiers de $2 deposes : $NODE_BASE/{bin,release,systemd} (SHA256SUMS ecrits)"
echo "Verification + copie de l'unite + epinglage (deployer, avant daemon-reload) : DEPLOYMENT/podman/verify-node-files.sh --pin $1 $2"
