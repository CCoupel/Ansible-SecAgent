#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
# SPDX-License-Identifier: AGPL-3.0-or-later

# Verification d'INTEGRITE des fichiers de deploiement d'un noeud Podman, executee par `deployer` (#267, LOT-4) AVANT
# `systemctl --user daemon-reload` / tout demarrage :
#
#   verify-node-files.sh <qualif|prod> <srvX>
#
# Le contenu ATTENDU est recalcule depuis le DEPOT (ou NODE_SOURCE_DIR) et les variables de la release (meme calcul
# que stage-node-files.sh) : le partage, modifiable par l'uid 1000, n'est jamais sa propre reference. Le contenu REEL
# est lu SUR LE NOEUD (`ssh cyril@<ip>` avec la cle et le known_hosts de l'environnement, StrictHostKeyChecking=yes) :
# empreintes de release/* et systemd/*, liste exacte des fichiers. REFUS (code 2) au premier ecart : fichier manquant,
# en trop, modifie, ou SHA256SUMS different. Lecture seule (sha256sum, find) ; rien n'est ecrit.
# Essais : VERIFY_LOCAL=1 lit le partage depuis le poste (meme chemin) au lieu du noeud.
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
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
expected_tree "$T" "$1" "$2"
( cd "$T" && find release systemd -mindepth 1 -maxdepth 1 -type f -print0 | sort -z | xargs -0 sha256sum ) > "$T/want"

# Releve REEL : sur le noeud (defaut) ou localement (essais). Meme format : "sha256  sous-dossier/nom", trie.
probe='cd "$1" && for f in release/* release/.[!.]* systemd/* systemd/.[!.]*; do [ -e "$f" ] || [ -L "$f" ] || continue; if [ -f "$f" ] && [ ! -L "$f" ]; then sha256sum -- "$f"; else echo "NON-FICHIER  $f"; fi; done | LC_ALL=C sort -k2'
if [ "${VERIFY_LOCAL:-0}" = 1 ]; then
  bash -c "$probe" _ "$NODE_BASE" > "$T/have" || refuse "lecture de $NODE_BASE impossible"
else
  key="$PRIVATE_DIR/$ENV/poste-cyril/id_ed25519"; kh="$PRIVATE_DIR/$ENV/poste-cyril/known_hosts"
  [ -f "$key" ] && [ -f "$kh" ] || refuse "cle ou known_hosts de $ENV absents ($key, $kh)"
  ssh -n -i "$key" -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$kh" \
    -o ConnectTimeout=10 "cyril@$NODE_IP" "$(printf '%q ' bash -c "$probe" _ "$NODE_BASE")" > "$T/have" \
    || refuse "lecture des fichiers de $2 sur le noeud impossible (ssh cyril@$NODE_IP)"
fi
LC_ALL=C sort -k2 "$T/want" -o "$T/want"
if ! diff -u "$T/want" "$T/have" > "$T/diff"; then
  sed 's/^/  /' "$T/diff" >&2
  refuse "fichiers de deploiement de $2 differents du depot (ci-dessus : - attendu, + sur le noeud) : relancer stage-node-files.sh $1 $2, ne PAS recharger les unites"
fi
echo "fichiers de deploiement de $2 conformes au depot ($(wc -l < "$T/want") fichiers, release/ et systemd/)"
