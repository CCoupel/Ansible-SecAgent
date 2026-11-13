#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
# SPDX-License-Identifier: AGPL-3.0-or-later

# Prepare DEPUIS LE POSTE les fichiers de deploiement d'un noeud Podman (LOT-4 v3.0.6, #267), centralises sur le
# partage : rien n'est ecrit sur le noeud lui-meme (decision utilisateur : eviter les changements directs sur les noeuds).
#
#   prepare-node-files.sh <qualif|prod> <srvX>      srvX : srv3|srv4 (qualif), srv1|srv2 (prod)
#
# Cree (0700, uid courant = 1000, sans toucher a ce qui existe) PRIVATE/<ENV>/<srvX>/cyril/secagent/ et ses
# sous-dossiers bin/ (garde check-private.sh, 0700), release/ (Compose de la release, deposes par deployer), run/
# (fichiers VOLATILS de la qualif : jetons et env_file de chain-test.sh, hors verification d'integrite) et systemd/
# (unite --user de reference, T44/T45 : COPIEE sur le noeud, hors partage, par `verify-node-files.sh --pin` apres
# verification ; jamais liee). Aucun secret n'est ecrit ni lu. Refus (code 2) si la racine PRIVATE/ est absente
# (jamais creee par les scripts, #250) ou relative.
# Variable : SECAGENT_PRIVATE_DIR (defaut <depot>/PRIVATE ; chemin ABSOLU du checkout depuis une copie).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
refuse() { echo "REFUS: $*" >&2; exit 2; }

PRIVATE_DIR="${SECAGENT_PRIVATE_DIR:-$REPO/PRIVATE}"; PRIVATE_DIR="${PRIVATE_DIR%/}"
case "$PRIVATE_DIR" in /*) ;; *) refuse "SECAGENT_PRIVATE_DIR=$PRIVATE_DIR n'est pas un chemin absolu" ;; esac
env="${1:-}" node="${2:-}"
case "$env:$node" in
  qualif:srv3|qualif:srv4) E=QUALIF ;;
  prod:srv1|prod:srv2) E=PROD ;;
  *) refuse "couple '$env $node' : attendu qualif srv3|srv4 ou prod srv1|srv2" ;;
esac
[ -d "$PRIVATE_DIR/$E" ] && [ ! -L "$PRIVATE_DIR/$E" ] || refuse "$PRIVATE_DIR/$E absent ou lien : racine des donnees privees introuvable (jamais creee ici)"

mkd() { # cree $1 en 0700 s'il manque ; un existant n'est jamais modifie ; un lien ou un non-repertoire est refuse
  [ ! -L "$1" ] || refuse "$1 est un lien symbolique"
  if [ -e "$1" ]; then [ -d "$1" ] || refuse "$1 existe et n'est pas un repertoire"; return 0; fi
  install -d -m 700 "$1"
}
base="$PRIVATE_DIR/$E/$node"
for d in "$base" "$base/cyril" "$base/cyril/secagent" "$base/cyril/secagent/bin" "$base/cyril/secagent/release" "$base/cyril/secagent/systemd" "$base/cyril/secagent/run"; do
  mkd "$d"
done
g="$base/cyril/secagent/bin/check-private.sh"
[ ! -L "$g" ] || refuse "$g est un lien symbolique"
install -m 700 "$HERE/check-private.sh" "$g"
echo "fichiers du noeud $node prets : $base/cyril/secagent/{bin/check-private.sh,release/,systemd/}"
