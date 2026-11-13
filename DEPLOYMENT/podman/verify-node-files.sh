#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
# SPDX-License-Identifier: AGPL-3.0-or-later

# Verification d'INTEGRITE des fichiers de deploiement d'un noeud Podman, executee par `deployer` (#267, LOT-4) AVANT
# `systemctl --user daemon-reload` / tout demarrage :
#
#   verify-node-files.sh [--pin] <qualif|prod> <srvX>
#
# --pin : apres une verification REUSSIE, ecrit sur le noeud, HORS partage (home local de cyril, 0600, atomique) :
#   - ~cyril/.config/systemd/user/secagent-<env>-<srvX>.service : COPIE de l'unite attendue (jamais un lien vers le
#     partage : systemd la relirait telle quelle au boot) ;
#   - ~cyril/.config/secagent/<env>-<srvX>.sha256 : manifeste epingle (empreintes ATTENDUES du depot, chemins absolus du
#     partage) que l'unite verifie par ExecStartPre a CHAQUE demarrage (boot, Restart=, relance manuelle), puis la garde
#     compare la liste exacte des fichiers : toute modification du partage apres la verification empeche le demarrage.
# Seules ecritures sur le noeud. Sans --pin : lecture seule.
#
# Le contenu ATTENDU est recalcule depuis le DEPOT (ou NODE_SOURCE_DIR) et les variables de la release (meme calcul
# que stage-node-files.sh) : le partage, modifiable par l'uid 1000, n'est jamais sa propre reference. Le contenu REEL
# est lu SUR LE NOEUD (`ssh cyril@<ip>` avec la cle et le known_hosts de l'environnement, StrictHostKeyChecking=yes) :
# empreintes de bin/* (garde executee par ExecStartPre), release/* et systemd/*, liste exacte des fichiers. REFUS (code 2) au premier ecart : fichier manquant,
# en trop, modifie, ou SHA256SUMS different (lecture : sha256sum, find).
# Essais : VERIFY_LOCAL=1 lit le partage depuis le poste (meme chemin) au lieu du noeud ; --pin ecrit alors l'unite et
# le manifeste sous $PIN_HOME (obligatoire, jamais le home du poste par defaut).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
refuse() { echo "REFUS: $*" >&2; exit 2; }
PIN=0; [ "${1:-}" = --pin ] && { PIN=1; shift; }
PRIVATE_DIR="${SECAGENT_PRIVATE_DIR:-$REPO/PRIVATE}"; PRIVATE_DIR="${PRIVATE_DIR%/}"
case "$PRIVATE_DIR" in /*) ;; *) refuse "SECAGENT_PRIVATE_DIR=$PRIVATE_DIR n'est pas un chemin absolu" ;; esac
case "${NODE_SOURCE_DIR:-/}" in /*) ;; *) refuse "NODE_SOURCE_DIR=$NODE_SOURCE_DIR n'est pas un chemin absolu" ;; esac
# shellcheck source=node-lib.sh
source "$HERE/node-lib.sh"
node_topology "${1:-}" "${2:-}"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
expected_tree "$T" "$1" "$2"
( cd "$T" && find bin release systemd -mindepth 1 -maxdepth 1 -type f -print0 | sort -z | xargs -0 sha256sum ) > "$T/want"

# Releve REEL : sur le noeud (defaut) ou localement (essais). Meme format : "sha256  sous-dossier/nom", trie.
probe='cd "$1" && for f in bin/* bin/.[!.]* release/* release/.[!.]* systemd/* systemd/.[!.]*; do [ -e "$f" ] || [ -L "$f" ] || continue; if [ -f "$f" ] && [ ! -L "$f" ]; then sha256sum -- "$f"; else echo "NON-FICHIER  $f"; fi; done | LC_ALL=C sort -k2'
node_run() { # $1 stdin|nostdin, puis commande executee en bash sur le noeud (ou localement si VERIFY_LOCAL=1)
  local in="$1"; shift
  if [ "${VERIFY_LOCAL:-0}" = 1 ]; then bash -c "$@"; return; fi
  local key="$PRIVATE_DIR/$ENV/poste-cyril/id_ed25519" kh="$PRIVATE_DIR/$ENV/poste-cyril/known_hosts" n=()
  [ -f "$key" ] && [ -f "$kh" ] || refuse "cle ou known_hosts de $ENV absents ($key, $kh)"
  [ "$in" = stdin ] || n=(-n)
  ssh "${n[@]}" -i "$key" -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$kh" \
    -o ConnectTimeout=10 "cyril@$NODE_IP" "$(printf '%q ' bash -c "$@")"
}
node_run nostdin "$probe" _ "$NODE_BASE" > "$T/have" || refuse "lecture des fichiers de $2 impossible (noeud cyril@$NODE_IP ou VERIFY_LOCAL)"
LC_ALL=C sort -k2 "$T/want" -o "$T/want"
if ! diff -u "$T/want" "$T/have" > "$T/diff"; then
  sed 's/^/  /' "$T/diff" >&2
  refuse "fichiers de deploiement de $2 differents du depot (ci-dessus : - attendu, + sur le noeud) : relancer stage-node-files.sh $1 $2, ne PAS recharger les unites"
fi
echo "fichiers de deploiement de $2 conformes au depot ($(wc -l < "$T/want") fichiers, bin/, release/ et systemd/)"
if [ "$PIN" = 1 ]; then
  pin_manifest "$T" > "$T/pin"
  [ -s "$T/pin" ] || refuse "manifeste epingle vide"
  put_home() { # $1 chemin relatif au home du noeud (PIN_HOME si VERIFY_LOCAL=1), contenu sur stdin ; ecriture atomique 0600
    if [ "${VERIFY_LOCAL:-0}" = 1 ]; then
      [ -n "${PIN_HOME:-}" ] || refuse "VERIFY_LOCAL=1 --pin : PIN_HOME obligatoire (essais ; jamais le home du poste)"
      # shellcheck disable=SC2016   # $1, $2 developpes par le bash enfant
      bash -c 'umask 077; f="$1/$2"; d="${f%/*}"; [ ! -L "$d" ] && mkdir -p "$d" && cat > "$f.tmp" && mv -f "$f.tmp" "$f"' _ "$PIN_HOME" "$1"
    else
      # shellcheck disable=SC2016   # $HOME, $1 developpes sur le noeud
      node_run stdin 'umask 077; f="$HOME/$1"; d="${f%/*}"; [ ! -L "$d" ] && mkdir -p "$d" && cat > "$f.tmp" && mv -f "$f.tmp" "$f"' _ "$1"
    fi
  }
  # unite d'abord (copie VERIFIEE de l'attendu, remplace un ancien lien), manifeste ensuite : un echec entre les deux
  # laisse au pire l'ancien manifeste, que la nouvelle release ne satisfait pas (demarrage refuse, fail-closed).
  put_home "$UNIT_REL" < "$T/systemd/$UNIT_NAME" || refuse "ecriture de l'unite ~/$UNIT_REL sur $2 impossible"
  put_home "$PIN_REL" < "$T/pin" || refuse "ecriture du manifeste epingle ~/$PIN_REL sur $2 impossible"
  echo "unite copiee hors partage (~cyril/$UNIT_REL) ; manifeste epingle ecrit (~cyril/$PIN_REL, $(wc -l < "$T/pin") empreintes) : verifie par ExecStartPre a chaque demarrage"
  echo "Puis, sur le noeud en cyril : systemctl --user daemon-reload && systemctl --user enable --now $UNIT_NAME"
fi
