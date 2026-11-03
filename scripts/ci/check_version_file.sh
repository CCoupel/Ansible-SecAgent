#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
# SPDX-License-Identifier: AGPL-3.0-or-later

# Controle du fichier VERSION (version_file de .claude/project-config.json, v3.0.5) : UNE ligne `X.Y.Z` (SemVer sans
# prefixe `v`, sans suffixe), terminee par LF, rien d'autre (ni CR, ni espace, ni ligne vide). La version d'un binaire
# vient toujours du TAG (-ldflags -X) : ce fichier est la source de verite LUE par l'outillage (publish/deploy) et
# VERIFIEE, jamais ecrite, par la CI (contrat C2).
#
#   check_version_file.sh [--expect X.Y.Z] [fichier]     (defaut : VERSION a la racine du depot)
#   code 0 = conforme (et egal a --expect s'il est donne), 1 = non conforme, 2 = usage
set -euo pipefail
EXPECT=""
if [ "${1:-}" = "--expect" ]; then
  EXPECT="${2:?--expect attend X.Y.Z}"; shift 2
fi
FILE="${1:-$(cd "$(dirname "$0")/../.." && pwd)/VERSION}"
[ $# -le 1 ] || { echo "usage : check_version_file.sh [--expect X.Y.Z] [fichier]" >&2; exit 2; }
SEMVER='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'

[ -f "$FILE" ] && [ ! -L "$FILE" ] || { echo "::error::$FILE absent (ou lien symbolique)"; exit 1; }
if [ -n "$EXPECT" ] && ! printf '%s' "$EXPECT" | grep -Eq "$SEMVER"; then
  echo "::error::--expect '$EXPECT' n'est pas une version X.Y.Z"; exit 2
fi
if LC_ALL=C grep -q $'\r' "$FILE"; then echo "::error::$FILE contient un CR (LF seul attendu)"; exit 1; fi
lines=$(wc -l < "$FILE")
V=$(cat "$FILE")
if [ "$lines" -ne 1 ] || [ "$(tail -c1 "$FILE" | od -An -c | tr -d ' ')" != '\n' ]; then
  echo "::error::$FILE doit contenir exactement une ligne terminee par LF (trouve $lines ligne(s))"; exit 1
fi
if ! printf '%s' "$V" | grep -Eq "$SEMVER"; then
  echo "::error::$FILE : '$V' n'est pas une version X.Y.Z (SemVer, sans 'v' ni suffixe)"; exit 1
fi
if [ -n "$EXPECT" ] && [ "$V" != "$EXPECT" ]; then
  echo "::error::$FILE = $V, attendu $EXPECT (tag ou branche milestone)"; exit 1
fi
echo "VERSION OK : $V${EXPECT:+ (= attendu)}"
