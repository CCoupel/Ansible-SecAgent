#!/usr/bin/env bash
# Extrait de CHANGELOG.md les notes de la release d'un tag : le contenu de la section `## [vX.Y.Z] …` jusqu'a la section
# `## [` suivante (parseur historique de release.yml, deplace ici pour etre teste et joue AVANT toute publication).
# Echec (code 1, ::error::) si la section n'existe pas ou ne contient aucune ligne non vide.
#   release_notes.sh <vX.Y.Z> [CHANGELOG.md]   -> notes sur la sortie standard
set -euo pipefail
TAG="${1:?tag (vX.Y.Z)}"; FILE="${2:-CHANGELOG.md}"
case "$TAG" in v[0-9]*.[0-9]*.[0-9]*) ;; *) echo "::error::tag invalide '$TAG' (attendu vX.Y.Z)" >&2; exit 2 ;; esac
[ -f "$FILE" ] || { echo "::error::$FILE introuvable" >&2; exit 2; }
NOTES="$(awk -v tag="$TAG" '
  /^## \[/ { if (found) exit; if (index($0, "[" tag "]")) { found=1; next } }
  found { print }
' "$FILE")"
if ! printf '%s\n' "$NOTES" | grep -q '[^[:space:]]'; then
  echo "::error::Aucune entree '## [$TAG]' non vide dans $FILE (la release echouerait apres la publication des images : ajouter la section avant de tagger)" >&2
  exit 1
fi
printf '%s\n' "$NOTES"
