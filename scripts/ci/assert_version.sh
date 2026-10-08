#!/usr/bin/env bash
# Verifie que `<commande> --version` affiche EXACTEMENT « secagent-server version <attendue> » (sortie cobra), sans
# demarrer de serveur : `--version` est gere par le CLI (tout argument inconnu est refuse, aucun serveur n'est lance).
#   assert_version.sh <version attendue sans le v> <commande...>
# Exemples : assert_version.sh 3.0.4 ./secagent-server ; assert_version.sh 3.0.4 docker run --rm secagent-server:ci
set -euo pipefail
WANT="${1:?version attendue (X.Y.Z)}"; shift
[ $# -ge 1 ] || { echo "commande manquante" >&2; exit 2; }
GOT="$("$@" --version 2>&1 | head -1)"
if [ "$GOT" != "secagent-server version $WANT" ]; then
  echo "::error::version affichee '$GOT' != 'secagent-server version $WANT' (ldflags -X .../internal/cli.Version non applique ?)" >&2
  exit 1
fi
echo "version OK : $GOT"
