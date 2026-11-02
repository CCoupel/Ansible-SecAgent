#!/usr/bin/env bash
# Verifie que `<commande> --version` affiche EXACTEMENT « <composant> version <attendue> », sans demarrer de service :
# `--version` est gere par le binaire (tout argument inconnu est refuse, rien n'est lance).
#   [COMPONENT=secagent-server|secagent-minion|secagent-inventory] assert_version.sh <version attendue sans le v> <commande...>
# Exemples : assert_version.sh 3.0.4 ./secagent-server ; assert_version.sh 3.0.4 docker run --rm secagent-server:ci
#            COMPONENT=secagent-minion assert_version.sh 3.0.4 docker run --rm secagent-minion:ci
set -euo pipefail
WANT="${1:?version attendue (X.Y.Z)}"; shift
COMPONENT="${COMPONENT:-secagent-server}"
case "$COMPONENT" in secagent-server|secagent-minion|secagent-inventory) ;; *) echo "COMPONENT invalide '$COMPONENT'" >&2; exit 2 ;; esac
[ $# -ge 1 ] || { echo "commande manquante" >&2; exit 2; }
# Format attendu : serveur et minion affichent « <composant> version <v> » ; secagent-inventory affiche
# « secagent-inventory <v> » (contrat de DOC/inventory/INVENTORY_SPEC.md, teste par GO/cmd/secagent-inventory/version_test.go).
case "$COMPONENT" in
  secagent-inventory) EXPECTED="$COMPONENT $WANT" ;;
  *) EXPECTED="$COMPONENT version $WANT" ;;
esac
GOT="$("$@" --version 2>&1 | head -1)"
if [ "$GOT" != "$EXPECTED" ]; then
  echo "::error::version affichee '$GOT' != '$EXPECTED' (ldflags -X non applique ou mauvais symbole ?)" >&2
  exit 1
fi
echo "version OK : $GOT"
