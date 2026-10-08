#!/usr/bin/env bash
# Autotest de assert_version.sh avec de fausses commandes (aucune compilation).
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
A="$HERE/assert_version.sh"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
FAIL=0
mk() { printf '#!/bin/sh\necho "%s"\n' "$2" > "$T/$1"; chmod +x "$T/$1"; }
mk good "secagent-server version 3.0.4"; mk dev "secagent-server version dev"; mk other "secagent-server version 3.0.40"
mk garbage "usage: something else"
expect() { local want="$1" what="$2"; shift 2; "$@" >/dev/null 2>&1; local rc=$?
  local good=0
  if [ "$want" = ok ]; then [ $rc -eq 0 ] && good=1; else [ $rc -ne 0 ] && good=1; fi
  if [ $good -eq 1 ]; then echo "ok   $what"; else echo "KO   $what (rc=$rc)"; FAIL=1; fi; }
expect ok "version attendue affichee" bash "$A" 3.0.4 "$T/good"
expect ko "binaire en version dev refuse" bash "$A" 3.0.4 "$T/dev"
expect ko "prefixe de version (3.0.40) refuse" bash "$A" 3.0.4 "$T/other"
expect ko "sortie inattendue refusee" bash "$A" 3.0.4 "$T/garbage"
expect ko "commande absente refusee" bash "$A" 3.0.4 "$T/absent"
expect ko "sans commande" bash "$A" 3.0.4
exit $FAIL
