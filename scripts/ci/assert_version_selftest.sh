#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
# SPDX-License-Identifier: AGPL-3.0-or-later

# Autotest de assert_version.sh avec de fausses commandes (aucune compilation).
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
A="$HERE/assert_version.sh"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
FAIL=0
mk() { printf '#!/bin/sh\necho "%s"\n' "$2" > "$T/$1"; chmod +x "$T/$1"; }
mk good "secagent-server version 3.0.4"; mk dev "secagent-server version dev"; mk other "secagent-server version 3.0.40"
mk garbage "usage: something else"
mk minion "secagent-minion version 3.0.4"; mk minion_dev "secagent-minion version dev"
mk inv "secagent-inventory version 3.0.4"; mk inv_dev "secagent-inventory version dev"; mk inv_prefix "secagent-inventory version 3.0.40"
# LOT-7 : --version affiche 3 lignes (version, licence, source) ; seule la ligne 1 est verifiee (`head -1`)
mk3() { printf '#!/bin/sh\necho "%s"\necho "%s"\necho "%s"\n' "$2" "$3" "$4" > "$T/$1"; chmod +x "$T/$1"; }
LIC="License: AGPL-3.0-or-later"; SRC="Source: https://github.com/CCoupel/Ansible-SecAgent"
mk3 three "secagent-server version 3.0.4" "$LIC" "$SRC"
mk3 three_junk "secagent-server version 3.0.4" "n'importe quoi" "encore autre chose"
mk3 three_nolic "secagent-server version 3.0.4" "" ""
mk3 three_wrong1 "secagent-server version 3.0.40" "$LIC" "$SRC"
mk3 three_dev "secagent-server version dev" "$LIC" "$SRC"
mk3 three_late "$LIC" "secagent-server version 3.0.4" "$SRC"
mk3 three_minion "secagent-minion version 3.0.4" "$LIC" "$SRC"
mk3 three_inv "secagent-inventory version 3.0.4" "$LIC" "$SRC"
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
expect ok "minion : version attendue (COMPONENT=secagent-minion)" env COMPONENT=secagent-minion bash "$A" 3.0.4 "$T/minion"
expect ko "minion : binaire en version dev refuse" env COMPONENT=secagent-minion bash "$A" 3.0.4 "$T/minion_dev"
expect ko "un binaire minion n'est pas accepte comme serveur (composant par defaut)" bash "$A" 3.0.4 "$T/minion"
expect ko "un binaire serveur n'est pas accepte comme minion" env COMPONENT=secagent-minion bash "$A" 3.0.4 "$T/good"
expect ok "inventory : version attendue (COMPONENT=secagent-inventory)" env COMPONENT=secagent-inventory bash "$A" 3.0.4 "$T/inv"
expect ko "inventory : binaire en version dev refuse" env COMPONENT=secagent-inventory bash "$A" 3.0.4 "$T/inv_dev"
expect ko "inventory : prefixe de version (3.0.40) refuse" env COMPONENT=secagent-inventory bash "$A" 3.0.4 "$T/inv_prefix"
expect ko "un binaire inventory n'est pas accepte comme serveur (composant par defaut)" bash "$A" 3.0.4 "$T/inv"
expect ko "un binaire minion n'est pas accepte comme inventory" env COMPONENT=secagent-inventory bash "$A" 3.0.4 "$T/minion"
expect ko "composant inconnu refuse" env COMPONENT=autre bash "$A" 3.0.4 "$T/good"
expect ok "3 lignes, ligne 1 correcte : OK" bash "$A" 3.0.4 "$T/three"
expect ok "3 lignes : les lignes 2-3 n'influencent pas le resultat (contenu quelconque)" bash "$A" 3.0.4 "$T/three_junk"
expect ok "3 lignes : lignes 2-3 vides, ligne 1 correcte : OK" bash "$A" 3.0.4 "$T/three_nolic"
expect ko "3 lignes : ligne 1 en prefixe de version (3.0.40) refusee malgre licence et source" bash "$A" 3.0.4 "$T/three_wrong1"
expect ko "3 lignes : ligne 1 en version dev refusee" bash "$A" 3.0.4 "$T/three_dev"
expect ko "3 lignes : la version en ligne 2 ne compte pas (ligne 1 = licence)" bash "$A" 3.0.4 "$T/three_late"
expect ok "3 lignes minion : COMPONENT=secagent-minion" env COMPONENT=secagent-minion bash "$A" 3.0.4 "$T/three_minion"
expect ok "3 lignes inventory : COMPONENT=secagent-inventory" env COMPONENT=secagent-inventory bash "$A" 3.0.4 "$T/three_inv"
expect ko "3 lignes : un binaire minion n'est pas accepte comme serveur" bash "$A" 3.0.4 "$T/three_minion"
out="$(bash "$A" 3.0.4 "$T/three" 2>&1)"
if [ "$out" = "version OK : secagent-server version 3.0.4" ]; then echo "ok   message de succes : ligne 1 seule, sans licence ni source"; else echo "KO   message de succes inattendu : $out"; FAIL=1; fi
exit $FAIL
