#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
# SPDX-License-Identifier: AGPL-3.0-or-later

# Autotest des garde-fous de `chain-test.sh reset-state` (T48, #267) : refus PROD (environnement et chemins), refus sans
# confirmation ou avec une mauvaise, refus si un conteneur existe, sauvegarde 0700/0600 avant effacement, et jamais
# d'appel implicite (down, bootstrap). Aucun noeud, aucun podman : `ctr` est remplace par un faux.
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
C="$HERE/../../DEPLOYMENT/qualif/chain-test.sh"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
bad=0
ok() { echo "ok   $*"; }
ko() { echo "KO   $*"; bad=1; }
SH="$T/share"
mk() { # $1 racine PRIVATE : arborescence QUALIF avec un etat dans root et child
  mkdir -p "$1/QUALIF/state/root" "$1/QUALIF/state/child"; chmod 700 "$1" "$1/QUALIF" "$1/QUALIF/state" "$1/QUALIF/state/root" "$1/QUALIF/state/child"
  echo etat > "$1/QUALIF/state/root/relay.state"; echo etat > "$1/QUALIF/state/child/relay.state"
}
# $1 racine PRIVATE, $2 conteneurs listes par le faux `ctr ps`, puis variables ; sortie dans $T/out, code de retour rendu
rs() {
  local p="$1" names="$2"; shift 2
  env -i PATH="$PATH" HOME="$T" TMPDIR="$T" CONTAINER_CLI=podman PODMAN_SHARE_ROOT="$SH" SECAGENT_PRIVATE_DIR="$p" \
    CONTAINER_SSHKEY=/dev/null CONTAINER_KNOWN_HOSTS=/dev/null NAMES="$names" "$@" bash -c '
      set -euo pipefail; source "$1"
      ctr() { case "$*" in "ps -a --format {{.Names}}") printf "%s\n" $NAMES ;; esac; }
      reset_state' _ "$C" > "$T/out" 2>&1
}
P="$SH/PRIVATE"; mk "$P"
rs "$P" ""; rc=$?
[ "$rc" = 2 ] && grep -q "RESET_STATE_CONFIRM=secagent-qualif" "$T/out" && [ -s "$P/QUALIF/state/root/relay.state" ] \
  && ok "sans confirmation : refus, etat intact" || ko "sans confirmation (rc=$rc) : $(cat "$T/out")"
rs "$P" "" RESET_STATE_CONFIRM=secagent-autre; rc=$?
[ "$rc" = 2 ] && [ -s "$P/QUALIF/state/root/relay.state" ] && ok "mauvaise confirmation : refus, etat intact" || ko "mauvaise confirmation (rc=$rc)"
rs "$P" "" RESET_STATE_CONFIRM=secagent-qualif SECAGENT_ENV=prod; rc=$?
[ "$rc" = 2 ] && grep -q "jamais PROD" "$T/out" && [ -s "$P/QUALIF/state/root/relay.state" ] && ok "SECAGENT_ENV=prod : refus" || ko "SECAGENT_ENV=prod (rc=$rc) : $(cat "$T/out")"
PP="$SH/X/PRIVATE/PROD"; mk "$PP"
rs "$PP" "" RESET_STATE_CONFIRM=secagent-qualif; rc=$?
[ "$rc" = 2 ] && grep -q "sous un dossier PROD" "$T/out" && [ -s "$PP/QUALIF/state/root/relay.state" ] && ok "chemin sous PRIVATE/PROD : refus, rien d'efface" || ko "chemin PROD (rc=$rc) : $(cat "$T/out")"
P2="$SH/Y/PRIVATE"; mk "$P2"; mkdir -p "$SH/Y/PROD/state"; echo prod > "$SH/Y/PROD/state/relay.state"
rm -rf "$P2/QUALIF/state/root"; mkdir -p "$SH/Y/PROD/state/root"; echo prod > "$SH/Y/PROD/state/root/relay.state"
ln -s "$SH/Y/PROD/state/root" "$P2/QUALIF/state/root"
rs "$P2" "" RESET_STATE_CONFIRM=secagent-qualif; rc=$?
[ "$rc" = 2 ] && [ -s "$SH/Y/PROD/state/root/relay.state" ] && ok "state/root lien vers un etat PROD : refus, PROD intact" || ko "lien PROD (rc=$rc) : $(cat "$T/out")"
P3="$SH/Z/PRIVATE"; mk "$P3"; mkdir -p "$SH/Z/PROD"; mv "$P3/QUALIF/state" "$SH/Z/PROD/state"; ln -s "$SH/Z/PROD/state" "$P3/QUALIF/state"
rs "$P3" "" RESET_STATE_CONFIRM=secagent-qualif; rc=$?
[ "$rc" = 2 ] && grep -q "PROD\|lien" "$T/out" && [ -s "$SH/Z/PROD/state/root/relay.state" ] && ok "state/ lien vers un dossier PROD (chemin reel) : refus" || ko "chemin reel PROD (rc=$rc) : $(cat "$T/out")"
rs "$P" "secagent-qualif-a" RESET_STATE_CONFIRM=secagent-qualif; rc=$?
[ "$rc" = 2 ] && grep -q "lancer d'abord chain-test.sh down" "$T/out" && [ -s "$P/QUALIF/state/root/relay.state" ] && ok "conteneur de la racine present : refus" || ko "conteneur present (rc=$rc) : $(cat "$T/out")"
rs "$P" "secagent-qualif_minion-root_1" RESET_STATE_CONFIRM=secagent-qualif; rc=$?
b="$(ls -d "$P"/QUALIF/state-backups/*/ 2>/dev/null | head -1)"; b="${b%/}"
if [ "$rc" = 0 ] && [ -n "$b" ] && [ "$(cat "$b/root/relay.state")" = etat ] && [ "$(cat "$b/child/relay.state")" = etat ] \
   && [ -z "$(ls -A "$P/QUALIF/state/root")" ] && [ -z "$(ls -A "$P/QUALIF/state/child")" ] \
   && [ "$(stat -c %a "$P/QUALIF/state/root")" = 700 ] && [ "$(stat -c %a "$P/QUALIF/state-backups")" = 700 ] \
   && [ -z "$(find "$b" -type d ! -perm 700)" ] && [ -z "$(find "$b" -type f ! -perm 600)" ]; then
  ok "confirmation correcte : sauvegarde 0700/0600 puis etat vide (repertoires gardes en 0700)"
else ko "effacement confirme (rc=$rc) : $(cat "$T/out")"; fi
# jamais d'appel implicite : reset_state n'apparait que dans sa definition et la commande explicite `reset-state`
[ "$(grep -cw 'reset_state' "$C")" = 2 ] && grep -q '^    reset-state) reset_state ;;$' "$C" \
  && ok "reset_state : seulement la definition et la commande reset-state" || ko "appel de reset_state hors de la commande : $(grep -nw reset_state "$C")"
fns="$(env -i PATH="$PATH" HOME="$T" TMPDIR="$T" CONTAINER_CLI=podman PODMAN_SHARE_ROOT="$SH" SECAGENT_PRIVATE_DIR="$P" bash -c 'source "$1"; declare -f bootstrap chain_down root_up test_services_up' _ "$C" 2>/dev/null)"
[ -n "$fns" ] && ! grep -qw reset_state <<<"$fns" && ok "bootstrap, down, root_up, test-services-up n'appellent pas reset_state" || ko "appel implicite de reset_state"
setters="$(grep -n 'RESET_STATE_CONFIRM=' "$C" "$HERE/../../DEPLOYMENT/qualif/failover-test.sh" "$HERE/../../DEPLOYMENT/qualif/admission-503.sh" \
  | grep -v 'refuse\|^[^:]*:[0-9]*:[[:space:]]*#')"
[ -z "$setters" ] && ok "aucun script de qualif ne fixe lui-meme RESET_STATE_CONFIRM" || ko "RESET_STATE_CONFIRM fixe par : $setters"
exit $bad
