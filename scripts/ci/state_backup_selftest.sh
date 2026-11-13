#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
# SPDX-License-Identifier: AGPL-3.0-or-later

# Autotest de `chain-test.sh state-backup` (Podman, ordre infra n°21, decision Q4) : le script execute sur le noeud (faux
# `podman`, HOME jetable) cree la copie hors partage en 0700/0600, verifie la copie, restaure sur un STATE_DIR temporaire
# puis le retire, sans jamais monter l'etat en service ; cote poste, verify sur le noeud du maitre puis script sur ce noeud.
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
C="$HERE/../../DEPLOYMENT/qualif/chain-test.sh"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
bad=0
ok() { echo "ok   $*"; }
ko() { echo "KO   $*"; bad=1; }
SH="$T/share"; P="$SH/PRIVATE"; mkdir -p "$P/QUALIF"
script="$(env -i PATH="$PATH" HOME="$T" TMPDIR="$T" CONTAINER_CLI=podman PODMAN_SHARE_ROOT="$SH" SECAGENT_PRIVATE_DIR="$P" \
  bash -c 'source "$1"; printf "%s" "$STATE_BACKUP_NODE_SCRIPT"' _ "$C" 2>/dev/null)"
[ -n "$script" ] && ok "script du noeud lu" || ko "STATE_BACKUP_NODE_SCRIPT vide"

# --- 1. script du noeud, faux podman --------------------------------------------------------------------------------
mkdir -p "$T/bin" "$T/home"
cat > "$T/bin/podman" <<'FAKE'
#!/bin/bash
printf '%s\n' "$*" >> "$FAKE_LOG"
case "$1" in
  cp) printf 'etat' > "$3" ;;
  run)
    [ "${FAKE_FAIL:-}" = restore ] && [[ " $* " == *" state restore "* ]] && { echo "Error: restore" >&2; exit 3; }
    prev=""; for a in "$@"; do
      if [ "$prev" = -v ] && [[ $a == *:/data ]] && [[ " $* " == *" state restore "* ]]; then printf 'restaure' > "${a%:/data}/relay.state"; fi
      prev="$a"
    done ;;
esac
exit 0
FAKE
chmod +x "$T/bin/podman"
nodebk() { env -i PATH="$T/bin:$PATH" HOME="$T/home" FAKE_LOG="$T/podman.log" "$@" bash -c "$script" _ 20261113T000000Z secagent-qualif-a img@sha256:x secagent-qualif_secrets > "$T/out" 2>&1; }
: > "$T/podman.log"; nodebk; rc=$?
d="$T/home/secagent-backup/20261113T000000Z"
[ "$rc" = 0 ] && ok "script du noeud : rc 0" || ko "script du noeud rc=$rc : $(cat "$T/out")"
[ "$(stat -c %a "$T/home/secagent-backup")" = 700 ] && [ "$(stat -c %a "$d")" = 700 ] && [ "$(stat -c %a "$d/relay.state")" = 600 ] \
  && ok "copie hors partage : ~/secagent-backup et <horodatage>/ en 0700, relay.state en 0600" || ko "modes : $(stat -c '%a %n' "$T/home/secagent-backup" "$d" "$d/relay.state" 2>&1)"
[ ! -e "$d/restore-check" ] && ok "STATE_DIR temporaire (restore-check) retire, copie gardee" || ko "restore-check present"
grep -q "^cp secagent-qualif-a:/data/relay.state $d/relay.state$" "$T/podman.log" && ok "podman cp depuis le conteneur du maitre" || ko "cp : $(cat "$T/podman.log")"
runs="$(grep -c '^run ' "$T/podman.log")"
[ "$runs" = 3 ] && sed -n '2p' "$T/podman.log" | grep -q "state verify /backup/relay.state" && sed -n '3p' "$T/podman.log" | grep -q "state restore --from /backup/relay.state" \
  && sed -n '4p' "$T/podman.log" | grep -q "state verify /data/relay.state" && ok "ordre : verify de la copie, restore sur la copie, verify du resultat" || ko "conteneurs : $(cat "$T/podman.log")"
sed -n '3p' "$T/podman.log" | grep -q -- "-v $d:/backup:ro -v $d/restore-check:/data " && ok "restore : copie en lecture seule, STATE_DIR temporaire en ecriture" || ko "montages du restore : $(sed -n 3p "$T/podman.log")"
! grep -E '^run ' "$T/podman.log" | grep -qvE -- "--userns keep-id:uid=10001,gid=10001 .*--read-only .*--cap-drop ALL .*--network none .*-v secagent-qualif_secrets:/run/secagent-secrets:ro" \
  && ok "conteneurs ephemeres : keep-id, lecture seule, cap_drop ALL, sans reseau, secrets ro" || ko "durcissement : $(grep '^run' "$T/podman.log")"
! grep -qE 'state/root|secagent_state|PRIVATE' "$T/podman.log" && ok "jamais l'etat en service ni le partage monte" || ko "montage interdit : $(cat "$T/podman.log")"
: > "$T/podman.log"; rm -rf "${T:?}/home"; mkdir -p "$T/home"; nodebk FAKE_FAIL=restore; rc=$?
[ "$rc" != 0 ] && ok "restore en echec : le script echoue (rc $rc)" || ko "echec du restore ignore"
rm -rf "${T:?}/home"; mkdir -p "$T/home/elsewhere"; ln -s "$T/home/elsewhere" "$T/home/secagent-backup"; nodebk; rc=$?
[ "$rc" = 2 ] && [ -z "$(ls -A "$T/home/elsewhere")" ] && ok "HOME/secagent-backup lien symbolique : refus" || ko "lien rc=$rc"

# --- 2. cote poste : verify sur le noeud du maitre, script sur ce noeud ------------------------------------------------
cat > "$T/bin/ssh" <<FAKE
#!/bin/bash
tgt=""; cmd=""
while [ \$# -gt 0 ]; do case "\$1" in -n) ;; -i|-o) shift ;; *) if [ -z "\$tgt" ]; then tgt="\$1"; else cmd="\$1"; fi ;; esac; shift; done
echo "\$tgt | \$cmd" >> "$T/ssh.log"
exit 0
FAKE
chmod +x "$T/bin/ssh"; : > "$T/k"; : > "$T/ssh.log"
env -i PATH="$T/bin:$PATH" HOME="$T" TMPDIR="$T" CONTAINER_CLI=podman PODMAN_SHARE_ROOT="$SH" SECAGENT_PRIVATE_DIR="$P" \
  CONTAINER_SSHKEY="$T/k" CONTAINER_KNOWN_HOSTS="$T/k" SECAGENT_IMAGE=img@sha256:x bash -c 'source "$1"; state_backup' _ "$C" > "$T/out" 2>&1; rc=$?
A='cyril@192.168.1.213'
[ "$rc" = 0 ] && grep -qE "^$A \| podman exec secagent-qualif-a /app/secagent-server state verify /data/relay.state" "$T/ssh.log" \
  && grep -qE "^$A \| bash -c .* _ [0-9]{8}T[0-9]{6}Z secagent-qualif-a img@sha256:x secagent-qualif_secrets" "$T/ssh.log" \
  && ok "poste : state verify puis script sur le noeud du maitre (A), arguments transmis" || ko "poste rc=$rc : $(cat "$T/out") / $(cat "$T/ssh.log")"
env -i PATH="$T/bin:$PATH" HOME="$T" TMPDIR="$T" SECAGENT_PRIVATE_DIR="$P" SECAGENT_IMAGE=x bash -c 'source "$1"; state_backup' _ "$C" > "$T/out" 2>&1; rc=$?
[ "$rc" = 2 ] && ok "Docker : refus (backup-restore)" || ko "Docker rc=$rc"
exit $bad
