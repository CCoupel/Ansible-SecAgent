#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
# SPDX-License-Identifier: AGPL-3.0-or-later

# Autotest de DEPLOYMENT/podman/{stage,verify}-node-files.sh (#267) : depot des Compose, de release.env et de l'unite
# --user d'un noeud sur le partage, puis verification d'INTEGRITE contre le depot (VERIFY_LOCAL=1 : lecture locale au
# lieu du noeud). Toute modification, tout fichier en trop ou manquant doit etre refuse (code 2). Sans reseau.
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
D="$HERE/../../DEPLOYMENT/podman"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
bad=0
ok() { echo "ok   $*"; }
ko() { echo "KO   $*"; bad=1; }
P="$T/PRIVATE"; mkdir -p "$P/QUALIF" "$P/PROD"; chmod 700 "$P" "$P/QUALIF" "$P/PROD"
for n in "qualif srv3" "qualif srv4" "prod srv1"; do
  # shellcheck disable=SC2086
  SECAGENT_PRIVATE_DIR="$P" bash "$D/prepare-node-files.sh" $n >/dev/null || ko "prepare $n"
done
export SECAGENT_PRIVATE_DIR="$P" SECAGENT_IMAGE=ghcr.io/ccoupel/secagent-server:sha-abc SECAGENT_MINION_IMAGE=ghcr.io/ccoupel/secagent-minion:sha-abc
rc_of() { "$@" >/dev/null 2>&1; echo $?; }
stage() { bash "$D/stage-node-files.sh" "$@"; }
verify() { VERIFY_LOCAL=1 bash "$D/verify-node-files.sh" "$@"; }
B="$P/QUALIF/srv4/cyril/secagent"

# --- depot nominal ---------------------------------------------------------------------------------------------------
[ "$(rc_of stage qualif srv4)" = 0 ] && ok "stage qualif srv4" || ko "stage qualif srv4"
for f in docker-compose.chain.yml docker-compose.server.yml docker-compose.hooks.yml docker-compose.podman.qualif.yml release.env SHA256SUMS; do
  [ -f "$B/release/$f" ] || ko "release/$f absent"
done && ok "release/ : 4 Compose, release.env, SHA256SUMS"
[ -f "$B/systemd/secagent-qualif-srv4.service" ] && [ -f "$B/systemd/SHA256SUMS" ] && ok "systemd/ : unite + SHA256SUMS" || ko "systemd/ incomplet"
[ "$(stat -c %a "$B/release/release.env")" = 600 ] && ok "fichiers deposes en 0600" || ko "mode $(stat -c %a "$B/release/release.env")"
( cd "$B/release" && sha256sum -c --quiet SHA256SUMS ) && ok "SHA256SUMS de release/ coherent" || ko "SHA256SUMS release incoherent"
cmp -s "$HERE/../../DEPLOYMENT/qualif/docker-compose.chain.yml" "$B/release/docker-compose.chain.yml" && ok "Compose copie a l'identique du depot" || ko "Compose different du depot"
grep -q "^SECAGENT_IMAGE=ghcr.io/ccoupel/secagent-server:sha-abc$" "$B/release/release.env" && grep -q "^QUALIF_NODE_A_ADDR=192.168.1.213$" "$B/release/release.env" \
  && ok "release.env : image et adresse de A" || ko "release.env : $(cat "$B/release/release.env")"
grep -qiE 'secret|token|key=' "$B/release/release.env" && ko "release.env contient un secret ?" || ok "release.env sans secret"
U="$B/systemd/secagent-qualif-srv4.service"
grep -q "^ExecStartPre=$B/bin/check-private.sh qualif srv4$" "$U" && ok "unite : ExecStartPre = garde du partage" || ko "unite ExecStartPre : $(grep ExecStartPre "$U")"
grep -q "^ExecStart=/usr/bin/podman-compose -p secagent-qualif -f docker-compose.chain.yml -f docker-compose.hooks.yml -f docker-compose.podman.qualif.yml up -d secagent-server-b secagent-child minion-root minion-child$" "$U" \
  && ok "unite : services de srv4 seulement" || ko "unite ExecStart : $(grep '^ExecStart=' "$U")"
grep -q "^StartLimitBurst=3$" "$U" && grep -q "^Restart=on-failure$" "$U" && grep -q "^After=network-online.target$" "$U" \
  && ok "unite : redemarrage borne, apres le reseau" || ko "unite : limites absentes"
grep -q "secagent-server-a" "$U" && ko "unite srv4 demarre a" || ok "unite srv4 ne demarre pas a"
[ "$(rc_of verify qualif srv4)" = 0 ] && ok "verify : conforme apres stage" || ko "verify apres stage"

# --- ecarts : refus ----------------------------------------------------------------------------------------------------
v_refus() { # $1 nom, $2 alteration (eval), $3 motif
  stage qualif srv4 >/dev/null
  eval "$2"
  local out rc; out="$(verify qualif srv4 2>&1)"; rc=$?
  if [ "$rc" = 2 ] && printf '%s' "$out" | grep -qF -- "$3"; then ok "verify refuse : $1"; else ko "verify $1 (rc=$rc) : $out"; fi
}
v_refus "Compose modifie" 'echo "# ajout" >> "$B/release/docker-compose.chain.yml"' "differents du depot"
v_refus "unite modifiee (ExecStartPre retire)" 'sed -i "/^ExecStartPre=/d" "$U"' "differents du depot"
v_refus "fichier en trop dans release/" ': > "$B/release/docker-compose.override.yml"' "+"
v_refus "fichier cache en trop dans systemd/" ': > "$B/systemd/.x.service"' "differents du depot"
v_refus "fichier manquant" 'rm -f "$B/release/docker-compose.hooks.yml"' "differents du depot"
v_refus "SHA256SUMS recalcule par un tiers" 'echo "# x" >> "$B/release/docker-compose.chain.yml"; ( cd "$B/release" && rm SHA256SUMS && sha256sum -- * > SHA256SUMS )' "differents du depot"
v_refus "lien symbolique a la place d'un Compose" 'rm -f "$B/release/docker-compose.hooks.yml"; ln -s /etc/hostname "$B/release/docker-compose.hooks.yml"' "differents du depot"
v_refus "release.env avec une autre image" 'sed -i "s/sha-abc/sha-evil/" "$B/release/release.env"' "differents du depot"
stage qualif srv4 >/dev/null
out="$(SECAGENT_IMAGE=ghcr.io/ccoupel/secagent-server:sha-other VERIFY_LOCAL=1 bash "$D/verify-node-files.sh" qualif srv4 2>&1)"; rc=$?
[ "$rc" = 2 ] && ok "verify refuse : release attendue differente (autre image)" || ko "verify autre image rc=$rc"

# --- stage : remplacement complet, gardes ------------------------------------------------------------------------------
: > "$B/release/en-trop.yml"; stage qualif srv4 >/dev/null
[ ! -e "$B/release/en-trop.yml" ] && ok "stage : fichier en trop retire" || ko "stage : fichier en trop conserve"
[ -d "$B/run" ] && ok "prepare : run/ (fichiers volatils) present, hors verification" || ko "run/ absent"
: > "$B/run/plugin.token"; [ "$(rc_of verify qualif srv4)" = 0 ] && ok "verify : run/ ignore (jetons volatils)" || ko "verify : run/ pris en compte"
[ "$(rc_of stage qualif srv1)" = 2 ] && ok "stage : couple qualif srv1 refuse" || ko "stage qualif srv1"
[ "$(rc_of stage prod srv2)" = 2 ] && ok "stage : noeud non prepare (prod srv2) refuse" || ko "stage prod srv2"
[ "$(rc_of stage prod srv1)" = 2 ] && ok "stage prod sans SECAGENT_VERSION refuse" || ko "stage prod sans version"
[ "$(SECAGENT_VERSION=v3.0.6 rc_of stage prod srv1)" = 0 ] && ok "stage prod srv1 (SECAGENT_VERSION)" || ko "stage prod srv1"
grep -q "^STATE_HOST_DIR=$P/PROD/state/root$" "$P/PROD/srv1/cyril/secagent/release/release.env" && ok "release.env prod : etat sur le partage" || ko "release.env prod"
grep -q "up -d secagent-server$" "$P/PROD/srv1/cyril/secagent/systemd/secagent-prod-srv1.service" && ok "unite prod : secagent-server" || ko "unite prod"
[ "$(SECAGENT_VERSION=v3.0.6 VERIFY_LOCAL=1 rc_of bash "$D/verify-node-files.sh" prod srv1)" = 0 ] && ok "verify prod srv1 conforme" || ko "verify prod srv1"
[ "$(SECAGENT_IMAGE='img x' rc_of stage qualif srv3)" = 2 ] && ok "release.env : valeur avec espace refusee" || ko "release.env espace"
[ "$(SECAGENT_IMAGE=$'img\nX=1' rc_of stage qualif srv3)" = 2 ] && ok "release.env : saut de ligne refuse" || ko "release.env saut de ligne"
[ "$(NODE_SOURCE_DIR=rel rc_of stage qualif srv3)" = 2 ] && ok "NODE_SOURCE_DIR relatif refuse" || ko "NODE_SOURCE_DIR relatif"
mkdir -p "$T/arch"; cp "$HERE/../../DEPLOYMENT/qualif/"docker-compose.{chain,server,hooks}.yml "$T/arch/"; cp "$D/docker-compose.podman.qualif.yml" "$T/arch/"
echo "# archive" >> "$T/arch/docker-compose.server.yml"
NODE_SOURCE_DIR="$T/arch" stage qualif srv3 >/dev/null
grep -q "# archive" "$P/QUALIF/srv3/cyril/secagent/release/docker-compose.server.yml" && ok "NODE_SOURCE_DIR : Compose pris dans l'archive" || ko "NODE_SOURCE_DIR ignore"
[ "$(NODE_SOURCE_DIR="$T/arch" VERIFY_LOCAL=1 rc_of bash "$D/verify-node-files.sh" qualif srv3)" = 0 ] && ok "verify avec la meme archive conforme" || ko "verify archive"
[ "$(VERIFY_LOCAL=1 rc_of bash "$D/verify-node-files.sh" qualif srv3)" = 2 ] && ok "verify contre le depot (archive differente) refuse" || ko "verify depot vs archive"

exit $bad
