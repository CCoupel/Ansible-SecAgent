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
[ "$(grep '^ExecStartPre=' "$U" | tr '\n' '|')" = "ExecStartPre=/usr/bin/sha256sum --quiet --strict -c %h/.config/secagent/qualif-srv4.sha256|ExecStartPre=$B/bin/check-private.sh qualif srv4 %h/.config/secagent/qualif-srv4.sha256|" ] \
  && ok "unite : ExecStartPre = empreintes epinglees PUIS garde (avec liste exacte)" || ko "unite ExecStartPre : $(grep ExecStartPre "$U")"
cmp -s "$HERE/../../DEPLOYMENT/podman/check-private.sh" "$B/bin/check-private.sh" && [ "$(stat -c %a "$B/bin/check-private.sh")" = 700 ] \
  && ok "stage : garde bin/check-private.sh re-ecrite depuis le depot (0700)" || ko "stage : garde bin/ differente du depot"
grep -q "^ExecStart=/usr/bin/podman-compose -p secagent-qualif -f docker-compose.chain.yml -f docker-compose.hooks.yml -f docker-compose.podman.qualif.yml up -d secagent-server-b$" "$U" \
  && ok "unite srv4 : racine b SEULEMENT (enfant et minions : chain-test.sh)" || ko "unite ExecStart : $(grep '^ExecStart=' "$U")"
grep -qE "secagent-child|minion-" "$U" && ko "unite srv4 demarre un service de test (enfant/minion)" || ok "unite srv4 : aucun service de test (pas de double chemin)"
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
v_refus "garde bin/check-private.sh falsifiee (exit 0 ajoute)" 'sed -i "s/^set -u$/set -u; exit 0/" "$B/bin/check-private.sh"' "bin/check-private.sh"
v_refus "garde bin/check-private.sh remplacee (pwned)" 'echo "echo pwned" >> "$B/bin/check-private.sh"' "differents du depot"
v_refus "fichier en trop dans bin/" ': > "$B/bin/autre.sh"' "differents du depot"
v_refus "fichier .env en trop dans release/ (lu par podman-compose)" ': > "$B/release/.env"' "differents du depot"
stage qualif srv4 >/dev/null
out="$(SECAGENT_IMAGE=ghcr.io/ccoupel/secagent-server:sha-other VERIFY_LOCAL=1 bash "$D/verify-node-files.sh" qualif srv4 2>&1)"; rc=$?
[ "$rc" = 2 ] && ok "verify refuse : release attendue differente (autre image)" || ko "verify autre image rc=$rc"

# --- --pin : copie locale de l'unite + manifeste epingle, verifies a CHAQUE demarrage (ExecStartPre simules) ---------
PH="$T/home-srv4"; FST="$(stat -f -c %T "$T")"
mkdir -p "$P/QUALIF/state/root" "$P/QUALIF/state/child" "$P/QUALIF/secrets" "$P/QUALIF/pki"
chmod 700 "$P/QUALIF/state" "$P/QUALIF/state/root" "$P/QUALIF/state/child" "$P/QUALIF/secrets"; chmod 711 "$P/QUALIF/pki"
: > "$P/QUALIF/pki/ca.crt"; chmod 644 "$P/QUALIF/pki/ca.crt"
pin() { VERIFY_LOCAL=1 PIN_HOME="$PH" bash "$D/verify-node-files.sh" --pin qualif srv4; }
PINF="$PH/.config/secagent/qualif-srv4.sha256"; LU="$PH/.config/systemd/user/secagent-qualif-srv4.service"
start_pre() { # execute les ExecStartPre de l'unite COPIEE, %h = PIN_HOME (comme systemd --user) ; code du premier echec
  local l rc=0
  [ -f "$LU" ] || return 9
  while IFS= read -r l; do
    l="${l#ExecStartPre=}"; l="${l//%h/$PH}"
    # shellcheck disable=SC2086   # ligne de commande d'unite : mots separes par des espaces, sans guillemets
    env SECAGENT_PRIVATE_ROOT="$P" SECAGENT_NODE_UID="$(id -u)" SECAGENT_NODE_NAME=srv4 SECAGENT_PRIVATE_FSTYPES="$FST" $l >/dev/null 2>&1 || { rc=$?; break; }
  done < <(grep '^ExecStartPre=' "$LU")
  return $rc
}
stage qualif srv4 >/dev/null
[ "$(VERIFY_LOCAL=1 rc_of bash "$D/verify-node-files.sh" --pin qualif srv4)" = 2 ] && ok "--pin sans PIN_HOME (essai local) refuse" || ko "--pin sans PIN_HOME"
[ "$(rc_of pin)" = 0 ] && ok "verify --pin conforme" || ko "verify --pin : $(pin 2>&1)"
[ -f "$PINF" ] && [ ! -L "$LU" ] && cmp -s "$U" "$LU" && ok "--pin : unite COPIEE hors partage (identique a l'attendu, pas un lien)" || ko "--pin : unite locale absente ou differente"
[ "$(stat -c %a "$PINF")" = 600 ] && [ "$(stat -c %a "$LU")" = 600 ] && [ "$(stat -c %a "$PH/.config/secagent")" = 700 ] \
  && ok "--pin : manifeste et unite en 0600, dossier 0700" || ko "--pin : modes $(stat -c %a "$PINF" "$LU")"
[ "$(wc -l < "$PINF")" = "$(find "$B/bin" "$B/release" "$B/systemd" -type f | wc -l)" ] && grep -q "  $B/bin/check-private.sh$" "$PINF" \
  && ok "--pin : manifeste couvre bin/, release/, systemd/ (garde comprise), chemins absolus" || ko "--pin : manifeste $(cat "$PINF")"
start_pre; [ $? = 0 ] && ok "demarrage simule : ExecStartPre conformes" || ko "demarrage simule nominal : rc $?"
sp_refus() { # $1 nom, $2 alteration du partage APRES --pin (eval)
  stage qualif srv4 >/dev/null; pin >/dev/null 2>&1 || ko "pin prealable ($1)"
  eval "$2"
  start_pre; local rc=$?
  [ "$rc" != 0 ] && ok "demarrage refuse : $1 (rc=$rc)" || ko "demarrage accepte malgre : $1"
}
sp_refus "garde falsifiee apres verification" 'sed -i "s/^set -u$/set -u; exit 0/" "$B/bin/check-private.sh"'
sp_refus "Compose modifie apres verification" 'echo "# x" >> "$B/release/docker-compose.chain.yml"'
sp_refus "release.env modifie apres verification" 'sed -i "s/sha-abc/sha-evil/" "$B/release/release.env"'
sp_refus "release/.env ajoute apres verification" 'echo "X=1" > "$B/release/.env"'
sp_refus "sous-dossier ajoute dans release/" 'mkdir "$B/release/sub"'
sp_refus "Compose remplace par un lien vers une copie IDENTIQUE" 'cp "$B/release/docker-compose.chain.yml" "$T/chain.copie"; rm "$B/release/docker-compose.chain.yml"; ln -s "$T/chain.copie" "$B/release/docker-compose.chain.yml"'
sp_refus "garde bin/check-private.sh remplacee par un lien vers une copie IDENTIQUE" 'cp -p "$B/bin/check-private.sh" "$T/garde.copie"; rm "$B/bin/check-private.sh"; ln -s "$T/garde.copie" "$B/bin/check-private.sh"'
sp_refus "unite du partage remplacee par un lien vers une copie IDENTIQUE" 'cp "$U" "$T/unite.copie"; rm "$U"; ln -s "$T/unite.copie" "$U"'
sp_refus "dossier release/ remplace par un lien vers une copie IDENTIQUE" 'cp -a "$B/release" "$T/release.copie"; rm -rf "$B/release"; ln -s "$T/release.copie" "$B/release"'
rm -f "$B/release"; mv "$T/release.copie" "$B/release"   # dossier reel remis (stage refuse un lien)
sp_refus "lien symbolique en trop (meme nom qu'un fichier cache)" 'ln -s /dev/null "$B/systemd/.lien"'
# la garde seule, juste apres un sha256sum -c qui SUIT le lien : c'est elle qui refuse, avec un message explicite
stage qualif srv4 >/dev/null; pin >/dev/null 2>&1
cp "$B/release/release.env" "$T/env.copie"; rm "$B/release/release.env"; ln -s "$T/env.copie" "$B/release/release.env"
sha256sum --quiet --strict -c "$PINF" >/dev/null 2>&1 && ok "lien vers copie identique : sha256sum -c l'accepte (il suit le lien)" || ko "sha256sum -c refuse deja le lien ?"
out="$(env SECAGENT_PRIVATE_ROOT="$P" SECAGENT_NODE_UID="$(id -u)" SECAGENT_NODE_NAME=srv4 SECAGENT_PRIVATE_FSTYPES="$FST" bash "$B/bin/check-private.sh" qualif srv4 "$PINF" 2>&1)"; rc=$?
[ "$rc" = 2 ] && printf '%s' "$out" | grep -q "l $B/release/release.env" && printf '%s' "$out" | grep -q "non fichier ordinaire" \
  && ok "garde : lien vers copie identique refuse (rc 2, entree nommee)" || ko "garde lien identique rc=$rc : $out"
rm -f "$B/release/release.env"
sp_refus "fichier manquant apres verification" 'rm -f "$B/release/docker-compose.hooks.yml"'
sp_refus "unite du partage modifiee apres verification" 'sed -i "/^ExecStartPre=/d" "$U"'
sp_refus "manifeste epingle absent" 'rm -f "$PINF"'
sp_refus "manifeste epingle vide" ': > "$PINF"'
sp_refus "partage inaccessible (PRIVATE/QUALIF absent)" 'mv "$P/QUALIF" "$P/QUALIF.off"'
mv "$P/QUALIF.off" "$P/QUALIF"
stage qualif srv4 >/dev/null; pin >/dev/null 2>&1; cp "$PINF" "$T/pin.before"
echo "# x" >> "$B/release/docker-compose.chain.yml"
[ "$(rc_of pin)" = 2 ] && cmp -s "$PINF" "$T/pin.before" && ok "--pin apres echec de verification : rien re-epingle" || ko "--pin a epingle un partage non conforme"
stage qualif srv4 >/dev/null; pin >/dev/null 2>&1
SECAGENT_IMAGE=ghcr.io/ccoupel/secagent-server:sha-new stage qualif srv4 >/dev/null
start_pre; [ $? != 0 ] && ok "nouvelle release deposee sans re-epinglage : demarrage refuse" || ko "nouvelle release non epinglee acceptee"
[ "$(SECAGENT_IMAGE=ghcr.io/ccoupel/secagent-server:sha-new rc_of pin)" = 0 ] && start_pre && ok "nouvelle release verifiee et re-epinglee : demarrage accepte" || ko "re-epinglage nouvelle release"
rm -rf "$P/QUALIF/state" "$P/QUALIF/secrets" "$P/QUALIF/pki"

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
[ "$(SECAGENT_PRIVATE_DIR="$P/x y" rc_of stage qualif srv3)" = 2 ] && ok "SECAGENT_PRIVATE_DIR avec espace refuse (ecrit dans l'unite)" || ko "PRIVATE_DIR espace"
[ "$(SECAGENT_PRIVATE_DIR=$'/tmp/a\nExecStartPre=/bin/x' VERIFY_LOCAL=1 rc_of bash "$D/verify-node-files.sh" qualif srv3)" = 2 ] && ok "SECAGENT_PRIVATE_DIR avec saut de ligne refuse (injection de directive)" || ko "PRIVATE_DIR saut de ligne"
[ "$(SECAGENT_PRIVATE_DIR="$P/../PRIVATE" rc_of stage qualif srv3)" = 2 ] && ok "SECAGENT_PRIVATE_DIR avec .. refuse" || ko "PRIVATE_DIR .."
[ "$(NODE_SOURCE_DIR=rel rc_of stage qualif srv3)" = 2 ] && ok "NODE_SOURCE_DIR relatif refuse" || ko "NODE_SOURCE_DIR relatif"
mkdir -p "$T/arch"; cp "$HERE/../../DEPLOYMENT/qualif/"docker-compose.{chain,server,hooks}.yml "$T/arch/"; cp "$D/docker-compose.podman.qualif.yml" "$T/arch/"
echo "# archive" >> "$T/arch/docker-compose.server.yml"
NODE_SOURCE_DIR="$T/arch" stage qualif srv3 >/dev/null
grep -q "# archive" "$P/QUALIF/srv3/cyril/secagent/release/docker-compose.server.yml" && ok "NODE_SOURCE_DIR : Compose pris dans l'archive" || ko "NODE_SOURCE_DIR ignore"
[ "$(NODE_SOURCE_DIR="$T/arch" VERIFY_LOCAL=1 rc_of bash "$D/verify-node-files.sh" qualif srv3)" = 0 ] && ok "verify avec la meme archive conforme" || ko "verify archive"
[ "$(VERIFY_LOCAL=1 rc_of bash "$D/verify-node-files.sh" qualif srv3)" = 2 ] && ok "verify contre le depot (archive differente) refuse" || ko "verify depot vs archive"

# --- PROD depuis la VRAIE archive de release (build_compose_archive.sh, digest factice) : NODE_SOURCE_DIR = archive extraite
FAKE="sha256:$(printf '0%.0s' $(seq 64))"
( cd "$HERE/../.." && STAGE_DIR="$T/rstage" bash scripts/ci/build_compose_archive.sh v3.0.6 3.0.6 "$FAKE" "$T/rout" ) >/dev/null 2>&1 \
  && mkdir -p "$T/rx" && tar -xzf "$T/rout/secagent-compose-3.0.6.tar.gz" -C "$T/rx" && ok "archive de release fabriquee et extraite" || ko "archive de release"
RX="$T/rx/secagent-compose-3.0.6"
[ "$(SECAGENT_VERSION=v3.0.6 NODE_SOURCE_DIR="$RX" rc_of stage prod srv1)" = 0 ] && ok "stage prod srv1 depuis l'archive extraite (surcharge Podman presente)" || ko "stage prod depuis l'archive : $(SECAGENT_VERSION=v3.0.6 NODE_SOURCE_DIR="$RX" stage prod srv1 2>&1 | tail -1)"
PB="$P/PROD/srv1/cyril/secagent"
cmp -s "$RX/docker-compose.podman.yml" "$PB/release/docker-compose.podman.yml" && ok "release/ : docker-compose.podman.yml de l'archive" || ko "surcharge Podman absente ou differente dans release/"
grep -q "image: ghcr.io/ccoupel/secagent-server:v3.0.6@$FAKE" "$PB/release/docker-compose.server.yml" && ok "release/ : Compose serveur epingle tag@digest (archive)" || ko "Compose serveur non epingle"
[ "$(SECAGENT_VERSION=v3.0.6 NODE_SOURCE_DIR="$RX" VERIFY_LOCAL=1 rc_of bash "$D/verify-node-files.sh" prod srv1)" = 0 ] && ok "verify prod srv1 contre la meme archive conforme" || ko "verify prod srv1 archive"
rm -f "$RX/docker-compose.podman.yml"
[ "$(SECAGENT_VERSION=v3.0.6 NODE_SOURCE_DIR="$RX" rc_of stage prod srv1)" = 2 ] && ok "archive sans surcharge Podman : stage prod refuse" || ko "archive sans surcharge Podman acceptee"

exit $bad
