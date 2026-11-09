#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
# SPDX-License-Identifier: AGPL-3.0-or-later

# Auto-test des chemins prives de la qualif (#250), sans docker ni reseau :
#  (a) SECAGENT_PRIVATE_DIR inexistant => `paths` refuse (code != 0, message citant SECAGENT_PRIVATE_DIR), rien n'est cree ;
#  (b) PRIVATE existant => PRIVATE_DIR, SECRETS_DIR, QUALIF_TLS_DIR (failover : qualif/ci-tls ; chain : qualif/pki), CHAIN_DIR (chain seul) ;
#  (c) une variable explicite (SECRETS_DIR=/x) prime sur le defaut ;
#  (d) pki/gen.sh refuse d'ecrire des cles dans un depot git ou le chemin n'est pas ignore ;
#  (f) SECAGENT_PRIVATE_DIR relatif => refus ("n'est pas un chemin absolu"), meme avec SECRETS_DIR absolu, y compris pki/gen.sh ;
#  (g) CHAIN_DIR (jetons volatils, defaut ${TMPDIR:-/tmp}/secagent-qualif-chain-<uid>) : refus relatif, '/', lien, non-repertoire, autre uid, droits > 0700 ;
#  (h) chain_dir_clean (down) : supprime un repertoire 0700 a soi, refuse sans rien supprimer vide, '/', relatif, lien (meme casse), fichier, 0755, autre uid ;
#  (e) plus aucun ancien defaut ($HERE/secrets, $HERE/pki/out, $HERE/.ci-tls, $HERE/chain) dans DEPLOYMENT/qualif.
# Contrat : sous-commande `paths` de failover-test.sh et chain-test.sh, imprimant PRIVATE_DIR=, SECRETS_DIR=, QUALIF_TLS_DIR= (+ CHAIN_DIR= pour chain-test.sh seul).
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
Q="$HERE/../../DEPLOYMENT/qualif"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
bad=0
ok() { echo "ok   $1"; }
ko() { echo "KO   $1"; bad=1; }
# val <sortie> <CLE> : valeur de la ligne CLE=...
val() { printf '%s\n' "$1" | sed -n "s/^$2=//p" | head -n1; }
clean_env() { env -u SECRETS_DIR -u QUALIF_TLS_DIR -u CHAIN_DIR -u PKI_OUT -u SECAGENT_PRIVATE_DIR "$@"; }

for s in failover-test.sh chain-test.sh; do
  # (a) racine absente : refus explicite, la racine n'est jamais creee
  MISSING="$TMP/absent-$s"
  out="$(clean_env SECAGENT_PRIVATE_DIR="$MISSING" bash "$Q/$s" paths 2>&1)"; rc=$?
  if [ $rc -ne 0 ]; then ok "(a) $s : racine absente => code != 0"; else ko "(a) $s : racine absente acceptee (rc=0)"; fi
  if printf '%s' "$out" | grep -q 'SECAGENT_PRIVATE_DIR'; then ok "(a) $s : message cite SECAGENT_PRIVATE_DIR"; else ko "(a) $s : message sans SECAGENT_PRIVATE_DIR"; fi
  if [ ! -e "$MISSING" ]; then ok "(a) $s : racine non creee"; else ko "(a) $s : racine creee par le script"; fi

  # (b) racine existante : defauts sous <PRIVATE>/QUALIF/ ; failover-test.sh : cert jetable ci-tls (jamais QUALIF/pki), pas de CHAIN_DIR
  if [ "$s" = failover-test.sh ]; then TLS_SUB=ci-tls; HAS_CHAIN=0; else TLS_SUB=pki; HAS_CHAIN=1; fi
  P="$TMP/private-$s"; mkdir -p "$P"
  out="$(clean_env SECAGENT_PRIVATE_DIR="$P" bash "$Q/$s" paths 2>&1)"; rc=$?
  [ $rc -eq 0 ] && ok "(b) $s : paths accepte une racine existante" || ko "(b) $s : paths refuse une racine existante (rc=$rc)"
  [ "$(val "$out" PRIVATE_DIR)" = "$P" ] && ok "(b) $s : PRIVATE_DIR" || ko "(b) $s : PRIVATE_DIR=$(val "$out" PRIVATE_DIR)"
  [ "$(val "$out" SECRETS_DIR)" = "$P/QUALIF/secrets" ] && ok "(b) $s : SECRETS_DIR" || ko "(b) $s : SECRETS_DIR=$(val "$out" SECRETS_DIR)"
  [ "$(val "$out" QUALIF_TLS_DIR)" = "$P/QUALIF/$TLS_SUB" ] && ok "(b) $s : QUALIF_TLS_DIR=QUALIF/$TLS_SUB" || ko "(b) $s : QUALIF_TLS_DIR=$(val "$out" QUALIF_TLS_DIR)"
  if [ $HAS_CHAIN = 1 ]; then
    # CHAIN_DIR volatil : ${TMPDIR:-/tmp}/secagent-qualif-chain-<uid>, hors PRIVATE/, non cree par `paths`
    TD="$TMP/tmpd"; mkdir -p "$TD"; UID_N="$(id -u)"
    out="$(clean_env SECAGENT_PRIVATE_DIR="$P" TMPDIR="$TD" bash "$Q/$s" paths 2>&1)"
    [ "$(val "$out" CHAIN_DIR)" = "$TD/secagent-qualif-chain-$UID_N" ] && ok "(b) $s : CHAIN_DIR=\$TMPDIR/secagent-qualif-chain-<uid>" || ko "(b) $s : CHAIN_DIR=$(val "$out" CHAIN_DIR)"
    [ ! -e "$TD/secagent-qualif-chain-$UID_N" ] && ok "(b) $s : CHAIN_DIR non cree par paths" || ko "(b) $s : paths a cree CHAIN_DIR"
    out="$(clean_env SECAGENT_PRIVATE_DIR="$P" TMPDIR="$TD/" bash "$Q/$s" paths 2>&1)"
    [ "$(val "$out" CHAIN_DIR)" = "$TD/secagent-qualif-chain-$UID_N" ] && ok "(b) $s : slash final de TMPDIR retire" || ko "(b) $s : TMPDIR avec slash : CHAIN_DIR=$(val "$out" CHAIN_DIR)"
    out="$(clean_env SECAGENT_PRIVATE_DIR="$P" bash "$Q/$s" paths 2>&1)"
    EXP_T="${TMPDIR:-/tmp}"; EXP_T="${EXP_T%/}"
    [ "$(val "$out" CHAIN_DIR)" = "$EXP_T/secagent-qualif-chain-$UID_N" ] && ok "(b) $s : defaut TMPDIR ou /tmp" || ko "(b) $s : defaut CHAIN_DIR=$(val "$out" CHAIN_DIR)"
    out="$(clean_env SECAGENT_PRIVATE_DIR="$P/absent" TMPDIR="$TD" bash "$Q/$s" paths 2>&1)"; rc=$?
    [ $rc -ne 0 ] && ok "(b) $s : racine PRIVATE absente refusee meme avec CHAIN_DIR sur /tmp" || ko "(b) $s : racine absente acceptee"
  else
    printf '%s\n' "$out" | grep -q '^CHAIN_DIR=' && ko "(b) $s : CHAIN_DIR imprime (hors contrat)" || ok "(b) $s : pas de CHAIN_DIR"
  fi

  # (c) variable explicite prioritaire, les autres gardent le defaut
  out="$(clean_env SECAGENT_PRIVATE_DIR="$P" SECRETS_DIR=/x bash "$Q/$s" paths 2>&1)"
  [ "$(val "$out" SECRETS_DIR)" = "/x" ] && ok "(c) $s : SECRETS_DIR explicite prime" || ko "(c) $s : SECRETS_DIR=$(val "$out" SECRETS_DIR)"
  [ "$(val "$out" QUALIF_TLS_DIR)" = "$P/QUALIF/$TLS_SUB" ] && ok "(c) $s : QUALIF_TLS_DIR garde son defaut" || ko "(c) $s : QUALIF_TLS_DIR=$(val "$out" QUALIF_TLS_DIR)"
  out="$(clean_env SECAGENT_PRIVATE_DIR="$P" QUALIF_TLS_DIR=/z bash "$Q/$s" paths 2>&1)"
  [ "$(val "$out" QUALIF_TLS_DIR)" = "/z" ] && ok "(c) $s : QUALIF_TLS_DIR explicite prime" || ko "(c) $s : QUALIF_TLS_DIR explicite ignore"
  if [ $HAS_CHAIN = 1 ]; then
    out="$(clean_env SECAGENT_PRIVATE_DIR="$P" CHAIN_DIR=/y bash "$Q/$s" paths 2>&1)"
    [ "$(val "$out" CHAIN_DIR)" = "/y" ] && ok "(c) $s : CHAIN_DIR explicite prime" || ko "(c) $s : CHAIN_DIR explicite ignore"
  fi
done

# (d) garde de pki/gen.sh : depot git temporaire, sortie NON ignoree => refus avant toute generation de cle
REPO="$TMP/repo"; mkdir -p "$REPO"
if git -C "$REPO" init -q 2>/dev/null; then
  out="$(bash "$Q/pki/gen.sh" "$REPO/out" 2>&1)"; rc=$?
  [ $rc -ne 0 ] && ok "(d) gen.sh refuse un chemin non ignore d'un depot git" || ko "(d) gen.sh a accepte un chemin non ignore"
  [ ! -e "$REPO/out/tls.key" ] && [ ! -e "$REPO/out/ca.key" ] && ok "(d) aucune cle ecrite" || ko "(d) cle ecrite dans un depot non ignore"
else
  ko "(d) git init impossible"
fi

# (f) SECAGENT_PRIVATE_DIR relatif => refus (meme avec SECRETS_DIR explicite absolu), message explicite
chk_rel() { # $1 nom, reste = commande ; env : SECAGENT_PRIVATE_DIR=relp
  local name="$1"; shift
  local out rc
  out="$(cd "$TMP" && "$@" 2>&1)"; rc=$?
  [ $rc -ne 0 ] && ok "(f) $name : chemin relatif => code != 0" || ko "(f) $name : chemin relatif accepte (rc=0)"
  printf '%s' "$out" | grep -q "n'est pas un chemin absolu" && ok "(f) $name : message 'n'est pas un chemin absolu'" || ko "(f) $name : message sans 'n'est pas un chemin absolu'"
  printf '%s' "$out" | grep -q 'SECAGENT_PRIVATE_DIR' && ok "(f) $name : message cite SECAGENT_PRIVATE_DIR" || ko "(f) $name : message sans SECAGENT_PRIVATE_DIR"
}
mkdir -p "$TMP/relp"
for s in failover-test.sh chain-test.sh; do
  chk_rel "$s" env -u SECRETS_DIR -u QUALIF_TLS_DIR -u CHAIN_DIR -u PKI_OUT SECAGENT_PRIVATE_DIR=relp bash "$Q/$s" paths
  chk_rel "$s + SECRETS_DIR absolu" env -u QUALIF_TLS_DIR -u CHAIN_DIR -u PKI_OUT SECAGENT_PRIVATE_DIR=relp SECRETS_DIR=/abs/secrets bash "$Q/$s" paths
done
chk_rel "pki/gen.sh" env -u PKI_OUT SECAGENT_PRIVATE_DIR=relp bash "$Q/pki/gen.sh"

# (g) garde de CHAIN_DIR (chain-test.sh paths) : refus fail-closed (rc != 0, ECHEC:, message stable), rien n'est corrige
Pg="$TMP/private-g"; mkdir -p "$Pg"
chk_chain() { # $1 nom, $2 sous-chaine attendue, $3 CHAIN_DIR
  local out rc
  out="$(clean_env SECAGENT_PRIVATE_DIR="$Pg" CHAIN_DIR="$3" bash "$Q/chain-test.sh" paths 2>&1)"; rc=$?
  [ $rc -ne 0 ] && ok "(g) $1 : code != 0" || ko "(g) $1 : accepte (rc=0)"
  printf '%s' "$out" | grep -qF -- "$2" && ok "(g) $1 : message '$2'" || ko "(g) $1 : message sans '$2'"
}
chk_chain "CHAIN_DIR relatif" "n'est pas un chemin absolu" "rel/chain"
chk_chain "CHAIN_DIR=/" "n'est pas un chemin absolu" "/"
ln -s "$TMP" "$TMP/lien-chain"
chk_chain "lien symbolique" "est un lien symbolique : refus" "$TMP/lien-chain"
: > "$TMP/fichier-chain"
chk_chain "fichier ordinaire" "existe et n'est pas un repertoire" "$TMP/fichier-chain"
if [ "$(stat -c %u /etc)" != "$(id -u)" ]; then
  chk_chain "autre proprietaire (/etc)" "appartient a l'uid" "/etc"
else
  echo "skip (g) autre proprietaire : /etc appartient a l'utilisateur courant"
fi
mkdir "$TMP/chain-755"; chmod 755 "$TMP/chain-755"
chk_chain "droits 0755" "plus larges que 0700" "$TMP/chain-755"
[ "$(stat -c %a "$TMP/chain-755")" = 755 ] && ok "(g) droits 0755 : pas de chmod correctif" || ko "(g) droits modifies par le script"
mkdir "$TMP/chain-700"; chmod 700 "$TMP/chain-700"
out="$(clean_env SECAGENT_PRIVATE_DIR="$Pg" CHAIN_DIR="$TMP/chain-700" bash "$Q/chain-test.sh" paths 2>&1)"; rc=$?
[ $rc -eq 0 ] && ok "(g) repertoire 0700 de l'utilisateur accepte" || ko "(g) 0700 refuse (rc=$rc)"

# (h) chain_dir_clean (down) : ne supprime QUE un repertoire 0700 a soi ; tout le reste est refuse sans rien supprimer
clean_run() { # $1 valeur de CHAIN_DIR (affectee apres `source`, donc meme vide) ; sortie 2>&1 ; rc dans $?
  clean_env bash -c 'source "$1"; CHAIN_DIR="$2"; chain_dir_clean' _ "$Q/chain-test.sh" "$1" 2>&1
}
chk_clean_refus() { # $1 nom, $2 sous-chaine, $3 valeur CHAIN_DIR, $4 chemin qui doit rester present (optionnel)
  local out rc
  out="$(clean_run "$3")"; rc=$?
  [ $rc -ne 0 ] && ok "(h) $1 : code != 0" || ko "(h) $1 : accepte (rc=0)"
  printf '%s' "$out" | grep -qF -- "$2" && ok "(h) $1 : message '$2'" || ko "(h) $1 : message sans '$2'"
  if [ -n "${4:-}" ]; then { [ -e "$4" ] || [ -L "$4" ]; } && ok "(h) $1 : rien supprime" || ko "(h) $1 : SUPPRIME ($4)"; fi
}
out="$(clean_run "$TMP/h-absent")"; rc=$?
{ [ $rc -eq 0 ] && [ ! -e "$TMP/h-absent" ]; } && ok "(h) CHAIN_DIR absent => rc 0, rien cree" || ko "(h) CHAIN_DIR absent (rc=$rc)"
mkdir "$TMP/h-ok"; chmod 700 "$TMP/h-ok"; : > "$TMP/h-ok/child.env"
out="$(clean_run "$TMP/h-ok")"; rc=$?
[ $rc -eq 0 ] && ok "(h) repertoire 0700 a soi : rc 0" || ko "(h) 0700 refuse (rc=$rc)"
[ ! -e "$TMP/h-ok" ] && ok "(h) repertoire 0700 supprime" || ko "(h) repertoire 0700 toujours present"
printf '%s' "$out" | grep -qF "jetons de la chaine supprimes ($TMP/h-ok)" && ok "(h) message de suppression" || ko "(h) message de suppression absent"
chk_clean_refus "CHAIN_DIR vide" "n'est pas un chemin absolu" ""
out="$(clean_run "/")"
printf '%s' "$out" | grep -qF "CHAIN_DIR='/'" && ok "(h) message de CHAIN_DIR=/ affiche la valeur fournie" || ko "(h) message de CHAIN_DIR=/ sans la valeur fournie"
chk_clean_refus "CHAIN_DIR=/" "n'est pas un chemin absolu" "/" "/"
mkdir "$TMP/h-rel"; chk_clean_refus "CHAIN_DIR relatif" "n'est pas un chemin absolu" "h-rel" "$TMP/h-rel"
mkdir "$TMP/h-cible"; : > "$TMP/h-cible/garde"; ln -s "$TMP/h-cible" "$TMP/h-lien"
chk_clean_refus "lien symbolique" "est un lien symbolique" "$TMP/h-lien" "$TMP/h-lien"
[ -e "$TMP/h-cible/garde" ] && ok "(h) lien symbolique : cible intacte" || ko "(h) lien symbolique : cible supprimee"
ln -s "$TMP/h-inexistant" "$TMP/h-lien-casse"
chk_clean_refus "lien symbolique casse" "est un lien symbolique" "$TMP/h-lien-casse" "$TMP/h-lien-casse"
: > "$TMP/h-fichier"; chk_clean_refus "fichier ordinaire" "n'est pas un repertoire" "$TMP/h-fichier" "$TMP/h-fichier"
mkdir "$TMP/h-755"; chmod 755 "$TMP/h-755"; chk_clean_refus "droits 0755" "plus larges que 0700" "$TMP/h-755" "$TMP/h-755"
if [ "$(stat -c %u /etc)" != "$(id -u)" ]; then chk_clean_refus "autre proprietaire (/etc)" "appartient a l'uid" "/etc" "/etc"
else echo "skip (h) autre proprietaire : /etc appartient a l'utilisateur courant"; fi

# (e) anciens defauts supprimes (hors README : la doc peut les citer pour la migration)
OLD='\$\{?HERE\}?/(secrets|pki/out|\.ci-tls|chain($|[^-A-Za-z0-9_.]))'
hits="$(grep -rIlE "$OLD" "$Q" --include='*.sh' --include='*.yml' --include='*.yaml' 2>/dev/null || true)"
if [ -z "$hits" ]; then ok "(e) aucun ancien defaut \$HERE/{secrets,pki/out,.ci-tls,chain}"; else ko "(e) anciens defauts presents dans : $(printf '%s' "$hits" | tr '\n' ' ')"; fi
exit $bad
