#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
# SPDX-License-Identifier: AGPL-3.0-or-later

# Auto-test des chemins prives de la qualif (#250), sans docker ni reseau :
#  (a) SECAGENT_PRIVATE_DIR inexistant => `paths` refuse (code != 0, message citant SECAGENT_PRIVATE_DIR), rien n'est cree ;
#  (b) PRIVATE existant => PRIVATE_DIR, SECRETS_DIR, QUALIF_TLS_DIR (failover : qualif/ci-tls ; chain : qualif/pki), CHAIN_DIR (chain seul) ;
#  (c) une variable explicite (SECRETS_DIR=/x) prime sur le defaut ;
#  (d) pki/gen.sh refuse d'ecrire des cles dans un depot git ou le chemin n'est pas ignore ;
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

  # (b) racine existante : defauts sous <PRIVATE>/qualif/ ; failover-test.sh : cert jetable ci-tls (jamais qualif/pki), pas de CHAIN_DIR
  if [ "$s" = failover-test.sh ]; then TLS_SUB=ci-tls; HAS_CHAIN=0; else TLS_SUB=pki; HAS_CHAIN=1; fi
  P="$TMP/private-$s"; mkdir -p "$P"
  out="$(clean_env SECAGENT_PRIVATE_DIR="$P" bash "$Q/$s" paths 2>&1)"; rc=$?
  [ $rc -eq 0 ] && ok "(b) $s : paths accepte une racine existante" || ko "(b) $s : paths refuse une racine existante (rc=$rc)"
  [ "$(val "$out" PRIVATE_DIR)" = "$P" ] && ok "(b) $s : PRIVATE_DIR" || ko "(b) $s : PRIVATE_DIR=$(val "$out" PRIVATE_DIR)"
  [ "$(val "$out" SECRETS_DIR)" = "$P/qualif/secrets" ] && ok "(b) $s : SECRETS_DIR" || ko "(b) $s : SECRETS_DIR=$(val "$out" SECRETS_DIR)"
  [ "$(val "$out" QUALIF_TLS_DIR)" = "$P/qualif/$TLS_SUB" ] && ok "(b) $s : QUALIF_TLS_DIR=qualif/$TLS_SUB" || ko "(b) $s : QUALIF_TLS_DIR=$(val "$out" QUALIF_TLS_DIR)"
  if [ $HAS_CHAIN = 1 ]; then
    [ "$(val "$out" CHAIN_DIR)" = "$P/qualif/chain" ] && ok "(b) $s : CHAIN_DIR" || ko "(b) $s : CHAIN_DIR=$(val "$out" CHAIN_DIR)"
  else
    printf '%s\n' "$out" | grep -q '^CHAIN_DIR=' && ko "(b) $s : CHAIN_DIR imprime (hors contrat)" || ok "(b) $s : pas de CHAIN_DIR"
  fi

  # (c) variable explicite prioritaire, les autres gardent le defaut
  out="$(clean_env SECAGENT_PRIVATE_DIR="$P" SECRETS_DIR=/x bash "$Q/$s" paths 2>&1)"
  [ "$(val "$out" SECRETS_DIR)" = "/x" ] && ok "(c) $s : SECRETS_DIR explicite prime" || ko "(c) $s : SECRETS_DIR=$(val "$out" SECRETS_DIR)"
  [ "$(val "$out" QUALIF_TLS_DIR)" = "$P/qualif/$TLS_SUB" ] && ok "(c) $s : QUALIF_TLS_DIR garde son defaut" || ko "(c) $s : QUALIF_TLS_DIR=$(val "$out" QUALIF_TLS_DIR)"
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

# (e) anciens defauts supprimes (hors README : la doc peut les citer pour la migration)
OLD='\$\{?HERE\}?/(secrets|pki/out|\.ci-tls|chain($|[^-A-Za-z0-9_.]))'
hits="$(grep -rIlE "$OLD" "$Q" --include='*.sh' --include='*.yml' --include='*.yaml' 2>/dev/null || true)"
if [ -z "$hits" ]; then ok "(e) aucun ancien defaut \$HERE/{secrets,pki/out,.ci-tls,chain}"; else ko "(e) anciens defauts presents dans : $(printf '%s' "$hits" | tr '\n' ' ')"; fi
exit $bad
