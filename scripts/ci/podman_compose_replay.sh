#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
# SPDX-License-Identifier: AGPL-3.0-or-later

# Rejeu LOCAL du chemin `chain-test.sh bootstrap` sous Podman (#267, LOT-4, T48) avec le VRAI podman-compose (1.5.0, celui
# des noeuds) et un FAUX `podman` a etat (volumes, reseaux, conteneurs par noeud) : chaque refus de podman-compose
# (fusion, volume externe absent, montage) apparait ici AVANT d'aller sur srv3/srv4. Aucun reseau, aucun noeud.
#
#   PODMAN_COMPOSE=<chemin de podman-compose 1.5.0> podman_compose_replay.sh
#
# Rejoue : prepare/stage des fichiers des noeuds (srv3, srv4 ; arborescence PRIVATE jetable), puis les VRAIES fonctions de
# chain-test.sh (CONTAINER_CLI=podman) avec `node_ssh` execute localement : push-hooks, push-events, push-secrets, state
# init de la racine (podman-compose run), root_up (faux systemctl qui joue l'ExecStart REEL de l'unite generee, avec son
# release.env), lien de dmz1, state init et demarrage de l'enfant, jetons, minions ; puis `down`. Les commandes
# `secagent-server` (adm) recoivent des reponses factices au bon format. Code 0 = chemin complet passe.
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
PC="${PODMAN_COMPOSE:-$(command -v podman-compose 2>/dev/null || true)}"
[ -n "$PC" ] && [ -x "$PC" ] || { echo "SKIP : podman-compose introuvable (PODMAN_COMPOSE=<chemin>)"; exit 0; }
T="$(mktemp -d)"; trap 'chmod -R u+w "$T" 2>/dev/null; rm -rf "$T"' EXIT
mkdir -p "$T/bin" "$T/A" "$T/B"
S="$T/share"; P="$S/PRIVATE"; Q="$P/QUALIF"
mkdir -p "$Q"/state/root "$Q"/state/child "$Q"/secrets "$Q"/pki "$Q"/pki-ca
chmod 700 "$P" "$Q" "$Q"/state "$Q"/state/root "$Q"/state/child "$Q"/secrets "$Q"/pki-ca; chmod 711 "$Q"/pki
for f in jwt_secret_key admin_token rsa_master_key; do printf '%064d' 0 > "$Q/secrets/$f"; chmod 400 "$Q/secrets/$f"; done
for f in ca.crt tls.crt; do : > "$Q/pki/$f"; chmod 644 "$Q/pki/$f"; done; : > "$Q/pki/tls.key"; chmod 600 "$Q/pki/tls.key"
Z64="$(printf '0%.0s' $(seq 64))"
SECAGENT_IMAGE="ghcr.io/ccoupel/secagent-server:sha-0000000@sha256:$Z64"
SECAGENT_MINION_IMAGE="ghcr.io/ccoupel/secagent-minion:sha-0000000@sha256:$Z64"
export SECAGENT_IMAGE SECAGENT_MINION_IMAGE
for n in srv3 srv4; do
  SECAGENT_PRIVATE_DIR="$P" bash "$REPO/DEPLOYMENT/podman/prepare-node-files.sh" qualif "$n" >/dev/null || { echo "KO prepare $n"; exit 1; }
  SECAGENT_PRIVATE_DIR="$P" bash "$REPO/DEPLOYMENT/podman/stage-node-files.sh" qualif "$n" >/dev/null || { echo "KO stage $n"; exit 1; }
done

# --- faux podman : etat par noeud (FAKE_PODMAN_STATE), journal des appels -------------------------------------------
cat > "$T/bin/podman" <<'EOF'
#!/bin/bash
st="${FAKE_PODMAN_STATE:?}"; mkdir -p "$st/vol" "$st/net" "$st/ctr"
printf 'podman' >> "$st/calls.log"; printf ' %q' "$@" >> "$st/calls.log"; echo >> "$st/calls.log"
die() { echo "Error: $*" >&2; exit 125; }
case "${1:-}" in
  --version|version) echo "podman version 5.7.0"; exit 0 ;;
  volume)
    case "$2" in
      inspect) v="${@: -1}"; [ -e "$st/vol/$v" ] || die "no such volume $v"
               case "$*" in *Options.device*) sed -n 's/.*device=\([^ ]*\).*/\1/p' "$st/vol/$v" ;; *) echo "[{\"Name\":\"$v\"}]" ;; esac; exit 0 ;;
      exists) [ -e "$st/vol/${@: -1}" ] ;;
      create) name="${@: -1}"; [ -e "$st/vol/$name" ] && die "volume $name already exists"; shift 2; echo "$*" > "$st/vol/$name"; echo "$name" ;;
      rm) shift 2; for v in "$@"; do case "$v" in -*) ;; *) rm -f "$st/vol/$v" ;; esac; done ;;
      ls) ls "$st/vol" ;;
    esac; exit 0 ;;
  network)
    case "$2" in exists) [ -e "$st/net/$3" ]; exit ;; create) touch "$st/net/${@: -1}" ;; esac; exit 0 ;;
  run|create)
    sub="$1"; shift; name=""; rmflag=0; prev=""
    for a in "$@"; do
      case "$prev" in --name) name="$a" ;; esac
      case "$a" in
        --rm) rmflag=1 ;;
        type=volume,*|*,type=volume,*) v="${a#*source=}"; v="${v%%,*}"; [ -e "$st/vol/$v" ] || die "volume $v absent (montage type=volume)" ;;
      esac
      if [ "$prev" = -v ] || [ "$prev" = --volume ]; then
        v="${a%%:*}"; case "$v" in /*|.*) ;; *) [ -e "$st/vol/$v" ] || die "volume $v absent (-v)" ;; esac
      fi
      prev="$a"
    done
    [ -t 0 ] || cat >/dev/null
    [ "$rmflag" = 1 ] || [ -z "$name" ] || touch "$st/ctr/$name"
    exit 0 ;;
  rm) shift; for c in "$@"; do case "$c" in -*) ;; *) rm -f "$st/ctr/$c" ;; esac; done; exit 0 ;;
  ps|pod|images) case "$*" in *json*) echo "[]" ;; esac; exit 0 ;;
  inspect)
    for a in "$@"; do case "$a" in *Health.Status*) echo healthy; exit 0 ;; esac; done; echo "[]"; exit 0 ;;
  exec)
    shift; c=""; while [ $# -gt 0 ]; do case "$1" in -e|--env|-u|--user|-w) shift 2 ;; -*) shift ;; *) c="$1"; shift; break ;; esac; done
    case "$*" in
      *proc/net/tcp*) [ "$c" = secagent-qualif-a ]; exit ;;            # a = maitre (ecoute), b = secondaire (silencieux)
      *"ls /data"*) echo 1; exit 0 ;;
      *"keys link-pubkey"*) printf -- '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA\n-----END PUBLIC KEY-----\n'; echo "root_id=root-0001 kid=k1" >&2; exit 0 ;;
      *"--role relay-child"*) printf 'Token: eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJkbXoxIn0.c2ln\n  ID: link-0001\n'; exit 0 ;;
      *"--role enrollment"*) printf 'Token: secagent_enr_%064d\n' 1; exit 0 ;;
      *"--role plugin"*) printf 'Token: secagent_plg_%064d\n' 2; exit 0 ;;
      *) exit 0 ;;
    esac ;;
  *) exit 0 ;;
esac
EOF
# --- faux systemctl --user : start/stop d'une unite = son ExecStart/ExecStop REELS (release.env, WorkingDirectory) ------
cat > "$T/bin/systemctl" <<'EOF'
#!/bin/bash
[ "$1" = --user ] && shift; act="$1"; unit="$2"
u="$(ls "$FAKE_SHARE"/PRIVATE/*/*/cyril/secagent/systemd/"$unit" 2>/dev/null | head -1)"
[ -n "$u" ] || { echo "Unit $unit not found." >&2; exit 5; }
wd="$(sed -n 's/^WorkingDirectory=//p' "$u")"; ef="$(sed -n 's/^EnvironmentFile=//p' "$u")"
case "$act" in start) key=ExecStart ;; stop) key=ExecStop ;; *) exit 0 ;; esac
cmd="$(sed -n "s/^$key=//p" "$u")"; cmd="${cmd/\/usr\/bin\/podman-compose/$PODMAN_COMPOSE}"
echo "systemctl $act $unit -> $cmd" >> "$FAKE_PODMAN_STATE/calls.log"
cd "$wd" && env -i PATH="$PATH" HOME="$HOME" FAKE_PODMAN_STATE="$FAKE_PODMAN_STATE" $(grep -v '^#' "$ef") bash -c "$cmd"
EOF
chmod +x "$T/bin/podman" "$T/bin/systemctl"
ln -s "$PC" "$T/bin/podman-compose"   # dc_on (chain-test.sh) l'appelle par son nom, comme sur le noeud

# --- rejeu des vraies fonctions de chain-test.sh ------------------------------------------------------------------------
export PATH="$T/bin:$PATH" FAKE_SHARE="$S" PODMAN_COMPOSE="$PC"
run_bootstrap() {
  env CONTAINER_CLI=podman PODMAN_SHARE_ROOT="$S" SECAGENT_PRIVATE_DIR="$P" CONTAINER_SSHKEY=/dev/null CONTAINER_KNOWN_HOSTS=/dev/null \
    SECAGENT_PULL_POLICY=missing TMPDIR="$T" T="$T" bash -c '
    set -euo pipefail
    source "$1"
    node_ssh() { local n="$1" in="$2"; shift 2; export FAKE_PODMAN_STATE="$T/$n"; if [ "$in" = stdin ]; then "$@"; else "$@" </dev/null; fi; }
    wait_for() { shift 2; "$@"; }   # pas d attente : le faux podman repond tout de suite
    sleep() { :; }
    bootstrap
    echo "== down (unites arretees, conteneurs retires, jamais -v)"
    chain_down
    echo "== second bootstrap apres down (idempotence : volume des secrets deja present)"
    bootstrap
    echo "REJEU COMPLET OK"
  ' _ "$REPO/DEPLOYMENT/qualif/chain-test.sh"
}
out="$T/replay.log"
if run_bootstrap > "$out" 2>&1; then rc=0; else rc=$?; fi
grep -E "^==|bootstrap OK|REJEU|WARNING|Error|RuntimeError|ValueError|ECHEC|REFUS" "$out" | sed 's/^/  /' | sort -u -k1,1 -s | head -0
grep -E "^==|bootstrap OK|REJEU|Error|RuntimeError|ValueError|ECHEC|REFUS|volume des secrets" "$out" | sed 's/^/  /' | tail -30
w="$(grep -c "WARNING:podman_compose" "$out")"; [ "$w" = 0 ] && echo "  aucun avertissement podman-compose" || { echo "  $w avertissement(s) podman-compose :"; grep "WARNING:podman_compose" "$out" | sort -u | sed 's/^/    /'; }
echo "--- appels podman (noeud A puis B), extrait :"
for n in A B; do grep -cE "^podman (run|create)" "$T/$n/calls.log" 2>/dev/null | sed "s/^/  noeud $n : conteneurs crees /"; grep -E "volume create|^systemctl" "$T/$n/calls.log" 2>/dev/null | sed "s/^/  $n /" | cut -c1-200; done
# --- PROD : demarrage de l'unite de srv1 (Compose serveur PROD + surcharge Podman), meme faux podman (noeud C) ---------
PP="$P/PROD"; mkdir -p "$PP"/state/root "$PP"/secrets "$PP"/pki; chmod 700 "$PP" "$PP"/state "$PP"/state/root "$PP"/secrets "$PP"/pki
for f in jwt_secret_key admin_token rsa_master_key; do printf '%064d' 0 > "$PP/secrets/$f"; chmod 400 "$PP/secrets/$f"; done
prod_ok=1
SECAGENT_PRIVATE_DIR="$P" bash "$REPO/DEPLOYMENT/podman/prepare-node-files.sh" prod srv1 >/dev/null \
  && SECAGENT_PRIVATE_DIR="$P" SECAGENT_VERSION=v3.0.6 bash "$REPO/DEPLOYMENT/podman/stage-node-files.sh" prod srv1 >/dev/null || prod_ok=0
mkdir -p "$T/C"; sed -i 's#PRIVATE/QUALIF/\*/#PRIVATE/*/*/#' "$T/bin/systemctl"
if [ "$prod_ok" = 1 ] && FAKE_PODMAN_STATE="$T/C" systemctl --user start secagent-prod-srv1.service > "$T/prod.log" 2>&1 </dev/null && ! grep -q "WARNING:podman_compose" "$T/prod.log"; then
  echo "ok   PROD : unite secagent-prod-srv1 (up -d secagent-server) acceptee par podman-compose"
else
  echo "KO   PROD : unite secagent-prod-srv1"; tail -15 "$T/prod.log"; rc=1
fi
if [ "$rc" = 0 ] && grep -q "REJEU COMPLET OK" "$out" && [ "$w" = 0 ]; then echo "ok   chemin bootstrap complet sous Podman ($(FAKE_PODMAN_STATE="$T/v" "$PC" --version 2>&1 | grep -o "podman-compose version [0-9.]*" | head -1))"; exit 0; fi
echo "KO   chemin bootstrap (rc=$rc), journal complet : $out"; tail -30 "$out"; trap - EXIT; exit 1
