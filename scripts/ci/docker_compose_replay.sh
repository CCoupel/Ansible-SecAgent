#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
# SPDX-License-Identifier: AGPL-3.0-or-later

# Rejeu LOCAL, sans demon, des chemins Docker de chain-test.sh et failover-test.sh (ordre infra n°24, regression de la
# CI 43436496433 : « external volume "secagent-qualif_link" not found »). Pendant de podman_compose_replay.sh pour Docker.
#
#   DOCKER_COMPOSE=<binaire docker compose v2 (plugin ou autonome)> docker_compose_replay.sh
#
# Un FAUX `docker` a etat (volumes, conteneurs) execute les VRAIES fonctions des scripts. Pour `docker compose`, il fait
# rendre le projet par le VRAI docker compose (`config --format json`, aucun demon), puis applique la regle du moteur :
# avant `up`/`run`/`create`, chaque volume EXTERNE monte par les services demarres (dependances comprises, sauf --no-deps)
# doit exister, sinon le message exact de docker compose. `docker run -v <volume>` cree le volume comme le vrai docker.
# Rejoue : chain-test.sh ci-prepare + bootstrap + down (TLS en bind, CI « Chaine en conteneurs ») ; bootstrap en
# TLS_MODE=volume (push-tls : volumes tls et tls_ca, Compose remote-tls) ; failover-test.sh setup-ci + demarrage de la
# racine (CI « bascule »). Les commandes `secagent-server` (adm) recoivent des reponses factices au bon format.
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
DCB="${DOCKER_COMPOSE:-}"
if [ -z "$DCB" ]; then
  for c in "$HOME/.docker/cli-plugins/docker-compose" /usr/libexec/docker/cli-plugins/docker-compose \
           /usr/lib/docker/cli-plugins/docker-compose /usr/local/lib/docker/cli-plugins/docker-compose; do
    [ -x "$c" ] && { DCB="$c"; break; }
  done
fi
[ -n "$DCB" ] && [ -x "$DCB" ] || { echo "SKIP : docker compose introuvable (DOCKER_COMPOSE=<binaire>)"; exit 0; }
T="$(mktemp -d)"; trap 'chmod -R u+w "$T" 2>/dev/null; rm -rf "$T"' EXIT
mkdir -p "$T/bin" "$T/st"
Z64="$(printf '0%.0s' $(seq 64))"
export SECAGENT_IMAGE="ghcr.io/ccoupel/secagent-server:sha-0000000@sha256:$Z64"
export SECAGENT_MINION_IMAGE="ghcr.io/ccoupel/secagent-minion:sha-0000000@sha256:$Z64"

# --- faux docker ------------------------------------------------------------------------------------------------------
cat > "$T/bin/docker" <<'EOF'
#!/bin/bash
st="${FAKE_DOCKER_STATE:?}"; mkdir -p "$st/vol" "$st/ctr"
printf 'docker' >> "$st/calls.log"; printf ' %q' "$@" >> "$st/calls.log"; echo >> "$st/calls.log"
die() { echo "$*" >&2; exit 1; }
compose() {
  local glob=() sub="" rest=() a prof=()
  while [ $# -gt 0 ]; do
    if [ -z "$sub" ]; then
      case "$1" in -p|-f|--env-file) glob+=("$1" "$2"); shift 2; continue ;; --profile) glob+=("$1" "$2"); shift 2; continue ;;
                   -*) glob+=("$1") ;; *) sub="$1" ;; esac
    else rest+=("$1"); fi
    shift
  done
  case "$sub" in
    config) exec "$FAKE_DCB" "${glob[@]}" config "${rest[@]}" ;;
    up|run|create|start|restart)
      local json; json="$("$FAKE_DCB" "${glob[@]}" config --format json 2>"$st/cfg.err")" || { cat "$st/cfg.err" >&2; exit 1; }
      printf '%s' "$json" | python3 -c '
import json, os, sys
d = json.load(sys.stdin); sub = sys.argv[1]; args = sys.argv[2:]; st = os.environ["FAKE_DOCKER_STATE"]
svcs = d.get("services", {}); vols = d.get("volumes") or {}; proj = d.get("name", "")
opts_with_val = {"-e", "--env", "-v", "--volume", "-u", "--user", "-w", "--workdir", "--name", "--entrypoint", "-l", "--label", "-p", "--publish", "-t", "--timeout"}
nodeps = "--no-deps" in args; named = []; skip = False
for a in args:
    if skip: skip = False; continue
    if a in opts_with_val: skip = True; continue
    if a.startswith("-"): continue
    named.append(a)
    if sub == "run": break          # run : service puis commande
if not named:
    if sub in ("up", "create"): named = list(svcs)
for n in named:
    if n not in svcs: sys.exit(f"no such service: {n}")
todo, seen = list(named), []
while todo:
    n = todo.pop(0)
    if n in seen: continue
    seen.append(n)
    if not nodeps and sub in ("up", "run", "create"):
        todo += list((svcs[n].get("depends_on") or {}).keys())
if sub in ("up", "run", "create"):
    for n in seen:
        for v in svcs[n].get("volumes") or []:
            if v.get("type") != "volume" or not v.get("source"): continue
            decl = vols.get(v["source"]) or {}
            src = v["source"]; name = decl.get("name") or f"{proj}_{src}"
            path = os.path.join(st, "vol", name)
            if decl.get("external"):
                if not os.path.exists(path): sys.exit("external volume \"" + name + "\" not found")
            else:
                open(path, "a").close()
for n in seen:
    c = svcs[n].get("container_name") or f"{proj}-{n}-1"
    if sub == "run" and n == named[0]: continue
    open(os.path.join(st, "ctr", c), "a").close()
    print(f"  started {c}", file=sys.stderr)
' "$sub" "${rest[@]}" || exit 1
      exit 0 ;;
    down)
      [[ " ${rest[*]} " == *" -v "* ]] && for v in "$st"/vol/*; do case "$(basename "$v")" in *_link|*_link_grand|*_hooks|*_events-*|*_secrets|*_tls|*_tls_ca) ;; *) rm -f "$v" ;; esac; done
      rm -f "$st"/ctr/*; exit 0 ;;
    stop|rm|logs|ps|kill|exec|pull) exit 0 ;;
    *) die "fake docker compose : sous-commande $sub non emulee" ;;
  esac
}
case "${1:-}" in
  compose) shift; compose "$@" ;;
  version|--version) echo "Docker version 29.0.0"; exit 0 ;;
  volume)
    case "$2" in
      inspect) [ -e "$st/vol/${@: -1}" ] || { echo "Error: No such volume: ${@: -1}" >&2; exit 1; }; echo "[]"; exit 0 ;;
      create) touch "$st/vol/${@: -1}"; echo "${@: -1}"; exit 0 ;;
      rm) shift 2; for v in "$@"; do case "$v" in -*) ;; *) rm -f "$st/vol/$v" ;; esac; done; exit 0 ;;
      ls) ls "$st/vol"; exit 0 ;;
    esac ;;
  run)
    prev=""; for a in "$@"; do
      if [ "$prev" = -v ]; then v="${a%%:*}"; case "$v" in /*|.*) ;; *) touch "$st/vol/$v" ;; esac; fi   # docker run cree le volume nomme
      prev="$a"; done
    for a in "$@"; do [ "$a" = -i ] && { cat >/dev/null; break; }; done; exit 0 ;;   # stdin lu seulement avec -i
  inspect)
    for a in "$@"; do case "$a" in *Health.Status*) echo healthy; exit 0 ;; esac; done; echo "[]"; exit 0 ;;
  image) exit 0 ;;
  exec)
    shift; c=""; while [ $# -gt 0 ]; do case "$1" in -e|--env|-u|--user|-w) shift 2 ;; -*) shift ;; *) c="$1"; shift; break ;; esac; done
    case "$*" in
      *proc/net/tcp*) [ "$c" = secagent-qualif-a ] || [ "$c" = secagent-failover-a ] || [[ $c == *-a ]]; exit ;;
      *"ls /data"*) echo 1; exit 0 ;;
      *"keys link-pubkey"*) printf -- '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA\n-----END PUBLIC KEY-----\n'; echo "root_id=root-0001 kid=k1" >&2; exit 0 ;;
      *"--role relay-child"*) printf 'Token: eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJkbXoxIn0.c2ln\n  ID: link-0001\n'; exit 0 ;;
      *"--role enrollment"*) printf 'Token: secagent_enr_%064d\n' 1; exit 0 ;;
      *"--role plugin"*) printf 'Token: secagent_plg_%064d\n' 2; exit 0 ;;
      *) exit 0 ;;
    esac ;;
  ps|logs|rm|stop|start|kill|cp) exit 0 ;;
esac
echo "fake docker : $* non emule" >&2; exit 1
EOF
chmod +x "$T/bin/docker"

rc=0
run_case() { # $1 libelle, $2 dossier d'etat, puis la commande (bash -c)
  local name="$1" stdir="$T/st/$2"; shift 2; mkdir -p "$stdir"
  if env PATH="$T/bin:$PATH" FAKE_DOCKER_STATE="$stdir" FAKE_DCB="$DCB" CONTAINER_CLI=docker TMPDIR="$T" \
       SECAGENT_PULL_POLICY=missing bash -c "$@" > "$stdir/out.log" 2>&1 </dev/null; then
    echo "ok   $name"
  else
    echo "KO   $name :"; grep -vE '^  started ' "$stdir/out.log" | tail -8 | sed 's/^/     /'; rc=1
  fi
}
mk_private() { local p="$T/$1/PRIVATE"; mkdir -p "$p/QUALIF"; chmod 700 "$p" "$p/QUALIF"; printf '%s' "$p"; }

# 1. Chaine en conteneurs (CI) : TLS en bind, ci-prepare, bootstrap, down
P1="$(mk_private p1)"
run_case "Docker : chain-test.sh ci-prepare + bootstrap + down (TLS en bind)" c1 '
  set -euo pipefail
  export SECAGENT_PRIVATE_DIR='"$P1"' QUALIF_TLS_DIR='"$P1"'/QUALIF/pki
  source "'"$REPO"'/DEPLOYMENT/qualif/chain-test.sh"
  wait_for() { shift 2; "$@"; }; sleep() { :; }
  ci_prepare; bootstrap; chain_down'
# 2. TLS_MODE=volume (hote Docker distant) : push-tls (volumes tls + tls_ca), puis bootstrap
P2="$(mk_private p2)"
run_case "Docker : TLS_MODE=volume, push-tls (tls, tls_ca) + bootstrap" c2 '
  set -euo pipefail
  export SECAGENT_PRIVATE_DIR='"$P2"' QUALIF_TLS_DIR='"$P2"'/QUALIF/pki TLS_MODE=volume
  source "'"$REPO"'/DEPLOYMENT/qualif/chain-test.sh"
  wait_for() { shift 2; "$@"; }; sleep() { :; }
  ci_prepare; push_tls; bootstrap'
# 3. Bascule (CI) : failover-test.sh setup-ci puis demarrage de la racine (projet par defaut, Compose serveur)
P3="$(mk_private p3)"
run_case "Docker : failover-test.sh setup-ci + root_up (Compose serveur)" c3 '
  set -euo pipefail
  export SECAGENT_PRIVATE_DIR='"$P3"'
  source "'"$REPO"'/DEPLOYMENT/qualif/failover-test.sh"
  wait_for() { shift 2; "$@"; }; sleep() { :; }
  setup_ci; root_up'
# Temoin : la regle du faux moteur refuse bien un `up` qui demarre l'enfant avant la creation du volume `link`
P4="$(mk_private p4)"
if env PATH="$T/bin:$PATH" FAKE_DOCKER_STATE="$T/st/c4" FAKE_DCB="$DCB" CONTAINER_CLI=docker TMPDIR="$T" bash -c '
  set -euo pipefail; mkdir -p "$FAKE_DOCKER_STATE"
  export SECAGENT_PRIVATE_DIR='"$P4"' QUALIF_TLS_DIR='"$P4"'/QUALIF/pki
  source "'"$REPO"'/DEPLOYMENT/qualif/chain-test.sh"
  ci_prepare; push_hooks; push_events; push_secrets; dc up -d' > "$T/st/c4.log" 2>&1; then
  echo "KO   temoin : un up de tout le Compose avant le volume link n'est pas refuse"; rc=1
elif grep -q 'external volume "secagent-qualif_link" not found' "$T/st/c4.log"; then
  echo "ok   temoin : up de toute la chaine avant le volume link refuse (message de docker compose)"
else
  echo "KO   temoin : echec inattendu"; tail -5 "$T/st/c4.log" | sed 's/^/     /'; rc=1
fi
[ "$rc" = 0 ] && echo "ok   chemins Docker rejoues ($("$DCB" version --short 2>/dev/null || echo compose))"
exit "$rc"
