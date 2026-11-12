#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
# SPDX-License-Identifier: AGPL-3.0-or-later

# Test des gardes de failover-test.sh en mode hote distant (faux `docker`, aucun demon) :
#  - distant sans TLS_MODE=volume => refus ; distant + volume => mode volume repris (chaine + surcharge + volume) ;
#  - SECAGENT_ENDPOINT_HOST non local => refus aussi ; local/CI => inchange ;
#  - guard_remote_binds : un bind mount vers un demon distant => refus, un volume => OK ; local => pas de verification ;
#  - run (#256) : tls.crt/tls.key absents (mode bind) => `REFUS:` rc 2 AVANT toute commande docker, sans DIAGNOSTIC ; presents => garde passee.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
F="$HERE/../../DEPLOYMENT/qualif/failover-test.sh"
bad=0
t() { # $1 attendu (ok|ko), $2 nom, $3 script bash (apres `source`), env via variables avant l'appel
  local want="$1" name="$2" body="$3" rc
  bash -c "$body" >/dev/null 2>&1; rc=$?
  if { [ "$want" = ok ] && [ $rc -eq 0 ]; } || { [ "$want" = ko ] && [ $rc -ne 0 ]; }; then echo "ok   $name"; else echo "KO   $name (rc=$rc)"; bad=1; fi
}
BIND='[{"type":"bind","source":"/home/poste/tls","target":"/certs"}]'
VOL='[{"type":"volume","source":"secagent_tls","target":"/certs"}]'
fake() { # $1 JSON des volumes du service ; faux `docker compose config`
  echo "docker() { if [ \"\$2\" = config ] || [ \"\${@: -1}\" = json ]; then printf '{\"services\":{\"s\":{\"volumes\":$1}}}'; fi; }"
}
unset DOCKER_HOST TLS_MODE COMPOSE_FILE COMPOSE_OVERRIDES SECAGENT_TLS_VOLUME CONTROL_HOST SECAGENT_ENDPOINT_HOST
t ko "distant sans TLS_MODE=volume : refus" "export DOCKER_HOST=tcp://192.168.1.218:2375; source '$F'"
t ko "point d'acces non local sans TLS_MODE=volume : refus" "export SECAGENT_ENDPOINT_HOST=192.168.1.218; source '$F'"
t ko "distant + COMPOSE_FILE=server.yml : refus" "export DOCKER_HOST=tcp://x:2375 TLS_MODE=volume COMPOSE_FILE=/a/docker-compose.server.yml; source '$F'"
t ok "distant + volume : mode volume repris" "export DOCKER_HOST=tcp://x:2375 TLS_MODE=volume; source '$F'; case \"\$COMPOSE_FILE\" in */docker-compose.chain.yml) ;; *) exit 1;; esac; case \"\$COMPOSE_OVERRIDES\" in *docker-compose.remote-tls.yml) ;; *) exit 1;; esac; [ \"\$SECAGENT_TLS_VOLUME\" = secagent-qualif_tls ]"
t ok "local/CI inchange" "source '$F'; case \"\$COMPOSE_FILE\" in */docker-compose.server.yml) ;; *) exit 1;; esac; [ -z \"\${COMPOSE_OVERRIDES:-}\" ]"
t ok "local : guard_remote_binds ne verifie rien" "$(fake "$BIND"); source '$F'; guard_remote_binds"
t ko "distant : bind mount du poste refuse" "$(fake "$BIND"); export DOCKER_HOST=tcp://x:2375 TLS_MODE=volume; source '$F'; guard_remote_binds"
t ok "distant : volume nomme accepte" "$(fake "$VOL"); export DOCKER_HOST=tcp://x:2375 TLS_MODE=volume; source '$F'; guard_remote_binds"

# --- #256 : certificat verifie avant `run`, refus (REFUS:, rc 2) avant toute commande docker ---
TMPD="$(mktemp -d)"; trap 'rm -rf "$TMPD"' EXIT
mkdir -p "$TMPD/priv" "$TMPD/tls-vide" "$TMPD/tls-ok" "$TMPD/tls-partiel"
: > "$TMPD/tls-ok/tls.crt"; : > "$TMPD/tls-ok/tls.key"; : > "$TMPD/tls-ok/ca.crt"
: > "$TMPD/tls-partiel/tls.crt"          # tls.key manquant
run_guard() { # $1 repertoire TLS ; sortie dans $out, code dans $rc, appels docker traces dans $TMPD/docker.log
  : > "$TMPD/docker.log"
  set +e
  out="$(env -u TLS_MODE -u DOCKER_HOST -u SECAGENT_ENDPOINT_HOST -u CONTROL_HOST SECAGENT_PRIVATE_DIR="$TMPD/priv" QUALIF_TLS_DIR="$1" bash -c '
    source "'"$F"'"
    docker() { echo "docker $*" >> "'"$TMPD"'/docker.log"; return 1; }   # faux docker : tout appel est trace
    run stop
  ' 2>&1)"; rc=$?
  set -e
}
chk() { # $1 nom, $2 "0" si la condition est tenue
  if [ "$2" = 0 ]; then echo "ok   $1"; else echo "KO   $1"; bad=1; fi
}
set -e
run_guard "$TMPD/tls-vide"
chk "run : cert absent => rc 2" "$([ "$rc" -eq 2 ]; echo $?)"
chk "run : cert absent => prefixe REFUS:" "$(printf '%s' "$out" | grep -q 'REFUS:'; echo $?)"
chk "run : cert absent => aucune commande docker" "$([ ! -s "$TMPD/docker.log" ]; echo $?)"
chk "run : cert absent => pas de DIAGNOSTIC" "$(if printf '%s' "$out" | grep -q 'DIAGNOSTIC'; then echo 1; else echo 0; fi)"
chk "run : cert absent => message cite tls.crt" "$(printf '%s' "$out" | grep -q 'tls.crt'; echo $?)"
run_guard "$TMPD/tls-partiel"
chk "run : tls.key seul absent => rc 2, REFUS:, sans docker" "$([ "$rc" -eq 2 ] && printf '%s' "$out" | grep -q 'REFUS:' && [ ! -s "$TMPD/docker.log" ]; echo $?)"
chk "run : tls.key seul absent => message cite tls.key" "$(printf '%s' "$out" | grep -q 'tls.key'; echo $?)"
run_guard "$TMPD/tls-ok"
chk "run : cert present => la garde ne refuse pas (REFUS: absent)" "$(if printf '%s' "$out" | grep -q 'REFUS:'; then echo 1; else echo 0; fi)"
chk "run : ca.crt non exige (setup_ci ne le produit pas)" "$(if printf '%s' "$out" | grep -q 'ca.crt'; then echo 1; else echo 0; fi)"

# --- v3.0.6 : FAILOVER_UP_SERVICES restreint le `up -d` de run (l'enfant arrete par converged-timeout reste arrete) ---
up_call() { # $1 valeur de FAILOVER_UP_SERVICES (vide = non definie) ; sortie : la ligne `docker compose ... up -d ...` tracee
  : > "$TMPD/docker.log"
  env -u TLS_MODE -u DOCKER_HOST -u SECAGENT_ENDPOINT_HOST -u CONTROL_HOST ${1:+FAILOVER_UP_SERVICES="$1"} SECAGENT_PRIVATE_DIR="$TMPD/priv" QUALIF_TLS_DIR="$TMPD/tls-ok" bash -c '
    source "'"$F"'"
    docker() { echo "docker $*" >> "'"$TMPD"'/docker.log"; return 1; }
    run stop' >/dev/null 2>&1
  grep -m1 ' up -d' "$TMPD/docker.log"
}
chk "run : FAILOVER_UP_SERVICES => up -d de ces services seulement" "$(up_call 'secagent-server-a secagent-server-b' | grep -q ' up -d secagent-server-a secagent-server-b$'; echo $?)"
chk "run : sans FAILOVER_UP_SERVICES => up -d de tout le Compose" "$(up_call '' | grep -q ' up -d$'; echo $?)"

# --- v3.0.6 : comptages sous `set -euo pipefail` (upstream-queue sortait en rc 1 SANS message, QUALIF 2026-11-12) ---
pf() { # $1 script apres `source` execute sous set -euo pipefail ; sortie = stdout ; code = celui du script
  env -u TLS_MODE -u DOCKER_HOST -u SECAGENT_ENDPOINT_HOST -u CONTROL_HOST SECAGENT_PRIVATE_DIR="$TMPD/priv" bash -c '
    set -euo pipefail; source "'"$F"'"; set -euo pipefail
    '"$1" 2>/dev/null
}
chk "pipefail : count_matches sans correspondance => 0, sans abandon" "$([ "$(pf 'x="$(printf "a\nb\n" | count_matches "upstream_dropped")"; echo "n=$x"')" = n=0 ]; echo $?)"
chk "pipefail : count_matches compte les occurrences (2 sur une ligne)" "$([ "$(pf 'printf "{\"action_type\": \"upstream_dropped\"},{\"action_type\":\"upstream_dropped\"}\n" | count_matches "\"action_type\": *\"upstream_dropped\""')" = 2 ]; echo $?)"
chk "pipefail : count_lines sans correspondance => 0, sans abandon" "$([ "$(pf 'x="$(count_lines SUCCESS < /dev/null)"; echo "n=$x"')" = n=0 ]; echo $?)"
chk "pipefail : extract sans correspondance => vide, sans abandon" "$([ "$(pf 'x="$(printf "rien\n" | extract "secagent_enr_[0-9a-f]{64}")"; echo "t=[$x]"')" = 't=[]' ]; echo $?)"
chk "pipefail : extract => derniere occurrence" "$([ "$(pf 'printf "eyJa.b.c\neyJd.e.f\n" | extract "eyJ[a-z]+\.[a-z]+\.[a-z]+"')" = eyJd.e.f ]; echo $?)"
chk "pipefail : extract vide | { read || true ; fail } => le message de refus est emis" "$(pf 'printf "" | extract zz | { read -r t || true; [ -n "$t" ] || echo REFUS-EMIS; }' | grep -q REFUS-EMIS; echo $?)"
chk "pipefail : temoin, l'ancien motif grep|wc -l abandonne sans message" "$(if pf 'x="$(printf "a\n" | grep -Eo zz | wc -l)"; echo atteint' | grep -q atteint; then echo 1; else echo 0; fi)"

# --- v3.0.6 : lecture du journal des hooks (events_log via faux `docker exec`), compteurs, surcharge des hooks ---
LOG="$TMPD/events.log"
cat > "$LOG" <<'EOF'
2026-11-11T10:00:00Z FAILOVER secagent-server start instance=i-a previous={{previous_instance_id}}
2026-11-11T10:00:02Z RELAY_UP dmz1 conn_seq=1 mode=pull hosts_routed=1
2026-11-11T10:00:03Z UP   minion-root
2026-11-11T10:05:00Z FAILOVER secagent-server takeover instance=i-b previous=i-a
2026-11-11T10:05:05Z RELAY_RECONNECT dmz1 conn_seq=2 mode=pull hosts_routed=1
2026-11-11T10:05:06Z RECONNECT minion-root
2026-11-11T10:06:00Z RELAY_DOWN dmz1 peer_closed:1001 hosts_routed=1
2026-11-11T10:06:30Z CONVERGED secagent-server relays_connected=0 relays_missing=1 hosts_direct=1 hosts_routed=0 dropped=0
2026-11-11T10:07:00Z CONVERGED secagent-server relays_connected=1 relays_missing=0 hosts_direct=1 hosts_routed=2 dropped=0
2026-11-11T10:08:00Z REROUTED minion-child direct old=dmz1 new=secagent-server old_chain=dmz1 new_chain=secagent-server
2026-11-11T10:09:00Z RELAY_REROUTED dmz2 old_chain=dmz1,dmz2 new_chain=dmz2 hosts_routed=1
EOF
ev() { # $1 script apres `source` (faux docker : `exec <c> cat ...` lit $LOG)
  env -u TLS_MODE -u DOCKER_HOST -u SECAGENT_ENDPOINT_HOST -u CONTROL_HOST SECAGENT_PRIVATE_DIR="$TMPD/priv" bash -c '
    source "'"$F"'"
    docker() { [ "$1" = exec ] && cat "'"$LOG"'"; }
    '"$1" 2>/dev/null
}
chk "hooks : hook_seen FAILOVER cause takeover" "$(ev 'hook_seen c secagent-server FAILOVER takeover' >/dev/null; echo $?)"
chk "hooks : hook_seen FAILOVER cause inconnue refuse" "$(if ev 'hook_seen c secagent-server FAILOVER autre' >/dev/null; then echo 1; else echo 0; fi)"
chk "hooks : hook_count FAILOVER = 2" "$([ "$(ev 'hook_count c secagent-server FAILOVER')" = 2 ]; echo $?)"
chk "hooks : hook_seen RELAY_DOWN raison peer_closed:1001" "$(ev 'hook_seen c dmz1 RELAY_DOWN peer_closed:1001' >/dev/null; echo $?)"
chk "hooks : RELAY_UP dmz1 ne compte pas RELAY_RECONNECT" "$([ "$(ev 'hook_count c dmz1 RELAY_UP')" = 1 ]; echo $?)"
chk "hooks : hook_more (1 > 0) vrai, (1 > 1) faux" "$(ev 'hook_more c minion-root RECONNECT 0 && ! hook_more c minion-root RECONNECT 1' >/dev/null; echo $?)"
chk "hooks : sujet exact (minion-root != minion-root2)" "$([ "$(ev 'hook_count c minion-root2 UP')" = 0 ]; echo $?)"
chk "hooks : journal absent => compte 0, rien vu" "$(env -u TLS_MODE -u DOCKER_HOST SECAGENT_PRIVATE_DIR="$TMPD/priv" bash -c 'source "'"$F"'"; docker() { return 1; }; [ "$(hook_count c dmz1 RELAY_UP)" = 0 ] && ! hook_seen c dmz1 RELAY_UP' 2>/dev/null; echo $?)"
chk "hooks : kind_count REROUTED (tous sujets) = 1, RELAY_REROUTED = 1" "$([ "$(ev 'kind_count c REROUTED')" = 1 ] && [ "$(ev 'kind_count c RELAY_REROUTED')" = 1 ]; echo $?)"
chk "hooks : kind_more REROUTED (1 > 0) vrai, (1 > 1) faux" "$(ev 'kind_more c REROUTED 0 && ! kind_more c REROUTED 1' >/dev/null; echo $?)"
chk "hooks : hook_last_kv lit la DERNIERE ligne CONVERGED (relays_connected=1)" "$([ "$(ev 'hook_last_kv c secagent-server CONVERGED relays_connected')" = 1 ]; echo $?)"
chk "hooks : hook_last_kv : cle exacte (hosts_routed != hosts_direct), chaine avec virgule" "$([ "$(ev 'hook_last_kv c secagent-server CONVERGED hosts_routed')" = 2 ] && [ "$(ev 'hook_last_kv c dmz2 RELAY_REROUTED old_chain')" = dmz1,dmz2 ]; echo $?)"
chk "hooks : hook_last_kv : cle absente => vide" "$([ -z "$(ev 'hook_last_kv c secagent-server CONVERGED absente')" ]; echo $?)"
chk "hooks : hook_last = derniere ligne du sujet/genre" "$(ev 'hook_last c minion-child REROUTED' | grep -q ' direct old=dmz1 '; echo $?)"
chk "hooks : hooks_enabled si COMPOSE_OVERRIDES contient docker-compose.hooks.yml" "$(ev 'COMPOSE_OVERRIDES="/x/docker-compose.remote-tls.yml /x/docker-compose.hooks.yml"; hooks_enabled' >/dev/null; echo $?)"
chk "hooks : hooks_enabled faux sans la surcharge" "$(if ev 'COMPOSE_OVERRIDES=/x/docker-compose.remote-tls.yml; hooks_enabled' >/dev/null; then echo 1; else echo 0; fi)"
set +e
exit $bad
