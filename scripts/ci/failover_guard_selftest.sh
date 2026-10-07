#!/usr/bin/env bash
# Test des gardes de failover-test.sh en mode hote distant (faux `docker`, aucun demon) :
#  - distant sans TLS_MODE=volume => refus ; distant + volume => mode volume repris (chaine + surcharge + volume) ;
#  - SECAGENT_ENDPOINT_HOST non local => refus aussi ; local/CI => inchange ;
#  - guard_remote_binds : un bind mount vers un demon distant => refus, un volume => OK ; local => pas de verification.
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
exit $bad
