# shellcheck shell=bash
# SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
# SPDX-License-Identifier: AGPL-3.0-or-later

# Etape `chain-test.sh admission-503` (#241) : exerce EN REEL le refus 503 memory_budget_exhausted de #179.
# Fichier SOURCE par chain-test.sh (jamais execute seul) : il reutilise ses fonctions et variables (DC, adm, master,
# connected, wait_for, fail, control_env, need, write_secret, CHAIN_DIR, ENDPOINT_HOST, QUALIF_TLS_DIR, C_CHILD...).
#
# Principe : le plafond par defaut (1 Gio => 204 taches) est inatteignable avec 2 minions. On abaisse
# MAX_STDOUT_BUFFER_TOTAL des deux noeuds racine (surcharge Compose ecrite dans ./chain/, rien dans le depot) :
# chaque tache admise RESERVE 5 Mio (stdoutMaxBytes) => 52428800 (50 Mio) = 10 taches simultanees, en dessous des
# 2 x 10 de MAX_TASKS_PER_AGENT : le refus est donc bien un 503 memoire, jamais un 429 agent_busy.
# Les taches relayees (minion-child) sont comptees aussi sur la racine, a chaque saut.
#
# Attentes (l'etape echoue clairement, avec la valeur observee, des qu'une n'est pas tenue) :
#   1. 10 `exec sleep` admis (5 vers minion-root, 5 vers minion-child) : tous encore en vol, aucun refuse ;
#   2. l'exec suivant (sonde, vers minion-root puis minion-child) : HTTP 503, {"error":"memory_budget_exhausted"},
#      Retry-After entier >= 1 ; la sonde ne figure PAS dans les journaux du minion (elle porte un stdin : une tache
#      admise y laisserait « Task <id>: stdin provided ») alors que les taches admises y figurent (temoin) ;
#   3. `[SECURITY WARNING] task refused at admission: reason=memory_budget_exhausted` dans le journal du maitre ;
#   4. liberation : apres la fin des taches, un exec est admis et 10 taches simultanees le sont a nouveau
#      (un compteur qui fuit refuserait avant) ;
#   5. plugin Ansible reel, 12 forks (6 + 6 alias de minion-root / minion-child) : au moins un hote UNREACHABLE avec
#      « memory_budget_exhausted » et « Retry-After » (AnsibleConnectionFailure explicite, pas de rejeu) ;
#   6. retour au defaut (surcharge retiree, noeuds recrees) : variable absente, 11 taches simultanees admises, smoke.
# Variables : ADM503_BUDGET (defaut 52428800), ADM503_HOLD (duree des `sleep`, defaut 45 s).
# Aucun jeton n'est affiche : l'en-tete d'autorisation est lu par curl dans un fichier 0600 de ./chain/.

ADM503_BUDGET="${ADM503_BUDGET:-52428800}"
ADM503_HOLD="${ADM503_HOLD:-45}"
ADM503_TASK_BYTES=5242880            # stdoutMaxBytes du serveur (ws/admission.go)
ADM503_PIDS=()                       # PID des exec de fond lances par cette etape (kills par PID, jamais par nom)
ADM503_OVERRIDE=""
ADM503_DIR=""

adm503_kill_tree() { # $1 PID : tue ses descendants (le `curl` est petit-fils du sous-shell) puis lui-meme ; par PID parent, jamais par nom
  local c
  for c in $(pgrep -P "$1" 2>/dev/null || true); do adm503_kill_tree "$c"; done
  kill "$1" 2>/dev/null || true
}

adm503_cleanup() { # sortie de l'etape (succes ou echec) : plus de tache en fond (curl compris), plafond par defaut restaure
  local p
  for p in "${ADM503_PIDS[@]:-}"; do if [ -n "$p" ]; then adm503_kill_tree "$p"; fi; done
  ADM503_PIDS=()
  if [ -n "$ADM503_OVERRIDE" ] && [ -f "$ADM503_OVERRIDE" ]; then
    echo "== nettoyage : plafond memoire par defaut restaure" >&2
    "${DC[@]}" up -d --no-deps --force-recreate secagent-server-a secagent-server-b >/dev/null 2>&1 || true
    rm -f "$ADM503_OVERRIDE"
  fi
}

adm503_uuid() { cat /proc/sys/kernel/random/uuid 2>/dev/null || python3 -c 'import uuid;print(uuid.uuid4())'; }

adm503_base() { # URL de l'API du maitre courant (a : 7770, b : 8770, voir docker-compose.server.yml)
  local m; m="$(master)" || fail "pas de maitre sur la racine"
  if [ "$m" = "$C_A" ]; then echo "https://${ENDPOINT_HOST}:7770"; else echo "https://${ENDPOINT_HOST}:8770"; fi
}

# $1 hote cible, $2 task_id, $3 commande, $4 delai max (s), $5 prefixe des fichiers de sortie (.hdr .body) ; affiche
# le code HTTP (000 si curl echoue). Le jeton plugin reste dans un fichier 0600 (curl -H @fichier).
adm503_exec() {
  local body code
  body="$(printf '{"task_id":"%s","cmd":"%s","stdin":"eA==","timeout":%s,"become":false}' "$2" "$3" "$4")"
  code="$(curl -sS --cacert "$QUALIF_TLS_DIR/ca.crt" -H "@$CHAIN_DIR/plugin.header" -H 'Content-Type: application/json' \
    -X POST --max-time "$(( $4 + 15 ))" -D "$5.hdr" -o "$5.body" -w '%{http_code}' -d "$body" \
    "$(adm503_base)/api/exec/$1" 2>/dev/null)" || code=000
  echo "$code"
}

# $1 prefixe, $2 duree du sleep, puis les hotes cibles (un exec de fond par hote cite) : ecrit
# $ADM503_DIR/$1-<n>.{host,id,code} ; les PID sont ajoutes a ADM503_PIDS (listes de ce lot dans ADM503_LOT).
adm503_fill() {
  local prefix="$1" hold="$2" n=0 h id; shift 2
  ADM503_LOT=()
  for h in "$@"; do
    n=$((n + 1)); id="$(adm503_uuid)"
    printf '%s' "$h" > "$ADM503_DIR/$prefix-$n.host"; printf '%s' "$id" > "$ADM503_DIR/$prefix-$n.id"
    rm -f "$ADM503_DIR/$prefix-$n.code"
    ( code="$(adm503_exec "$h" "$id" "sleep $hold" "$(( hold + 30 ))" "$ADM503_DIR/$prefix-$n")" || code=000
      printf '%s' "$code" > "$ADM503_DIR/$prefix-$n.code" ) &
    ADM503_PIDS+=("$!"); ADM503_LOT+=("$!")
  done
}

adm503_lot_alive() { local p; for p in "${ADM503_LOT[@]}"; do kill -0 "$p" 2>/dev/null || return 1; done; }
adm503_lot_wait() { # attend le lot, puis retire ses PID de ADM503_PIDS (deja attendus : un PID recycle ne doit pas etre vise par le nettoyage)
  local p q keep=()
  for p in "${ADM503_LOT[@]}"; do wait "$p" 2>/dev/null || true; done
  for q in "${ADM503_PIDS[@]:-}"; do
    [ -n "$q" ] || continue
    for p in "${ADM503_LOT[@]}"; do [ "$q" = "$p" ] && continue 2; done
    keep+=("$q")
  done
  ADM503_PIDS=()
  if [ "${#keep[@]}" -gt 0 ]; then ADM503_PIDS=("${keep[@]}"); fi
}

# $1 prefixe, $2 nombre attendu : tous les exec du lot ont recu 200 avec rc 0.
adm503_lot_all_ok() {
  local prefix="$1" want="$2" n code
  for n in $(seq 1 "$want"); do
    code="$(cat "$ADM503_DIR/$prefix-$n.code" 2>/dev/null || echo manquant)"
    [ "$code" = 200 ] || fail "admission-503 : exec $prefix-$n vers $(cat "$ADM503_DIR/$prefix-$n.host") : HTTP $code (attendu 200, corps : $(head -c 200 "$ADM503_DIR/$prefix-$n.body" 2>/dev/null))"
    grep -Eq '"rc"[[:space:]]*:[[:space:]]*0' "$ADM503_DIR/$prefix-$n.body" || fail "admission-503 : exec $prefix-$n sans rc 0 : $(head -c 200 "$ADM503_DIR/$prefix-$n.body")"
  done
}

adm503_minion_logs() { "${DC[@]}" logs --no-color "$1" 2>&1; }  # $1 service minion-root | minion-child

# Surcharge Compose temporaire (./chain/, non versionnee) : MAX_STDOUT_BUFFER_TOTAL sur les deux noeuds racine.
adm503_write_override() {
  ADM503_OVERRIDE="$CHAIN_DIR/docker-compose.admission-503.yml"
  cat > "$ADM503_OVERRIDE" <<EOF
services:
  secagent-server-a:
    environment:
      MAX_STDOUT_BUFFER_TOTAL: "$ADM503_BUDGET"
  secagent-server-b:
    environment:
      MAX_STDOUT_BUFFER_TOTAL: "$ADM503_BUDGET"
EOF
}

# Recree les deux noeuds racine (avec la surcharge si $1 = with) et attend maitre + minions + enfant reconnectes.
adm503_recreate_root() {
  if [ "$1" = with ]; then
    "${DC[@]}" -f "$ADM503_OVERRIDE" up -d --no-deps --force-recreate secagent-server-a secagent-server-b
  else
    "${DC[@]}" up -d --no-deps --force-recreate secagent-server-a secagent-server-b
  fi
  wait_for "racine healthy" 120 bash -c "[ \"\$(docker inspect -f '{{.State.Health.Status}}' $C_A)\" = healthy ] && [ \"\$(docker inspect -f '{{.State.Health.Status}}' $C_B)\" = healthy ]" >/dev/null
  sleep 3
  local m; m="$(master)" || fail "pas de maitre sur la racine apres recreation"
  connected "$m" relays dmz1 4
  connected "$m" minions minion-root 2
  connected "$C_CHILD" minions minion-child 2
}

adm503_env_of() { docker exec "$1" printenv MAX_STDOUT_BUFFER_TOTAL 2>/dev/null || true; }  # $1 conteneur : valeur ou vide

admission_503() {
  verify_images; need INVENTORY_BIN
  local slots=$(( ADM503_BUDGET / ADM503_TASK_BYTES )) m n code probe
  [ "$slots" -ge 2 ] || fail "ADM503_BUDGET=$ADM503_BUDGET trop bas (moins de 2 taches)"
  [ "$slots" -le 20 ] || fail "ADM503_BUDGET=$ADM503_BUDGET : $slots taches > 2 x MAX_TASKS_PER_AGENT, le refus serait un 429 et non un 503"
  ADM503_DIR="$CHAIN_DIR/admission-503"; rm -rf "$ADM503_DIR"; mkdir -p "$ADM503_DIR"; chmod 700 "$ADM503_DIR"
  trap adm503_cleanup EXIT
  # 0. jeton plugin frais -> en-tete d'autorisation en fichier 0600 (jamais affiche)
  plugin_token
  printf 'Authorization: Bearer %s\n' "$(cat "$CHAIN_DIR/plugin.token")" | write_secret plugin.header
  echo "== 1. plafond abaisse : MAX_STDOUT_BUFFER_TOTAL=$ADM503_BUDGET => $slots taches simultanees"
  adm503_write_override
  adm503_recreate_root with
  for n in "$C_A" "$C_B"; do
    [ "$(adm503_env_of "$n")" = "$ADM503_BUDGET" ] || fail "admission-503 : $n n'a pas MAX_STDOUT_BUFFER_TOTAL=$ADM503_BUDGET (valeur : '$(adm503_env_of "$n")')"
  done
  m="$(master)"

  echo "== 2. $slots exec sleep ${ADM503_HOLD}s en vol (moities vers minion-root et minion-child)"
  local hosts=() half=$(( slots / 2 ))
  for n in $(seq 1 "$half"); do hosts+=(minion-child); done
  for n in $(seq 1 $(( slots - half ))); do hosts+=(minion-root); done
  local refused_before; refused_before="$(docker logs "$m" 2>&1 | grep -c 'task refused at admission: reason=memory_budget_exhausted' || true)"
  adm503_fill fill "$ADM503_HOLD" "${hosts[@]}"
  # sonde : exec court, repete jusqu'au refus (les premieres sondes peuvent preceder l'admission des $slots taches)
  local t0 probe_host
  for probe_host in minion-root minion-child; do
    t0=$(date +%s); code=""
    while :; do
      probe="$(adm503_uuid)"
      code="$(adm503_exec "$probe_host" "$probe" "true" 20 "$ADM503_DIR/probe-$probe_host")"
      [ "$code" = 503 ] && break
      # 200 : sonde admise avant la saturation, on recommence ; tout autre code est une anomalie (429 = mauvais refus)
      [ "$code" = 200 ] || fail "admission-503 : HTTP $code vers $probe_host (attendu 200 puis 503 ; un 429 = agent_busy/too_many_tasks au lieu du refus memoire) : $(head -c 200 "$ADM503_DIR/probe-$probe_host.body" 2>/dev/null)"
      [ $(( $(date +%s) - t0 )) -lt 30 ] || fail "admission-503 : aucun 503 vers $probe_host apres 30 s (dernier code HTTP : $code) ; $slots taches en vol ?"
      sleep 1
    done
    echo "$probe" > "$ADM503_DIR/probe-$probe_host.id"
    grep -Eq '"error"[[:space:]]*:[[:space:]]*"memory_budget_exhausted"' "$ADM503_DIR/probe-$probe_host.body" \
      || fail "admission-503 : 503 vers $probe_host sans error=memory_budget_exhausted : $(head -c 200 "$ADM503_DIR/probe-$probe_host.body")"
    grep -Eiq '^retry-after:[[:space:]]*[1-9][0-9]*[[:space:]]*$' "$ADM503_DIR/probe-$probe_host.hdr" \
      || fail "admission-503 : 503 vers $probe_host sans Retry-After entier >= 1 (en-tetes : $(tr -d '\r' < "$ADM503_DIR/probe-$probe_host.hdr" | grep -i '^retry' || echo aucun))"
    echo "503 memory_budget_exhausted + $(tr -d '\r' < "$ADM503_DIR/probe-$probe_host.hdr" | grep -i '^retry-after') vers $probe_host"
  done
  adm503_lot_alive || fail "admission-503 : une des $slots taches de fond est deja terminee (refusee ?) : $(cat "$ADM503_DIR"/fill-*.code 2>/dev/null)"

  echo "== 3. rien cote minion, avertissement cote relay"
  sleep 2
  local svc logs fid
  for svc in root child; do
    logs="$(adm503_minion_logs "minion-$svc")"
    for n in $(seq 1 "$slots"); do   # temoin : les taches ADMISES laissent une trace dans le journal de leur minion
      fid="$(cat "$ADM503_DIR/fill-$n.id")"
      [ "$(cat "$ADM503_DIR/fill-$n.host")" = "minion-$svc" ] || continue
      printf '%s' "$logs" | grep -q "Task $fid" || fail "admission-503 : tache admise $fid absente du journal de minion-$svc : la preuve par absence serait non concluante"
    done
    if printf '%s' "$logs" | grep -q "$(cat "$ADM503_DIR/probe-minion-$svc.id")"; then
      fail "admission-503 : la tache refusee (sonde vers minion-$svc) a ete ENVOYEE au minion"
    fi
  done
  local refused_after; refused_after="$(docker logs "$m" 2>&1 | grep -c 'task refused at admission: reason=memory_budget_exhausted' || true)"
  [ "$refused_after" -gt "$refused_before" ] || fail "admission-503 : '[SECURITY WARNING] task refused at admission: reason=memory_budget_exhausted' absent du journal de $m ($refused_before -> $refused_after)"
  docker logs "$m" 2>&1 | grep 'task refused at admission: reason=memory_budget_exhausted' | tail -1 | sed 's/^/extrait du journal : /'

  echo "== 4. liberation : fin des taches, puis admission a nouveau possible"
  adm503_lot_wait
  adm503_lot_all_ok fill "$slots"
  code="$(adm503_exec minion-root "$(adm503_uuid)" "echo admission-503-ok" 30 "$ADM503_DIR/after")"
  [ "$code" = 200 ] || fail "admission-503 : exec apres liberation : HTTP $code ($(head -c 200 "$ADM503_DIR/after.body"))"
  adm503_fill refill 5 "${hosts[@]}"
  adm503_lot_wait
  adm503_lot_all_ok refill "$slots"   # $slots simultanes a nouveau : un compteur qui fuit aurait refuse avant
  echo "liberation OK ($slots taches de nouveau admises)"

  echo "== 5. plugin Ansible reel : 12 forks > plafond ($slots)"
  control_env
  local inv="$CHAIN_DIR/admission-503-inventory.ini" out="$CHAIN_DIR/admission-503-ansible.log"
  { echo "[all]"
    for n in $(seq 1 6); do echo "adm-root-$n ansible_host=minion-root ansible_connection=relay"; done
    for n in $(seq 1 6); do echo "adm-child-$n ansible_host=minion-child ansible_connection=relay"; done
  } > "$inv"
  ANSIBLE_CONNECTION_PLUGINS="$REPO/SECAGENT-PYTHON/ansible_plugins/connection_plugins" \
    "${ANSIBLE_BIN:-ansible}" all -i "$inv" -f 12 -m command -a "sleep 20" > "$out" 2>&1 || true   # rc != 0 attendu (UNREACHABLE)
  local unreach ok_hosts
  unreach="$(grep -c 'UNREACHABLE!' "$out" || true)"; ok_hosts="$(grep -c 'CHANGED\|SUCCESS' "$out" || true)"
  [ "$unreach" -ge 1 ] || fail "admission-503 : aucun hote UNREACHABLE avec 12 forks et un plafond de $slots (voir $out)"
  grep -q 'memory_budget_exhausted' "$out" || fail "admission-503 : message du plugin sans 'memory_budget_exhausted' (voir $out)"
  grep -q 'Retry-After' "$out" || fail "admission-503 : message du plugin sans 'Retry-After' (voir $out)"
  [ "$ok_hosts" -ge 1 ] || fail "admission-503 : aucun hote n'a abouti, le plafond ($slots) n'a pas ete respecte comme prevu (voir $out)"
  echo "plugin : $unreach hote(s) UNREACHABLE (AnsibleConnectionFailure explicite), $ok_hosts hote(s) abouti(s)"
  grep -m1 'memory_budget_exhausted' "$out" | sed 's/^/extrait : /' | cut -c1-300

  echo "== 6. retour au plafond par defaut"
  rm -f "$ADM503_OVERRIDE"; ADM503_OVERRIDE=""
  adm503_recreate_root without
  for n in "$C_A" "$C_B"; do
    [ -z "$(adm503_env_of "$n")" ] || fail "admission-503 : $n garde MAX_STDOUT_BUFFER_TOTAL='$(adm503_env_of "$n")' apres le retour au defaut"
  done
  plugin_token
  printf 'Authorization: Bearer %s\n' "$(cat "$CHAIN_DIR/plugin.token")" | write_secret plugin.header
  hosts=(); for n in $(seq 1 $(( half + 1 ))); do hosts+=(minion-child); done
  for n in $(seq 1 $(( slots - half ))); do hosts+=(minion-root); done   # slots + 1 taches, sans depasser 10 par minion
  adm503_fill nominal 5 "${hosts[@]}"
  adm503_lot_wait
  adm503_lot_all_ok nominal "${#hosts[@]}"
  smoke
  trap - EXIT
  rm -rf "$ADM503_DIR"
  echo "admission-503 OK ($slots taches admises, la suivante refusee en 503 memory_budget_exhausted avec Retry-After, rien envoye au minion, liberation constatee, plugin explicite, defaut restaure)"
}
