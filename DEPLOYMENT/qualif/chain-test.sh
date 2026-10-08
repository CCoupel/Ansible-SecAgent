#!/usr/bin/env bash
# Topologie de qualif EN CHAINE (#188) : amorcage, smoke et bascule de la racine.
#
#   chain-test.sh ci-prepare   # CI uniquement : PKI de test + qualif.env aleatoire et jetable
#   chain-test.sh bootstrap    # state init (racine, enfant), relays add, jetons enrolement/plugin, demarrage
#   chain-test.sh smoke        # relais connectes, minions connectes, inventaire hierarchique, ansible -m ping
#   chain-test.sh failover     # arret propre du maitre de la racine (failover-test.sh) puis smoke
#   chain-test.sh backup-restore  # sauvegarde de l etat + de RSA_MASTER_KEY (a part), perte du volume, restauration
#   chain-test.sh load-images <dir>  # docker load des images d'un artefact CI (sans registre), SECAGENT_PULL_POLICY=never
#   chain-test.sh push-tls     # TLS_MODE=volume : copie les certificats dans le volume Docker (hote distant)
#   chain-test.sh push-hooks    # hooks.json -> volume ${PROJECT}_hooks (fait par bootstrap)
#   chain-test.sh push-link-key  # cle publique racine (+ jeton de lien s'il existe) -> volume ${PROJECT}_link
#   chain-test.sh link-rotation  # rotation de la cle de lien, confirmation, nouveau jeton, retire-link-previous (v3.0.4)
#   chain-test.sh link-revoke    # revocation du lien d'un enfant : fermeture 4010, pas de reconnexion, puis remise en etat
#   chain-test.sh hooks        # journal des hooks (host.up/host.down) de la racine et de l'enfant (#197, hooks.json)
#   chain-test.sh negative-ca  # essai CA negatif (profil Compose `negative`) : un minion sans la CA est refuse (#197)
#   chain-test.sh logs | down
#
# Variables : SECAGENT_IMAGE, SECAGENT_MINION_IMAGE (obligatoires, references promues ou locales),
#   QUALIF_TLS_DIR (defaut ./pki/out), INVENTORY_BIN (binaire secagent-inventory du poste de controle),
#   ANSIBLE_BIN (defaut `ansible`), PROJECT (defaut secagent-chain), TOKEN_TTL (defaut 2h).
#   LINK_TTL (defaut = TOKEN_TTL) : duree du jeton de lien relay-child de l'enfant.
# Les jetons sont ecrits UNIQUEMENT dans ./chain/ (0700, fichiers 0600, ignore par git) : jamais affiches.
# Le poste de controle Ansible (plugin SECAGENT-PYTHON + secagent-inventory) est ici le poste qui lance ce script,
# il joint la racine par les ports d'hote 7770 (a) et 8770 (b) avec la CA de test.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
# Projet dedie `secagent-qualif` (conteneurs secagent-qualif-a/-b/-child, ports d'hote 7770/7772 + 8770/8772 pour b,
# admin 127.0.0.1:7771/8771/9771). Deployer sur un hote qui heberge deja une ancienne qualif : liberer ces ports avant.
export COMPOSE_FILE="$HERE/docker-compose.chain.yml" PROJECT="${PROJECT:-${COMPOSE_PROJECT_NAME:-secagent-qualif}}"
# TLS_MODE=volume : certificats dans un VOLUME Docker nomme (hote Docker distant) au lieu d'un bind mount.
# Les hooks de qualif sont TOUJOURS livres par un volume nomme (docker-compose.hooks.yml), jamais par un fichier du client.
export SECAGENT_HOOKS_VOLUME="${SECAGENT_HOOKS_VOLUME:-${PROJECT}_hooks}"
export COMPOSE_OVERRIDES="$HERE/docker-compose.hooks.yml"
if [ "${TLS_MODE:-bind}" = volume ]; then
  export SECAGENT_TLS_VOLUME="${SECAGENT_TLS_VOLUME:-${PROJECT}_tls}"
  export COMPOSE_OVERRIDES="$HERE/docker-compose.remote-tls.yml $COMPOSE_OVERRIDES"
fi
# Hote sur lequel le poste de controle joint la racine (ports d'hote 7770 et 8770) ; defaut : poste local / runner.
# Hote distant : SECAGENT_ENDPOINT_HOST=192.168.1.218 (doit figurer dans les SAN : PKI_EXTRA_SAN=IP:192.168.1.218).
ENDPOINT_HOST="${CONTROL_HOST:-${SECAGENT_ENDPOINT_HOST:-127.0.0.1}}"   # CONTROL_HOST = alias
export QUALIF_TLS_DIR="${QUALIF_TLS_DIR:-$HERE/pki/out}"
export SECAGENT_LINK_VOLUME="${SECAGENT_LINK_VOLUME:-${PROJECT}_link}"   # volume de l'ancre (cle publique racine)
C_A="secagent-qualif-a"; C_B="secagent-qualif-b"; C_CHILD="secagent-qualif-child"
export C_A C_B
TOKEN_TTL="${TOKEN_TTL:-2h}"
LINK_TTL="${LINK_TTL:-$TOKEN_TTL}"
CHAIN_DIR="$HERE/chain"
# shellcheck source=failover-test.sh
source "$HERE/failover-test.sh"   # fonctions : listening, is_master, wait_for, health, fail, DC...

adm() { # $1 conteneur, puis la commande secagent-server : CLI admin en TLS (CA de test), ADMIN_TOKEN du conteneur
  local c="$1"; shift
  docker exec -e RELAY_API_URL=https://localhost:7771 -e REPEATER_CA_FILE=/certs/ca.crt "$c" /app/secagent-server "$@"
}
master() { is_master "$C_A" && echo "$C_A" || { is_master "$C_B" && echo "$C_B"; }; }
write_secret() { # $1 fichier relatif a chain/, valeur lue sur stdin : jamais affichee
  ( umask 077; cat > "$CHAIN_DIR/$1" )
  chmod 600 "$CHAIN_DIR/$1"
}
extract() { grep -oE "$1" | tail -1; }   # extrait un jeton de la sortie du CLI sans l'afficher
need() { [ -n "${!1:-}" ] || fail "variable $1 obligatoire"; }

# Diagnostic des conteneurs du projet qui ne sont pas sains (appele par fail() : la CI montre la vraie cause d'un
# healthcheck qui ne passe jamais). UNIQUEMENT l'etat (jamais `docker inspect` complet : Config.Env contient
# JWT_SECRET_KEY / ADMIN_TOKEN / RSA_MASTER_KEY de qualif.env) et la fin des logs (les valeurs de secrets n'y figurent pas).
diag_unhealthy() {
  local c st
  echo "== DIAGNOSTIC (projet $PROJECT) ==" >&2
  for c in $(docker ps -a --filter "label=com.docker.compose.project=$PROJECT" --format '{{.Names}}' 2>/dev/null); do
    st="$(docker inspect -f '{{.State.Status}} exit={{.State.ExitCode}} oom={{.State.OOMKilled}} restarts={{.RestartCount}} health={{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}} err={{.State.Error}}' "$c" 2>/dev/null)" || continue
    echo "-- $c : $st" >&2
    case "$st" in *"health=healthy"*) ;; *) docker logs --tail=40 "$c" 2>&1 | sed 's/^/   | /' >&2 ;; esac
  done
}
# Sourcer failover-test.sh a defini fail() ; on l'enrichit sans changer son contrat (message + exit 1).
fail() { echo "ECHEC: $*" >&2; diag_unhealthy || true; exit 1; }

# Pousse tls.crt/tls.key/ca.crt de QUALIF_TLS_DIR dans le volume `$SECAGENT_TLS_VOLUME` de l'hote Docker (distant ou
# non) via un conteneur ephemere (flux tar sur stdin, image alpine epinglee) : TLS_MODE=volume requis.
push_tls() {
  [ "${TLS_MODE:-bind}" = volume ] || fail "push-tls exige TLS_MODE=volume"
  local f; for f in tls.crt tls.key ca.crt; do [ -f "$QUALIF_TLS_DIR/$f" ] || fail "$QUALIF_TLS_DIR/$f absent (lancer ci-prepare)"; done
  docker volume create "$SECAGENT_TLS_VOLUME" >/dev/null
  tar -C "$QUALIF_TLS_DIR" -cf - tls.crt tls.key ca.crt | docker run --rm -i -v "$SECAGENT_TLS_VOLUME:/certs" \
    alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc \
    sh -c 'tar -xf - -C /certs && chmod 755 /certs && chmod 644 /certs/tls.crt /certs/tls.key /certs/ca.crt'
  echo "certificats de test pousses dans le volume $SECAGENT_TLS_VOLUME"
}

# Depose hooks.json dans le volume `$SECAGENT_HOOKS_VOLUME` (hote Docker distant ou non) par un conteneur ephemere
# (flux tar sur stdin, image alpine epinglee) : aucun bind mount, aucun fichier du client reference par Compose.
push_hooks() {
  [ -f "$HERE/hooks.json" ] || fail "$HERE/hooks.json absent"
  docker volume create "$SECAGENT_HOOKS_VOLUME" >/dev/null
  tar -C "$HERE" -cf - hooks.json | docker run --rm -i -v "$SECAGENT_HOOKS_VOLUME:/hooks" \
    alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc \
    sh -c 'set -e; tar -xf - -C /hooks; chown 0:0 /hooks /hooks/hooks.json; chmod 755 /hooks; chmod 644 /hooks/hooks.json'
  echo "hooks.json depose dans le volume $SECAGENT_HOOKS_VOLUME"
}

# Empreinte STABLE d'une image : sha256 de la liste des couches (RootFS.Layers). L'ID `.Id` varie selon le magasin
# (overlay2 / containerd, Docker >= 29, Desktop) ; les couches (diff ids) sont identiques apres save/load.
# Meme calcul dans le job `images-artifact` de ci.yml (images.ids = "<ref> <empreinte>").
image_fp() { docker image inspect --format '{{json .RootFS.Layers}}' "$1" 2>/dev/null | sha256sum | cut -d' ' -f1; }

# Garde (BAS-3) : avec SECAGENT_PULL_POLICY=never, Docker reutiliserait SILENCIEUSEMENT un tag local preexistant. Avant
# tout demarrage, l'ID reel des images du demon doit etre celui enregistre par `load-images` (non secret).
verify_images() {
  [ "${SECAGENT_PULL_POLICY:-missing}" = never ] || return 0
  local f="$CHAIN_DIR/image-ids" var ref want id
  [ -f "$f" ] || fail "SECAGENT_PULL_POLICY=never mais $f est absent : lancer d'abord 'chain-test.sh load-images <repertoire-de-l-artefact>'"
  for var in SECAGENT_IMAGE SECAGENT_MINION_IMAGE; do
    ref="${!var:-}"; [ -n "$ref" ] || fail "$var non defini"
    want="$(awk -v r="$ref" '$1==r {print $2}' "$f")"
    [ -n "$want" ] || fail "$ref ne figure pas dans $f (images non chargees par load-images)"
    docker image inspect "$ref" >/dev/null 2>&1 || fail "image $ref absente du demon Docker"
    id="$(image_fp "$ref")"
    [ "$id" = "$want" ] || fail "empreinte des couches de $ref differente de l'artefact charge (demon: $id, attendu: $want) : un tag local preexistant ? relancer load-images"
  done
}

# Charge sur l'hote Docker (distant ou non) les images d'un ARTEFACT de run CI (docker save), sans registre :
#   gh run download <id> -n secagent-images-<sha> -D images && chain-test.sh load-images images
# Verifie SHA256SUMS, `docker load` des deux archives, puis affiche les variables a exporter (images.env).
load_images() {
  local d="${1:?repertoire de l artefact (images.env SHA256SUMS archives)}"
  [ -f "$d/images.env" ] && [ -f "$d/SHA256SUMS" ] || fail "$d : images.env ou SHA256SUMS absent"
  ( cd "$d" && sha256sum -c SHA256SUMS ) || fail "empreintes de l'artefact invalides"
  [ -f "$d/images.ids" ] || fail "$d/images.ids absent (artefact trop ancien)"
  # upload-artifact perd le bit d'execution : il est restaure ici (et le binaire est obligatoire).
  [ -f "$d/secagent-inventory" ] || fail "$d/secagent-inventory absent de l'artefact (binaire du poste de controle)"
  chmod +x "$d/secagent-inventory"
  local a; for a in "$d"/secagent-server-ci-*.tar.gz "$d"/secagent-minion-ci-*.tar.gz; do
    [ -f "$a" ] || fail "archive d'image absente ($a)"
    gunzip -c "$a" | docker load
  done
  # Empreintes reelles apres chargement == celles de l'artefact ; ils sont enregistres dans l'etat local (verify_images).
  local ref want id; mkdir -p "$CHAIN_DIR"; chmod 700 "$CHAIN_DIR"
  while read -r ref want; do
    [ -n "$ref" ] || continue
    docker image inspect "$ref" >/dev/null 2>&1 || fail "image $ref absente apres docker load"
    id="$(image_fp "$ref")"
    [ "$id" = "$want" ] || fail "empreinte de $ref apres chargement ($id) != artefact ($want)"
  done < "$d/images.ids"
  cp "$d/images.ids" "$CHAIN_DIR/image-ids"; chmod 600 "$CHAIN_DIR/image-ids"
  echo "images chargees. A exporter :"; cat "$d/images.env"
  echo "(binaire du poste de controle : $d/secagent-inventory -> INVENTORY_BIN)"
}

ci_prepare() {
  bash "$HERE/pki/gen.sh" "$QUALIF_TLS_DIR"
  ( umask 077
    { echo "JWT_SECRET_KEY=$(openssl rand -hex 32)"; echo "ADMIN_TOKEN=$(openssl rand -hex 24)"
      echo "RSA_MASTER_KEY=$(openssl rand -hex 32)"; } > "$HERE/qualif.env" )
}

bootstrap() {
  need SECAGENT_IMAGE; need SECAGENT_MINION_IMAGE
  verify_images
  mkdir -p "$CHAIN_DIR"; chmod 700 "$CHAIN_DIR"
  push_hooks
  echo "== etat initial (racine)"
  "${DC[@]}" run --rm --no-deps secagent-server-a state init
  echo "== racine : demarrage et identification du maitre"
  "${DC[@]}" up -d secagent-server-a secagent-server-b
  wait_for "racine healthy" 120 bash -c "[ \"\$(docker inspect -f '{{.State.Health.Status}}' $C_A)\" = healthy ] && [ \"\$(docker inspect -f '{{.State.Health.Status}}' $C_B)\" = healthy ]" >/dev/null
  sleep 3
  local m; m="$(master)" || fail "pas de maitre sur la racine"
  echo "maitre de la racine : $m"
  echo "== lien de l'enfant dmz1 (v3.0.4) : declaration, ancre (cle publique racine), jeton de lien relay-child"
  # `relays add` en mode pull ne mint plus aucun jeton (BREAKING v3.0.4) : il declare seulement l'enfant attendu.
  adm "$m" relays add --id dmz1 --description "chain child" >/dev/null || fail "relays add dmz1 refuse"
  link_anchor_prepare "$m"
  link_mint_child "$m"
  "${DC[@]}" run --rm --no-deps secagent-child state init
  "${DC[@]}" up -d secagent-child
  wait_for "enfant healthy" 120 bash -c "[ \"\$(docker inspect -f '{{.State.Health.Status}}' $C_CHILD)\" = healthy ]" >/dev/null
  echo "== jetons d'enrolement (un par minion, hostname exact) et jeton plugin (FICHIER 0600)"
  adm "$m" tokens create --role enrollment --hostname-pattern '^minion-root$' --expires "$TOKEN_TTL" 2>&1 \
    | extract 'secagent_enr_[0-9a-f]{64}' | { read -r t; [ -n "$t" ] || fail "jeton minion-root non extrait"; printf 'RELAY_ENROLLMENT_TOKEN=%s\n' "$t" | write_secret minion-root.env; }
  adm "$C_CHILD" tokens create --role enrollment --hostname-pattern '^minion-child$' --expires "$TOKEN_TTL" 2>&1 \
    | extract 'secagent_enr_[0-9a-f]{64}' | { read -r t; [ -n "$t" ] || fail "jeton minion-child non extrait"; printf 'RELAY_ENROLLMENT_TOKEN=%s\n' "$t" | write_secret minion-child.env; }
  plugin_token
  echo "== minions"
  "${DC[@]}" up -d minion-root minion-child
  echo "bootstrap OK (jetons dans $CHAIN_DIR, non affiches)"
}

connected() { # $1 conteneur CLI, $2 commande (relays|minions), $3 nom, $4 colonne du statut
  # Attend (150 s max : backoff de reconnexion du minion jusqu'a 60 s) que $3 soit `connected` sur 3 releves
  # CONSECUTIFS espaces de 2 s : un statut perime (« connected » herite de l'ancien maitre) ne suffit pas.
  local ok=0 t0; t0=$(now)
  while [ "$ok" -lt 3 ]; do
    if docker exec -e RELAY_API_URL=https://localhost:7771 -e REPEATER_CA_FILE=/certs/ca.crt "$1" /app/secagent-server "$2" list 2>/dev/null \
       | awk -v n="$3" -v c="$4" '$1==n && $c=="connected" {f=1} END{exit !f}'; then ok=$((ok+1)); else ok=0; fi
    awk -v a="$t0" -v b="$(now)" 'BEGIN{exit !(b-a>150)}' && fail "$3 n'est pas connected (150 s) sur $1"
    sleep 2
  done
}

# Attend (120 s max) que les DEUX minions apparaissent dans l'inventaire de la racine (propagation des hotes de
# l'enfant) avant tout `ansible -m ping`.
wait_inventory() {
  local t0 inv; t0=$(now)
  while :; do
    inv="$(RELAY_TOKEN="$(cat "$RELAY_TOKEN_FILE")" "$INVENTORY_BIN" --list 2>/dev/null || true)"
    if printf '%s' "$inv" | grep -q minion-root && printf '%s' "$inv" | grep -q minion-child; then return 0; fi
    awk -v a="$t0" -v b="$(now)" 'BEGIN{exit !(b-a>120)}' && fail "minion-root et minion-child absents de l'inventaire de la racine apres 120 s"
    sleep 3
  done
}

# Jeton plugin FRAIS a chaque appel (#197) : plus de dependance a un jeton cree au bootstrap qui expire (TOKEN_TTL).
# Cree sur le maitre courant (l'etat est partage par a/b), ecrit en FICHIER 0600, jamais affiche. Un ancien jeton
# non revoque expire de lui-meme (TTL) ; description horodatee pour les reperer dans `tokens list`.
plugin_token() {
  local m; m="$(master)" || fail "pas de maitre sur la racine (jeton plugin)"
  mkdir -p "$CHAIN_DIR"; chmod 700 "$CHAIN_DIR"
  adm "$m" tokens create --role plugin --description "chain-smoke-$(date +%s)" --expires "$TOKEN_TTL" 2>&1 \
    | extract 'secagent_plg_[0-9a-f]{64}' | { read -r t; [ -n "$t" ] || fail "jeton plugin non extrait"; printf '%s' "$t" | write_secret plugin.token; }
}

control_env() { # variables du poste de controle Ansible : listes d'adresses, CA de test, jeton en FICHIER
  plugin_token   # jeton frais a chaque appel (smoke, failover, hooks)
  export RELAY_SERVER_URL="https://${ENDPOINT_HOST}:7770,https://${ENDPOINT_HOST}:8770" RELAY_CA_BUNDLE="$QUALIF_TLS_DIR/ca.crt"
  export RELAY_TOKEN_FILE="$CHAIN_DIR/plugin.token"
}

smoke() {
  local m; m="$(master)" || fail "pas de maitre sur la racine"
  echo "== relais et minions connectes"
  connected "$m" relays dmz1 4
  connected "$m" minions minion-root 2
  connected "$C_CHILD" minions minion-child 2
  echo "== inventaire hierarchique (liste d'adresses de la racine)"
  control_env
  need INVENTORY_BIN
  wait_inventory
  echo "== ansible -m ping sur tous les hotes (plugin de connexion, CA de test)"
  local inv_script="$CHAIN_DIR/inventory.sh"
  printf '#!/bin/sh\nRELAY_TOKEN="$(cat "%s")" exec "%s" "$@"\n' "$RELAY_TOKEN_FILE" "$INVENTORY_BIN" | write_secret inventory.sh
  chmod 700 "$inv_script"
  ANSIBLE_CONNECTION_PLUGINS="$REPO/SECAGENT-PYTHON/ansible_plugins/connection_plugins" ANSIBLE_HOST_KEY_CHECKING=False \
    "${ANSIBLE_BIN:-ansible}" all -i "$inv_script" -m ping | tee "$CHAIN_DIR/ping.log"
  [ "$(grep -c SUCCESS "$CHAIN_DIR/ping.log")" -ge 2 ] || fail "ansible -m ping : moins de 2 hotes SUCCESS"
  echo "smoke OK"
}

# Sauvegarde / restauration en conteneurs (#170) : l'etat (relay.state) et RSA_MASTER_KEY sont sauvegardes SEPAREMENT
# (repertoires distincts, hors du volume). Perte totale du volume d'etat, puis restauration sur un volume vierge :
# sans la cle, `state verify` refuse (code 6) ; avec une MAUVAISE cle il refuse (code 2) ; avec la bonne cle l'etat
# est restaure, la racine redemarre et le minion DEJA enrole se reconnecte SANS re-enrolement (meme identite).
backup_restore() {
  guard_project
  verify_images
  local m bk key; m="$(master)" || fail "pas de maitre sur la racine"
  bk="$CHAIN_DIR/backup-state"; key="$CHAIN_DIR/backup-key"
  local bkvol="${PROJECT}_backup"   # volume NOMME (pas de bind mount local : le demon peut etre distant)
  rm -rf "$bk" "$key"; mkdir -p "$bk" "$key"; chmod 700 "$key"
  connected "$m" minions minion-root 2    # le minion doit etre enrole et connecte avant la sauvegarde
  echo "== sauvegarde (etat) et sauvegarde distincte de RSA_MASTER_KEY"
  docker exec "$m" /app/secagent-server state verify /data/relay.state >/dev/null || fail "etat source invalide"
  docker cp "$m:/data/relay.state" "$bk/relay.state"; chmod 755 "$bk"; chmod 644 "$bk/relay.state"
  docker volume create "$bkvol" >/dev/null
  tar -C "$bk" -cf - relay.state | docker run --rm -i -v "$bkvol:/backup" \
    alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc \
    sh -c 'tar -xf - -C /backup && chmod 755 /backup && chmod 644 /backup/relay.state'

  grep '^RSA_MASTER_KEY=' "$HERE/qualif.env" | write_secret "backup-key/rsa_master_key"
  echo "== sinistre : arret de la racine, perte du volume d'etat, perte de la cle sur l'hote"
  "${DC[@]}" rm -sf secagent-server-a secagent-server-b >/dev/null
  docker volume rm "${PROJECT}_secagent_state" >/dev/null
  cp "$HERE/qualif.env" "$CHAIN_DIR/qualif.env.lost"; chmod 600 "$CHAIN_DIR/qualif.env.lost"
  sed -i '/^RSA_MASTER_KEY=/d' "$HERE/qualif.env"
  local rc=0
  "${DC[@]}" run --rm --no-deps -v "$bkvol:/backup:ro" secagent-server-a state verify /backup/relay.state >/dev/null 2>&1 || rc=$?
  [ "$rc" = 6 ] || fail "sans RSA_MASTER_KEY : code 6 attendu, obtenu $rc"
  echo "sans la cle : refus (code 6) comme attendu"
  rc=0
  "${DC[@]}" run --rm --no-deps -e RSA_MASTER_KEY=mauvaise-cle -v "$bkvol:/backup:ro" secagent-server-a state verify /backup/relay.state >/dev/null 2>&1 || rc=$?
  [ "$rc" = 2 ] || fail "avec une mauvaise cle : code 2 attendu, obtenu $rc"
  echo "mauvaise cle : refus (code 2) comme attendu"
  echo "== restauration de la cle (depuis la sauvegarde distincte) puis de l'etat sur un volume vierge"
  { cat "$key/rsa_master_key"; echo; } >> "$HERE/qualif.env"
  "${DC[@]}" run --rm --no-deps -v "$bkvol:/backup:ro" secagent-server-a state verify /backup/relay.state >/dev/null || fail "etat sauvegarde refuse avec la cle restauree"
  "${DC[@]}" run --rm --no-deps -v "$bkvol:/backup:ro" secagent-server-a state restore --from /backup/relay.state
  "${DC[@]}" up -d secagent-server-a secagent-server-b
  wait_for "racine healthy apres restauration" 120 bash -c "[ \"\$(docker inspect -f '{{.State.Health.Status}}' $C_A)\" = healthy ] && [ \"\$(docker inspect -f '{{.State.Health.Status}}' $C_B)\" = healthy ]" >/dev/null
  sleep 3
  m="$(master)" || fail "pas de maitre apres restauration"
  echo "== le minion DEJA enrole se reconnecte sans re-enrolement (aucun nouveau jeton cree)"
  connected "$m" minions minion-root 2
  docker volume rm "$bkvol" >/dev/null || true
  echo "backup-restore OK (meme identite : le minion, authentifie par l'etat restaure, est reconnecte)"
}

# --- Jetons de lien v3.0.4 (#141/#146) -----------------------------------------------------------------------------
# La RACINE mint un jeton par lien (Ed25519) ; la cle publique racine est epinglee sur chaque relay non racine.
#   pull : racine `tokens create --role relay-child --sub dmz1 --aud <root_id>` -> fichier `upstream-token` du volume
#          ${PROJECT}_link (proprietaire 10001, mode 0400) = REPEATER_UPSTREAM_TOKEN_FILE de l'enfant ; REPEATER_ROOT_ID
#          dans chain/child.env (non secret). PAS de `secrets:` Compose : hors Swarm il monte le fichier de l'HOTE
#          (uid/gid/mode ignores), illisible par l'uid 10001 du conteneur et irrealisable contre un demon distant.
#   ancre : `keys link-pubkey` (PEM sur stdout, `root_id=... kid=...` sur stderr) -> meme volume (0644)
# L'enfant n'a PLUS de jeton en variable d'environnement (docker inspect ne montre aucun secret).

# Pousse dans le volume `$SECAGENT_LINK_VOLUME` (hote Docker distant ou non) la cle publique racine
# (chain/root-link.pub, NON secrete, 0644) et, s'il existe, le jeton de lien (chain/upstream-token, SECRET, 0400,
# proprietaire 10001 = uid du conteneur), par un conteneur ephemere (flux tar sur stdin, image alpine epinglee) : aucun
# bind mount, aucun droit requis sur l'hote. Le jeton local est supprime apres la copie (il vit alors dans le volume).
push_link_key() {
  [ -f "$CHAIN_DIR/root-link.pub" ] || fail "$CHAIN_DIR/root-link.pub absent (lancer bootstrap)"
  local files="root-link.pub"
  [ -f "$CHAIN_DIR/upstream-token" ] && files="root-link.pub upstream-token"
  docker volume create "$SECAGENT_LINK_VOLUME" >/dev/null
  # shellcheck disable=SC2086
  tar -C "$CHAIN_DIR" -cf - $files | docker run --rm -i -v "$SECAGENT_LINK_VOLUME:/link" \
    alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc \
    sh -c 'set -e; tar -xf - -C /link; chmod 755 /link; chown 0:0 /link/root-link.pub; chmod 644 /link/root-link.pub
           if [ -f /link/upstream-token ]; then chown 10001:10001 /link/upstream-token; chmod 0400 /link/upstream-token; fi'
  rm -f "$CHAIN_DIR/upstream-token"
  echo "ancre (et jeton de lien) deposes dans le volume $SECAGENT_LINK_VOLUME"
}

# $1 conteneur maitre : exporte la cle publique racine, releve root_id, ecrit chain/root-link.pub, chain/root-id et
# chain/child.env (REPEATER_ROOT_ID, non secret).
link_anchor_prepare() {
  local m="$1" rid
  # stdout = PEM (fichier) ; stderr = "root_id=<id> kid=<kid>" (capture), jamais de cle privee.
  rid="$(adm "$m" keys link-pubkey 2>&1 >"$CHAIN_DIR/root-link.pub" | sed -n 's/^root_id=\([^ ]*\) .*/\1/p')"
  [ -n "$rid" ] || fail "root_id non releve (keys link-pubkey)"
  grep -q 'BEGIN PUBLIC KEY' "$CHAIN_DIR/root-link.pub" || fail "keys link-pubkey n'a pas produit de PEM public"
  chmod 644 "$CHAIN_DIR/root-link.pub"
  printf '%s' "$rid" | write_secret root-id
  printf 'REPEATER_ROOT_ID=%s\n' "$rid" | write_secret child.env
  # le depot dans le volume est fait par link_mint_child (cle publique et jeton ensemble)
}

# $1 conteneur maitre : mint (sur la racine) du jeton relay-child de dmz1 -> chain/upstream-token puis DEPOT dans le
# volume (push_link_key : 0400, proprietaire 10001, fichier local supprime) et chain/upstream-token.id (identifiant du
# registre, non secret, pour `tokens revoke`). Jamais affiche.
link_mint_child() {
  local m="$1" out t id rid
  rid="$(cat "$CHAIN_DIR/root-id")" || fail "chain/root-id absent (link_anchor_prepare)"
  out="$(adm "$m" tokens create --role relay-child --sub dmz1 --aud "$rid" --expires "$LINK_TTL" 2>&1)" \
    || fail "mint du jeton de lien dmz1 -> $rid refuse (tokens create --role relay-child)"
  t="$(printf '%s\n' "$out" | extract 'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+')"
  id="$(printf '%s\n' "$out" | sed -n 's/^ *ID: *//p' | head -1)"
  [ -n "$t" ] || fail "jeton de lien non extrait"
  [ -n "$id" ] || fail "identifiant du jeton de lien non extrait"
  printf '%s' "$t" | write_secret upstream-token
  printf '%s' "$id" | write_secret upstream-token.id
  push_link_key
}

relay_connected() { # $1 conteneur CLI, $2 relay_id
  adm "$1" relays list 2>/dev/null | awk -v n="$2" '$1==n && $4=="connected" {f=1} END{exit !f}'
}
relay_gone() { ! relay_connected "$1" "$2"; }
link_confirmed() { # $1 conteneur CLI, $2 relay_id : la rotation est confirmee par ce relay (keys link-status)
  adm "$1" keys link-status 2>/dev/null | awk -v n="$2" '$1==n && $4=="true" {f=1} END{exit !f}'
}
link_field() { # $1 conteneur CLI, $2 champ de la 1re ligne de keys link-status (current|previous|seq)
  adm "$1" keys link-status 2>/dev/null | head -1 | sed -n "s/.* $2=\([^ ]*\).*/\1/p"
}
recreate_child() { # remplace le conteneur de l'enfant (le jeton n'est lu qu'au demarrage) et attend healthy
  "${DC[@]}" up -d --force-recreate --no-deps secagent-child
  wait_for "enfant healthy" 120 bash -c "[ \"\$(docker inspect -f '{{.State.Health.Status}}' $C_CHILD)\" = healthy ]" >/dev/null
}

# Scenario link-rotation : rotation de la cle de signature -> confirmation par dmz1 (link_state) -> nouveau jeton signe
# par la nouvelle cle -> retire-link-previous (sans --force : refuse tant que non confirme) -> le lien survit a une
# reconnexion de l'enfant. Termine par un smoke (inventaire, ping).
link_rotation() {
  verify_images; need INVENTORY_BIN
  local m kid0 kid1 prev; m="$(master)" || fail "pas de maitre sur la racine"
  connected "$m" relays dmz1 4
  kid0="$(link_field "$m" current)"; [ -n "$kid0" ] || fail "kid courant illisible (keys link-status)"
  echo "== rotation de la cle de lien (kid courant $kid0)"
  adm "$m" keys rotate-link || fail "rotate-link refuse"
  kid1="$(link_field "$m" current)"
  [ -n "$kid1" ] && [ "$kid1" != "$kid0" ] || fail "le kid courant n'a pas change apres la rotation"
  [ "$(link_field "$m" previous)" = "$kid0" ] || fail "previous != ancien kid (fenetre de double acceptation absente)"
  wait_for "dmz1 confirme la rotation (keys link-status)" 90 link_confirmed "$m" dmz1 >/dev/null
  echo "== nouveau jeton de lien (signe par la nouvelle cle) et remplacement du conteneur de l'enfant"
  link_mint_child "$m"; recreate_child
  connected "$m" relays dmz1 4
  echo "== retire-link-previous (refus attendu tant que non confirme : ici confirme)"
  adm "$m" keys retire-link-previous || fail "retire-link-previous refuse (rotation non confirmee ?)"
  prev="$(link_field "$m" previous)"
  case "$prev" in ""|"<nil>"|"-") ;; *) fail "previous encore present apres retire ($prev)" ;; esac
  echo "== le lien survit a une reconnexion de l'enfant apres le retrait"
  "${DC[@]}" restart secagent-child >/dev/null
  connected "$m" relays dmz1 4
  smoke
  echo "link-rotation OK (kid $kid0 -> $kid1, previous retire, lien reconnecte)"
}

# Scenario link-revoke : revocation du jeton de lien de dmz1 sur la racine -> lien ferme (4010, refus PERMANENT),
# l'enfant ne se reconnecte pas avec ce jeton ; remise en etat avec un nouveau jeton.
link_revoke() {
  verify_images; need INVENTORY_BIN
  local m id; m="$(master)" || fail "pas de maitre sur la racine"
  connected "$m" relays dmz1 4
  id="$(cat "$CHAIN_DIR/upstream-token.id")" || fail "chain/upstream-token.id absent"
  echo "== revocation du jeton de lien de dmz1 ($id)"
  adm "$m" tokens revoke "$id" || fail "tokens revoke refuse"
  wait_for "dmz1 deconnecte de la racine (fermeture 4010)" 60 relay_gone "$m" dmz1 >/dev/null
  echo "== pas de reconnexion avec le jeton revoque (40 s)"
  sleep 40
  ! relay_connected "$m" dmz1 || fail "dmz1 s'est reconnecte avec un jeton revoque"
  docker logs "$C_CHILD" 2>&1 | grep -Eiq '4010|permanent|revoked' \
    && echo "journal de l'enfant : refus permanent constate" \
    || echo "info : aucune mention de refus permanent dans les logs de l'enfant (a analyser a l'execution)"
  echo "== remise en etat : nouveau jeton de lien"
  link_mint_child "$m"; recreate_child
  connected "$m" relays dmz1 4
  smoke
  echo "link-revoke OK (lien ferme et non retabli avec le jeton revoque ; retabli avec un nouveau jeton)"
}

# --- Hooks en reel (#197 item 1) -----------------------------------------------------------------------------------
# hooks.json (DEPLOYMENT/qualif/hooks.json, livre par le volume `${PROJECT}_hooks`, push-hooks) ecrit chaque host.up / host.down dans
# /run/secagent/events.log (tmpfs) de chaque conteneur. Seul le MAITRE de la racine execute ses hooks.
events_log() { docker exec "$1" cat /run/secagent/events.log 2>/dev/null || true; }
# $1 conteneur, $2 hote, $3 UP|DOWN : une ligne "<horodatage> <UP|DOWN> <hote>" existe dans le journal.
hook_seen() { events_log "$1" | awk -v h="$2" -v k="$3" '$2==k && $3==h {f=1} END{exit !f}'; }

check_hooks() {
  local m; m="$(master)" || fail "pas de maitre sur la racine"
  echo "== hooks : host.up de minion-root au maitre ($m), de minion-child a l'enfant ($C_CHILD)"
  wait_for "host.up minion-root dans le journal du maitre $m" 60 hook_seen "$m" minion-root UP >/dev/null
  wait_for "host.up minion-child dans le journal de l'enfant" 60 hook_seen "$C_CHILD" minion-child UP >/dev/null
  echo "hooks OK (journaux : docker exec <conteneur> cat /run/secagent/events.log)"
}

# Bascule avec hooks : apres l'arret propre du maitre, le NOUVEAU maitre doit journaliser host.up de minion-root
# (reconnexion du minion). minion-child : informatif (il reste connecte a l'enfant, qui ne redemarre pas ; l'evenement
# remonte-t-il a la nouvelle racine ? TODO a confirmer a l'execution, pas de verdict ici).
check_hooks_after_failover() {
  local m; m="$(master)" || fail "pas de maitre apres la bascule"
  echo "== hooks apres bascule : nouveau maitre $m"
  wait_for "host.up minion-root journalise par le nouveau maitre $m" 150 hook_seen "$m" minion-root UP >/dev/null
  if hook_seen "$m" minion-child UP; then echo "info : host.up minion-child aussi journalise par $m"; else echo "info : host.up minion-child absent du journal de $m (a analyser a l'execution)"; fi
  echo "hooks apres bascule OK"
}

# --- Essai CA negatif (#197 item 2) : service Compose `minion-negca`, profil `negative` -----------------------------
negative_ca() {
  verify_images
  local m; m="$(master)" || fail "pas de maitre sur la racine"
  echo "== minion sans la CA privee (store systeme seul) : doit etre REFUSE"
  "${DC[@]}" --profile negative up -d --no-deps minion-negca
  local ok=0 i
  for i in $(seq 1 30); do
    if "${DC[@]}" --profile negative logs minion-negca 2>&1 | grep -Eiq 'x509|certificate|unknown authority'; then ok=1; break; fi
    sleep 2
  done
  local listed=0
  adm "$m" minions list 2>/dev/null | awk '$1=="minion-negca" {f=1} END{exit !f}' && listed=1
  "${DC[@]}" --profile negative rm -sf minion-negca >/dev/null
  [ "$ok" = 1 ] || fail "negative-ca : aucune erreur de certificat dans les logs de minion-negca (60 s)"
  [ "$listed" = 0 ] || fail "negative-ca : minion-negca figure dans minions list malgre l'absence de CA"
  echo "negative-ca OK (erreur de certificat, minion absent de la liste)"
}

failover() {
  verify_images
  need INVENTORY_BIN
  control_env
  # Arret propre du maitre : l'enfant et les minions doivent se reconnecter par leurs listes, ping OK ensuite.
  bash "$HERE/failover-test.sh" run stop
  smoke
  check_hooks_after_failover
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  case "${1:-}" in
    ci-prepare) ci_prepare ;;
    bootstrap) bootstrap ;;
    smoke) smoke ;;
    failover) failover ;;
    backup-restore) backup_restore ;;
    logs) "${DC[@]}" logs --tail=100 ;;
    load-images) load_images "${2:-}" ;;
    push-tls) push_tls ;;
    push-hooks) push_hooks ;;
    push-link-key) push_link_key ;;
    link-rotation) link_rotation ;;
    link-revoke) link_revoke ;;
    hooks) check_hooks ;;
    negative-ca) negative_ca ;;
    down) guard_project; "${DC[@]}" down -v
          # le volume du jeton de lien est EXTERNE (non supprime par down -v) et contient un secret : retrait explicite
          docker volume rm "$SECAGENT_LINK_VOLUME" "$SECAGENT_HOOKS_VOLUME" >/dev/null 2>&1 || true ;;
    *) sed -n '2,26p' "$0"; exit 2 ;;
  esac
fi
