#!/usr/bin/env bash
#
# ============================================================================================
# OBSOLETE v3.0.3 : appartient a l'ancienne topologie relay-proxy / relay-dmz1 / relay-dmz2
# (DEPLOYMENT/qualif/docker-compose.proxy.yml, elle-meme obsolete). Les conteneurs, le CLI
# (`tokens create`, `relays add`), la base de tokens et les jetons d'enrolement qu'il suppose ne
# correspondent plus au serveur actuel (etat sur fichier, `state init` + RSA_MASTER_KEY, TLS natif,
# jetons d'enrolement obligatoires, plugin avec fichier de jeton 0600 / RELAY_TOKEN_FILE).
# Le script REFUSE de s'executer sans I_KNOW_THIS_IS_OBSOLETE=1 ; il sera remplace avec la
# topologie en chaine de relais (issue dediee).
# ============================================================================================
if [ "${I_KNOW_THIS_IS_OBSOLETE:-}" != "1" ]; then
  echo "OBSOLETE v3.0.3 : bootstrap-qualif.sh ne correspond plus au serveur actuel ; arret." >&2
  exit 2
fi
# bootstrap-qualif.sh — Initialise les tokens et relay nodes pour la qualif multi-zones.
#
# À exécuter APRÈS `docker compose up -d`, une fois tous les services healthy.
# Idempotent : relançable sans créer de doublons ni écraser les secrets existants.
#
# Usage :
#   ADMIN_TOKEN=<token> bash scripts/bootstrap-qualif.sh
#   ADMIN_TOKEN=<token> DOCKER_HOST=tcp://192.168.1.218:2375 bash scripts/bootstrap-qualif.sh
#
# Variables requises :
#   ADMIN_TOKEN   : token Bearer admin (défini dans DEPLOYMENT/qualif/.env)
#
# Variables optionnelles :
#   DOCKER_HOST        : socket Docker remote (défaut: tcp://192.168.1.218:2375)
#   ZONES              : zones séparées par des espaces (défaut: "dmz1 dmz2")
#   RELAY_PROXY        : nom du container proxy (défaut: relay-proxy)
#   EXPIRES_ENR        : durée des tokens d'enrollment (défaut: 24h)
#                        NOTE : token réutilisable (--reusable) — relancer le bootstrap
#                        après expiration pour générer un nouveau token.
#   EXPIRES_PLUGIN     : durée du token plugin Ansible (défaut: 365d)
#   OUTPUT_FILE        : fichier de sortie des secrets (défaut: DEPLOYMENT/qualif/.env.bootstrap)
#
# Sécurité :
#   - ADMIN_TOKEN lu depuis l'environnement, jamais affiché dans les logs
#     (visible dans la liste de processus de la machine locale via docker exec -e)
#   - Tokens générés écrits dans OUTPUT_FILE uniquement (permissions 600, mode append)
#   - Les valeurs existantes dans OUTPUT_FILE ne sont JAMAIS écrasées
#   - OUTPUT_FILE est dans .gitignore
#
# ATTENTION (qualif uniquement) :
#   - Les tokens d'enrollment utilisent --hostname-pattern ".*" (tout hostname accepté)
#   - En production, utiliser un pattern plus restrictif
#
# Limitations (issues pendantes) :
#   - Connexion relay→proxy (mode pull) : non implémentée (#124/#125/#140)
#   - Le JWT relay-child affiché par 'relays add' est sauvegardé dans OUTPUT_FILE
#     mais ne sera utile qu'après implémentation du repeater-client (#124/#125)

set -euo pipefail

# ─── Configuration ────────────────────────────────────────────────────────────

DOCKER_HOST="${DOCKER_HOST:-tcp://192.168.1.218:2375}"
export DOCKER_HOST

if [ -z "${ADMIN_TOKEN:-}" ]; then
  echo "ERREUR : ADMIN_TOKEN est requis (non défini)." >&2
  echo "Usage : ADMIN_TOKEN=<token> bash $0" >&2
  exit 1
fi

ZONES="${ZONES:-dmz1 dmz2}"
RELAY_PROXY="${RELAY_PROXY:-relay-proxy}"
EXPIRES_ENR="${EXPIRES_ENR:-24h}"
EXPIRES_PLUGIN="${EXPIRES_PLUGIN:-365d}"
OUTPUT_FILE="${OUTPUT_FILE:-DEPLOYMENT/qualif/.env.bootstrap}"

PASS=0
FAIL=0
ok()   { echo "  ✓ $*"; PASS=$((PASS + 1)); }
warn() { echo "  ⚠ $*"; }
fail() { echo "  ✗ $*" >&2; FAIL=$((FAIL + 1)); }

# ─── Gestion sécurisée du fichier de secrets ──────────────────────────────────

# Crée le fichier avec permissions 600 si absent ; en mode append sinon.
init_secrets_file() {
  mkdir -p "$(dirname "$OUTPUT_FILE")"
  if [ ! -f "$OUTPUT_FILE" ]; then
    (umask 077 && touch "$OUTPUT_FILE")
    chmod 600 "$OUTPUT_FILE"
    {
      echo "# Tokens générés par bootstrap-qualif.sh"
      echo "# Date : $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
      echo "# NE PAS VERSIONNER — ajouté à .gitignore"
      echo "# Permissions : 600 (lecture seule propriétaire)"
      echo ""
    } >> "$OUTPUT_FILE"
    echo "  Fichier $OUTPUT_FILE créé (permissions 600)."
  else
    echo "  Fichier $OUTPUT_FILE existant — les nouveaux secrets seront ajoutés (mode append)."
    echo "  Les valeurs déjà présentes NE seront PAS écrasées."
    chmod 600 "$OUTPUT_FILE"  # s'assurer des permissions même si déjà présent
  fi
}

# Écrit une paire clé=valeur dans OUTPUT_FILE uniquement si la clé est absente.
# À utiliser quand le token n'a PAS été recréé (run idempotent normal).
write_secret() {
  local key="$1"
  local value="$2"
  if grep -q "^${key}=" "$OUTPUT_FILE" 2>/dev/null; then
    warn "Secret '${key}' déjà présent dans ${OUTPUT_FILE} — non écrasé (idempotent)"
  else
    printf '%s=%s\n' "$key" "$value" >> "$OUTPUT_FILE"
  fi
}

# Remplace une paire clé=valeur dans OUTPUT_FILE si la clé existe déjà,
# ou l'ajoute si elle est absente. Commente l'ancienne valeur avec # REVOKED.
# À utiliser lorsqu'un token vient d'être RECRÉÉ (ancien révoqué ou absent).
# Cela évite de garder une valeur révoquée active dans le fichier.
replace_secret() {
  local key="$1"
  local value="$2"
  if grep -q "^${key}=" "$OUTPUT_FILE" 2>/dev/null; then
    local date_str tmp
    date_str=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
    tmp="${OUTPUT_FILE}.tmp"
    # Nettoyage du fichier temporaire en cas d'interruption
    trap 'rm -f "$tmp"' EXIT
    # Créer le fichier temporaire sous umask 077 (permissions 600 dès la création)
    (umask 077; sed "s|^${key}=|# REVOKED ${date_str} ${key}=|" "$OUTPUT_FILE" > "$tmp")
    printf '%s=%s\n' "$key" "$value" >> "$tmp"
    chmod 600 "$tmp"
    mv "$tmp" "$OUTPUT_FILE"
    trap - EXIT
    warn "Secret '${key}' remplacé (ancienne valeur marquée REVOKED ${date_str})"
  else
    printf '%s=%s\n' "$key" "$value" >> "$OUTPUT_FILE"
  fi
}

# ─── Fonction : exec CLI secagent-server dans un container ────────────────────

docker_cli() {
  local container="$1"
  shift
  DOCKER_HOST="$DOCKER_HOST" docker exec \
    -e "ADMIN_TOKEN=${ADMIN_TOKEN}" \
    "$container" secagent-server "$@"
}

# ─── Étape 1 : Vérification des containers ────────────────────────────────────

echo ""
echo "=== Bootstrap Qualif Multi-Zones ==="
echo ""
echo "── Étape 1/4 : Vérification des containers ──────────────────"

ALL_CONTAINERS="$RELAY_PROXY"
for z in $ZONES; do ALL_CONTAINERS="$ALL_CONTAINERS relay-${z}"; done

for svc in $ALL_CONTAINERS; do
  STATUS=$(DOCKER_HOST="$DOCKER_HOST" docker inspect --format='{{.State.Status}}' "$svc" 2>/dev/null || echo "absent")
  if [ "$STATUS" = "running" ]; then
    ok "$svc : running"
  else
    fail "$svc : $STATUS (attendu: running)"
  fi
done

if [ "$FAIL" -gt 0 ]; then
  echo ""
  echo "ARRÊT : containers non prêts. Lancez 'docker compose up -d' d'abord." >&2
  exit 1
fi

init_secrets_file

# ─── Étape 2 : Tokens d'enrollment par zone ───────────────────────────────────

echo ""
echo "── Étape 2/4 : Tokens d'enrollment par zone ─────────────────"
echo ""
echo "  NOTE (qualif) : tokens créés avec --hostname-pattern '.*' (tout hostname)."
echo "  En production, utiliser un pattern restrictif."
echo ""

for zone in $ZONES; do
  container="relay-${zone}"
  desc="bootstrap-${zone}"
  ZONE_UPPER="$(printf '%s' "$zone" | tr '[:lower:]' '[:upper:]')"
  SECRET_KEY="RELAY_ENROLLMENT_TOKEN_${ZONE_UPPER}"

  echo ""
  echo "  Zone : $zone (container: $container)"

  # Idempotence : vérifier si un token actif (non révoqué) avec cette description existe.
  # Format 'tokens list' : ID ROLE HASH PATTERN/DESC EXPIRES USED REVOKED
  # On filtre les lignes contenant la description ET dont le dernier champ n'est pas 'true'
  # (REVOKED=true).
  # LIMITATION — tokens expirés : le filtre '$NF != "true"' détecte la révocation
  # mais PAS l'expiration. Un token enrollment de 24h expiré (non révoqué explicitement)
  # sera considéré comme « actif » par ce filtre, et le script ne le recréera pas.
  # Si les agents ne peuvent plus s'enroller, révoquer manuellement le token expiré
  # ('secagent-server tokens revoke <id>') puis relancer ce script.
  EXISTING_ENR=$(docker_cli "$container" tokens list --role enrollment 2>/dev/null \
    | awk -v d="$desc" '$0 ~ d && $NF != "true"' || true)

  if [ -n "$EXISTING_ENR" ]; then
    warn "Token enrollment actif '$desc' déjà présent sur $container — non recréé (idempotent)"
    # Le secret est peut-être déjà dans OUTPUT_FILE (run précédent)
    if ! grep -q "^${SECRET_KEY}=" "$OUTPUT_FILE" 2>/dev/null; then
      warn "Mais ${SECRET_KEY} absent de ${OUTPUT_FILE} — relancer après 'tokens revoke' si nécessaire"
    fi
    continue
  fi

  TOKEN_OUT=$(docker_cli "$container" tokens create \
    --role enrollment \
    --hostname-pattern ".*" \
    --reusable \
    --expires "$EXPIRES_ENR" \
    --description "$desc" 2>&1) || {
    fail "Échec création token enrollment zone $zone"
    continue
  }

  # Format de sortie CLI : "Token (save now — shown only once): secagent_enr_<hex>"
  TOKEN_VALUE=$(printf '%s' "$TOKEN_OUT" | grep -oE 'secagent_[A-Za-z0-9_]+' | head -1 || true)
  if [ -n "$TOKEN_VALUE" ]; then
    ok "Token enrollment zone $zone créé"
    # Le token vient d'être créé (recréé si révoqué) : replace_secret remplace
    # l'éventuelle ancienne valeur révoquée dans OUTPUT_FILE.
    replace_secret "$SECRET_KEY" "$TOKEN_VALUE"
  else
    fail "Token enrollment zone $zone créé mais valeur non extraite (consulter $container)"
    printf '# %s=<non extrait — vérifier container %s>\n' "$SECRET_KEY" "$container" >> "$OUTPUT_FILE"
  fi
done

# ─── Étape 3 : Token plugin Ansible (sur relay-proxy) ────────────────────────

echo ""
echo "── Étape 3/4 : Token plugin Ansible ─────────────────────────"

# Idempotence : vérifier si un token plugin ansible-qualif actif existe déjà.
# LIMITATION — tokens expirés : même filtre que pour l'enrollment ($NF != "true").
# Un token plugin expiré (non révoqué) sera considéré actif ; révoquer manuellement
# puis relancer si nécessaire.
EXISTING_PLUGIN=$(docker_cli "$RELAY_PROXY" tokens list --role plugin 2>/dev/null \
  | awk '/ansible-qualif/ && $NF != "true"' || true)

if [ -n "$EXISTING_PLUGIN" ]; then
  warn "Token plugin 'ansible-qualif' actif déjà présent — non recréé (idempotent)"
  if ! grep -q "^RELAY_PLUGIN_TOKEN=" "$OUTPUT_FILE" 2>/dev/null; then
    warn "Mais RELAY_PLUGIN_TOKEN absent de ${OUTPUT_FILE} — valeur perdue (token non récupérable)"
    warn "Révoquer l'ancien token et relancer le bootstrap pour en créer un nouveau."
  fi
else
  PLUGIN_OUT=$(docker_cli "$RELAY_PROXY" tokens create \
    --role plugin \
    --description "ansible-qualif" \
    --expires "$EXPIRES_PLUGIN" 2>&1) || {
    fail "Échec création token plugin Ansible"
    printf '\n# RELAY_PLUGIN_TOKEN=<echec creation>\n' >> "$OUTPUT_FILE"
    PLUGIN_OUT=""
  }

  if [ -n "$PLUGIN_OUT" ]; then
    PLUGIN_VALUE=$(printf '%s' "$PLUGIN_OUT" | grep -oE 'secagent_[A-Za-z0-9_]+' | head -1 || true)
    if [ -n "$PLUGIN_VALUE" ]; then
      ok "Token plugin Ansible créé"
      printf '\n' >> "$OUTPUT_FILE"
      # Token venant d'être créé (recréé si supprimé du serveur) : replace_secret.
      replace_secret "RELAY_PLUGIN_TOKEN" "$PLUGIN_VALUE"
    else
      fail "Token plugin créé mais valeur non extraite (consulter $RELAY_PROXY)"
      printf '\n# RELAY_PLUGIN_TOKEN=<non extrait — vérifier container %s>\n' "$RELAY_PROXY" >> "$OUTPUT_FILE"
    fi
  fi
fi

# ─── Étape 4 : Enregistrement des relay nodes sur relay-proxy ─────────────────

echo ""
echo "── Étape 4/4 : Enregistrement des relays ────────────────────"
echo ""
# TODO #124 #125 #140 : En mode pull, le relay-child doit s'auto-enregistrer
# via /ws/relay + relay_hello (repeater-client non implémenté).
# Les relay nodes sont enregistrés ici (DB relay-proxy) mais la connexion WS
# relay→proxy n'est pas établie avant l'implémentation du repeater-client (#124).
#
# TODO #124 #125 : Pour activer le mode push (parent ouvre vers enfant), ajouter :
#   --mode push --url ws://relay-${zone}:7772 --token <relay-parent-token>
# (roles JWT relay-child/relay-parent non implémentés — voir §9.4 SERVER_SPEC.md).
#
# Le JWT relay-child retourné par 'relays add' (mode pull) est sauvegardé dans
# OUTPUT_FILE. Il sera utile pour le repeater-client une fois #124/#125 livrés.
echo "  NOTE : mode=pull enregistré ; connexion WS relay→proxy pending #124/#125/#140"
echo "  Les relays apparaîtront comme 'disconnected' jusqu'à résolution de #124/#125."
echo ""

for zone in $ZONES; do
  relay_id="$zone"
  ZONE_UPPER="$(printf '%s' "$zone" | tr '[:lower:]' '[:upper:]')"
  desc="Zone ${ZONE_UPPER}"

  # Idempotence : relay déjà enregistré ?
  if docker_cli "$RELAY_PROXY" relays list 2>/dev/null | awk -v id="$relay_id" '$0 ~ id {found=1} END {exit !found}' 2>/dev/null; then
    warn "Relay '$relay_id' déjà enregistré — non recréé (idempotent)"
    continue
  fi

  RELAY_OUT=$(docker_cli "$RELAY_PROXY" relays add \
    --id "$relay_id" \
    --description "$desc" 2>&1) || {
    # Gérer le 409 conflict (race condition entre check et création)
    if printf '%s' "$RELAY_OUT" | grep -qiE "already|conflict|409|exists"; then
      warn "Relay '$relay_id' : conflit à l'enregistrement (déjà existant)"
    else
      fail "Relay '$relay_id' : échec enregistrement"
      printf '%s\n' "$RELAY_OUT" >&2
    fi
    continue
  }

  ok "Relay $relay_id enregistré (mode=pull, connexion pending #124/#125)"

  # Sauvegarder le JWT relay-child (affiché une seule fois par le CLI en mode pull).
  # Ce JWT sera utile pour le repeater-client une fois #124/#125 implémentés.
  # TODO #124 #125 : utiliser ce JWT pour l'authentification relay-child→parent.
  RELAY_JWT=$(printf '%s' "$RELAY_OUT" | grep -oE 'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+' | head -1 || true)
  if [ -n "$RELAY_JWT" ]; then
    # Relay venant d'être créé : replace_secret en cas de ré-enregistrement.
    replace_secret "RELAY_JWT_${ZONE_UPPER}" "$RELAY_JWT"
    ok "JWT relay-child zone $zone sauvegardé dans $OUTPUT_FILE (TODO #124/#125)"
  else
    warn "JWT relay-child zone $zone non extrait de la sortie (vérifier si le CLI le fournit en mode pull)"
    printf '# RELAY_JWT_%s=<non extrait — vérifier relays add output>\n' "$ZONE_UPPER" >> "$OUTPUT_FILE"
  fi
done

# ─── Résumé ───────────────────────────────────────────────────────────────────

echo ""
echo "════════════════════════════════════════════════════════════"
echo "  Bootstrap terminé.  PASS=${PASS}  FAIL=${FAIL}"
echo ""
echo "  Secrets écrits dans : ${OUTPUT_FILE} (permissions 600)"
echo "  (Vérifier que ${OUTPUT_FILE} est dans .gitignore)"
echo ""
echo "  Prochaines étapes :"
echo "  1. Copier les RELAY_ENROLLMENT_TOKEN_* depuis ${OUTPUT_FILE} dans DEPLOYMENT/qualif/.env"
echo "  2. Recréer les containers agents (--force-recreate relit .env) :"
echo "     DOCKER_HOST=${DOCKER_HOST} \\"
echo "       docker compose -f DEPLOYMENT/qualif/docker-compose.proxy.yml \\"
echo "       up -d --force-recreate agent-dmz1 agent-dmz2"
echo "  3. Vérifier avec : bash DEPLOYMENT/qualif/smoke-proxy.sh"
echo ""
echo "  LIMITATIONS (issues pendantes) :"
echo "  - Connexion relay→proxy (mode pull) : non implémentée (#124/#125/#140)"
echo "  - Les relays resteront 'disconnected' jusqu'à résolution de #124/#125"
echo "  - 5 checks smoke-proxy.sh échoueront jusqu'à #124/#125"
echo "════════════════════════════════════════════════════════════"
echo ""

[ "$FAIL" -eq 0 ] && exit 0 || exit 1
