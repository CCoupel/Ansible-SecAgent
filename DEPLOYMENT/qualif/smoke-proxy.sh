#!/usr/bin/env bash
# smoke-proxy.sh — Smoke test topologie multi-zones (issue #120)
#
# Vérifie :
#   1. Health des 3 relays (proxy + dmz1 + dmz2)
#   2. Agents enregistrés dans chaque relay DMZ (via agrégation proxy)
#   3. relay-proxy agrège les agents des 2 zones via GET /api/inventory
#   4. Isolation réseau : relay-dmz1 ne voit pas relay-dmz2
#
# Usage :
#   bash smoke-proxy.sh
#   ADMIN_TOKEN=mytoken bash smoke-proxy.sh
#
# Variables d'environnement :
#   PROXY_API    : URL API publique relay-proxy (défaut: http://192.168.1.218:7780)
#   PROXY_ADMIN  : URL API admin relay-proxy    (défaut: http://192.168.1.218:7781)
#   DMZ1_API     : URL API relay-dmz1           (défaut: http://192.168.1.218:7783)
#   DMZ2_API     : URL API relay-dmz2           (défaut: http://192.168.1.218:7784)
#   ADMIN_TOKEN  : token Bearer admin           (défaut: qualif-admin-token-ansiblerelay-2026)
#   WAIT_AGENTS  : secondes à attendre avant de compter les agents (défaut: 5)
#   DOCKER_HOST  : remote Docker daemon         (défaut: tcp://192.168.1.218:2375)

set -euo pipefail

PROXY_API="${PROXY_API:-http://192.168.1.218:7780}"
PROXY_ADMIN="${PROXY_ADMIN:-http://192.168.1.218:7781}"
DMZ1_API="${DMZ1_API:-http://192.168.1.218:7783}"
DMZ2_API="${DMZ2_API:-http://192.168.1.218:7784}"
ADMIN_TOKEN="${ADMIN_TOKEN:-qualif-admin-token-ansiblerelay-2026}"
WAIT_AGENTS="${WAIT_AGENTS:-5}"

PASS=0
FAIL=0

# ─────────────────────────────────────────────────────────────────────────────
# Helpers — utilise $((PASS + 1)) au lieu de ((PASS++)) pour éviter set -e exit
# ─────────────────────────────────────────────────────────────────────────────

ok()   { echo "  ✓ $*"; PASS=$((PASS + 1)); }
fail() { echo "  ✗ $*"; FAIL=$((FAIL + 1)); }

# count_zone_agents <relay_id> — compte les agents par zone via l'inventaire agrégé proxy
count_zone_agents() {
  local relay_id="$1"
  local raw
  raw=$(curl -sf --max-time 5 \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    "${PROXY_ADMIN}/api/inventory" 2>/dev/null) || { echo "0"; return; }

  echo "$raw" | python3 -c "
import json, sys
data = json.load(sys.stdin)
hosts = data.get('_meta', {}).get('hostvars', {})
count = sum(1 for h in hosts.values() if h.get('secagent_relay_id') == '$relay_id')
print(count)
" 2>/dev/null || echo "0"
}

# count_proxy_agents — compte le total d'agents agrégés sur le proxy
count_proxy_agents() {
  local raw
  raw=$(curl -sf --max-time 5 \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    "${PROXY_ADMIN}/api/inventory" 2>/dev/null) || { echo "0"; return; }

  echo "$raw" | python3 -c "
import json, sys
data = json.load(sys.stdin)
print(len(data.get('all', {}).get('hosts', [])))
" 2>/dev/null || echo "0"
}

# ─────────────────────────────────────────────────────────────────────────────
# Étape 1 — Health checks
# ─────────────────────────────────────────────────────────────────────────────

echo ""
echo "=== Smoke Test — Multi-Zone Proxy (issue #120) ==="
echo ""
echo "── Étape 1/4 : Health checks ──────────────────────────────"

for entry in "relay-proxy:${PROXY_API}" "relay-dmz1:${DMZ1_API}" "relay-dmz2:${DMZ2_API}"; do
  svc="${entry%%:*}"
  url="${entry#*:}"
  if curl -sf --max-time 5 "${url}/health" > /dev/null 2>&1; then
    ok "${svc} /health → OK"
  else
    fail "${svc} /health → ÉCHEC (URL: ${url})"
  fi
done

# ─────────────────────────────────────────────────────────────────────────────
# Étape 2 — Attendre l'enrollment des agents
# ─────────────────────────────────────────────────────────────────────────────

echo ""
echo "── Étape 2/4 : Attente enrollment agents (${WAIT_AGENTS}s) ──────────────"
sleep "${WAIT_AGENTS}"

# ─────────────────────────────────────────────────────────────────────────────
# Étape 3 — Agents par zone + agrégation proxy
# ─────────────────────────────────────────────────────────────────────────────

echo ""
echo "── Étape 3/4 : Agents par zone + agrégation proxy ────────"

DMZ1_COUNT=$(count_zone_agents "dmz1")
DMZ2_COUNT=$(count_zone_agents "dmz2")
PROXY_COUNT=$(count_proxy_agents)

echo "  relay-dmz1  (via proxy) : ${DMZ1_COUNT} agent(s)"
echo "  relay-dmz2  (via proxy) : ${DMZ2_COUNT} agent(s)"
echo "  relay-proxy (agrégé)    : ${PROXY_COUNT} agent(s)"

if [ "${DMZ1_COUNT}" -gt 0 ]; then
  ok "Agents présents dans DMZ1 (${DMZ1_COUNT})"
else
  fail "Aucun agent dans DMZ1"
fi

if [ "${DMZ2_COUNT}" -gt 0 ]; then
  ok "Agents présents dans DMZ2 (${DMZ2_COUNT})"
else
  fail "Aucun agent dans DMZ2"
fi

TOTAL_DMZ=$((DMZ1_COUNT + DMZ2_COUNT))
if [ "${PROXY_COUNT}" -ge "${TOTAL_DMZ}" ] && [ "${PROXY_COUNT}" -gt 0 ]; then
  ok "relay-proxy agrège ${PROXY_COUNT}/${TOTAL_DMZ} agents (DMZ1 + DMZ2)"
else
  fail "relay-proxy voit ${PROXY_COUNT} agents — attendu >= ${TOTAL_DMZ}"
fi

# Vérification status relays dans le proxy
echo ""
RELAY_STATUS=$(curl -sf --max-time 5 \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  "${PROXY_ADMIN}/api/admin/relays/status" 2>/dev/null) || RELAY_STATUS="{}"

DMZ1_STATUS=$(echo "$RELAY_STATUS" | python3 -c "
import json,sys
data=json.load(sys.stdin)
r=[x for x in data.get('relays',[]) if x['relay_id']=='dmz1']
print(r[0]['status'] if r else 'unknown')
" 2>/dev/null || echo "unknown")

DMZ2_STATUS=$(echo "$RELAY_STATUS" | python3 -c "
import json,sys
data=json.load(sys.stdin)
r=[x for x in data.get('relays',[]) if x['relay_id']=='dmz2']
print(r[0]['status'] if r else 'unknown')
" 2>/dev/null || echo "unknown")

if [ "${DMZ1_STATUS}" = "connected" ]; then
  ok "relay-dmz1 status=connected (routage WebSocket actif)"
else
  fail "relay-dmz1 status=${DMZ1_STATUS} (attendu: connected)"
fi

if [ "${DMZ2_STATUS}" = "connected" ]; then
  ok "relay-dmz2 status=connected (routage WebSocket actif)"
else
  fail "relay-dmz2 status=${DMZ2_STATUS} (attendu: connected)"
fi

# ─────────────────────────────────────────────────────────────────────────────
# Étape 4 — Isolation réseau : relay-dmz1 ne peut pas joindre relay-dmz2
# ─────────────────────────────────────────────────────────────────────────────

echo ""
echo "── Étape 4/4 : Isolation réseau ──────────────────────────"

DOCKER_HOST_VAR="${DOCKER_HOST:-tcp://192.168.1.218:2375}"

# Détection docker CLI (local ou via DOCKER_HOST)
if DOCKER_HOST="${DOCKER_HOST_VAR}" docker info > /dev/null 2>&1; then
  # relay-dmz1 n'est que sur dmz1-net — relay-dmz2 n'est que sur dmz2-net
  # wget avec timeout court : doit échouer (NXDOMAIN ou refus connexion)
  if DOCKER_HOST="${DOCKER_HOST_VAR}" docker exec relay-dmz1 \
       wget -q --timeout=3 -O- "http://relay-dmz2:7770/health" > /dev/null 2>&1; then
    fail "Isolation DMZ — relay-dmz1 peut joindre relay-dmz2 (attendu: ÉCHEC)"
  else
    ok "Isolation DMZ — relay-dmz1 ne voit pas relay-dmz2 (réseaux isolés)"
  fi
else
  echo "  ~ docker CLI non disponible — test isolation ignoré"
  echo "    (Pour tester : DOCKER_HOST=${DOCKER_HOST_VAR} bash smoke-proxy.sh)"
fi

# ─────────────────────────────────────────────────────────────────────────────
# Bilan
# ─────────────────────────────────────────────────────────────────────────────

echo ""
echo "════════════════════════════════════════════════════════════"
echo "  RÉSULTAT : ${PASS} PASS  /  ${FAIL} FAIL"
echo "════════════════════════════════════════════════════════════"
echo ""

[ "${FAIL}" -eq 0 ] && exit 0 || exit 1
