#!/bin/bash
# Script de test des plugins Ansible (connection + inventory)

set -e

RELAY_SERVER="192.168.1.218:7770"
TOKEN_FILE="/tmp/secagent_token.jwt"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "[*] Ansible-SecAgent Plugin Test"
echo "[*] Server: http://$RELAY_SERVER"
echo ""

# 1. Generate JWT plugin token
echo "[*] Step 1: Generating plugin JWT token..."

python3 << 'EOF' > "$TOKEN_FILE"
import json, uuid, base64, hmac, hashlib
from datetime import datetime, timezone

jwt_secret = "dev-secret-key-for-qualification-only-change-in-prod"

# Header
header_b64 = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).rstrip(b'=')

# Payload
jti = str(uuid.uuid4())
now = int(datetime.now(timezone.utc).timestamp())
payload = {
    "sub": "ansible-plugin-test",
    "role": "plugin",
    "jti": jti,
    "iat": now,
    "exp": now + 3600,
}
payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=')

# Signature
message = header_b64 + b'.' + payload_b64
signature = hmac.new(jwt_secret.encode(), message, hashlib.sha256).digest()
signature_b64 = base64.urlsafe_b64encode(signature).rstrip(b'=')

token = (header_b64 + b'.' + payload_b64 + b'.' + signature_b64).decode()
print(token)
EOF

echo "[OK] Token saved to $TOKEN_FILE"
echo ""

# 2. Verify server is reachable
echo "[*] Step 2: Verifying relay server connectivity..."
if curl -s "http://$RELAY_SERVER/health" | grep -q "ok"; then
    echo "[OK] Server is healthy"
else
    echo "[ERROR] Server is not responding"
    exit 1
fi
echo ""

# 3. Test inventory plugin (port 7772 for inventory plugin)
echo "[*] Step 3: Testing inventory plugin (GET /api/inventory on port 7772)..."
RELAY_INVENTORY="192.168.1.218:7772"
INVENTORY=$(curl -s "http://$RELAY_INVENTORY/api/inventory" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)")

echo "Inventory:"
echo "$INVENTORY" | python3 -m json.tool 2>/dev/null || echo "$INVENTORY"
echo ""

# 4. Check that agents are in inventory
echo "[*] Step 4: Verifying agents in inventory..."
if echo "$INVENTORY" | grep -q "qualif-host"; then
    echo "[OK] Agents found in inventory"
else
    echo "[ERROR] No agents found in inventory"
    exit 1
fi
echo ""

# 5. Run Ansible playbook test (uses secagent_inventory.yml with port 7772 for inventory, 7771 for exec)
echo "[*] Step 5: Running Ansible playbook with relay connection plugin..."
cd "$SCRIPT_DIR"

export RELAY_TOKEN_FILE="$TOKEN_FILE"
export ANSIBLE_LIBRARY="./ansible_plugins"
export ANSIBLE_CONFIG="./ansible.cfg"

echo "[*] Command: ansible-playbook playbooks/test_secagent_plugins.yml -i playbooks/secagent_inventory.yml -v"
echo ""

if ansible-playbook \
  playbooks/test_secagent_plugins.yml \
  -i playbooks/secagent_inventory.yml \
  -v; then
    echo ""
    echo "[OK] All tests completed successfully!"
    echo ""
    echo "Token file: $TOKEN_FILE (valid for 1 hour)"
else
    echo ""
    echo "[ERROR] Some tests failed"
    exit 1
fi
