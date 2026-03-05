#!/bin/bash
# E2E Multi-Agent Test Runner
#
# Exécute le playbook Ansible sur les agents relay distants
# Pré-conditions :
#   - relay-api déployé sur 192.168.1.218 via docker-compose
#   - relay-agent-02 et relay-agent-03 enregistrés et connectés
#   - Ansible installé localement avec les plugins relay
#

set -e

RELAY_SERVER="192.168.1.218:7770"
JWT_SECRET_KEY="dev-secret-key-for-qualification-only-change-in-prod"
RELAY_TOKEN_FILE="/tmp/relay_e2e_plugin_token.jwt"

echo "[*] Generating plugin JWT token..."

# Générer un JWT plugin valide pour authentifier les appels REST au serveur
# Note : en production, ce token serait fourni sécurisément (vault, secrets manager, etc.)

python3 << 'PYEOF'
import json
import uuid
from datetime import datetime, timezone
import base64
import hmac
import hashlib

JWT_SECRET_KEY = "dev-secret-key-for-qualification-only-change-in-prod"
JWT_ALGORITHM = "HS256"
JWT_TTL_SECONDS = 3600

# Header
header = {"alg": "HS256", "typ": "JWT"}
header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b'=')

# Payload
jti = str(uuid.uuid4())
now = int(datetime.now(timezone.utc).timestamp())
payload = {
    "sub": "e2e-test-plugin",
    "role": "plugin",
    "jti": jti,
    "iat": now,
    "exp": now + JWT_TTL_SECONDS,
}
payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=')

# Signature
message = header_b64 + b'.' + payload_b64
signature = hmac.new(JWT_SECRET_KEY.encode(), message, hashlib.sha256).digest()
signature_b64 = base64.urlsafe_b64encode(signature).rstrip(b'=')

# Token
token = (header_b64 + b'.' + payload_b64 + b'.' + signature_b64).decode()
print(token)
PYEOF

# Si Python 3 n'est pas disponible, créer un token manuellement
# (en production, ceci serait fourni par le système)
if [ ! -f "$RELAY_TOKEN_FILE" ]; then
    echo "WARNING: Could not generate JWT token. Using placeholder (will fail)."
    echo "DUMMY_TOKEN" > "$RELAY_TOKEN_FILE"
fi

export RELAY_TOKEN_FILE="$RELAY_TOKEN_FILE"
export ANSIBLE_LIBRARY="$(pwd)/ansible_plugins"
export ANSIBLE_PLUGINS="$(pwd)/ansible_plugins"

echo "[*] Running Ansible playbook on relay agents..."
echo "    Relay server: http://$RELAY_SERVER"
echo "    Agents: qualif-host-02, qualif-host-03"

# Exécuter le playbook
ansible-playbook -i tests/inventory_relay.ini tests/e2e_multiagent_test.yml \
  -e "relay_server_url=http://$RELAY_SERVER" \
  -v

echo "[*] E2E test completed successfully!"
