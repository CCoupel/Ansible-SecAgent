# Testing AnsibleRelay Plugins

Complete guide for testing the Ansible plugins (connection + inventory) with the deployed relay server.

## Prerequisites

1. **Server deployed** on 192.168.1.218:7770
   ```bash
   curl http://192.168.1.218:7770/health
   # {"status":"ok","db":"ok","nats":"ok"}
   ```

2. **Agents registered and connected**
   ```bash
   docker logs relay-agent-01 | grep "WebSocket connecté"
   docker logs relay-agent-02 | grep "WebSocket connecté"
   docker logs relay-agent-03 | grep "WebSocket connecté"
   ```

3. **Local requirements**
   - Python 3.8+
   - Ansible 2.9+ (or 2.13+ recommended)
   - `pip install httpx websockets python-jose cryptography`

## Quick Test

### Automated Test Script

```bash
chmod +x test_plugins.sh
./test_plugins.sh
```

This will:
1. Generate a JWT plugin token
2. Verify server connectivity
3. Test inventory plugin (GET /api/inventory)
4. Run Ansible playbook with relay connection plugin
5. Execute test tasks on all agents

### Manual Test Steps

#### Step 1: Generate JWT Token

```bash
python3 << 'EOF'
import json, uuid, base64, hmac, hashlib
from datetime import datetime, timezone

jwt_secret = "dev-secret-key-for-qualification-only-change-in-prod"

header_b64 = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).rstrip(b'=')

jti = str(uuid.uuid4())
now = int(datetime.now(timezone.utc).timestamp())
payload = {
    "sub": "test-plugin",
    "role": "plugin",
    "jti": jti,
    "iat": now,
    "exp": now + 3600,
}
payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=')

message = header_b64 + b'.' + payload_b64
signature = hmac.new(jwt_secret.encode(), message, hashlib.sha256).digest()
signature_b64 = base64.urlsafe_b64encode(signature).rstrip(b'=')

token = (header_b64 + b'.' + payload_b64 + b'.' + signature_b64).decode()
print(token)
EOF
```

Save the token to an environment variable:
```bash
export RELAY_TOKEN=$(python3 -c "...")  # Run the above
export RELAY_TOKEN_FILE=/tmp/relay_token.jwt
echo $RELAY_TOKEN > $RELAY_TOKEN_FILE
```

#### Step 2: Test Inventory Plugin

```bash
# Get inventory in Ansible JSON format
curl -s http://192.168.1.218:7770/api/inventory \
  -H "Authorization: Bearer $(cat /tmp/relay_token.jwt)" | jq .

# Expected output:
# {
#   "all": {
#     "hosts": ["qualif-host-01", "qualif-host-02", "qualif-host-03"]
#   },
#   "_meta": {
#     "hostvars": {
#       "qualif-host-01": {
#         "ansible_connection": "relay",
#         "ansible_host": "qualif-host-01",
#         "relay_status": "connected",
#         "relay_last_seen": "2026-03-05T..."
#       },
#       ...
#     }
#   }
# }
```

#### Step 3: Test with Static Inventory

If inventory plugin doesn't work, use static inventory:

```ini
# tests/inventory_relay.ini
[relay_agents]
qualif-host-01 ansible_connection=relay ansible_host=qualif-host-01
qualif-host-02 ansible_connection=relay ansible_host=qualif-host-02
qualif-host-03 ansible_connection=relay ansible_host=qualif-host-03

[all:vars]
relay_server_url=http://192.168.1.218:7770
```

#### Step 4: Run Ansible Playbook

```bash
export RELAY_TOKEN_FILE=/tmp/relay_token.jwt
export ANSIBLE_LIBRARY=./ansible_plugins
export ANSIBLE_CONFIG=./ansible.cfg

# Test with static inventory
ansible-playbook playbooks/test_relay_plugins.yml -i tests/inventory_relay.ini -v

# Or test with dynamic inventory
ansible-playbook playbooks/test_relay_plugins.yml -i relay_inventory -v
```

## What Gets Tested

The playbook `playbooks/test_relay_plugins.yml` tests:

1. **Connection Plugin**
   - Establish connection to agent via relay connection plugin
   - Verify connectivity message

2. **exec_command()**
   - Run `hostname` command
   - Run `uptime` command
   - Run `df` command
   - Verify stdout capture

3. **put_file()**
   - Create test file via relay
   - Verify file exists on agent

4. **fetch_file()**
   - Read file back from agent
   - Verify content integrity

5. **gather_facts**
   - Collect system facts (OS, kernel, CPU, memory)
   - Verify facts are available

6. **become (optional)**
   - Test sudo/become_user functionality
   - Verify privilege escalation

7. **Cleanup**
   - Remove test files

## Expected Output

Successful test run shows:
```
TASK [Test 1: Basic connectivity via relay connection plugin] ***
ok: [qualif-host-01]
ok: [qualif-host-02]
ok: [qualif-host-03]

TASK [Test 2: Get hostname (exec_command)] ***
changed: [qualif-host-01]
changed: [qualif-host-02]
changed: [qualif-host-03]

TASK [Display hostname] ***
ok: [qualif-host-01] => {
    "msg": "qualif-host-01 hostname: qualif-host-01"
}
...

PLAY RECAP ***
qualif-host-01             : ok=10   changed=3   unreachable=0   failed=0
qualif-host-02             : ok=10   changed=3   unreachable=0   failed=0
qualif-host-03             : ok=10   changed=3   unreachable=0   failed=0
```

## Troubleshooting

### "Connection refused" or "No route to host"

Check server is running:
```bash
curl http://192.168.1.218:7770/health
docker logs relay-api | tail -20
```

### "Inventory plugin not found"

Verify ansible.cfg has correct path:
```bash
grep inventory_plugins ansible.cfg
# Should point to ./ansible_plugins/inventory_plugins
```

### "Invalid authentication token"

Regenerate JWT token (it expires after 1 hour):
```bash
./test_plugins.sh  # Regenerates token automatically
```

### "hostname_not_authorized" errors from agents

Agent wasn't pre-authorized. See DEPLOYMENT.md section "Pre-authorize agents".

### Plugin can't decrypt JWT

Check the JWT_SECRET_KEY matches in:
- Server `.env` file
- Agent config (if any)
- Token generation script

## Advanced Testing

### Test Individual Commands

```bash
ansible all -i tests/inventory_relay.ini -m command -a "hostname"
ansible all -i tests/inventory_relay.ini -m shell -a "df -h /"
ansible all -i tests/inventory_relay.ini -m copy -a "content='test' dest=/tmp/test.txt"
```

### Test with Extra Variables

```bash
ansible-playbook playbooks/test_relay_plugins.yml \
  -i tests/inventory_relay.ini \
  -e "relay_server_url=http://192.168.1.218:7770" \
  -e "ansible_connection_timeout=30" \
  -v
```

### Performance Testing

```bash
# Measure plugin execution time
time ansible-playbook playbooks/test_relay_plugins.yml -i tests/inventory_relay.ini

# Run in parallel (default is sequential per agent)
ansible-playbook playbooks/test_relay_plugins.yml \
  -i tests/inventory_relay.ini \
  -f 3  # Run 3 tasks in parallel
```

## Integration Testing

To test full E2E with real Ansible workflow:

```bash
# 1. Verify inventory discovery
ansible-inventory -i relay_inventory --list | jq '.all.hosts[]'

# 2. Verify plugin is used
ansible-playbook playbooks/test_relay_plugins.yml -i relay_inventory -vvv 2>&1 | grep -i relay

# 3. Verify results are captured
ansible-playbook playbooks/test_relay_plugins.yml -i relay_inventory -v 2>&1 | grep -i "ok\|changed"
```

## Next Steps

After successful plugin testing:

1. Run full E2E tests: `pytest tests/phase3/`
2. QA report generation
3. Security review
4. Production deployment (Phase 4 - Kubernetes Helm)
