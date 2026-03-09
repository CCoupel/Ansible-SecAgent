# Ansible Container Deployment Guide

## Overview

Le container Ansible inclut les plugins/binaires relay pour exécuter des playbooks Ansible contre les agents Ansible-SecAgent.

**Architecture :**
```
Ansible Container (relay-ansible)
    ├── secagent_inventory (binaire GO)   — inventaire dynamique
    ├── secagent.py (plugin connection)   — exécution tâches
    ↓
Relay Server (relay-api, port 7770)
    ↓
Relay Agents (qualif-host-01/02/03)
```

**Note** : L'inventaire utilise le binaire `secagent-inventory` (Phase 9, GO) plutôt qu'un plugin Python. Le plugin connection `secagent.py` reste Python (contrainte Ansible API).

---

## Deployment

### 1. Build the Ansible Container

```bash
cd DEPLOYMENT/qualif

# Build image
docker build -f ../../GO/Dockerfile.ansible -t relay-ansible .
```

Ou utiliser docker-compose pour la construction automatique.

### 2. Deploy with Docker Compose

```bash
cd DEPLOYMENT/qualif

# Set environment variables
export RELAY_SERVER_URL="http://relay-api:7770"
export RELAY_ADMIN_TOKEN="your-admin-token-here"

# Deploy container
DOCKER_HOST=tcp://192.168.1.218:2375 docker-compose -f docker-compose.ansible.yml up -d

# Verify deployment
DOCKER_HOST=tcp://192.168.1.218:2375 docker-compose -f docker-compose.ansible.yml ps
```

### 3. Manual Deployment (without docker-compose)

```bash
# Build image
docker build -f ../../GO/Dockerfile.ansible -t relay-ansible .

# Run container
docker run -it \
  -e RELAY_SERVER_URL="http://relay-api:7770" \
  -e RELAY_ADMIN_TOKEN="your-admin-token" \
  -v $(pwd)/playbooks:/ansible/playbooks \
  -v $(pwd)/inventory:/ansible/inventory \
  --name relay-ansible \
  relay-ansible bash
```

---

## Usage

### Inside the Container

```bash
# 1. Enter the container shell
docker exec -it relay-ansible bash

# 2. Create a playbook
cat > /ansible/playbooks/my-playbook.yml <<'EOF'
---
- hosts: all
  gather_facts: yes
  tasks:
    - name: Ping all hosts
      ansible.builtin.ping:

    - name: Get system info
      ansible.builtin.setup:
        filter: ansible_os_family

    - name: Run a command
      ansible.builtin.command: echo "Hello from {{ ansible_hostname }}"
      register: result

    - name: Display result
      ansible.builtin.debug:
        msg: "{{ result.stdout }}"
EOF

# 3. List inventory (via secagent-inventory binary — external inventory)
ansible-inventory -i /usr/local/bin/secagent-inventory --list -y

# Or directly list agents
secagent-inventory --list

# 4. Run playbook (using secagent-inventory binary)
ansible-playbook -i /usr/local/bin/secagent-inventory /ansible/playbooks/my-playbook.yml

# 5. Run with verbosity
ansible-playbook -i /usr/local/bin/secagent-inventory -vvv /ansible/playbooks/my-playbook.yml
```

**Note** : The container uses `secagent-inventory` (GO binary, Phase 9) for dynamic inventory.
This is an external inventory script compatible with Ansible's `--list` / `--host` protocol.

### From Host (docker exec)

```bash
# Run playbook without entering container
docker exec -it relay-ansible \
  ansible-playbook -i /usr/local/bin/secagent-inventory /ansible/playbooks/my-playbook.yml

# List inventory (binary)
docker exec -it relay-ansible \
  secagent-inventory --list

# List inventory (Ansible interface)
docker exec -it relay-ansible \
  ansible-inventory -i /usr/local/bin/secagent-inventory --list -y

# Get facts from all hosts
docker exec -it relay-ansible \
  ansible all -i /usr/local/bin/secagent-inventory -m setup
```

---

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `RELAY_SERVER_URL` | `http://relay-api:7770` | Relay server API URL |
| `RELAY_TOKEN` | (required) | Plugin token for secagent-inventory (Bearer auth) |
| `RELAY_CA_BUNDLE` | (empty) | Path to CA certificate bundle (for TLS) |
| `RELAY_ONLY_CONNECTED` | `false` | Only include connected agents in inventory |
| `RELAY_INSECURE_TLS` | `false` | Disable TLS verification (TESTS ONLY) |
| `ANSIBLE_LIBRARY` | `/ansible/ansible_plugins/modules` | Ansible modules directory |
| `ANSIBLE_PLUGINS` | `/ansible/ansible_plugins` | Ansible plugins directory |
| `ANSIBLE_HOST_KEY_CHECKING` | `false` | Disable SSH key checking (for agents) |

### ansible.cfg

Located in `/ansible/ansible.cfg` :

```ini
[defaults]
# Using secagent-inventory binary (external inventory script)
inventory = /usr/local/bin/secagent-inventory

# Plugins for connection (still needed for execution)
connection_plugins = ./ansible_plugins/connection_plugins

host_key_checking = False
timeout = 30

[secagent_connection]
secagent_server_url = http://relay-api:7770
plugin_token = $RELAY_ADMIN_TOKEN
secagent_ca_bundle =
```

**Inventory method** : External binary (`secagent-inventory`) instead of plugin. See `DOC/inventory/INVENTORY_SPEC.md` for details.

---

## Directory Structure

```
DEPLOYMENT/qualif/
├── docker-compose.ansible.yml   ← Ansible container composition
├── playbooks/                   ← User playbooks (mounted volume)
│   └── my-playbook.yml
├── inventory/                   ← Static inventory files (mounted volume)
│   └── hosts.yml
└── roles/                       ← Ansible roles (mounted volume)
    └── common/
```

### Create Playbook Directory

```bash
cd DEPLOYMENT/qualif
mkdir -p playbooks inventory roles
```

---

## Examples

### Example 1 : Simple Ping Playbook

```bash
docker exec -it relay-ansible bash

# Create playbook
cat > /ansible/playbooks/ping.yml <<'EOF'
---
- hosts: all
  tasks:
    - name: Ping all agents
      ansible.builtin.ping:
EOF

# Run playbook
ansible-playbook -i secagent_inventory /ansible/playbooks/ping.yml
```

**Expected Output :**
```
PLAY [all] ****

TASK [Ping all agents] ****
ok: [qualif-host-01]
ok: [qualif-host-02]
ok: [qualif-host-03]

PLAY RECAP ****
qualif-host-01 : ok=1 changed=0
qualif-host-02 : ok=1 changed=0
qualif-host-03 : ok=1 changed=0
```

### Example 2 : Execute Commands on Agents

```yaml
---
- hosts: all
  gather_facts: yes
  tasks:
    - name: Get system uptime
      ansible.builtin.command: uptime
      register: uptime

    - name: Display uptime
      ansible.builtin.debug:
        msg: "{{ inventory_hostname }} uptime: {{ uptime.stdout }}"

    - name: Create test file
      ansible.builtin.copy:
        content: "Hello from Ansible on {{ inventory_hostname }}\n"
        dest: /tmp/ansible-test.txt
        mode: "0644"

    - name: Read test file
      ansible.builtin.slurp:
        src: /tmp/ansible-test.txt
      register: testfile

    - name: Display file content
      ansible.builtin.debug:
        msg: "{{ testfile['content'] | b64decode }}"
```

### Example 3 : Parallel Execution

```bash
# Execute on multiple hosts in parallel (3 processes)
ansible-playbook -i secagent_inventory -f 3 /ansible/playbooks/my-playbook.yml

# Execute on single host
ansible-playbook -i secagent_inventory -l qualif-host-01 /ansible/playbooks/my-playbook.yml
```

---

## Troubleshooting

### Issue : "secagent_inventory not found"

```
ERROR! Unable to parse /ansible/secagent_inventory as an inventory source
```

**Solution :** Vérifier que le fichier `ansible_plugins/inventory_plugins/secagent_inventory.py` est monté.

```bash
docker exec relay-ansible ls -la /ansible/ansible_plugins/inventory_plugins/
```

### Issue : "Connection to relay-api failed"

```
Failed to connect to relay-api:7770
```

**Solution :** Vérifier la variable `RELAY_SERVER_URL` et que le serveur est accessible.

```bash
docker exec relay-ansible curl -v http://relay-api:7770/health
```

### Issue : "Inventory returned empty"

```
No hosts matched
```

**Solution :** Vérifier que les agents sont connectés au serveur.

```bash
docker exec relay-api /app/secagent-server minions list
```

### Issue : "Permission denied on playbook"

```
Permission denied: /ansible/playbooks/my-playbook.yml
```

**Solution :** Vérifier les permissions du fichier sur le host.

```bash
# On host
chmod +r DEPLOYMENT/qualif/playbooks/my-playbook.yml
```

---

## Performance Tips

### 1. Increase Parallel Execution

```bash
# Default : serial execution
# Parallel with 5 processes
ansible-playbook -i secagent_inventory -f 5 /ansible/playbooks/my-playbook.yml
```

### 2. Use Async for Long Tasks

```yaml
tasks:
  - name: Long running task
    ansible.builtin.command: /usr/bin/long-running-command
    async: 300  # timeout after 5 minutes
    poll: 0     # don't wait for result
    register: long_task

  - name: Wait for long task
    ansible.builtin.async_status:
      jid: "{{ long_task.ansible_job_id }}"
    register: job_result
    until: job_result.finished
    retries: 30
    delay: 10
```

### 3. Use Caching

```bash
# Enable fact caching
export ANSIBLE_FACT_CACHING=jsonfile
export ANSIBLE_FACT_CACHING_CONNECTION=/tmp/ansible_cache
export ANSIBLE_FACT_CACHING_TIMEOUT=86400  # 24 hours
```

---

## Integration with CI/CD

### GitLab CI Example

```yaml
ansible_deploy:
  stage: deploy
  image: relay-ansible:latest
  script:
    - ansible-playbook -i secagent_inventory /ansible/playbooks/my-playbook.yml
  only:
    - main
  environment:
    name: production
    url: http://192.168.1.218:7770
```

### Jenkins Example

```groovy
stage('Ansible Deploy') {
    steps {
        script {
            sh '''
                docker exec relay-ansible \
                  ansible-playbook -i secagent_inventory /ansible/playbooks/my-playbook.yml
            '''
        }
    }
}
```

---

## Cleanup

### Stop and Remove Container

```bash
DOCKER_HOST=tcp://192.168.1.218:2375 docker-compose -f docker-compose.ansible.yml down
```

### Remove Image

```bash
docker rmi relay-ansible
```

### Remove All Data

```bash
DOCKER_HOST=tcp://192.168.1.218:2375 docker-compose -f docker-compose.ansible.yml down -v
```

---

## Reference

- [Ansible Documentation](https://docs.ansible.com/)
- [Ansible-SecAgent Plugin Documentation](../../PYTHON/ansible.cfg)
- [Connection Plugin Spec](../../PYTHON/ansible_plugins/connection_plugins/secagent.py)
- [Inventory Plugin Spec](../../DOC/plugins/PLUGINS_SPEC.md)
