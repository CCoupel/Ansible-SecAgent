# AnsibleRelay Deployment Guide

## Overview

Ce répertoire contient les scripts et configurations pour déployer AnsibleRelay sur qualif (192.168.1.218).

**Composants :**
- **Relay Server** : serveur central (NATS + relay-api + caddy)
- **Relay Agents** : agents clients (relay-agent-01/02/03)
- **Ansible Container** : container Ansible avec plugins relay pour exécuter des playbooks

---

## Quick Start

### Deploy Everything

```bash
cd DEPLOYMENT

# Set environment variables (if needed)
export DOCKER_HOST=tcp://192.168.1.218:2375
export RELAY_ADMIN_TOKEN=your-admin-token-here

# Deploy server, agents, and Ansible container
./deploy.sh all

# Check status
./deploy.sh status
```

### Deploy Individual Components

```bash
# Deploy server only
./deploy.sh server

# Deploy agents only
./deploy.sh minion

# Deploy Ansible container only
./deploy.sh ansible

# Stop everything
./deploy.sh stop
```

---

## Directory Structure

```
DEPLOYMENT/
├── deploy.sh                      ← Main deployment script
├── deploy.bat                     ← Windows deployment script
├── README.md                      ← This file
├── ANSIBLE_DEPLOYMENT.md          ← Ansible container guide
├── qualif/                        ← Qualif environment config
│   ├── docker-compose.server.yml  ← Server composition (nats + relay-api)
│   ├── docker-compose.minion.yml  ← Agents composition
│   ├── docker-compose.ansible.yml ← Ansible container composition
│   ├── playbooks/                 ← User playbooks (created on deploy)
│   ├── inventory/                 ← Inventory files (created on deploy)
│   └── roles/                     ← Ansible roles (created on deploy)
└── (other environments)
```

---

## Components

### 1. Relay Server

**What it does :**
- Central relay server for agents
- NATS JetStream for message bus
- REST API for agent enrollment + task execution
- WebSocket listener for agent connections

**Ports :**
- 7770 : Agent API (enrollment, task execution)
- 7771 : Plugin API (inventory, execution)
- 7772 : WebSocket (agent connections)
- 7443 : HTTPS (reverse proxy via caddy)

**Environment :**
- `JWT_SECRET_KEY` : HMAC-SHA256 secret for JWT signing
- `ADMIN_TOKEN` : Bearer token for admin API access
- `NATS_URL` : NATS server URL (default: nats://relay-nats:4222)
- `DATABASE_URL` : SQLite database file (default: /data/relay.db)

### 2. Relay Agents

**What they do :**
- Connect to relay server via WebSocket
- Execute tasks received from relay server
- Report results back to relay server
- Persist state locally

**Containers :**
- `relay-agent-01` (qualif-host-01)
- `relay-agent-02` (qualif-host-02)
- `relay-agent-03` (qualif-host-03)

**Environment :**
- `RELAY_SERVER_URL` : Server address (default: http://relay-api:7770)
- `RELAY_ENROLLMENT_TOKEN` : Token for enrollment (Phase 10)
- `HOSTNAME` : Agent hostname

### 3. Ansible Container

**What it does :**
- Provides Ansible with relay plugins (connection + inventory)
- Executes playbooks against relay agents
- Supports all standard Ansible features

**Features :**
- Pre-installed plugins (relay.py, relay_inventory.py)
- Mounted playbooks, inventory, and roles
- Ansible CLI and modules

**Usage :**
```bash
# Enter container
docker exec -it relay-ansible bash

# Run playbook
ansible-playbook -i relay_inventory /ansible/playbooks/my-playbook.yml

# List inventory
ansible-inventory -i relay_inventory -y

# Run command on all agents
ansible all -i relay_inventory -m command -a "uptime"
```

---

## Deployment Workflow

### 1. Prepare Environment

```bash
cd DEPLOYMENT

# Set Docker host
export DOCKER_HOST=tcp://192.168.1.218:2375

# Set credentials (optional, defaults available)
export JWT_SECRET_KEY="your-secret-key"
export ADMIN_TOKEN="your-admin-token"
export RELAY_ADMIN_TOKEN="$ADMIN_TOKEN"  # For Ansible container
```

### 2. Deploy Relay Server

```bash
./deploy.sh server

# Wait for health check
sleep 15

# Verify server is running
./deploy.sh status
```

### 3. Deploy Relay Agents

```bash
./deploy.sh minion

# Check agent status
docker logs relay-agent-01 | tail -20
```

### 4. Deploy Ansible Container

```bash
./deploy.sh ansible

# Test Ansible
docker exec -it relay-ansible ansible-inventory -i relay_inventory -y
```

### 5. Verify Full Stack

```bash
# Check all containers
./deploy.sh status

# Check relay inventory
docker exec -it relay-ansible ansible-inventory -i relay_inventory -y

# Test playbook execution
docker exec -it relay-ansible ansible-playbook -i relay_inventory \
  -c relay playbooks/ping.yml  # Use relay connection plugin
```

---

## Configuration Files

### server/docker-compose.yml

Server configuration with NATS and relay-api.

**Key services :**
- `nats` : JetStream message broker
- `relay-api` : Python FastAPI server (multi-port)
- `caddy` : Reverse proxy (optional)

**Volumes :**
- `nats_data` : NATS persistence
- `relay_data` : Server database + state

### minion/docker-compose.yml

Agent configuration with 3 containers.

**Key services :**
- `relay-agent-01/02/03` : GO agent instances

**Environment :**
- `RELAY_ENROLLMENT_TOKEN` : Required for enrollment (Phase 10)
- `HOSTNAME` : Unique agent identifier

### qualif/docker-compose.ansible.yml

Ansible container with plugins.

**Volumes :**
- `/ansible/playbooks` : User playbooks
- `/ansible/inventory` : Static inventory
- `/ansible/roles` : Ansible roles
- `/ansible/ansible_plugins` : Relay plugins (read-only)

---

## Troubleshooting

### Server won't start

```bash
# Check server logs
docker logs relay-api

# Check NATS
docker logs relay-nats

# Verify ports are free
netstat -an | grep 777
```

### Agents won't connect

```bash
# Check agent logs
docker logs relay-agent-01

# Verify enrollment token (Phase 10)
echo $RELAY_ENROLLMENT_TOKEN

# Check server is accepting connections
curl http://192.168.1.218:7770/health
```

### Ansible container issues

```bash
# Check container logs
docker logs relay-ansible

# Verify plugins are mounted
docker exec relay-ansible ls /ansible/ansible_plugins/

# Test ansible installation
docker exec relay-ansible ansible --version

# Test inventory plugin
docker exec relay-ansible ansible-inventory -i relay_inventory -y
```

---

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DOCKER_HOST` | No | `tcp://192.168.1.218:2375` | Docker daemon address |
| `JWT_SECRET_KEY` | Yes | (generated) | JWT signing secret |
| `ADMIN_TOKEN` | Yes | (generated) | Admin API token |
| `RELAY_ENROLLMENT_TOKEN` | No | (env) | Agent enrollment token |
| `RELAY_ADMIN_TOKEN` | No | `$ADMIN_TOKEN` | Ansible container token |
| `RELAY_SERVER_URL` | No | `http://relay-api:7770` | Server URL for Ansible |
| `NATS_URL` | No | `nats://relay-nats:4222` | NATS server URL |
| `DATABASE_URL` | No | `/data/relay.db` | SQLite database file |

---

## Logs and Debugging

### View Server Logs

```bash
./deploy.sh logs-server
```

### View Agent Logs

```bash
./deploy.sh logs-agent 01  # or 02, 03
```

### View Ansible Logs

```bash
./deploy.sh logs-ansible
```

### Follow Logs in Real-Time

```bash
docker logs -f relay-api       # Server
docker logs -f relay-agent-01  # Agent
docker logs -f relay-ansible   # Ansible container
```

---

## Security Considerations

### Credentials

- Store `JWT_SECRET_KEY` and `ADMIN_TOKEN` securely
- Rotate tokens regularly (see `relay-server security keys rotate`)
- Use environment variables or `.env` files, not hardcoded values

### Network

- `DOCKER_HOST` should point to a secure Docker socket
- Use TLS for production (caddy handles this)
- Restrict access to ports 7770-7772

### Enrollment

- Use enrollment tokens (Phase 10) for agent registration
- Rotate enrollment tokens periodically
- One-shot tokens are consumed after first use
- Permanent tokens can be revoked

---

## Advanced Topics

### Custom Playbooks

See [ANSIBLE_DEPLOYMENT.md](./ANSIBLE_DEPLOYMENT.md) for playbook examples.

### Performance Tuning

```bash
# Parallel execution
ansible-playbook -i relay_inventory -f 5 playbooks/my-playbook.yml

# Enable fact caching
export ANSIBLE_FACT_CACHING=jsonfile
export ANSIBLE_FACT_CACHING_CONNECTION=/tmp/ansible_cache
```

### CI/CD Integration

See [ANSIBLE_DEPLOYMENT.md](./ANSIBLE_DEPLOYMENT.md) for GitLab/Jenkins examples.

---

## Support

For issues or questions:

1. Check logs with `./deploy.sh logs-*`
2. See [ANSIBLE_DEPLOYMENT.md](./ANSIBLE_DEPLOYMENT.md) for Ansible-specific help
3. Review [DEPLOYMENT/qualif/test_plugins.sh](./qualif/test_plugins.sh) for test examples
4. Check project documentation in [DOC/](../DOC/)

---

## Related Documentation

- [ANSIBLE_DEPLOYMENT.md](./ANSIBLE_DEPLOYMENT.md) — Detailed Ansible guide
- [DOC/ARCHITECTURE.md](../DOC/common/ARCHITECTURE.md) — System architecture
- [DOC/PLUGINS_SPEC.md](../DOC/plugins/PLUGINS_SPEC.md) — Plugin specifications
- [DOC/AGENT_SPEC.md](../DOC/agent/AGENT_SPEC.md) — Agent specifications
- [DOC/SERVER_SPEC.md](../DOC/server/SERVER_SPEC.md) — Server specifications
