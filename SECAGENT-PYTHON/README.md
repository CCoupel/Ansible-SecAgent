# Ansible-SecAgent — Python MVP (Phase 1-3)

**Status**: ✅ COMPLETE — Production-ready

This directory contains the original Python implementation of Ansible-SecAgent, developed during Phase 1-3.

## Directory Structure

```
PYTHON/
├── agent/                      # Relay agent client (systemd daemon)
│   ├── secagent_agent.py          # Main entry point
│   ├── async_registry.py       # Async task registry
│   ├── facts_collector.py      # System facts collection
│   └── secagent-minion.service     # Systemd unit file
├── server/                     # Relay server (FastAPI + NATS)
│   ├── api/
│   │   ├── main.py             # FastAPI application
│   │   ├── routes_register.py  # JWT, enrollment, auth
│   │   ├── routes_exec.py      # Task execution endpoints
│   │   ├── routes_inventory.py # Ansible inventory
│   │   └── ws_handler.py       # WebSocket connections
│   ├── db/
│   │   └── agent_store.py      # SQLite persistence
│   └── broker/
│       └── nats_client.py      # NATS JetStream client
├── ansible_plugins/            # Ansible integration
│   ├── connection_plugins/
│   │   └── secagent.py            # Custom connection plugin
│   └── inventory_plugins/
│       └── secagent_inventory.py  # Dynamic inventory
├── tests/                      # Test suite
│   ├── unit/
│   ├── integration/
│   └── robustness/
├── docker-compose.yml          # Local dev environment
├── Dockerfile                  # Server container image
└── .env                        # Configuration

```

## Quick Start

### Prerequisites
- Python 3.11+
- NATS server running (via docker-compose)
- Ansible 2.9+

### Install Dependencies
```bash
pip install -r requirements.txt
```

### Run Server
```bash
# With NATS and database
docker-compose up -d

# Start server
python -m server.api.main
```

### Run Agent
```bash
python agent/secagent_agent.py \
  --server=ws://localhost:7770 \
  --hostname=minion-01
```

### Run Ansible Playbook
```bash
export ANSIBLE_PLUGINS=./ansible_plugins
ansible-playbook -i inventory.yml playbooks/site.yml
```

## Architecture

### Agent (secagent_agent.py)
- Registers with server via POST /api/register
- Opens persistent WebSocket connection (WSS)
- Receives and executes tasks
- Streams stdout, uploads/fetches files
- Auto-reconnect with exponential backoff

### Server (FastAPI)
- Enrollment endpoint: POST /api/register
- Admin pre-authorization: POST /api/admin/authorize
- Task execution: POST /api/exec/{hostname}
- File transfer: POST /api/upload, POST /api/fetch
- Dynamic inventory: GET /api/inventory
- WebSocket: /ws/agent
- NATS JetStream for HA message routing

### Plugins (Ansible)
- Custom connection plugin: `ansible_connection: relay`
- Dynamic inventory plugin: reads from /api/inventory
- Replaces SSH with relay protocol

## Security

- **JWT HS256**: All API requests signed and verified
- **RSA-4096 OAEP/SHA256**: Agent enrollment encryption
- **Bearer tokens**: Admin authorization
- **JTI blacklist**: Token revocation support
- **WebSocket WSS**: TLS-encrypted agent connections
- **mTLS**: NATS connections in production (configurable)

## Configuration

### Environment Variables
- `JWT_SECRET_KEY`: Secret for JWT signing
- `ADMIN_TOKEN`: Bearer token for admin endpoints
- `NATS_URL`: NATS server URL (default: nats://nats:4222)
- `DATABASE_URL`: SQLite path (default: sqlite:////data/relay.db)
- `LOG_LEVEL`: Logging level (default: INFO)

### File Structure
- `authorized_keys` table: Pre-authorized agent public keys
- `agents` table: Enrolled agents with status
- `blacklist` table: Revoked JWT identifiers

## Testing

```bash
# Unit tests
pytest tests/unit/

# Integration tests
pytest tests/integration/

# E2E tests
pytest tests/robustness/ -v
```

## Performance Baseline

- **Latency**: ~100ms round-trip (task dispatch → result)
- **Memory**: ~100MB per server instance
- **Throughput**: ~500 tasks/min per agent
- **Concurrency**: ~50 agents per relay node

## Phase History

| Phase | Component | Status | Date |
|-------|-----------|--------|------|
| Phase 1 | secagent-minion | ✅ Complete | 2026-03-03 |
| Phase 2 | secagent-server | ✅ Complete | 2026-03-03 |
| Phase 3 | ansible_plugins | ✅ Complete | 2026-03-04 |

## Next Phase: GO Migration (Phase 7)

See `GO/README.md` for the high-performance GO rewrite.

---

**Last Updated**: 2026-03-05
**Maintainer**: Ansible-SecAgent Team
