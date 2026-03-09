# Ansible-SecAgent

Système permettant d'exécuter des playbooks Ansible sur des hôtes distants sans connexion SSH entrante. Les agents clients initient eux-mêmes la connexion vers un serveur central (modèle **Salt Minion**, connexions inversées).

## Quick Start

### 1. Serveur
```bash
cd ansible_server
docker compose up --build -d
curl http://localhost:7770/health
```

### 2. Agents
```bash
cd ansible_minion
docker compose up --build -d
docker logs secagent-minion-01  # Vérifier la connexion
```

## Structure du Projet

```
ansible-secagent/
├── ansible_server/              # Déploiement serveur (Phase 2)
│   ├── docker-compose.yml       - nats, relay-api, caddy
│   └── .env                     - Variables d'environnement
│
├── ansible_minion/              # Déploiement agents (Phase 1)
│   └── docker-compose.yml       - secagent-minion-01/02/03
│
├── agent/                       # Code agent client
│   ├── secagent_agent.py           - Point d'entrée principal
│   ├── async_registry.py        - Registre des tâches async
│   ├── facts_collector.py       - Collecte system facts
│   ├── agent_entrypoint.py      - Wrapper d'initialisation
│   └── Dockerfile.agent         - Image Docker agent
│
├── server/                      # Code serveur FastAPI
│   ├── api/
│   │   ├── main.py              - Application FastAPI
│   │   ├── routes_register.py   - Enrollment + JWT auth
│   │   ├── ws_handler.py        - Gestionnaire WebSocket
│   │   ├── routes_exec.py       - Task exec/upload/fetch
│   │   └── routes_inventory.py  - Inventaire dynamique
│   ├── db/
│   │   └── agent_store.py       - Modèles + ORM SQLite
│   ├── broker/
│   │   └── nats_client.py       - Client NATS JetStream
│   ├── Dockerfile               - Image Docker server
│   └── requirements.txt          - Dépendances Python
│
├── ansible_plugins/             # Plugins Ansible
│   ├── connection_plugins/
│   │   └── secagent.py             - ConnectionBase (remplace SSH)
│   └── inventory_plugins/
│       └── secagent_inventory.py   - InventoryModule dynamique
│
├── tests/                       # Tests & qualification
│   ├── unit/                    - Tests unitaires
│   ├── integration/             - Tests intégration
│   ├── e2e_multiagent_test.yml  - Playbook E2E
│   └── inventory_relay.ini      - Inventaire test
│
├── ARCHITECTURE.md              # Spécifications techniques v1.1
├── DEPLOYMENT.md                # Guide de déploiement
├── HLD.md                       # Design haut niveau
└── CLAUDE.md                    # Instructions Claude Code
```

## Documentation

| Document | Contenu |
|----------|---------|
| **ARCHITECTURE.md** | Spécifications techniques détaillées (protocoles, formats, sécurité) |
| **DEPLOYMENT.md** | Guide complet de déploiement (server + minions) |
| **HLD.md** | Architecture haut niveau et flux de messages |
| **CLAUDE.md** | Instructions projet pour Claude Code |

## Concept

### Flux d'Exécution

```
┌─────────┐        ┌──────────┐        ┌─────────┐        ┌──────────┐
│ Ansible │        │  Relay   │        │  NATS   │        │  Relay   │
│ Control │───────▶│ Server   │───────▶│ Message │◀──────▶│  Agent   │
│ Machine │        │ (FastAPI)│        │  Broker │        │ (Minion) │
└─────────┘        └──────────┘        └─────────┘        └──────────┘
                         │                                       │
                         └──────────── WebSocket ───────────────┘
                                     (Bidirectionnel)
```

1. **Playbook Ansible** → Plugin connection_relay (HTTP/REST)
2. **Server relay-api** → Enqueue task dans NATS stream
3. **Agent WebSocket** → Reçoit tâche via canal persistant
4. **Agent subprocess** → Exécute la commande Ansible
5. **Agent → Server** → Upload résultat via HTTP
6. **Server → NATS** → Persiste résultat
7. **Plugin reads** → Récupère résultat via /api/exec/{task_id}

### Avantages par rapport à SSH

| Aspect | SSH | Ansible-SecAgent |
|--------|-----|--------------|
| **Connexion** | Entrante (serveur initie) | Sortante (agent initie) |
| **Firewall** | SSH port ouvert | Sortante HTTPS uniquement |
| **Credentials** | SSH keys distribuées | JWT + RSA-4096 |
| **Scaling** | N connexions SSH | 1 WebSocket par agent |
| **NAT Friendly** | Difficile | Natif (agents derrière NAT) |

## Stack Technique

- **Agent** : Python 3.11+, asyncio, websockets, RSA-4096
- **Serveur** : Python 3.11+, FastAPI, NATS JetStream, SQLite/PostgreSQL
- **Plugins Ansible** : Python, ConnectionBase, InventoryModule
- **Transport** : WSS (obligatoire TLS), HTTP/REST
- **Authentification** : JWT HMAC-SHA256, RSA challenge-response
- **Orchestration** : Docker Compose (qualif), Kubernetes Helm (prod)

## Sécurité MVP

✅ **Validé par security review** (0 findings CRITICAL/HAUT)

- JWT signé HMAC-SHA256
- RSA-4096 key exchange à l'enrollment
- Challenge-response pour token refresh
- JTI blacklist (revocation)
- TLS obligatoire pour production
- Rôles RBAC (agent/plugin/admin)

## Phase de Développement

- ✅ **Phase 0** : Backlog + architecture (41 tâches)
- ✅ **Phase 1** : secagent-minion + tests
- ✅ **Phase 2** : secagent-server + NATS JetStream
- ✅ **Phase 3** : Plugins Ansible + E2E tests
- ⏳ **Phase 4** : Production Kubernetes (après validation)

## Contacts & Support

- **Architecture** : Voir `ARCHITECTURE.md` et `HLD.md`
- **Déploiement** : Voir `DEPLOYMENT.md`
- **Développement** : Voir `CLAUDE.md` pour les conventions
- **Tests** : `pytest tests/ -v`

---

**MVP Status** : ✅ COMPLETE — Prêt pour qualification et production Kubernetes
