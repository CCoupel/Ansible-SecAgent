# Ansible-SecAgent

[![CI](https://github.com/CCoupel/Ansible-SecAgent/actions/workflows/ci.yml/badge.svg)](https://github.com/CCoupel/Ansible-SecAgent/actions/workflows/ci.yml)

Système permettant d'exécuter des playbooks Ansible sur des hôtes distants sans connexion SSH entrante. Les agents clients initient eux-mêmes la connexion vers un serveur central (modèle **Salt Minion**, connexions inversées).

## Fonctionnalités principales

- **Connexions inversées** — les agents initient la connexion sortante vers le serveur (NAT/firewall friendly)
- **Auth JWT + RSA-4096** — enrollment sécurisé, rôles RBAC (`agent` / `plugin` / `admin` / `relay`)
- **Event Hooks** — actions configurables via JSON (webhook, shell, file, API) déclenchées par événements agent
- **Repeater Relay Chain** — topologie arbre hiérarchique (v3.0.1+) : relays enfants se connectent au parent (pull) ou parent se connecte aux enfants (push), inventaire unifié par héritage
- **Propagation d'événements** (v3.0.2+) — événements remontant l'arbre (host.up/down/new/conflict, relay.updated) avec chaînes d'origine exactes, hooks et variables configurables
- **Inventaire hiérarchique** (v3.0.2+) — groupes Ansible = relays, hiérarchie récursive, group vars par relay, paramètre `?relay=<id>` pour le scoping
- **Validation group vars** (v3.0.2+) — JSON persisté, refus de préfixes `ansible_*` et `secagent_*`, marqueurs Jinja interdits

## Quick Start

**Prérequis** : Docker, Docker Compose, certificats TLS auto-signés

### 1. Initialiser l'état du relay
```bash
cd DEPLOYMENT/qualif
mkdir -p state && docker compose run --rm secagent-server state init
```

### 2. Démarrer le relay
```bash
docker compose up -d relay
curl -k https://localhost:7770/health  # Vérifier la santé
```

### 3. Enrôler et démarrer les agents
```bash
TOKEN=$(docker compose exec relay secagent-server admin token create --role agent --duration 1h | tail -1)
export RELAY_ENROLLMENT_TOKEN=$TOKEN
docker compose up -d minion-01 minion-02 minion-03
docker compose logs minion-01 | grep -i "enrolled"
```

### 4. Vérifier l'inventaire
```bash
ADMIN_JWT=$(docker compose exec relay secagent-server admin token create --role admin --duration 1h | tail -1)
curl -k -H "Authorization: Bearer $ADMIN_JWT" https://localhost:7770/api/inventory | jq .
```

Voir [DEPLOYMENT/README.md](./DEPLOYMENT/README.md) pour un guide complet.

## Structure du Projet v3.0.3

```
ansible-secagent/
├── GO/                          # Code source GO (compilé)
│   ├── cmd/secagent-server/     # Serveur relay (TLS natif, état fichier, actif/passif)
│   ├── cmd/secagent-minion/     # Agent client (WebSocket persistante, subprocess)
│   └── cmd/secagent-inventory/  # Inventaire statique/dynamique (binaire GO)
│
├── SECAGENT-PYTHON/             # Plugin Ansible (Python — contrainte Ansible)
│   ├── ansible_plugins/
│   │   ├── connection_plugins/relay.py  - ConnectionBase (dispatch vers relay)
│   │   └── inventory_plugins/relay.py   - Inventaire dynamique
│   └── README.md
│
├── DEPLOYMENT/                  # Configs Docker Compose
│   ├── qualif/docker-compose.yml    - Single-host Compose avec certificats self-signed
│   ├── prod/docker-compose.yml      - Multi-host Compose actif/passif
│   ├── prod/.env.example            - Variables non-secrets
│   ├── prod/prod.env.example        - Secrets (TLS_*, RSA_MASTER_KEY, JWT_*)
│   └── README.md                    - Guide déploiement complet
│
├── DOC/                         # Documentation vivante
│   ├── common/ARCHITECTURE.md       - Spécifications techniques v3.0.3
│   ├── common/HLD.md                - Architecture haut niveau
│   ├── security/SECURITY.md         - Modèle sécurité (enrollment, tokens, avis)
│   ├── security/PORTS_SECURITY.md   - Architecture ports (7770/7771/7772)
│   ├── server/SERVER_SPEC.md        - Specs secagent-server
│   ├── agent/AGENT_SPEC.md          - Specs secagent-minion
│   ├── plugins/PLUGINS_SPEC.md      - Specs plugins Ansible
│   ├── inventory/INVENTORY_SPEC.md  - Specs secagent-inventory
│   └── project/                     - Guides opérationnels
│       ├── DEPLOYMENT.md
│       ├── QUICKSTART.md
│       └── RELEASE_NOTES.md
│
├── README.md                    # Ce fichier
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

- ✅ **Phases 1–9** : Agents, serveur, NATS, WebSocket, plugins Ansible, inventaire, JWT, CLI, sécurité RSA-4096
- ✅ **Phase 10** : Enrollment Token (système de tokens pré-signés)
- ✅ **Phase 11** : Event Hooks unifiés (JSON config, 4 executors, action_log)
- ✅ **Phase 12** : Proxy/Gateway multi-zone (pull/push, inventaire agrégé, chaînage, JWT rôle relay)
- ✅ **Phase 13** : Repeater Relay Chain v3.0.1 (arbre hiérarchique, pull/push modes, token relay-parent, révocation JTI, état des liens dans l'API d'administration et /health avec drapeau degraded)
- ⏳ **Phase 14** : Production Kubernetes (après validation qualif)

**Version actuelle : v3.0.1** — Repeater chain IMPLEMENTED (GO rewrite 100% complete)

## Contacts & Support

- **Architecture** : Voir `ARCHITECTURE.md` et `HLD.md`
- **Déploiement** : Voir `DEPLOYMENT.md`
- **Développement** : Voir `CLAUDE.md` pour les conventions
- **Tests** : `pytest tests/ -v`

---

**MVP Status** : ✅ COMPLETE — Prêt pour qualification et production Kubernetes
