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

### Flux d'Exécution v3.0.3

```
┌─────────────┐        ┌──────────────┐        ┌──────────────┐
│   Ansible   │        │  Relay v3.0.3│        │  Relay Agent │
│  Control    │───────▶│  Server      │◀──────▶│  (Minion)    │
│  Machine    │        │  (GO, TLS)   │        │  (GO)        │
└─────────────┘        └──────────────┘        └──────────────┘
       │                       │                       │
       └── HTTPS REST ─────────┘                       │
       │                  ▲                            │
       │                  │                            │
       └─ WSS (7772) ─ WebSocket Direct ──────────────┘
              (Connexion persistante, multiplexée par task_id)
```

1. **Playbook Ansible** → Plugin connection_relay (HTTPS/REST)
2. **Server relay** → Dispatch direct via WebSocket (7772) au minion
3. **Agent minion** → Reçoit tâche via WSS persistante
4. **Agent subprocess** → Exécute la commande Ansible
5. **Agent → Server** → Retour résultat via WebSocket
6. **Server → STATE_DIR** → Persiste dans relay.state (file-based)
7. **Plugin reads** → Récupère résultat via REST HTTP

### Avantages par rapport à SSH

| Aspect | SSH | Ansible-SecAgent |
|--------|-----|--------------|
| **Connexion** | Entrante (serveur initie) | Sortante (agent initie) |
| **Firewall** | SSH port ouvert | Sortante HTTPS uniquement |
| **Credentials** | SSH keys distribuées | JWT + RSA-4096 |
| **Scaling** | N connexions SSH | 1 WebSocket par agent |
| **NAT Friendly** | Difficile | Natif (agents derrière NAT) |

## Stack Technique v3.0.3

- **Agent (secagent-minion)** : GO, gorilla/websocket, subprocess, RSA-4096, JWT
- **Serveur (secagent-server)** : GO, net/http natif, TLS natif, état fichier (STATE_DIR), verrou actif/passif
- **Inventaire (secagent-inventory)** : GO binary, multi-adresses, support repeater
- **Plugins Ansible** : Python, ConnectionBase, InventoryModule (contrainte Ansible)
- **Transport** : WSS (TLS obligatoire sur 7770/7772), HTTPS/REST
- **Authentification** : JWT HMAC-SHA256, RSA-4096 challenge-response, JTI blacklist
- **État** : Fichier (relay.state), signé HMAC, chiffré RSA, verrou multi-hôtes (NFS)
- **Orchestration** : Docker Compose multi-hôtes (qualif + prod actif/passif)

## Sécurité MVP

✅ **Validé par security review** (0 findings CRITICAL/HAUT)

- JWT signé HMAC-SHA256
- RSA-4096 key exchange à l'enrollment
- Challenge-response pour token refresh
- JTI blacklist (revocation)
- TLS obligatoire pour production
- Rôles RBAC (agent/plugin/admin)

## Phases de Développement

- ✅ **Phases 1–9** : Agents GO, serveur WebSocket, plugins Ansible, inventaire, JWT, CLI, RSA-4096
- ✅ **Phase 10** : Enrollment Token (tokens pré-signés)
- ✅ **Phase 11** : Event Hooks (JSON, 4 executors, action_log JSON Lines)
- ✅ **Phase 12** : Proxy/Gateway multi-zone (relays enfants/parents)
- ✅ **Phase 13** : Repeater Chain v3.0.1 (arbre hiérarchique, pull/push)
- ✅ **Phase 14** : Stabilité v3.0.2-3.0.3 (event propagation, group vars, topologie dynamique)
  - ✅ v3.0.2 : Événements origin-first, inventory hiérarchique, group vars validés
  - ✅ v3.0.3 : État fichier (retiré NATS), TLS natif, Compose multi-hôtes, verrou HA

**Version actuelle : v3.0.3** — Production stable (GO rewrite 100%, NATS retiré, state file HA)

## Contacts & Support

- **Architecture** : Voir `ARCHITECTURE.md` et `HLD.md`
- **Déploiement** : Voir `DEPLOYMENT.md`
- **Développement** : Voir `CLAUDE.md` pour les conventions
- **Tests** : `pytest tests/ -v`

---

**MVP Status** : ✅ COMPLETE — Prêt pour qualification et production Kubernetes
