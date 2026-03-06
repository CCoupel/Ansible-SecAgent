# AnsibleRelay — Instructions projet pour Claude Code

## Présentation

**AnsibleRelay** est un système permettant d'exécuter des playbooks Ansible sur des hôtes distants sans connexion SSH entrante. Les agents clients initient eux-mêmes la connexion vers un serveur central (modèle Salt Minion, connexions inversées).

## Documentation de référence

| Fichier | Contenu |
|---|---|
| `DOC/common/HLD.md` | Architecture haut niveau, schémas composants et flux de messages |
| `DOC/common/ARCHITECTURE.md` | Spécifications techniques détaillées (protocoles, formats, sécurité, déploiement) |
| `DOC/security/SECURITY.md` | Modèle de sécurité complet (enrollment, rôles, tokens, rotation) |
| `DOC/common/BACKLOG.md` | État des phases et tâches |
| `DOC/server/SERVER_SPEC.md` | Specs relay-server (API, WS, CLI, schéma DB) |
| `DOC/agent/AGENT_SPEC.md` | Specs relay-agent (enrollment, WS, executor, async) |
| `DOC/plugins/PLUGINS_SPEC.md` | Specs plugins Ansible (connection + inventory) |
| `DOC/inventory/INVENTORY_SPEC.md` | Specs relay-inventory binary GO |

**Lire ces fichiers avant toute implémentation.**

## Structure du projet

```
ansible-relay/
├── README.md                 # Point d'entrée projet
├── CLAUDE.md                 # Instructions Claude Code
├── DOC/                      # Documentation vivante (specs, architecture, sécurité)
│   ├── common/               # Specs transversales
│   │   ├── ARCHITECTURE.md   # Spécifications techniques v1.1+ (§1-§22)
│   │   ├── HLD.md            # High-Level Design
│   │   └── BACKLOG.md        # Phases et tâches
│   ├── security/             # Modèle de sécurité
│   │   └── SECURITY.md       # Enrollment, rôles, tokens, rotation
│   ├── server/               # Specs relay-server
│   │   ├── SERVER_SPEC.md
│   │   └── MANAGEMENT_CLI_SPECS.md
│   ├── agent/                # Specs relay-agent
│   │   └── AGENT_SPEC.md
│   ├── inventory/            # Specs relay-inventory
│   │   └── INVENTORY_SPEC.md
│   ├── plugins/              # Specs plugins Ansible
│   │   └── PLUGINS_SPEC.md
│   └── project/              # Guides opérationnels
│       ├── QUICKSTART.md
│       └── DEPLOYMENT.md
├── RELEASE/                  # Historique d'implémentation (phases, rapports, migrations)
├── GO/                       # Code source GO
│   ├── cmd/server/           # relay-server (API + WS + CLI cobra)
│   ├── cmd/agent/            # relay-agent
│   └── cmd/inventory/        # relay-inventory binary
├── DEPLOYMENT/               # Scripts et configs de déploiement
│   ├── deploy.sh / deploy.bat
│   └── qualif/               # Docker Compose qualif (192.168.1.218)
└── PYTHON/                   # Connection plugin Ansible (Python — contrainte Ansible)
```

## Stack technique

- **Agent** : GO, gorilla/websocket, subprocess, RSA-4096, JWT
- **Serveur** : GO, net/http, gorilla/websocket, NATS JetStream, SQLite (modernc)
- **Inventory** : GO binary standalone (`relay-inventory`)
- **Plugins Ansible** : Python (contrainte Ansible — ConnectionBase / InventoryModule)
- **Tests** : `JWT_SECRET_KEY=test ADMIN_TOKEN=test go test ./... -v`
- **Déploiement** : systemd (agent), Docker Compose (qualif), Kubernetes (prod)

## Décisions techniques majeures (non négociables)

- Transport : **WSS** obligatoire (TLS sur toutes les connexions)
- Canal agent : **1 WebSocket persistante** par agent, multiplexée par `task_id`
- Bus de messages : **NATS JetStream** (streams `RELAY_TASKS` + `RELAY_RESULTS`)
- Plugin Ansible → serveur : **REST HTTP bloquant**
- Auth : **JWT signé** (rôles `agent` / `plugin` / `admin`), blacklist JTI — voir `DOC/security/SECURITY.md`
- `authorized_keys` : **table DB** (pas de fichiers), alimentée par API admin
- Concurrence agent : **subprocess par tâche** (pas de threads)
- Stdout MVP : **buffer 5MB max**, truncation + flag
- Fichiers MVP : **< 500KB**, base64 inline
- Scope v1 : **Linux uniquement**

## Conventions de code

- GO : `gofmt`, erreurs explicitement retournées, pas de panic en production
- Python (plugins uniquement) : PEP 8, type hints, docstrings sur les fonctions publiques
- Logs : `log/slog` (GO) — **masquer `become_pass` dans tous les logs** (CRITIQUE sécurité)
- Tests GO : `JWT_SECRET_KEY=test ADMIN_TOKEN=test go test ./... -v`
- Tests Python : pytest, fichier `test_<module>.py` par module
- Commits : conventionnel (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`)

## Workflow équipe

- `/start-session` : démarre la team complète AnsibleRelay (8 agents)
- Ordre d'implémentation MVP : `relay-agent` → `relay server` → `plugins Ansible`
- Chaque composant est validé par `qa` avant de passer au suivant
- `security-reviewer` audite chaque PR avant merge

### Règle de démarrage — OBLIGATOIRE

**Au lancement de la team (via `/start-session` ou manuellement) :**

- **TOUS les agents** (cdp inclus) restent en **IDLE** après leur initialisation
- **Aucun agent ne démarre de travail de sa propre initiative**
- Le **CDP attend un ordre explicite de l'utilisateur** avant toute action
- Les agents spécialisés (dev, qa, security, deploy…) attendent une affectation de tâche par le CDP
- **Interdit** : lire le backlog, créer des tâches, coder ou déployer au lancement sans ordre préalable

Séquence correcte :
1. `/start-session` → agents démarrés → tous en IDLE
2. Utilisateur donne un ordre au CDP (ex. : "Lance la Phase 1")
3. CDP distribue les tâches aux agents concernés
4. Les agents commencent **seulement après réception d'une tâche assignée**
