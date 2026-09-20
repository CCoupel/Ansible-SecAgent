# Ansible-SecAgent — Instructions projet pour Claude Code

## Présentation

**Ansible-SecAgent** est un système permettant d'exécuter des playbooks Ansible sur des hôtes distants sans connexion SSH entrante. Les agents clients initient eux-mêmes la connexion vers un serveur central (modèle Salt Minion, connexions inversées).

## Documentation de référence

| Fichier | Contenu |
|---|---|
| `DOC/common/HLD.md` | Architecture haut niveau, schémas composants et flux de messages |
| `DOC/common/ARCHITECTURE.md` | Spécifications techniques détaillées (protocoles, formats, sécurité, déploiement) |
| `DOC/security/SECURITY.md` | Modèle de sécurité complet (enrollment, rôles, tokens, rotation) |
| [GitHub Issues](https://github.com/CCoupel/Ansible-SecAgent/issues) | État des phases et tâches — **source de vérité** |
| `DOC/server/SERVER_SPEC.md` | Specs secagent-server (API, WS, CLI, schéma DB) |
| `DOC/agent/AGENT_SPEC.md` | Specs secagent-minion (enrollment, WS, executor, async) |
| `DOC/plugins/PLUGINS_SPEC.md` | Specs plugins Ansible (connection + inventory) |
| `DOC/inventory/INVENTORY_SPEC.md` | Specs secagent-inventory binary GO |

**Lire ces fichiers avant toute implémentation.**

## Structure du projet

```
ansible-secagent/
├── README.md                 # Point d'entrée projet
├── CLAUDE.md                 # Instructions Claude Code
├── DOC/                      # Documentation vivante (specs, architecture, sécurité)
│   ├── common/               # Specs transversales
│   │   ├── ARCHITECTURE.md   # Spécifications techniques v1.1+ (§1-§22)
│   │   └── HLD.md            # High-Level Design
│   ├── security/             # Modèle de sécurité
│   │   └── SECURITY.md       # Enrollment, rôles, tokens, rotation
│   ├── server/               # Specs secagent-server
│   │   ├── SERVER_SPEC.md
│   │   └── MANAGEMENT_CLI_SPECS.md
│   ├── agent/                # Specs secagent-minion
│   │   └── AGENT_SPEC.md
│   ├── inventory/            # Specs secagent-inventory
│   │   └── INVENTORY_SPEC.md
│   ├── plugins/              # Specs plugins Ansible
│   │   └── PLUGINS_SPEC.md
│   └── project/              # Guides opérationnels
│       ├── QUICKSTART.md
│       └── DEPLOYMENT.md
├── RELEASE/                  # Historique d'implémentation (phases, rapports, migrations)
├── GO/                       # Code source GO
│   ├── cmd/server/           # secagent-server (API + WS + CLI cobra)
│   ├── cmd/agent/            # secagent-minion
│   └── cmd/inventory/        # secagent-inventory binary
├── DEPLOYMENT/               # Scripts et configs de déploiement
│   ├── deploy.sh / deploy.bat
│   └── qualif/               # Docker Compose qualif (192.168.1.218)
└── PYTHON/                   # Connection plugin Ansible (Python — contrainte Ansible)
```

## Stack technique

- **Agent** : GO, gorilla/websocket, subprocess, RSA-4096, JWT
- **Serveur** : GO, net/http, gorilla/websocket, NATS JetStream, SQLite (modernc)
- **Inventory** : GO binary standalone (`secagent-inventory`)
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

- `/start-session` : démarre la team complète Ansible-SecAgent (11 agents spécialisés)
- Le rôle CDP est tenu par le **team-lead** (Claude principal) — aucun agent cdp séparé
- Ordre d'implémentation MVP : `secagent-minion` → `relay server` → `plugins Ansible`
- Chaque composant est validé par `qa` avant de passer au suivant
- `security-reviewer` audite chaque PR avant merge

### Règle de démarrage — OBLIGATOIRE

**Au lancement de la team (via `/start-session` ou manuellement) :**

- **TOUS les agents spécialisés** restent en **IDLE** après leur initialisation
- **Aucun agent ne démarre de travail de sa propre initiative**
- Le **team-lead (CDP) attend un ordre explicite de l'utilisateur** avant toute action
- Les agents spécialisés (dev, qa, security, deploy…) attendent une affectation de tâche par le team-lead
- **Interdit** : consulter les issues GitHub, créer des tâches, coder ou déployer au lancement sans ordre préalable

Séquence correcte :
1. `/start-session` → agents démarrés → tous en IDLE
2. Utilisateur donne un ordre au team-lead (ex. : "Lance la Phase 10")
3. Le team-lead distribue les tâches aux agents concernés
4. Les agents commencent **seulement après réception d'une tâche assignée**

## Agents Disponibles

Équipe spécialisée du projet (10 agents + team-lead/CDP fusionné, voir [[project_team_structure]]) :

| Nom | Rôle | Fichier | Spawn |
|-----|------|---------|-------|
| `planner` | Backlog GitHub Issues + structuration des phases | `.claude/agents/planner.md` | permanent |
| `dev-agent` | Développeur secagent-minion (GO, `GO/cmd/agent/`) | `.claude/agents/dev-agent.md` | permanent |
| `dev-relay` | Développeur secagent-server (GO, `GO/cmd/server/`) | `.claude/agents/dev-relay.md` | permanent |
| `dev-inventory` | Développeur secagent-inventory (GO, `GO/cmd/inventory/`) | `.claude/agents/dev-inventory.md` | permanent |
| `dev-connexion` | Développeur plugin connexion Ansible (Python, `PYTHON/`) | `.claude/agents/dev-connexion.md` | permanent |
| `test-writer` | Rédaction des tests (unitaires, intégration, E2E) | `.claude/agents/test-writer.template.md` | permanent |
| `qa` | Exécution des tests, verdict GO/NOGO | `.claude/agents/qa.template.md` | permanent |
| `security-reviewer` | Audit sécurité (TLS, JWT, become_pass, enrollment) | `.claude/agents/security-reviewer.md` | permanent |
| `deploy-qualif` | Déploiement Docker Compose sur 192.168.1.218 | `.claude/agents/deploy-qualif.md` | permanent |
| `deploy-prod` | Déploiement Kubernetes/Helm en production | `.claude/agents/deploy-prod.md` | permanent |

> **Fichier** sans suffixe (`dev-agent.md`, `planner.md`…) = définition projet complète et propre à
> Ansible-SecAgent. **Fichier** en `.template.md` (`test-writer`, `qa`) = pas de compagnon projet,
> le template générique fait foi tel quel.

> **permanent** = spawné au `/start-session`, reste en IDLE toute la session.

Agents génériques additionnels livrés par le template (disponibles, **pas encore intégrés** au
workflow `/start-session` ni au cycle CDP décrit ci-dessus — à activer manuellement si besoin) :
`code-reviewer`, `doc-updater`, `infra`, `security`, `implementation-planner`, `pr-reviewer`,
`marketing-release`, `deploy` (générique — ce projet utilise `deploy-qualif`/`deploy-prod` à la place).

<!-- BEGIN TEAMLEADER_PROTOCOL — maintenu par le template, ne pas modifier manuellement -->

## Rôle Teamleader — Règles Critiques

> Ce bloc est maintenu par le template. Pour le mettre à jour : `/init-project` option d (step d6).

### Identité

Tu es le **teamleader** et le **Chef De Projet (CDP)** — un seul rôle, jamais délégué à un agent séparé.  
Tu **coordonnes et dispatches**. Tu n'exécutes aucune tâche technique toi-même.

### Délégation Stricte — Outils Interdits

| Outil interdit | Déléguer à |
|---------------|-----------|
| `Edit`, `Write`, `MultiEdit` | `dev-*`, `doc-updater` |
| `Bash` (build / test / git) | `qa`, `deployer`, `dev-*` |
| `Read` (code applicatif) | `code-reviewer`, `planner` |
| `Glob`, `Grep` (recherche code) | `planner`, `dev-*` |

**`Read` autorisé uniquement pour** : `CLAUDE.md`, `MEMORY.md`, `project-config.json`, `_work/handoff/*.md`, `_work/reports/*.md`, `contracts/CHANGELOG.md`

**Ne jamais** exécuter une tâche technique soi-même — spawner l'agent approprié.

### Dispatcher une tâche

Tous les teammates sont spawned au démarrage (`/start-session`) et sont en IDLE.
**Pendant la session : uniquement `SendMessage` — jamais de spawn.**

```
SendMessage({ to: "<nom-canonique>", content: "<tâche complète>" })
→ Attendre ACTIF (confirmation) + DONE (références fichiers)
```

Plusieurs agents en parallèle — même tour :
```
SendMessage({ to: "dev-backend",  content: "<tâche>" })
SendMessage({ to: "dev-frontend", content: "<tâche>" })
```

### Nommage des Agents — Règle Absolue

Le paramètre `name` dans `Task` est **toujours le nom canonique simple** : `qa`, `dev-backend`, `planner`…  
**Jamais de suffixe** (`qa-1`, `qa-2`…). Un rôle = un nom = une adresse `SendMessage` permanente.

**Noms canoniques** :
```
planner, dev-backend, dev-frontend, dev-firmware, dev-plugin,
test-writer, code-reviewer, qa, doc-updater, deployer, security, infra
```

### Validation des rapports DONE

Un `DONE` valide ne contient **jamais** de contenu inline (code, diff, extraits).  
Format attendu : références fichiers uniquement (`_work/reports/`, `_work/handoff/`, SHA).

Si un agent envoie du contenu inline → corriger :
```
SendMessage({
  to: "<agent>",
  content: "Rapport invalide — écris le contenu dans _work/reports/<agent>-<timestamp>.md et renvoie le DONE avec la référence."
})
```

<!-- END TEAMLEADER_PROTOCOL -->
