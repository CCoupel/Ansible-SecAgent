# Ansible-SecAgent — Index du projet

**Projet** : exécution de playbooks Ansible sur des hôtes distants sans SSH entrant (agents à connexion inversée).
**Version documentée** : v3.0.3 (relay actif/passif, état sur fichier, TLS natif, WebSocket direct).
**Suivi des tâches** : [GitHub Issues](https://github.com/CCoupel/Ansible-SecAgent/issues) (source de vérité). `DOC/common/BACKLOG.md` est archivé.

> Les anciennes implémentations Python du serveur et de l'agent (FastAPI, NATS, SQLite) sont **retirées** : le serveur et le minion sont écrits en GO. Seul le plugin de connexion Ansible reste en Python (contrainte de l'API Ansible). `RELEASE/` conserve l'historique des phases (documents datés, non maintenus).

---

## Structure du dépôt

```
Ansible_SecAgent/
├── README.md, CHANGELOG.md, CLAUDE.md
├── DOC/                         # Documentation vivante
│   ├── common/                  # ARCHITECTURE, HLD, GO_README, INDEX (ce fichier), BACKLOG (archivé)
│   ├── contracts/               # Contrats d'interface : REST_ADMIN, REST_ENROLLMENT, REST_PLUGIN, WEBSOCKET
│   ├── security/                # SECURITY (modèle + avis), PORTS_SECURITY
│   ├── server/                  # SERVER_SPEC, STATE_SPEC, LOCK_SPEC, HOOKS_SPEC, MANAGEMENT_CLI_SPECS
│   ├── agent/                   # AGENT_SPEC (secagent-minion)
│   ├── inventory/               # INVENTORY_SPEC (secagent-inventory)
│   ├── plugins/                 # PLUGINS_SPEC (plugin de connexion)
│   └── project/                 # QUICKSTART, DEPLOYMENT, plans CDP
├── GO/
│   ├── cmd/secagent-server/     # API + WebSocket + CLI cobra ; internal/{handlers,ws,state,storage,lock,server,cli,hooks,repeater,proxy,…}
│   ├── cmd/secagent-minion/     # agent ; internal/{enrollment,ws,executor,registry,facts,files}
│   └── cmd/secagent-inventory/  # binaire d'inventaire dynamique Ansible
├── SECAGENT-PYTHON/             # plugin de connexion Ansible (ansible_plugins/connection_plugins/relay.py) + tests
├── DEPLOYMENT/                  # qualif/ (Compose actif/passif), prod/, ANSIBLE_DEPLOYMENT.md
└── RELEASE/                     # historique des phases (archive)
```

---

## Documents clés

| Sujet | Document |
|---|---|
| Architecture technique | `DOC/common/ARCHITECTURE.md` |
| Design haut niveau | `DOC/common/HLD.md` |
| Sécurité (rôles, jetons, révocation, avis) | `DOC/security/SECURITY.md`, `DOC/security/PORTS_SECURITY.md` |
| Contrats d'interface (référence canonique) | `DOC/contracts/` |
| Serveur : API, état, verrou, hooks, CLI | `DOC/server/` |
| Agent (minion) | `DOC/agent/AGENT_SPEC.md` |
| Plugins et inventaire Ansible | `DOC/plugins/PLUGINS_SPEC.md`, `DOC/inventory/INVENTORY_SPEC.md` |
| Démarrage / déploiement | `DOC/project/QUICKSTART.md`, `DOC/project/DEPLOYMENT.md`, `DEPLOYMENT/README.md` |
| Conventions de travail | `CLAUDE.md` |

---

## Développement

```bash
# Tests GO (depuis GO/)
JWT_SECRET_KEY=test ADMIN_TOKEN=test go test ./... -v

# Build du serveur (sans CGO)
cd GO && CGO_ENABLED=0 go build -o secagent-server ./cmd/secagent-server

# Tests du plugin Python
cd SECAGENT-PYTHON && pytest tests/
```

Avant de travailler : lire `CLAUDE.md`, puis les specs concernées, puis vérifier les issues GitHub. Commits conventionnels (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`).

---

## Sécurité en bref

- TLS natif sur toutes les connexions (WSS/HTTPS) ; ports 7770 (API), 7771 (admin), 7772 (WebSocket).
- Enrôlement : jeton d'enrôlement (`secagent_enr_…`) + challenge RSA-4096 OAEP ; JWT HS256 de rôle `agent` ; blacklist de JTI et drapeau persistant de révocation.
- Plugins : jeton plugin opaque (`secagent_plg_…`) ; admin : `ADMIN_TOKEN`.
- État : fichier `relay.state` authentifié par HMAC, secrets chiffrés AES-256-GCM (`RSA_MASTER_KEY`).
