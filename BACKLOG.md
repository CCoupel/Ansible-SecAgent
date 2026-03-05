# BACKLOG AnsibleRelay — 102 tâches

Date création : 2026-03-03
Date mise à jour : 2026-03-05
Status : Phase 0-3 complètes, Phase 4-6 planifiées, Phase 7-9 (GO migration) planifiées

## Vue d'ensemble

### MVP (Python)
- **Phase 1 (relay-agent)** : 13 tâches (#4 à #23) ✅ COMPLÈTE
- **Phase 2 (relay-server)** : 11 tâches (#24 à #34) ✅ COMPLÈTE
- **Phase 3 (plugins Ansible)** : 7 tâches (#35 à #41) ✅ COMPLÈTE
- **Phase 4 (Production Kubernetes)** : 12 tâches (#42 à #53) 🆕 À DÉMARRER
- **Phase 5 (Documentation & Hardening)** : 8 tâches (#54 à #61) 🆕 À DÉMARRER
- **Phase 6 (Management CLI)** : 8 tâches (#62 à #69) 🆕 À DÉMARRER

### Optimisation (GO)
- **Phase 7 (Server rewrite GO)** : 12 tâches (#70 à #81) 🆕 À DÉMARRER
- **Phase 8 (Agent rewrite GO)** : 10 tâches (#82 à #91) 🆕 À DÉMARRER
- **Phase 9 (Plugins wrapper GO)** : 5 tâches (#92 à #96) 🆕 À DÉMARRER

**Total** : 102 tâches

---

## PHASE 1 — relay-agent (dossier agent/) — 13 tâches

### Prérequis
- Lire ARCHITECTURE.md section "Agent"
- Lire HLD.md schémas agent

### Tâches Phase 1

| # | Tâche | Owner | Status | Bloquée par |
|---|-------|-------|--------|------------|
| #4 | facts_collector.py — collecte facts système | dev-agent | pending | - |
| #6 | relay_agent.py — enrollment POST /api/register + RSA-4096 | dev-agent | pending | #4 |
| #8 | relay_agent.py — connexion WSS + backoff exponentiel (1s→60s) | dev-agent | pending | #6 |
| #9 | relay_agent.py — dispatcher messages WS (exec/put_file/fetch_file/cancel) | dev-agent | pending | #8 |
| #11 | relay_agent.py — exec_command subprocess + stdout streaming + buffer 5MB | dev-agent | pending | #9 |
| #13 | relay_agent.py — put_file (base64, mkdir -p, chmod) | dev-agent | pending | #9 |
| #14 | relay_agent.py — fetch_file (lecture, base64, limite 500KB) | dev-agent | pending | #9 |
| #15 | async_registry.py — registre JSON persisté, reprise redémarrage | dev-agent | pending | #9 |
| #17 | relay-agent.service — unit file systemd (NoNewPrivileges, ProtectSystem) | dev-agent | pending | - |
| #19 | Tests unitaires relay-agent Phase 1 | test-writer | pending | #4, #6, #8, #9, #11, #13, #14, #15, #17 |
| #20 | QA — pytest Phase 1, rapport (nb tests, pass, fail, détails) | qa | pending | #19 |
| #22 | Security review — audit Phase 1 relay-agent | security-reviewer | pending | #20 |
| #23 | Deploy qualif Phase 1 — relay-agent sur 192.168.1.218 | deploy-qualif | pending | #22 |

**Validation Phase 1 → Phase 2** :
- ✓ TOUTES tâches #4-#23 completed
- ✓ qa : 0 test en échec
- ✓ security-reviewer : 0 finding CRITIQUE/HAUT
- ✓ deploy-qualif : OK
- ✓ Confirmation utilisateur

---

## PHASE 2 — relay-server (dossier server/) — 11 tâches

### Prérequis
- Lire ARCHITECTURE.md section "Server"
- Lire HLD.md flux messages et broker
- Phase 1 validée et déployée

### Tâches Phase 2

| # | Tâche | Owner | Status | Bloquée par |
|---|-------|-------|--------|------------|
| #24 | agent_store.py — modèles SQLite (agents, authorized_keys, blacklist) | dev-relay | pending | - |
| #25 | routes_register.py — enrollment + auth JWT + blacklist JTI | dev-relay | pending | #24 |
| #26 | ws_handler.py — connexions WS, futures, on_ws_close | dev-relay | pending | #25 |
| #27 | nats_client.py — NATS JetStream (RELAY_TASKS, RELAY_RESULTS) | dev-relay | pending | #24 |
| #28 | routes_exec.py — endpoints /api/exec, /api/upload, /api/fetch, /api/inventory | dev-relay | pending | #26, #27 |
| #29 | main.py — FastAPI app (lifespan, health check) | dev-relay | pending | #25, #26, #27, #28 |
| #30 | docker-compose.yml + Dockerfile — NATS, relay-api, caddy | dev-relay | pending | #29 |
| #31 | Tests unitaires relay-server Phase 2 | test-writer | pending | #24-#30 |
| #32 | QA — pytest Phase 2, rapport | qa | pending | #31 |
| #33 | Security review — audit Phase 2 relay-server | security-reviewer | pending | #32 |
| #34 | Deploy qualif Phase 2 — relay-server complet sur 192.168.1.218 | deploy-qualif | pending | #33, #23 |

**Validation Phase 2 → Phase 3** :
- ✓ TOUTES tâches #24-#34 completed
- ✓ qa : 0 test en échec
- ✓ security-reviewer : 0 finding CRITIQUE/HAUT
- ✓ deploy-qualif : OK
- ✓ Confirmation utilisateur

---

## PHASE 3 — plugins Ansible (dossier ansible_plugins/) — 7 tâches

### Prérequis
- Lire ARCHITECTURE.md section "Ansible Plugins"
- Lire HLD.md flux plugins
- Phase 2 validée et déployée

### Tâches Phase 3

| # | Tâche | Owner | Status | Bloquée par |
|---|-------|-------|--------|------------|
| #35 | connection_plugins/relay.py — ConnectionBase (exec_command, put_file, fetch_file, pipelining, become) | dev-plugins | pending | #34 |
| #36 | inventory_plugins/relay_inventory.py — InventoryModule (GET /api/inventory) | dev-plugins | pending | #34 |
| #37 | Tests unitaires + E2E plugins Phase 3 | test-writer | pending | #35, #36 |
| #38 | QA — pytest Phase 3 (unitaire + E2E), rapport | qa | pending | #37 |
| #39 | Security review global — audit Phase 3 + revue MVP complète | security-reviewer | pending | #38 |
| #40 | Deploy qualif Phase 3 — test E2E complet sur 192.168.1.218 | deploy-qualif | pending | #39 |
| #41 | Deploy prod — Helm chart Kubernetes (après confirmation utilisateur) | deploy-prod | pending | #40 |

**Validation Phase 3 → Prod** :
- ✓ TOUTES tâches #35-#40 completed
- ✓ qa : 0 test en échec, tests E2E couvrant cas nominaux + erreurs + async
- ✓ security-reviewer : 0 finding CRITIQUE/HAUT, audit global MVP cohérent
- ✓ deploy-qualif : OK
- ✓ Confirmation utilisateur explicite pour #41 (prod)

---

## PHASE 4 — Production Kubernetes — 12 tâches

### Prérequis
- Phase 3 complète et validée
- Confirmation utilisateur explicite
- Kubernetes cluster disponible
- Helm 3.x installé

### Tâches Phase 4

| # | Tâche | Owner | Status | Bloquée par |
|---|-------|-------|--------|------------|
| #42 | Helm chart structure — values.yaml, templates/, Chart.yaml | deploy-prod | pending | #40 |
| #43 | Helm StatefulSet NATS JetStream — persistance, replicas, antiaffinity | deploy-prod | pending | #42 |
| #44 | Helm Deployment relay-server — multi-port, replicas, PDB | deploy-prod | pending | #42 |
| #45 | Helm DaemonSet relay-agent — 1 par nœud, node affinity, tolerations | deploy-prod | pending | #42 |
| #46 | Helm ConfigMap + Secrets — JWT_SECRET, ADMIN_TOKEN, TLS certs | deploy-prod | pending | #42 |
| #47 | Helm Ingress — TLS termination, routing 7770/7771/7772 | deploy-prod | pending | #42 |
| #48 | Helm Service (ClusterIP + LoadBalancer) — NATS, relay-api | deploy-prod | pending | #42 |
| #49 | Helm PersistentVolumeClaim — NATS data, relay DB, agent state | deploy-prod | pending | #42 |
| #50 | Helm tests — helm lint, helm template, helm dry-run | deploy-prod | pending | #42 |
| #51 | Helm deployment script — helm install/upgrade sur cluster K8s | deploy-prod | pending | #50 |
| #52 | Documentation Helm — values.yaml comments, deployment guide, troubleshooting | deploy-prod | pending | #51 |
| #53 | Deploy prod Phase 4 — Helm install sur Kubernetes cluster | deploy-prod | pending | #52 |

**Validation Phase 4 → Phase 5** :
- ✓ Helm lint : 0 erreurs
- ✓ Helm template : YAML valide
- ✓ Helm dry-run : OK
- ✓ Deploy sur cluster K8s : 3 agents enregistrés et connectés
- ✓ Ingress TLS fonctionnelle
- ✓ Persistance NATS et DB vérifiée après redémarrage pod

---

## PHASE 5 — Documentation & Hardening — 8 tâches

### Prérequis
- Phase 4 déployée en production

### Tâches Phase 5

| # | Tâche | Owner | Status | Bloquée par |
|---|-------|-------|--------|------------|
| #54 | Runbooks prod — escalade, diagnostics, rollback | deploy-prod | pending | #53 |
| #55 | Monitoring setup — Prometheus métriques, alerting, dashboards Grafana | deploy-prod | pending | #53 |
| #56 | Hardening sécurité prod — network policies, RBAC, admission controllers | security-reviewer | pending | #53 |
| #57 | Disaster recovery — backup NATS, DB recovery, failover procedure | deploy-prod | pending | #53 |
| #58 | Performance tuning — load testing, baseline metrics, optimization | qa | pending | #53 |
| #59 | Migration guide — from qualif to prod, zero-downtime strategy | deploy-prod | pending | #53 |
| #60 | SLA & Support — métriques, escalade, on-call procedure | deploy-prod | pending | #53 |
| #61 | MVP Final Review & Sign-off | cdp | pending | #54-#60 |

**Validation Phase 5 → Live** :
- ✓ Runbooks testées
- ✓ Monitoring opérationnel
- ✓ Security audit : 0 findings CRITIQUE/HAUT
- ✓ DR tested : RTO/RPO validés
- ✓ Performance : SLA met
- ✓ Sign-off CDO + Utilisateur

---

## PHASE 6 — Management CLI — 8 tâches

### Prérequis
- Phase 4 déployée en production (K8s avec Helm)
- Phase 5 complète (hardening + monitoring)

### Objectif
CLI de management pour administrer les minions (agents) et l'inventaire Ansible :
- Lister les minions enregistrés et leur état (connecté/déconnecté/expiré)
- Visualiser métriques minion (dernière activité, facts, version)
- Revoquer/supprimer un minion
- Éditer l'inventaire Ansible (ajouter/modifier/supprimer hosts/variables)
- Visualiser les logs d'activité par minion
- Pré-autoriser de nouveaux minions (admin endpoint)
- Configuration multi-serveur (context, profile)

### Tâches Phase 6

| # | Tâche | Owner | Status | Bloquée par |
|---|-------|-------|--------|------------|
| #62 | Spécifications CLI — commands, options, output format | dev-plugins | pending | #61 |
| #63 | Backend API — endpoints management (GET /api/admin/minions, DELETE, PATCH) | dev-relay | pending | #62 |
| #64 | CLI tool (Python click/typer) — minions, inventory, auth commands | dev-plugins | pending | #62 |
| #65 | CLI auth — login, token management, context switching | dev-plugins | pending | #63 |
| #66 | CLI inventory editor — view, edit, validate, diff, rollback | dev-plugins | pending | #64 |
| #67 | Tests unitaires + E2E CLI commands | test-writer | pending | #64, #65, #66 |
| #68 | QA — CLI tests, help output, edge cases, security | qa | pending | #67 |
| #69 | CLI package — pip install, bash completion, man pages, Helm chart | deploy-prod | pending | #68 |

**Validation Phase 6 → Production** :
- ✓ TOUTES tâches #62-#69 completed
- ✓ qa : 0 test en échec
- ✓ CLI opérationnelle : minions list/detail/revoke/delete, inventory edit/diff/rollback
- ✓ Security : JWT auth, token storage (secure), admin-only commands
- ✓ Usability : --help, bash completion, clear output formatting
- ✓ Performance : API response < 500ms, CLI latency < 1s
- ✓ Confirmation utilisateur

---

## PHASE 7 — Rewrite relay-server (GO) — 12 tâches

### Prérequis
- Phase 6 complète (CLI opérationnelle)
- GO 1.21+ installé
- Aucune modification aux API contracts (backward-compatible)

### Objectif
Réécrire relay-server (FastAPI Python) en GO compilé pour performance + sécurité :
- Latency : 100ms → 5ms (20x faster)
- Memory : 100MB → 10MB per instance
- Single compiled binary (no runtime)
- Type-safe crypto (RSA, JWT, SHA256)
- High-concurrency WebSocket (500+ agents)

### Tâches Phase 7

| # | Tâche | Owner | Status | Bloquée par |
|---|-------|-------|--------|------------|
| #70 | Spécifications architecture GO — project layout, dependencies | dev-relay | pending | #69 |
| #71 | Server main.go — multi-port app (7770/7771/7772), lifespan | dev-relay | pending | #70 |
| #72 | handlers/register.go — enrollment, JWT, RSA-4096 encryption | dev-relay | pending | #71 |
| #73 | handlers/exec.go — /api/exec, /api/upload, /api/fetch endpoints | dev-relay | pending | #71 |
| #74 | handlers/inventory.go — /api/inventory (Ansible format) | dev-relay | pending | #71 |
| #75 | ws/handler.go — WebSocket agent connections, dispatcher | dev-relay | pending | #71 |
| #76 | storage/agent_store.go — SQLite wrapper (agents, authorized_keys, blacklist) | dev-relay | pending | #71 |
| #77 | broker/nats.go — NATS JetStream client (RELAY_TASKS, RELAY_RESULTS) | dev-relay | pending | #71 |
| #78 | Tests unitaires relay-server GO | test-writer | pending | #72-#77 |
| #79 | Migration Python → GO : verify API contracts, protocol compatibility | dev-relay | pending | #78 |
| #80 | QA — pytest E2E vs GO server (agents enroll, exec, inventory) | qa | pending | #79 |
| #81 | Deploy qualif Phase 7 — GO server on 192.168.1.218 | deploy-qualif | pending | #80 |

**Validation Phase 7 → Phase 8** :
- ✓ TOUTES tâches #70-#81 completed
- ✓ API contracts : 100% compatible with Python version
- ✓ qa : 0 test en échec, E2E tests pass vs GO server
- ✓ Performance : p95 latency < 10ms, p99 < 20ms
- ✓ Memory : < 10MB per instance
- ✓ Throughput : 1000+ req/s
- ✓ deploy-qualif : GO server running stable 24h

---

## PHASE 8 — Rewrite relay-agent (GO) — 10 tâches

### Prérequis
- Phase 7 déployée (GO server)
- GO 1.21+ installé

### Objectif
Réécrire relay-agent (Python daemon) en GO compilé :
- Memory : 30MB → 2-3MB per agent
- Startup : 500ms → 10ms
- Better subprocess isolation
- Single systemd binary
- No Python garbage collector latency

### Tâches Phase 8

| # | Tâche | Owner | Status | Bloquée par |
|---|-------|-------|--------|------------|
| #82 | Agent architecture GO — project layout, async model | dev-agent | pending | #81 |
| #83 | agent/main.go — enrollment, WSS connection, reconnection backoff | dev-agent | pending | #82 |
| #84 | agent/dispatcher.go — message dispatcher (exec/put_file/fetch_file) | dev-agent | pending | #83 |
| #85 | agent/executor.go — exec_command subprocess + stdout streaming (5MB buffer) | dev-agent | pending | #83 |
| #86 | agent/files.go — put_file, fetch_file (base64, 500KB limit) | dev-agent | pending | #83 |
| #87 | agent/registry.go — async task registry (JSON persistence) | dev-agent | pending | #83 |
| #88 | agent/facts.go — system facts collection (via gopsutil) | dev-agent | pending | #83 |
| #89 | Tests unitaires relay-agent GO | test-writer | pending | #85-#88 |
| #90 | QA — pytest E2E vs GO agent (enrollment, exec, facts) | qa | pending | #89 |
| #91 | Deploy qualif Phase 8 — GO agents on 192.168.1.218 | deploy-qualif | pending | #90 |

**Validation Phase 8 → Phase 9** :
- ✓ TOUTES tâches #82-#91 completed
- ✓ qa : 0 test en échec
- ✓ Memory : < 3MB per agent
- ✓ Startup : < 50ms
- ✓ Subprocess isolation : no threads, separate processes
- ✓ Systemd : works with existing relay-agent.service
- ✓ Backward-compatible : no changes to agent protocol

---

## PHASE 9 — Plugins wrapper (GO) — 5 tâches

### Prérequis
- Phase 8 déployée (GO agents)
- Ansible plugins Python working

### Objectif
Wrapper GO pour plugins Ansible (inventory + connection) :
- relay-inventory-go : compiled binary called by relay_inventory.py
- relay-exec-go : compiled binary called by relay.py ConnectionBase
- Transparent to Ansible (Python plugins unchanged)
- Eliminates Python startup overhead (inventory refresh, exec)

### Architecture
```
ansible-playbook
    ↓
relay_inventory.py (Python, unchanged)
    ↓ subprocess call
relay-inventory-go (compiled wrapper)
    ↓ HTTP
relay-server:7772 (/api/inventory)
    ↓
response → Ansible inventory

relay.py (Python ConnectionBase, unchanged)
    ↓ subprocess call
relay-exec-go (compiled wrapper)
    ↓ HTTP
relay-server:7771 (/api/exec, /api/upload, /api/fetch)
    ↓
response → Ansible module result
```

### Tâches Phase 9

| # | Tâche | Owner | Status | Bloquée par |
|---|-------|-------|--------|------------|
| #92 | inventory-wrapper/main.go — CLI arg parsing, HTTP client | dev-plugins | pending | #91 |
| #93 | inventory-wrapper/inventory.go — fetch /api/inventory, format for Ansible | dev-plugins | pending | #92 |
| #94 | exec-wrapper/main.go — CLI arg parsing, subprocess handling | dev-plugins | pending | #91 |
| #95 | Tests + integration : Python plugins → GO wrappers | test-writer | pending | #93, #94 |
| #96 | Deploy qualif Phase 9 — E2E Ansible playbook via GO wrappers | deploy-qualif | pending | #95 |

**Validation Phase 9 → Production** :
- ✓ TOUTES tâches #92-#96 completed
- ✓ qa : 0 test en échec, E2E playbooks pass with GO wrappers
- ✓ Ansible plugins : unchanged (backward compatible)
- ✓ Performance : inventory refresh < 500ms, exec < 1s startup
- ✓ No Python startup overhead

---

## Dépendances critiques

```
PHASE 1:
#4 (facts) → #6 (enrollment) → #8 (WSS) → #9 (dispatcher) → #11/#13/#14/#15
#19 (tests) bloque par toutes tâches Phase 1
#20 (QA) → #22 (security) → #23 (deploy-qualif Phase 1)

PHASE 2:
#24 (DB) → #25 (auth) → #26 (WS) + #27 (NATS)
#26+#27 → #28 (endpoints) → #29 (main)
#31 (tests) bloque par toutes tâches Phase 2
#32 (QA) → #33 (security) → #34 (deploy-qualif Phase 2)

PHASE 3:
#34 (Phase 2 déployée) → #35 (connection) + #36 (inventory)
#37 (tests E2E) → #38 (QA) → #39 (security global) → #40 (deploy E2E)
#40 (deploy qualif Phase 3) → #41 (prod MVP final) [après confirmation utilisateur]

PHASE 4 (PRODUCTION K8S):
#40 (MVP qualifié) → #42 (structure Helm)
#42 → #43/#44/#45/#46/#47/#48/#49 (en parallèle)
#42 → #50 (tests Helm) → #51 (deploy script) → #52 (docs) → #53 (prod deploy)

PHASE 5 (HARDENING & LIVE):
#53 (prod déployée) → #54/#55/#56/#57/#58/#59/#60 (en parallèle)
#54/#55/#56/#57/#58/#59/#60 → #61 (final review & sign-off)

PHASE 6 (MANAGEMENT CLI):
#61 (sign-off) → #62 (specs)
#62 → #63 (backend API) + #64 (CLI tool)
#63 → #65 (auth) bloqué par #63
#64/#65/#66 (inventory editor) bloqué par #64
#64/#65/#66 → #67 (tests) → #68 (QA) → #69 (CLI package)

PHASE 7 (SERVER REWRITE GO):
#69 (CLI done) → #70 (GO specs)
#70 → #71 (main.go) → #72-#77 (handlers, storage, broker, ws - parallèle)
#72-#77 → #78 (tests) → #79 (migration verify) → #80 (QA E2E) → #81 (deploy)

PHASE 8 (AGENT REWRITE GO):
#81 (GO server done) → #82 (agent specs)
#82 → #83 (main.go) → #84-#88 (dispatcher, executor, files, registry, facts - parallèle)
#84-#88 → #89 (tests) → #90 (QA E2E) → #91 (deploy)

PHASE 9 (PLUGINS WRAPPER GO):
#91 (GO agent done) → #92 (inventory wrapper) + #94 (exec wrapper - parallèle)
#92/#94 → #95 (tests + integration) → #96 (E2E playbook)
```

---

## Checklist sécurité par phase

### Phase 1 (relay-agent)
- [ ] TLS obligatoire (WSS)
- [ ] JWT signé côté agent
- [ ] Masquage `become_pass` dans logs
- [ ] Validation entrées (command injection)
- [ ] Isolation subprocess (pas de threads)
- [ ] RSA-4096 pour enrollment

### Phase 2 (relay-server)
- [ ] TLS obligatoire (WSS + HTTPS)
- [ ] JWT signé + rôles agent/plugin/admin
- [ ] Blacklist JTI (token revocation)
- [ ] Validation entrées API (injection)
- [ ] Masquage `become_pass` dans logs et stockage
- [ ] Rate limiting

### Phase 3 (plugins Ansible)
- [ ] Validation tokens plugin
- [ ] Pas de fuite credentials dans logs
- [ ] TLS sur appels REST au serveur
- [ ] Audit global bout-en-bout

### Phase 6 (Management CLI)
- [ ] Authentification JWT avec session expiry
- [ ] Autorisation : admin-only commands (revoke, delete minions)
- [ ] Token storage : secure (chmod 600, XDG_CONFIG_HOME)
- [ ] Validation input (inventory YAML, host names, command injection)
- [ ] Masquage données sensibles (JWT tokens masqués, secrets non loggés)
- [ ] Audit logs : changements inventaire, revokes, deletes
- [ ] TLS obligatoire (API calls over HTTPS)
- [ ] Rate limiting sur API management
- [ ] Pas de credentials stockées en clair (token refresh obligatoire)

---

## Métriques de succès

| Phase | Métriques | Status |
|-------|-----------|--------|
| Phase 1 | 0 test en échec, relay-agent enregistré et connecté en WSS | ✅ COMPLÈTE |
| Phase 2 | 0 test en échec, relay-server reçoit enregistrement, gère WebSocket | ✅ COMPLÈTE |
| Phase 3 | 0 test en échec, playbook Ansible exécuté via plugin relay, inventaire dynamique | ✅ COMPLÈTE |
| MVP Qualif | E2E : enrollment → playbook exec → résultat sur 192.168.1.218 | ✅ VALIDÉE |
| Phase 4 | Helm deploy réussie, 3 agents K8s connectés, Ingress TLS OK, persistance vérifiée | 🆕 À FAIRE |
| Phase 5 | Runbooks testées, monitoring opérationnel, DR validated, sign-off utilisateur | 🆕 À FAIRE |
| Phase 6 | CLI opérationnelle : minions list/detail/revoke/delete, inventory edit/diff/rollback | 🆕 À FAIRE |
| Phase 7 | GO server : p95 latency < 10ms, memory < 10MB, 1000+ req/s, API 100% compatible | 🆕 À FAIRE |
| Phase 8 | GO agent : memory < 3MB, startup < 50ms, systemd service, backward-compatible | 🆕 À FAIRE |
| Phase 9 | GO wrappers : inventory refresh < 500ms, exec < 1s, Ansible plugins unchanged | 🆕 À FAIRE |
| LIVE | Production Kubernetes optimisée GO : SLA garantis, performance, CLI management | 🆕 À FAIRE |
