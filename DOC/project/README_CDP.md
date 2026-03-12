# Ansible-SecAgent — Guide CDP & Exécution du projet

**Ce document est le point d'entrée unique pour comprendre et exécuter le projet.**

---

## Documents de référence obligatoires

Lire **dans cet ordre avant toute action** :

1. **HLD.md** — Architecture haut niveau, schémas, flux de messages
2. **ARCHITECTURE.md** — Spécifications techniques détaillées (protocoles, sécurité, déploiement)
3. **[GitHub Issues](https://github.com/CCoupel/Ansible-SecAgent/issues)** — 96 issues, 10 phases, labels, milestones (source de vérité)
4. **PLAN_CDP.md** — Workflow CDP, règles absolues, conditions passage phases

---

## État du projet

- **Phase 0** : ✓ COMPLÈTE — Backlog créé (41 tâches, 3 phases, dépendances OK)
- **Phase 1** : ⏳ En attente de lancement (secagent-minion)
- **Phase 2** : À partir de Phase 1 validée (secagent-server)
- **Phase 3** : À partir de Phase 2 validée (plugins Ansible)
- **Production** : Après clôture MVP + confirmation utilisateur explicite

---

## Comment relancer le projet

### Pour un nouveau collaborateur ou une nouvelle session

1. Lire ce README_CDP.md (ce fichier)
2. Lire HLD.md + ARCHITECTURE.md
3. Consulter les [GitHub Issues](https://github.com/CCoupel/Ansible-SecAgent/issues) pour l'état des tâches
4. Consulter PLAN_CDP.md pour le workflow
5. Consulter TaskList (système interne) pour l'état en temps réel

### Pour relancer les agents de la team

Utiliser `/start-session` si disponible, ou démarrer manuellement.

**IMPORTANT — Comportement attendu au démarrage :**

- Tous les agents démarrent en **IDLE** — aucun ne commence de travail automatiquement
- Le CDP attend un ordre de l'utilisateur avant toute action
- L'utilisateur doit donner un ordre explicite (ex. : "Lance la Phase 1") pour que le CDP commence à orchestrer
- Les agents spécialisés restent inactifs jusqu'à réception d'une tâche assignée par le CDP

---

## Structure du projet

```
Ansible_Agent/
├── README_CDP.md           ← Vous êtes ici
├── HLD.md                  ← Architecture haute niveau
├── ARCHITECTURE.md         ← Spécifications techniques
├── BACKLOG.md              ← Table correspondance (archivé) → voir GitHub Issues
├── PLAN_CDP.md             ← Workflow CDP, règles absolues
├── agent/                  ← Phase 1 : secagent-minion daemon
│   ├── secagent_agent.py
│   ├── facts_collector.py
│   ├── async_registry.py
│   └── secagent-minion.service
├── server/                 ← Phase 2 : secagent-server FastAPI
│   ├── api/
│   ├── db/
│   └── broker/
├── ansible_plugins/        ← Phase 3 : plugins Ansible
│   ├── connection_plugins/secagent.py
│   └── inventory_plugins/secagent_inventory.py
├── tests/                  ← Tests unitaires + E2E
│   ├── unit/
│   ├── integration/
│   └── robustness/
└── docker-compose.yml      ← Déploiement qualif (à créer)
```

---

## Rôles de la team

- **cdp** : Chef de Projet — orchestration (ce rôle)
- **planner** : Architecte — backlog, spécifications
- **dev-agent** : Implémente agent/ (Phase 1)
- **dev-relay** : Implémente server/ (Phase 2)
- **dev-plugins** : Implémente ansible_plugins/ (Phase 3)
- **test-writer** : Tests unitaires + E2E
- **qa** : Exécute pytest, valide
- **security-reviewer** : Audit sécurité avant validation
- **deploy-qualif** : Docker Compose → 192.168.1.218
- **deploy-prod** : Kubernetes via Helm → production

---

## Workflow des phases

### PHASE 1 : secagent-minion (13 tâches #4-#23)

Pour chaque tâche, dans l'ordre des dépendances :
1. Assigner à dev-agent
2. dev-agent code + teste localement
3. test-writer écrit tests unitaires
4. qa lance pytest → valide 0 fail
5. security-reviewer audit → 0 CRITIQUE/HAUT
6. deploy-qualif déploie sur 192.168.1.218
7. Répéter pour tâche suivante

**Condition passage Phase 1 → 2** :
- ✓ TOUTES tâches #4-#23 completed
- ✓ qa : 0 test en échec
- ✓ security : 0 finding CRITIQUE/HAUT
- ✓ deploy-qualif : OK
- ✓ Confirmation utilisateur

### PHASE 2 : secagent-server (11 tâches #24-#34)

Même processus, avec dev-relay. **Dépend de Phase 1 déployée.**

**Condition passage Phase 2 → 3** : Idem Phase 1.

### PHASE 3 : plugins Ansible (7 tâches #35-#41)

Même processus, avec dev-plugins. **Dépend de Phase 2 déployée.**

Tests E2E obligatoires :
- Enrollment agent → serveur OK
- Playbook Ansible exécuté via plugin relay
- Résultats retournés

**Condition clôture MVP** :
- ✓ TOUTES tâches #35-#40 completed
- ✓ qa : 0 test en échec, E2E complets (nominaux + erreurs + async)
- ✓ security : 0 finding CRITIQUE/HAUT, audit global cohérent
- ✓ deploy-qualif : OK
- ✓ Confirmation utilisateur

### PRODUCTION (tâche #41)

Déploiement Kubernetes via Helm chart.

**Condition** : Clôture MVP validée + **confirmation utilisateur EXPLICITE**.

---

## Checklist sécurité

### Phase 1 (secagent-minion)
- [ ] TLS obligatoire (WSS)
- [ ] JWT signé côté agent
- [ ] Masquage `become_pass` dans logs
- [ ] Validation entrées (command injection)
- [ ] Isolation subprocess (pas de threads)
- [ ] RSA-4096 pour enrollment

### Phase 2 (secagent-server)
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

---

## Décisions techniques non négociables

- Transport : **WSS** obligatoire (TLS sur toutes les connexions)
- Canal agent : **1 WebSocket persistante** par agent, multiplexée par task_id
- Bus de messages : **NATS JetStream** (streams RELAY_TASKS + RELAY_RESULTS)
- Plugin Ansible → serveur : **REST HTTP bloquant**
- Auth : **JWT signé** (rôles agent/plugin/admin), blacklist JTI
- `authorized_keys` : **table DB** (pas de fichiers)
- Concurrence agent : **subprocess par tâche** (pas de threads)
- Stdout MVP : **buffer 5MB max**, truncation + flag
- Fichiers MVP : **< 500KB**, base64 inline
- Scope v1 : **Linux uniquement**

---

## Comment lancer une phase

### Phase 1 (secagent-minion)

```bash
# Utilisateur confirme le lancement
# CDP assigne tâche #4 à dev-agent
# dev-agent implémente facts_collector.py
# ...
```

**Vérifier dans TaskList** :
```
TaskList → voir tâches #4-#23 (Phase 1)
```

### Pour relancer après interruption

1. Consulter TaskList pour voir état des tâches
2. Reprendre à partir de la tâche en cours ou suivante
3. Les dépendances sont gérées par TaskList (blocked by)

---

## Stack technique

| Composant | Stack |
|-----------|-------|
| Agent | Python 3.11+, asyncio, websockets, subprocess, systemd |
| Serveur | Python 3.11+, FastAPI, NATS JetStream, SQLite/PostgreSQL, JWT |
| Plugins Ansible | Python, Ansible ConnectionBase / InventoryModule |
| Tests | pytest, pytest-asyncio, httpx |
| Déploiement qualif | Docker Compose |
| Déploiement prod | Kubernetes, Helm chart |

---

## Documents clés

| Fichier | Contenu | Lire avant |
|---------|---------|-----------|
| **HLD.md** | Architecture haute niveau, schémas, flux | Phase 1 |
| **ARCHITECTURE.md** | Spécifications détaillées (v1.1) | Phase 1 |
| **[GitHub Issues](https://github.com/CCoupel/Ansible-SecAgent/issues)** | 96 issues, phases, labels, milestones — source de vérité | Assignation |
| **BACKLOG.md** | Table correspondance backlog→issues (archivé) | Référence |
| **PLAN_CDP.md** | Workflow CDP, messages types, règles | Chaque phase |
| **.claude/commands/start-session.md** | Démarrage automatique team (si dispo) | Initial |

---

## Commandes utiles

```bash
# Consulter l'état des tâches
TaskList

# Assigner une tâche à dev-agent
TaskUpdate(taskId: "4", owner: "dev-agent", status: "in_progress")

# Marquer une tâche complète
TaskUpdate(taskId: "4", status: "completed")

# Communiquer avec la team
SendMessage(type: "message", recipient: "dev-agent", content: "...")
```

---

## Conditions absolues de passage entre phases

### Phase 0 → 1
- ✓ Backlog créé (41 tâches)
- ✓ Dépendances configurées
- ✓ Confirmation utilisateur

### Phase 1 → 2
- ✓ TOUTES tâches #4-#23 completed
- ✓ qa : 0 test en échec
- ✓ security : 0 CRITIQUE/HAUT
- ✓ deploy-qualif : OK
- ✓ Confirmation utilisateur

### Phase 2 → 3
- ✓ TOUTES tâches #24-#34 completed
- ✓ qa : 0 test en échec
- ✓ security : 0 CRITIQUE/HAUT
- ✓ deploy-qualif : OK (Phase 1 + 2)
- ✓ Confirmation utilisateur

### Phase 3 → Production
- ✓ TOUTES tâches #35-#40 completed
- ✓ qa : 0 test en échec (tests E2E complets)
- ✓ security : 0 CRITIQUE/HAUT (audit global)
- ✓ deploy-qualif : OK (E2E complet)
- ✓ **Confirmation utilisateur EXPLICITE pour prod**

---

## Métriques de succès

| Étape | Métrique |
|-------|----------|
| Phase 1 | secagent-minion enregistré + connecté WSS, 0 test fail |
| Phase 2 | secagent-server reçoit enrollment + gère WebSocket, 0 test fail |
| Phase 3 | Playbook Ansible exécuté via plugin relay, 0 test fail |
| MVP | E2E : enrollment → playbook → résultat, 0 fail, prod déployée Kubernetes |

---

## Points clés à retenir

1. **Démarrage IDLE obligatoire** : Au lancement, CDP et tous les agents restent en IDLE — aucune action sans ordre utilisateur
2. **Autonomie du projet** : Tous les documents (HLD, ARCHITECTURE, PLAN) sont dans le dossier du projet
3. **Traçabilité** : [GitHub Issues](https://github.com/CCoupel/Ansible-SecAgent/issues) = source de vérité pour l'état des tâches
4. **Validation stricte** : qa 0 fail + security 0 CRITIQUE/HAUT obligatoires pour chaque phase
5. **Pas de parallélisation** : Phases séquentielles uniquement, dépendances gérées par TaskList
6. **Confirmation utilisateur** : Jamais d'action sans ordre explicite pour passer une phase
7. **Sécurité d'abord** : Checklist sécurité validée avant chaque déploiement

---

**Date de création** : 2026-03-03
**Statut** : Phase 0 complète, Phase 1 en attente de lancement
