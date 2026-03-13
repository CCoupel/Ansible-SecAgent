#!/usr/bin/env python3
"""
Script to create GitHub issues from the Ansible-SecAgent backlog.
"""

import json
import os
import time
import urllib.request
import urllib.error

TOKEN = os.environ.get("GITHUB_TOKEN", "")
if not TOKEN:
    raise SystemExit("Error: GITHUB_TOKEN environment variable not set")
REPO = "CCoupel/Ansible-SecAgent"
BASE_URL = f"https://api.github.com/repos/{REPO}"

HEADERS = {
    "Authorization": f"token {TOKEN}",
    "Accept": "application/vnd.github.v3+json",
    "Content-Type": "application/json",
    "User-Agent": "Ansible-SecAgent-Bot"
}


def api_request(method, url, data=None):
    body = json.dumps(data).encode() if data else None
    req = urllib.request.Request(url, data=body, headers=HEADERS, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        print(f"HTTP Error {e.code}: {e.read().decode()}")
        return None


def create_label(name, color, description=""):
    data = {"name": name, "color": color, "description": description}
    result = api_request("POST", f"{BASE_URL}/labels", data)
    if result and "id" in result:
        print(f"  ✓ Label created: {name}")
    else:
        print(f"  ~ Label may exist: {name}")
    time.sleep(0.3)


def create_milestone(title, description, state="open"):
    data = {"title": title, "description": description, "state": state}
    result = api_request("POST", f"{BASE_URL}/milestones", data)
    if result and "number" in result:
        print(f"  ✓ Milestone created: {title} (#{result['number']})")
        return result["number"]
    else:
        # Try to get existing
        milestones = api_request("GET", f"{BASE_URL}/milestones?state=all&per_page=100")
        if milestones:
            for m in milestones:
                if m["title"] == title:
                    print(f"  ~ Milestone exists: {title} (#{m['number']})")
                    return m["number"]
    return None


def create_issue(title, body, labels=None, milestone=None):
    data = {"title": title, "body": body}
    if labels:
        data["labels"] = labels
    if milestone:
        data["milestone"] = milestone
    result = api_request("POST", f"{BASE_URL}/issues", data)
    if result and "number" in result:
        print(f"  ✓ Issue #{result['number']}: {title[:60]}")
        return result["number"]
    else:
        print(f"  ✗ Failed: {title[:60]}")
        return None


def close_issue(issue_number):
    data = {"state": "closed"}
    api_request("PATCH", f"{BASE_URL}/issues/{issue_number}", data)


# ─── LABELS ─────────────────────────────────────────────────────────────────

LABELS = [
    # Phases
    ("phase:1-minion",     "0075ca", "Phase 1 — secagent-minion"),
    ("phase:2-server",     "e4e669", "Phase 2 — secagent-server"),
    ("phase:3-plugins",    "d93f0b", "Phase 3 — plugins Ansible"),
    ("phase:4-k8s",        "0052cc", "Phase 4 — Production Kubernetes"),
    ("phase:5-hardening",  "b60205", "Phase 5 — Documentation & Hardening"),
    ("phase:6-cli",        "5319e7", "Phase 6 — Management CLI GO"),
    ("phase:7-server-go",  "006b75", "Phase 7 — Server rewrite GO"),
    ("phase:8-agent-go",   "1d76db", "Phase 8 — Agent rewrite GO"),
    ("phase:9-plugins-go", "0e8a16", "Phase 9 — Plugins wrapper GO"),
    ("phase:10-enrollment","e11d48", "Phase 10 — Enrollment Token Security"),
    # Status
    ("status:completed",   "0e8a16", "Tâche terminée"),
    ("status:suspended",   "e4e669", "Tâche suspendue"),
    ("status:obsolete",    "cfd3d7", "Tâche obsolète"),
    ("status:todo",        "d876e3", "À faire"),
    # Owners
    ("owner:dev-agent",    "bfd4f2", "Developer Agent"),
    ("owner:dev-relay",    "bfd4f2", "Developer Relay/Server"),
    ("owner:dev-plugins",  "bfd4f2", "Developer Plugins"),
    ("owner:test-writer",  "fef2c0", "Test Writer"),
    ("owner:qa",           "fef2c0", "QA"),
    ("owner:security",     "f9d0c4", "Security Reviewer"),
    ("owner:deploy-qualif","c5def5", "Deploy Qualif"),
    ("owner:deploy-prod",  "c5def5", "Deploy Prod"),
    ("owner:cdp",          "e4e669", "Chef de Projet"),
    # Types
    ("type:implementation","0075ca", "Implémentation"),
    ("type:test",          "0e8a16", "Tests"),
    ("type:qa",            "fef2c0", "Quality Assurance"),
    ("type:security",      "b60205", "Security Review"),
    ("type:deploy",        "c5def5", "Déploiement"),
    ("type:validation",    "e4e669", "Validation de phase"),
]

# ─── MILESTONES ──────────────────────────────────────────────────────────────

MILESTONES_DEF = [
    ("Phase 1 — secagent-minion",         "Agent Python MVP : enrollment, WSS, exec, fichiers, systemd"),
    ("Phase 2 — secagent-server",         "Serveur Python MVP : SQLite, JWT, WS, NATS, FastAPI"),
    ("Phase 3 — plugins Ansible",         "Plugin connection Python + secagent-inventory binary"),
    ("Phase 4 — Production Kubernetes",   "Helm chart K8s complet (SUSPENDU — pas de cluster K8s)"),
    ("Phase 5 — Hardening & Docs",        "Runbooks, monitoring, DR, performance (SUSPENDU)"),
    ("Phase 6 — Management CLI GO",       "CLI cobra : minions, security keys, inventory, server status"),
    ("Phase 7 — Server GO",               "Réécriture serveur en GO : perf 20x, binary unique"),
    ("Phase 8 — Agent GO",                "Réécriture agent en GO : 2-3MB, startup 10ms"),
    ("Phase 9 — Plugins GO",              "Wrappers GO pour inventory et exec depuis Ansible"),
    ("Phase 10 — Enrollment Token",       "Token single-use + challenge-response OAEP + plugin tokens"),
]

# ─── ISSUES ──────────────────────────────────────────────────────────────────

def make_issues(milestones):
    m = milestones  # shorthand

    # ── PHASE 1 ──────────────────────────────────────────────────────────────
    p1_labels = ["phase:1-minion", "status:completed"]

    tasks_p1 = [
        ("#4 — facts_collector.py : collecte facts système",
         """## Description
Implémenter `facts_collector.py` — collecte des facts système de l'agent.

## Spécifications
- Collecter : hostname, IP, OS, version, architecture
- Format JSON compatible Ansible facts
- Utilisé lors de l'enrollment (POST /api/register)

## Références
- `DOC/common/ARCHITECTURE.md` section "Agent"
- `DOC/agent/AGENT_SPEC.md`

## Dépendances
Aucune (tâche de base)

## Bloquée par
Aucune""",
         ["phase:1-minion", "status:completed", "owner:dev-agent", "type:implementation"], m[0]),

        ("#6 — secagent_agent.py : enrollment POST /api/register + RSA-4096",
         """## Description
Implémenter l'enrollment de l'agent : génération RSA-4096, envoi POST `/api/register`, stockage du JWT reçu.

## Spécifications
- Générer keypair RSA-4096 au premier démarrage
- POST `/api/register` avec hostname, pubkey, facts
- Stocker JWT reçu de façon sécurisée
- Gérer les erreurs d'enrollment (retry, backoff)

## Références
- `DOC/security/SECURITY.md` §3 (enrollment)
- `DOC/agent/AGENT_SPEC.md`

## Bloquée par
- #4 (facts_collector.py)""",
         ["phase:1-minion", "status:completed", "owner:dev-agent", "type:implementation"], m[0]),

        ("#8 — secagent_agent.py : connexion WSS + backoff exponentiel (1s→60s)",
         """## Description
Implémenter la connexion WebSocket Secure (WSS) de l'agent avec reconnexion automatique.

## Spécifications
- Connexion WSS au serveur avec JWT Bearer
- Backoff exponentiel : 1s → 2s → 4s → ... → 60s max
- Reconnexion automatique sur déconnexion
- Log des tentatives de reconnexion

## Références
- `DOC/common/ARCHITECTURE.md` section "Agent WebSocket"
- `DOC/common/HLD.md` schémas agent

## Bloquée par
- #6 (enrollment)""",
         ["phase:1-minion", "status:completed", "owner:dev-agent", "type:implementation"], m[0]),

        ("#9 — secagent_agent.py : dispatcher messages WS (exec/put_file/fetch_file/cancel)",
         """## Description
Implémenter le dispatcher de messages WebSocket de l'agent.

## Spécifications
- Parser les messages JSON entrants
- Router vers les handlers : `exec`, `put_file`, `fetch_file`, `cancel`
- Répondre avec `task_id` pour le multiplexage
- Gérer les messages inconnus gracieusement

## Références
- `DOC/common/ARCHITECTURE.md` section "Protocol Messages"
- `DOC/agent/AGENT_SPEC.md`

## Bloquée par
- #8 (connexion WSS)""",
         ["phase:1-minion", "status:completed", "owner:dev-agent", "type:implementation"], m[0]),

        ("#11 — secagent_agent.py : exec_command subprocess + stdout streaming + buffer 5MB",
         """## Description
Implémenter l'exécution de commandes via subprocess avec streaming stdout.

## Spécifications
- Lancer subprocess pour chaque commande (pas de threads)
- Streamer stdout/stderr via WebSocket
- Buffer max 5MB — truncation + flag `truncated: true` si dépassé
- Masquer `become_pass` dans tous les logs (CRITIQUE sécurité)
- Support `become` (sudo)

## Sécurité
- **CRITIQUE** : `become_pass` ne doit jamais apparaître dans les logs

## Références
- `DOC/agent/AGENT_SPEC.md` section "exec_command"
- `DOC/common/ARCHITECTURE.md` §"Stdout MVP"

## Bloquée par
- #9 (dispatcher)""",
         ["phase:1-minion", "status:completed", "owner:dev-agent", "type:implementation"], m[0]),

        ("#13 — secagent_agent.py : put_file (base64, mkdir -p, chmod)",
         """## Description
Implémenter le transfert de fichiers vers l'agent.

## Spécifications
- Recevoir fichier en base64 via message WS
- Créer le répertoire parent (`mkdir -p`)
- Écrire le fichier et appliquer chmod
- Limite : 500KB max par fichier

## Références
- `DOC/agent/AGENT_SPEC.md` section "put_file"

## Bloquée par
- #9 (dispatcher)""",
         ["phase:1-minion", "status:completed", "owner:dev-agent", "type:implementation"], m[0]),

        ("#14 — secagent_agent.py : fetch_file (lecture, base64, limite 500KB)",
         """## Description
Implémenter la récupération de fichiers depuis l'agent.

## Spécifications
- Lire un fichier local et l'encoder en base64
- Limite stricte 500KB — erreur si dépassé
- Envoyer via message WS de réponse

## Références
- `DOC/agent/AGENT_SPEC.md` section "fetch_file"

## Bloquée par
- #9 (dispatcher)""",
         ["phase:1-minion", "status:completed", "owner:dev-agent", "type:implementation"], m[0]),

        ("#15 — async_registry.py : registre JSON persisté, reprise redémarrage",
         """## Description
Implémenter le registre des tâches asynchrones avec persistance JSON.

## Spécifications
- Stocker l'état de chaque tâche en cours (task_id, status, pid)
- Persister sur disque (JSON) pour survie redémarrage
- Au démarrage : reprendre les tâches interrompues ou les marquer failed
- Thread-safe (même si subprocess-only, plusieurs tâches concurrentes)

## Références
- `DOC/agent/AGENT_SPEC.md` section "async_registry"

## Bloquée par
- #9 (dispatcher)""",
         ["phase:1-minion", "status:completed", "owner:dev-agent", "type:implementation"], m[0]),

        ("#17 — secagent-minion.service : unit file systemd (NoNewPrivileges, ProtectSystem)",
         """## Description
Créer l'unit file systemd pour l'agent secagent-minion.

## Spécifications
- `NoNewPrivileges=true`
- `ProtectSystem=strict`
- `PrivateTmp=true`
- `Restart=always`, `RestartSec=5`
- Variables d'environnement : `RELAY_URL`, `RELAY_ENROLLMENT_TOKEN`
- User dédié non-root

## Références
- `DOC/agent/AGENT_SPEC.md` section "systemd"

## Bloquée par
Aucune (indépendant du code)""",
         ["phase:1-minion", "status:completed", "owner:dev-agent", "type:implementation"], m[0]),

        ("#19 — Tests unitaires secagent-minion Phase 1",
         """## Description
Écrire les tests unitaires pour tous les composants Phase 1.

## Spécifications
- Tests pytest pour : facts_collector, enrollment, WSS, dispatcher, exec, put_file, fetch_file, async_registry
- Mocking des dépendances externes (WSS, subprocess)
- Coverage > 80%

## Bloquée par
- #4, #6, #8, #9, #11, #13, #14, #15, #17""",
         ["phase:1-minion", "status:completed", "owner:test-writer", "type:test"], m[0]),

        ("#20 — QA Phase 1 : pytest, rapport (nb tests, pass, fail, détails)",
         """## Description
Exécuter la suite de tests Phase 1 et produire un rapport QA.

## Critères
- 0 test en échec
- Rapport : nombre total, pass, fail, détails des failures
- Couverture code > 80%

## Bloquée par
- #19 (tests unitaires Phase 1)""",
         ["phase:1-minion", "status:completed", "owner:qa", "type:qa"], m[0]),

        ("#22 — Security review Phase 1 : audit secagent-minion",
         """## Description
Audit de sécurité complet du code secagent-minion Phase 1.

## Critères d'audit
- [ ] TLS obligatoire (WSS)
- [ ] JWT signé côté agent
- [ ] `become_pass` masqué dans tous les logs
- [ ] Validation des entrées (command injection)
- [ ] Isolation subprocess (pas de threads)
- [ ] RSA-4096 pour enrollment

## Critères de sortie
- 0 finding CRITIQUE ou HAUT

## Bloquée par
- #20 (QA Phase 1)""",
         ["phase:1-minion", "status:completed", "owner:security", "type:security"], m[0]),

        ("#23 — Deploy qualif Phase 1 : secagent-minion sur 192.168.1.218",
         """## Description
Déployer secagent-minion sur l'environnement de qualification (192.168.1.218).

## Critères
- Agent enregistré et connecté via WSS
- Systemd service opérationnel
- Exec de commandes fonctionnel

## Bloquée par
- #22 (security review Phase 1)""",
         ["phase:1-minion", "status:completed", "owner:deploy-qualif", "type:deploy"], m[0]),
    ]

    # ── PHASE 2 ──────────────────────────────────────────────────────────────
    tasks_p2 = [
        ("#24 — agent_store.py : modèles SQLite (agents, authorized_keys, blacklist)",
         """## Description
Implémenter le store SQLite du serveur : tables agents, authorized_keys, blacklist JTI.

## Schéma
- `agents` : id, hostname, pubkey_pem, jwt, status, last_seen
- `authorized_keys` : id, hostname, pubkey_pem, added_by
- `blacklist` : jti, expires_at

## Références
- `DOC/server/SERVER_SPEC.md` section "Database"
- `DOC/common/ARCHITECTURE.md` §"Storage"

## Bloquée par
Aucune""",
         ["phase:2-server", "status:completed", "owner:dev-relay", "type:implementation"], m[1]),

        ("#25 — routes_register.py : enrollment + auth JWT + blacklist JTI",
         """## Description
Implémenter les routes d'enrollment et d'authentification JWT avec blacklist JTI.

## Spécifications
- POST `/api/register` : vérifier authorized_keys, générer JWT, stocker agent
- Middleware JWT : vérifier signature, expiry, JTI blacklist
- Rôles JWT : `agent`, `plugin`, `admin`
- Blacklist JTI : consulter DB à chaque requête

## Références
- `DOC/security/SECURITY.md` §2 (JWT roles), §4 (blacklist)
- `DOC/server/SERVER_SPEC.md`

## Bloquée par
- #24 (agent_store)""",
         ["phase:2-server", "status:completed", "owner:dev-relay", "type:implementation"], m[1]),

        ("#26 — ws_handler.py : connexions WS, futures, on_ws_close",
         """## Description
Implémenter le handler WebSocket du serveur pour les connexions agents.

## Spécifications
- Accepter connexions WSS agents avec JWT
- Registry des connexions actives (dict hostname → ws)
- Futures pour les réponses async (task_id → Future)
- Nettoyage sur `on_ws_close` (libérer futures pending)

## Références
- `DOC/common/HLD.md` flux messages et broker
- `DOC/server/SERVER_SPEC.md` section "WebSocket"

## Bloquée par
- #25 (auth JWT)""",
         ["phase:2-server", "status:completed", "owner:dev-relay", "type:implementation"], m[1]),

        ("#27 — nats_client.py : NATS JetStream (RELAY_TASKS, RELAY_RESULTS)",
         """## Description
Implémenter le client NATS JetStream pour les streams de tâches et résultats.

## Spécifications
- Stream `RELAY_TASKS` : publish tasks vers agents
- Stream `RELAY_RESULTS` : consume résultats depuis agents
- Consumer durable pour persistence
- Retry en cas d'échec NATS

## Références
- `DOC/common/ARCHITECTURE.md` §"NATS JetStream"
- `DOC/server/SERVER_SPEC.md` section "NATS"

## Bloquée par
- #24 (agent_store)""",
         ["phase:2-server", "status:completed", "owner:dev-relay", "type:implementation"], m[1]),

        ("#28 — routes_exec.py : endpoints /api/exec, /api/upload, /api/fetch, /api/inventory",
         """## Description
Implémenter les endpoints REST que les plugins Ansible appellent.

## Endpoints
- `POST /api/exec` : exécuter une commande sur un agent
- `POST /api/upload` : envoyer un fichier vers un agent
- `POST /api/fetch` : récupérer un fichier depuis un agent
- `GET /api/inventory` : inventaire dynamique Ansible

## Références
- `DOC/server/SERVER_SPEC.md` section "REST API"
- `DOC/plugins/PLUGINS_SPEC.md`

## Bloquée par
- #26 (WS handler), #27 (NATS)""",
         ["phase:2-server", "status:completed", "owner:dev-relay", "type:implementation"], m[1]),

        ("#29 — main.py : FastAPI app (lifespan, health check)",
         """## Description
Implémenter l'application FastAPI principale avec lifespan et health check.

## Spécifications
- App FastAPI avec lifespan (init NATS, SQLite, shutdown propre)
- `GET /health` : status 200 + version
- Multi-port : 7770 (API), 7771 (exec), 7772 (inventory)
- Configuration via variables d'environnement

## Références
- `DOC/server/SERVER_SPEC.md` section "Application"

## Bloquée par
- #25, #26, #27, #28""",
         ["phase:2-server", "status:completed", "owner:dev-relay", "type:implementation"], m[1]),

        ("#30 — docker-compose.yml + Dockerfile : NATS, relay-api, caddy",
         """## Description
Créer la configuration Docker Compose pour l'environnement de qualification.

## Services
- `nats` : NATS JetStream avec persistance
- `relay-api` : secagent-server (FastAPI)
- `caddy` : reverse proxy TLS (ports 7770/7771/7772)

## Références
- `DOC/project/DEPLOYMENT.md`
- `DEPLOYMENT/qualif/`

## Bloquée par
- #29 (main.py)""",
         ["phase:2-server", "status:completed", "owner:dev-relay", "type:deploy"], m[1]),

        ("#31 — Tests unitaires secagent-server Phase 2",
         """## Description
Écrire les tests unitaires pour tous les composants Phase 2.

## Spécifications
- Tests pytest : agent_store, routes_register, ws_handler, nats_client, routes_exec
- Mocking NATS, SQLite en mémoire
- Coverage > 80%

## Bloquée par
- #24 à #30""",
         ["phase:2-server", "status:completed", "owner:test-writer", "type:test"], m[1]),

        ("#32 — QA Phase 2 : pytest, rapport",
         """## Description
Exécuter la suite de tests Phase 2 et produire un rapport QA.

## Critères
- 0 test en échec
- Rapport : nombre total, pass, fail, détails

## Bloquée par
- #31 (tests Phase 2)""",
         ["phase:2-server", "status:completed", "owner:qa", "type:qa"], m[1]),

        ("#33 — Security review Phase 2 : audit secagent-server",
         """## Description
Audit de sécurité complet du serveur secagent-server Phase 2.

## Critères d'audit
- [ ] TLS obligatoire (WSS + HTTPS)
- [ ] JWT signé + rôles agent/plugin/admin
- [ ] Blacklist JTI (token revocation)
- [ ] Validation entrées API (injection)
- [ ] `become_pass` masqué dans logs et stockage
- [ ] Rate limiting

## Critères de sortie
- 0 finding CRITIQUE ou HAUT

## Bloquée par
- #32 (QA Phase 2)""",
         ["phase:2-server", "status:completed", "owner:security", "type:security"], m[1]),

        ("#34 — Deploy qualif Phase 2 : secagent-server complet sur 192.168.1.218",
         """## Description
Déployer le serveur complet sur l'environnement de qualification.

## Critères
- NATS JetStream opérationnel
- secagent-server démarré sur 3 ports
- Agent de Phase 1 se connecte avec succès

## Bloquée par
- #33 (security review Phase 2), #23 (deploy Phase 1)""",
         ["phase:2-server", "status:completed", "owner:deploy-qualif", "type:deploy"], m[1]),
    ]

    # ── PHASE 3 ──────────────────────────────────────────────────────────────
    tasks_p3 = [
        ("#35 — connection_plugins/secagent.py : ConnectionBase (exec, put_file, fetch_file, pipelining, become)",
         """## Description
Implémenter le plugin de connexion Ansible `secagent.py`.

## Spécifications
- Hériter de `ConnectionBase`
- Implémenter : `exec_command`, `put_file`, `fetch_file`
- Support `become` (sudo via `become_pass`)
- Support pipelining
- Appels REST HTTP vers secagent-server (bloquant)
- **Obligatoire Python** — API Ansible uniquement disponible en Python

## Sécurité
- `become_pass` ne doit JAMAIS apparaître dans les logs

## Références
- `DOC/plugins/PLUGINS_SPEC.md`
- `DOC/common/ARCHITECTURE.md` §"Ansible Plugin"

## Notes
Ce plugin est **obligatoirement en Python** : l'API Ansible (`ConnectionBase`) n'est disponible qu'en Python.

## Bloquée par
- #34 (serveur déployé)""",
         ["phase:3-plugins", "status:completed", "owner:dev-plugins", "type:implementation"], m[2]),

        ("#36 — inventory_plugins/secagent_inventory.py : InventoryModule (GET /api/inventory)",
         """## Description
Plugin inventory Ansible Python (OBSOLÈTE — remplacé par secagent-inventory binaire GO, Phase 9).

## Statut
⏸ **OBSOLÈTE** — `secagent-inventory` binaire GO (Phase 9) remplace ce plugin.

## Notes architecture
L'alternative GO (`secagent-inventory` binaire, Phase 9) remplace ce plugin Python.
Le plugin Python reste en place comme fallback mais n'est plus maintenu activement.

## Bloquée par
- #34 (serveur déployé)""",
         ["phase:3-plugins", "status:obsolete", "owner:dev-plugins", "type:implementation"], m[2]),

        ("#37 — Tests unitaires + E2E plugins Phase 3",
         """## Description
Écrire les tests unitaires et E2E pour les plugins Ansible Phase 3.

## Spécifications
- Tests unitaires : plugin connection (mocking HTTP)
- Tests E2E : playbook Ansible réel via plugin secagent
- Tests secagent-inventory binary

## Bloquée par
- #35, #36""",
         ["phase:3-plugins", "status:completed", "owner:test-writer", "type:test"], m[2]),

        ("#38 — QA Phase 3 : pytest (unitaire + E2E), rapport",
         """## Description
Exécuter la suite de tests Phase 3 (connection plugin + secagent-inventory binary) et produire un rapport QA.

## Critères
- 0 test en échec
- Tests E2E couvrant : cas nominaux, erreurs, async

## Bloquée par
- #37 (tests Phase 3)""",
         ["phase:3-plugins", "status:completed", "owner:qa", "type:qa"], m[2]),

        ("#39 — Security review global : audit Phase 3 + revue MVP complète",
         """## Description
Audit de sécurité global couvrant Phase 3 et revue bout-en-bout du MVP.

## Critères d'audit
- [ ] Validation tokens plugin
- [ ] Pas de fuite credentials dans les logs
- [ ] TLS sur appels REST au serveur
- [ ] Audit global bout-en-bout

## Critères de sortie
- 0 finding CRITIQUE ou HAUT

## Bloquée par
- #38 (QA Phase 3)""",
         ["phase:3-plugins", "status:completed", "owner:security", "type:security"], m[2]),

        ("#40 — Deploy qualif Phase 3 : test E2E complet sur 192.168.1.218",
         """## Description
Déployer et valider le MVP complet en qualification : connection plugin + secagent-inventory binary.

## Critères
- Playbook Ansible exécuté de bout en bout
- Inventaire dynamique fonctionnel
- E2E : enrollment → playbook exec → résultat

## Bloquée par
- #39 (security review global)""",
         ["phase:3-plugins", "status:completed", "owner:deploy-qualif", "type:deploy"], m[2]),

        ("#41 — Deploy prod Phase 3 : Helm chart Kubernetes (après confirmation utilisateur)",
         """## Description
Déployer le MVP en production via Helm chart Kubernetes.

## Statut
⏸ **SUSPENDU** — Pas de cluster Kubernetes en production actuellement.

## Prérequis
- Confirmation explicite de l'utilisateur
- Cluster Kubernetes disponible
- Helm 3.x installé

## Bloquée par
- #40 (deploy qualif Phase 3)""",
         ["phase:3-plugins", "status:suspended", "owner:deploy-qualif", "type:deploy"], m[2]),
    ]

    # ── PHASE 4 ──────────────────────────────────────────────────────────────
    tasks_p4 = [
        ("#42 — Helm chart structure : values.yaml, templates/, Chart.yaml",
         """## Description
Créer la structure de base du Helm chart pour Ansible-SecAgent.

## Statut
⏸ **SUSPENDU** — Pas de cluster Kubernetes en production actuellement.

## Fichiers à créer
- `Chart.yaml` : métadonnées du chart
- `values.yaml` : valeurs par défaut commentées
- `templates/` : répertoire templates

## Bloquée par
- #40 (MVP qualifié)""",
         ["phase:4-k8s", "status:suspended", "owner:deploy-prod", "type:implementation"], m[3]),

        ("#43 — Helm StatefulSet NATS JetStream : persistance, replicas, antiaffinity",
         """## Description
Créer le StatefulSet Helm pour NATS JetStream avec persistance.

## Statut
⏸ **SUSPENDU** — Pas de cluster Kubernetes en production actuellement.

## Spécifications
- StatefulSet avec PVC pour persistance JetStream
- Anti-affinity pour haute disponibilité
- Replicas configurables via values.yaml

## Bloquée par
- #42 (Helm structure)""",
         ["phase:4-k8s", "status:suspended", "owner:deploy-prod", "type:implementation"], m[3]),

        ("#44 — Helm Deployment secagent-server : multi-port, replicas, PDB",
         """## Description
Créer le Deployment Helm pour secagent-server.

## Statut
⏸ **SUSPENDU**

## Spécifications
- Deployment multi-port (7770/7771/7772)
- PodDisruptionBudget pour HA
- Replicas configurables

## Bloquée par
- #42""",
         ["phase:4-k8s", "status:suspended", "owner:deploy-prod", "type:implementation"], m[3]),

        ("#45 — Helm DaemonSet secagent-minion : 1 par nœud, node affinity, tolerations",
         """## Description
Créer le DaemonSet Helm pour secagent-minion (1 agent par nœud K8s).

## Statut
⏸ **SUSPENDU**

## Spécifications
- DaemonSet : 1 pod par nœud
- Node affinity et tolerations configurables
- Variables d'environnement : RELAY_URL, RELAY_ENROLLMENT_TOKEN

## Bloquée par
- #42""",
         ["phase:4-k8s", "status:suspended", "owner:deploy-prod", "type:implementation"], m[3]),

        ("#46 — Helm ConfigMap + Secrets : JWT_SECRET, ADMIN_TOKEN, TLS certs",
         """## Description
Créer les ConfigMap et Secrets Helm pour la configuration sécurisée.

## Statut
⏸ **SUSPENDU**

## Spécifications
- Secret : JWT_SECRET_KEY, ADMIN_TOKEN
- Secret : certificats TLS
- ConfigMap : configuration non-sensible

## Bloquée par
- #42""",
         ["phase:4-k8s", "status:suspended", "owner:deploy-prod", "type:implementation"], m[3]),

        ("#47 — Helm Ingress : TLS termination, routing 7770/7771/7772",
         """## Description
Créer l'Ingress Helm avec terminaison TLS.

## Statut
⏸ **SUSPENDU**

## Spécifications
- TLS termination
- Routing vers les 3 ports (7770/7771/7772)
- Annotations configurables (nginx/traefik)

## Bloquée par
- #42""",
         ["phase:4-k8s", "status:suspended", "owner:deploy-prod", "type:implementation"], m[3]),

        ("#48 — Helm Service (ClusterIP + LoadBalancer) : NATS, relay-api",
         """## Description
Créer les Services Helm pour NATS et relay-api.

## Statut
⏸ **SUSPENDU**

## Spécifications
- ClusterIP pour communication interne
- LoadBalancer optionnel pour accès externe
- Annotations cloud provider configurables

## Bloquée par
- #42""",
         ["phase:4-k8s", "status:suspended", "owner:deploy-prod", "type:implementation"], m[3]),

        ("#49 — Helm PersistentVolumeClaim : NATS data, relay DB, agent state",
         """## Description
Créer les PVC Helm pour la persistance des données.

## Statut
⏸ **SUSPENDU**

## Spécifications
- PVC NATS : données JetStream
- PVC relay : SQLite DB
- PVC agent : état async registry
- StorageClass configurables

## Bloquée par
- #42""",
         ["phase:4-k8s", "status:suspended", "owner:deploy-prod", "type:implementation"], m[3]),

        ("#50 — Helm tests : helm lint, helm template, helm dry-run",
         """## Description
Valider le Helm chart avec lint, template et dry-run.

## Statut
⏸ **SUSPENDU**

## Critères
- `helm lint` : 0 erreurs
- `helm template` : YAML valide
- `helm dry-run` : OK

## Bloquée par
- #42 (structure complète)""",
         ["phase:4-k8s", "status:suspended", "owner:deploy-prod", "type:test"], m[3]),

        ("#51 — Helm deployment script : helm install/upgrade sur cluster K8s",
         """## Description
Script de déploiement Helm (install/upgrade/rollback).

## Statut
⏸ **SUSPENDU**

## Bloquée par
- #50 (tests Helm)""",
         ["phase:4-k8s", "status:suspended", "owner:deploy-prod", "type:deploy"], m[3]),

        ("#52 — Documentation Helm : values.yaml comments, deployment guide, troubleshooting",
         """## Description
Documenter le Helm chart : values commentés, guide de déploiement, troubleshooting.

## Statut
⏸ **SUSPENDU**

## Bloquée par
- #51 (script déploiement)""",
         ["phase:4-k8s", "status:suspended", "owner:deploy-prod", "type:implementation"], m[3]),

        ("#53 — Deploy prod Phase 4 : Helm install sur Kubernetes cluster",
         """## Description
Déploiement final en production Kubernetes.

## Statut
⏸ **SUSPENDU** — Pas de cluster Kubernetes en production actuellement.

## Critères
- 3 agents enregistrés et connectés
- Ingress TLS fonctionnelle
- Persistance NATS et DB vérifiée après redémarrage pod

## Bloquée par
- #52 (documentation)""",
         ["phase:4-k8s", "status:suspended", "owner:deploy-prod", "type:deploy"], m[3]),
    ]

    # ── PHASE 5 ──────────────────────────────────────────────────────────────
    tasks_p5 = [
        ("#54 — Runbooks prod : escalade, diagnostics, rollback",
         """## Description
Créer les runbooks de production : escalade, diagnostics, rollback.

## Statut
⏸ **SUSPENDU** — Dépend de Phase 4 (pas de K8s prod).

## Bloquée par
- #53 (prod déployée)""",
         ["phase:5-hardening", "status:suspended", "owner:deploy-prod", "type:implementation"], m[4]),

        ("#55 — Monitoring setup : Prometheus métriques, alerting, dashboards Grafana",
         """## Description
Mettre en place le monitoring avec Prometheus et Grafana.

## Statut
⏸ **SUSPENDU**

## Bloquée par
- #53""",
         ["phase:5-hardening", "status:suspended", "owner:deploy-prod", "type:implementation"], m[4]),

        ("#56 — Hardening sécurité prod : network policies, RBAC, admission controllers",
         """## Description
Appliquer le hardening de sécurité en production.

## Statut
⏸ **SUSPENDU**

## Bloquée par
- #53""",
         ["phase:5-hardening", "status:suspended", "owner:security", "type:security"], m[4]),

        ("#57 — Disaster recovery : backup NATS, DB recovery, failover procedure",
         """## Description
Mettre en place les procédures de disaster recovery.

## Statut
⏸ **SUSPENDU**

## Bloquée par
- #53""",
         ["phase:5-hardening", "status:suspended", "owner:deploy-prod", "type:implementation"], m[4]),

        ("#58 — Performance tuning : load testing, baseline metrics, optimization",
         """## Description
Tests de charge et optimisation des performances en production.

## Statut
⏸ **SUSPENDU**

## Bloquée par
- #53""",
         ["phase:5-hardening", "status:suspended", "owner:qa", "type:qa"], m[4]),

        ("#59 — Migration guide : from qualif to prod, zero-downtime strategy",
         """## Description
Guide de migration de l'environnement qualif vers la production avec stratégie zero-downtime.

## Statut
⏸ **SUSPENDU**

## Bloquée par
- #53""",
         ["phase:5-hardening", "status:suspended", "owner:deploy-prod", "type:implementation"], m[4]),

        ("#60 — SLA & Support : métriques, escalade, on-call procedure",
         """## Description
Définir les SLA, les métriques de support et la procédure on-call.

## Statut
⏸ **SUSPENDU**

## Bloquée par
- #53""",
         ["phase:5-hardening", "status:suspended", "owner:deploy-prod", "type:implementation"], m[4]),

        ("#61 — MVP Final Review & Sign-off",
         """## Description
Revue finale du MVP et sign-off utilisateur.

## Statut
⏸ **SUSPENDU**

## Critères
- Runbooks testées
- Monitoring opérationnel
- Security audit : 0 findings CRITIQUE/HAUT
- DR tested : RTO/RPO validés
- Performance : SLA met
- Sign-off CDO + Utilisateur

## Bloquée par
- #54 à #60""",
         ["phase:5-hardening", "status:suspended", "owner:cdp", "type:validation"], m[4]),
    ]

    # ── PHASE 6 ──────────────────────────────────────────────────────────────
    tasks_p6 = [
        ("#62 — Server : endpoints admin manquants (minions, suspend/resume, vars CRUD, status)",
         """## Description
Implémenter les endpoints admin manquants dans le serveur GO.

## Endpoints à créer
- `GET /api/admin/minions` : liste des minions
- `POST /api/admin/minions/:hostname/suspend`
- `POST /api/admin/minions/:hostname/resume`
- `GET/POST/DELETE /api/admin/minions/:hostname/vars` : CRUD variables
- `GET /api/admin/status` : état du serveur

## Références
- `DOC/server/SERVER_SPEC.md`
- `DOC/server/MANAGEMENT_CLI_SPECS.md`

## Bloquée par
Aucune (tâche indépendante)""",
         ["phase:6-cli", "status:completed", "owner:dev-relay", "type:implementation"], m[5]),

        ("#63 — Server : DB server_config + persistance RSA keypair + dual-key JWT validation",
         """## Description
Implémenter la table `server_config` pour persister la keypair RSA et gérer la validation JWT dual-key (rotation avec grâce).

## Spécifications
- Table `server_config` : key, value (keypair RSA sérialisée)
- Chargement keypair au démarrage, génération si absente
- JWT validation : accepter les tokens signés avec l'ancienne ET la nouvelle clef pendant la période de grâce

## Références
- `DOC/common/ARCHITECTURE.md` §22 (rotation avec grâce)
- `DOC/security/SECURITY.md` §5

## Bloquée par
- #62""",
         ["phase:6-cli", "status:completed", "owner:dev-relay", "type:implementation"], m[5]),

        ("#64 — Server : rotation des clefs (POST /api/admin/keys/rotate, grace period, message WS rekey)",
         """## Description
Implémenter la rotation des clefs JWT avec période de grâce.

## Spécifications
- `POST /api/admin/keys/rotate?grace=24h` : générer nouvelle keypair
- Pendant la période de grâce : accepter tokens signés avec ancienne OU nouvelle clef
- Envoyer message WS `rekey` à tous les agents connectés
- Purger l'ancienne clef après la période de grâce

## Références
- `DOC/common/ARCHITECTURE.md` §22 (rotation)

## Bloquée par
- #63""",
         ["phase:6-cli", "status:completed", "owner:dev-relay", "type:implementation"], m[5]),

        ("#65 — Agent : handler WS rekey + gestion 401 sur connect → ré-enrôlement auto",
         """## Description
Implémenter le handler `rekey` dans l'agent GO et la gestion automatique du 401.

## Spécifications
- Handler message WS `rekey` : re-fetch JWT avec nouvelle clef
- Sur 401 à la connexion WSS : déclencher ré-enrôlement automatique
- Backoff exponentiel sur échecs ré-enrôlement

## Bloquée par
- #64 (rotation serveur)""",
         ["phase:6-cli", "status:completed", "owner:dev-agent", "type:implementation"], m[5]),

        ("#66 — CLI cobra : toutes les commandes §21 intégrées dans cmd/server/main.go",
         """## Description
Intégrer toutes les commandes CLI cobra dans le binaire `secagent-server`.

## Commandes à implémenter
```
minions list/get/set-state/suspend/resume/revoke/authorize/vars
security keys status/rotate
security tokens list
security blacklist list/purge
inventory list
server status/stats
```

## Architecture
Même binaire : `secagent-server` (daemon) ou `secagent-server <cmd>` (CLI)

## Références
- `DOC/server/MANAGEMENT_CLI_SPECS.md`
- `DOC/common/ARCHITECTURE.md` §21

## Bloquée par
- #64 (rotation)""",
         ["phase:6-cli", "status:completed", "owner:dev-relay", "type:implementation"], m[5]),

        ("#67 — Tests GO : CLI commands, rotation, rekey, 401 ré-enrôlement",
         """## Description
Écrire les tests GO pour la CLI, la rotation des clefs et le ré-enrôlement.

## Tests à couvrir
- Toutes les commandes CLI (minions, security, inventory, server)
- Rotation des clefs avec période de grâce
- Message WS `rekey` et traitement agent
- 401 → ré-enrôlement automatique

## Bloquée par
- #65, #66""",
         ["phase:6-cli", "status:completed", "owner:test-writer", "type:test"], m[5]),

        ("#68 — QA Phase 6 : go test ./... 0 fail + smoke test CLI depuis container",
         """## Description
Exécuter la suite de tests GO Phase 6 et valider la CLI en smoke test.

## Critères
- `JWT_SECRET_KEY=test ADMIN_TOKEN=test go test ./... -v` : 0 fail
- Smoke test CLI : `docker exec secagent-server minions list` fonctionnel
- `--format json|table|yaml` sur toutes les commandes

## Bloquée par
- #67 (tests Phase 6)""",
         ["phase:6-cli", "status:completed", "owner:qa", "type:qa"], m[5]),

        ("#69 — Deploy qualif Phase 6 : CLI fonctionnelle sur 192.168.1.218",
         """## Description
Déployer et valider la CLI en qualification.

## Critères
- CLI opérationnelle depuis `docker exec secagent-server <cmd>`
- Rotation des clefs avec période de grâce : agents migrés sans interruption
- Agent : handler `rekey` + ré-enrôlement sur 401 automatique

## Bloquée par
- #68 (QA Phase 6)""",
         ["phase:6-cli", "status:completed", "owner:deploy-qualif", "type:deploy"], m[5]),
    ]

    # ── PHASE 7 ──────────────────────────────────────────────────────────────
    tasks_p7 = [
        ("#70 — Spécifications architecture GO server : project layout, dependencies",
         """## Description
Définir l'architecture du serveur GO : layout projet, dépendances, interfaces.

## Objectifs GO server
- Latency : 100ms → 5ms (20x faster)
- Memory : 100MB → 10MB per instance
- Single compiled binary (no runtime)
- Type-safe crypto (RSA, JWT, SHA256)
- High-concurrency WebSocket (500+ agents)

## Bloquée par
- #69 (Phase 6 complète)""",
         ["phase:7-server-go", "status:completed", "owner:dev-relay", "type:implementation"], m[6]),

        ("#71 — Server main.go : multi-port app (7770/7771/7772), lifespan",
         """## Description
Implémenter le point d'entrée principal du serveur GO.

## Spécifications
- Multi-port : 7770 (API admin), 7771 (exec plugin), 7772 (inventory)
- Lifespan : init NATS, SQLite, shutdown propre
- Configuration via env vars
- Signal handling (SIGTERM/SIGINT)

## Bloquée par
- #70 (specs)""",
         ["phase:7-server-go", "status:completed", "owner:dev-relay", "type:implementation"], m[6]),

        ("#72 — handlers/register.go : enrollment, JWT, RSA-4096 encryption",
         """## Description
Implémenter le handler d'enrollment GO avec JWT et RSA-4096.

## Spécifications
- POST `/api/register` : vérifier authorized_keys, générer JWT
- Chiffrement RSA-4096 du JWT retourné
- Blacklist JTI en DB

## Bloquée par
- #71 (main.go)""",
         ["phase:7-server-go", "status:completed", "owner:dev-relay", "type:implementation"], m[6]),

        ("#73 — handlers/exec.go : /api/exec, /api/upload, /api/fetch endpoints",
         """## Description
Implémenter les handlers REST d'exécution GO.

## Bloquée par
- #71""",
         ["phase:7-server-go", "status:completed", "owner:dev-relay", "type:implementation"], m[6]),

        ("#74 — handlers/inventory.go : /api/inventory (format Ansible)",
         """## Description
Implémenter le handler d'inventaire GO au format Ansible.

## Bloquée par
- #71""",
         ["phase:7-server-go", "status:completed", "owner:dev-relay", "type:implementation"], m[6]),

        ("#75 — ws/handler.go : WebSocket agent connections, dispatcher",
         """## Description
Implémenter le handler WebSocket GO pour les connexions agents.

## Spécifications
- gorilla/websocket
- Registry connexions actives
- Multiplexage par task_id
- Channels GO pour async

## Bloquée par
- #71""",
         ["phase:7-server-go", "status:completed", "owner:dev-relay", "type:implementation"], m[6]),

        ("#76 — storage/agent_store.go : SQLite wrapper (agents, authorized_keys, blacklist)",
         """## Description
Implémenter le wrapper SQLite GO avec modernc (sans CGO).

## Spécifications
- modernc.org/sqlite (pure GO, no CGO)
- Tables : agents, authorized_keys, blacklist, server_config
- Transactions pour opérations atomiques

## Bloquée par
- #71""",
         ["phase:7-server-go", "status:completed", "owner:dev-relay", "type:implementation"], m[6]),

        ("#77 — broker/nats.go : NATS JetStream client (RELAY_TASKS, RELAY_RESULTS)",
         """## Description
Implémenter le client NATS JetStream GO.

## Spécifications
- Streams : RELAY_TASKS, RELAY_RESULTS
- Consumer durable
- Reconnexion automatique

## Bloquée par
- #71""",
         ["phase:7-server-go", "status:completed", "owner:dev-relay", "type:implementation"], m[6]),

        ("#78 — Tests unitaires secagent-server GO",
         """## Description
Écrire les tests unitaires GO pour le serveur.

## Commande
```
JWT_SECRET_KEY=test ADMIN_TOKEN=test go test ./... -v
```

## Bloquée par
- #72 à #77""",
         ["phase:7-server-go", "status:completed", "owner:test-writer", "type:test"], m[6]),

        ("#79 — Migration Python → GO : vérification API contracts, protocol compatibility",
         """## Description
Vérifier la compatibilité complète entre le serveur Python et GO.

## Critères
- 100% API contracts compatibles
- Protocol WebSocket identique
- Agents Python et GO fonctionnent avec le serveur GO

## Bloquée par
- #78 (tests)""",
         ["phase:7-server-go", "status:completed", "owner:dev-relay", "type:implementation"], m[6]),

        ("#80 — QA Phase 7 : pytest E2E vs GO server (agents enroll, exec, inventory)",
         """## Description
Tests E2E complets contre le serveur GO.

## Critères
- Agents enroll OK
- Exec fonctionnel
- Inventaire dynamique OK
- Performance : p95 < 10ms, p99 < 20ms

## Bloquée par
- #79""",
         ["phase:7-server-go", "status:completed", "owner:qa", "type:qa"], m[6]),

        ("#81 — Deploy qualif Phase 7 : GO server sur 192.168.1.218",
         """## Description
Déployer le serveur GO en qualification.

## Critères
- GO server running stable 24h
- 0 restart
- Performance validée
- Binary : ~5MB

## Bloquée par
- #80 (QA E2E)""",
         ["phase:7-server-go", "status:completed", "owner:deploy-qualif", "type:deploy"], m[6]),
    ]

    # ── PHASE 8 ──────────────────────────────────────────────────────────────
    tasks_p8 = [
        ("#82 — Agent architecture GO : project layout, async model",
         """## Description
Définir l'architecture de l'agent GO : layout, modèle async (goroutines vs subprocess).

## Objectifs GO agent
- Memory : 30MB → 2-3MB per agent
- Startup : 500ms → 10ms
- Better subprocess isolation
- Single systemd binary

## Bloquée par
- #81 (GO server déployé)""",
         ["phase:8-agent-go", "status:completed", "owner:dev-agent", "type:implementation"], m[7]),

        ("#83 — agent/main.go : enrollment, WSS connection, reconnection backoff",
         """## Description
Implémenter le point d'entrée de l'agent GO avec enrollment et connexion WSS.

## Spécifications
- Enrollment via RELAY_ENROLLMENT_TOKEN env var
- Connexion WSS avec gorilla/websocket
- Backoff exponentiel : 1s → 60s

## Bloquée par
- #82""",
         ["phase:8-agent-go", "status:completed", "owner:dev-agent", "type:implementation"], m[7]),

        ("#84 — agent/dispatcher.go : message dispatcher (exec/put_file/fetch_file)",
         """## Description
Implémenter le dispatcher de messages WS de l'agent GO.

## Bloquée par
- #83""",
         ["phase:8-agent-go", "status:completed", "owner:dev-agent", "type:implementation"], m[7]),

        ("#85 — agent/executor.go : exec_command subprocess + stdout streaming (5MB buffer)",
         """## Description
Implémenter l'exécuteur de commandes GO avec subprocess et streaming.

## Spécifications
- os/exec pour subprocess (pas de goroutines)
- Streaming stdout via WS
- Buffer 5MB max, truncation + flag

## Sécurité
- `become_pass` masqué dans tous les logs (CRITIQUE)

## Bloquée par
- #83""",
         ["phase:8-agent-go", "status:completed", "owner:dev-agent", "type:implementation"], m[7]),

        ("#86 — agent/files.go : put_file, fetch_file (base64, 500KB limit)",
         """## Description
Implémenter les opérations fichiers de l'agent GO.

## Bloquée par
- #83""",
         ["phase:8-agent-go", "status:completed", "owner:dev-agent", "type:implementation"], m[7]),

        ("#87 — agent/registry.go : async task registry (JSON persistence)",
         """## Description
Implémenter le registre des tâches async avec persistance JSON.

## Bloquée par
- #83""",
         ["phase:8-agent-go", "status:completed", "owner:dev-agent", "type:implementation"], m[7]),

        ("#88 — agent/facts.go : system facts collection (via gopsutil)",
         """## Description
Implémenter la collecte des facts système via gopsutil.

## Dépendance
- github.com/shirou/gopsutil/v3

## Bloquée par
- #83""",
         ["phase:8-agent-go", "status:completed", "owner:dev-agent", "type:implementation"], m[7]),

        ("#89 — Tests unitaires secagent-minion GO",
         """## Description
Écrire les tests unitaires GO pour l'agent.

## Commande
```
JWT_SECRET_KEY=test ADMIN_TOKEN=test go test ./... -v
```
94 tests PASS attendus.

## Bloquée par
- #85 à #88""",
         ["phase:8-agent-go", "status:completed", "owner:test-writer", "type:test"], m[7]),

        ("#90 — QA Phase 8 : pytest E2E vs GO agent (enrollment, exec, facts)",
         """## Description
Tests E2E complets avec l'agent GO.

## Critères
- Enrollment fonctionnel
- Exec de commandes OK
- Facts collection OK
- Memory < 3MB par agent

## Bloquée par
- #89""",
         ["phase:8-agent-go", "status:completed", "owner:qa", "type:qa"], m[7]),

        ("#91 — Deploy qualif Phase 8 : GO agents sur 192.168.1.218",
         """## Description
Déployer les agents GO en qualification.

## Critères
- 3 agents GO connectés et stables
- Memory < 3MB par agent
- Systemd service compatible avec l'unit file existant
- Backward-compatible avec serveur GO

## Bloquée par
- #90 (QA E2E)""",
         ["phase:8-agent-go", "status:completed", "owner:deploy-qualif", "type:deploy"], m[7]),
    ]

    # ── PHASE 9 ──────────────────────────────────────────────────────────────
    tasks_p9 = [
        ("#92 — inventory-wrapper/main.go : CLI arg parsing, HTTP client",
         """## Description
Implémenter le wrapper GO pour le plugin inventory Ansible.

## Architecture
```
secagent_inventory.py → subprocess → secagent-inventory-go → HTTP → server:7772
```

## Bloquée par
- #91 (GO agents déployés)""",
         ["phase:9-plugins-go", "status:completed", "owner:dev-plugins", "type:implementation"], m[8]),

        ("#93 — inventory-wrapper/inventory.go : fetch /api/inventory, format Ansible",
         """## Description
Implémenter la logique de fetching inventaire et formatage pour Ansible.

## Bloquée par
- #92""",
         ["phase:9-plugins-go", "status:completed", "owner:dev-plugins", "type:implementation"], m[8]),

        ("#94 — exec-wrapper/main.go : CLI arg parsing, subprocess handling",
         """## Description
Implémenter le wrapper GO pour le plugin connection Ansible.

## Architecture
```
secagent.py → subprocess → relay-exec-go → HTTP → server:7771
```

## Bloquée par
- #91""",
         ["phase:9-plugins-go", "status:completed", "owner:dev-plugins", "type:implementation"], m[8]),

        ("#95 — Tests + integration : Python plugins → GO wrappers",
         """## Description
Tests d'intégration entre les plugins Python Ansible et les wrappers GO.

## Critères
- Plugin Python appelle wrapper GO correctement
- Résultats identiques entre Python pur et Python+GO wrapper

## Bloquée par
- #93, #94""",
         ["phase:9-plugins-go", "status:completed", "owner:test-writer", "type:test"], m[8]),

        ("#96 — Deploy qualif Phase 9 : E2E Ansible playbook via GO wrappers",
         """## Description
Déployer et valider les wrappers GO en qualification avec un playbook Ansible réel.

## Critères
- Playbook Ansible exécuté via GO wrappers
- Inventory refresh < 500ms
- Exec < 1s startup
- Ansible plugins Python : inchangés (backward compatible)
- 19 tests PASS

## Bloquée par
- #95 (tests intégration)""",
         ["phase:9-plugins-go", "status:completed", "owner:deploy-qualif", "type:deploy"], m[8]),
    ]

    # ── PHASE 10 ──────────────────────────────────────────────────────────────
    tasks_p10 = [
        ("#97 — Store : table enrollment_tokens",
         """## Description
Créer la table `enrollment_tokens` dans le store SQLite.

## Schéma
```sql
CREATE TABLE enrollment_tokens (
    id            INTEGER PRIMARY KEY,
    token_hash    TEXT NOT NULL UNIQUE,
    hostname_pattern TEXT NOT NULL,  -- regexp
    reusable      INTEGER DEFAULT 0, -- 0=one-shot, 1=permanent
    use_count     INTEGER DEFAULT 0,
    last_used_at  DATETIME,
    expires_at    DATETIME,          -- nullable
    created_by    TEXT NOT NULL
);
```

## Références
- `DOC/security/SECURITY.md` §3 (enrollment token)

## Bloquée par
Aucune""",
         ["phase:10-enrollment", "status:todo", "owner:dev-relay", "type:implementation"], m[9]),

        ("#98 — Store : table plugin_tokens",
         """## Description
Créer la table `plugin_tokens` dans le store SQLite.

## Schéma
```sql
CREATE TABLE plugin_tokens (
    id                       INTEGER PRIMARY KEY,
    token_hash               TEXT NOT NULL UNIQUE,
    description              TEXT,
    role                     TEXT NOT NULL,
    allowed_ips              TEXT,  -- CIDRs comma-separated
    allowed_hostname_pattern TEXT,  -- regexp
    expires_at               DATETIME,
    last_used_at             DATETIME,
    revoked                  INTEGER DEFAULT 0
);
```

## Références
- `DOC/security/SECURITY.md` §6 (plugin tokens)

## Bloquée par
Aucune""",
         ["phase:10-enrollment", "status:todo", "owner:dev-relay", "type:implementation"], m[9]),

        ("#99 — Server : refactorer RegisterAgent avec enrollment_token + challenge-response OAEP",
         """## Description
Refactorer `RegisterAgent` pour accepter et valider les enrollment tokens avec challenge-response OAEP.

## Flow
1. Agent POST `/api/register` avec `{hostname, pubkey, token}`
2. Serveur valide : non expiré, `reusable=0` → `use_count==0`, regexp hostname
3. Serveur génère challenge : `OAEP(nonce, agent_pubkey)`
4. Agent déchiffre nonce, répond : `OAEP(nonce+token, server_pubkey)`
5. Serveur vérifie nonce, incrémente `use_count`, retourne JWT chiffré

## Références
- `DOC/security/SECURITY.md` §3

## Bloquée par
- #97 (enrollment_tokens table)""",
         ["phase:10-enrollment", "status:todo", "owner:dev-relay", "type:implementation"], m[9]),

        ("#100 — Server : endpoints admin tokens (create, list, revoke, delete, purge)",
         """## Description
Implémenter les endpoints admin de gestion des tokens.

## Endpoints
- `POST /api/admin/tokens` : créer token (champs `reusable`, `expires_at` nullable)
- `GET /api/admin/tokens?role=enrollment|plugin` : liste
- `POST /api/admin/tokens/:id/revoke`
- `DELETE /api/admin/tokens/:id`
- `POST /api/admin/tokens/purge?expired=1&used=1`

## Bloquée par
- #97 (enrollment_tokens), #98 (plugin_tokens)""",
         ["phase:10-enrollment", "status:todo", "owner:dev-relay", "type:implementation"], m[9]),

        ("#101 — Server : vérification plugin token (CIDR multi-valeurs + regexp hostname)",
         """## Description
Implémenter la vérification des plugin tokens avec CIDR multi-valeurs et regexp hostname.

## Spécifications
- CIDR matching multi-valeurs (`net.ParseCIDR` pour chaque CIDR de la liste)
- Regexp matching `allowed_hostname_pattern` sur header `X-Relay-Client-Host`
- Mise à jour `last_used_at` à chaque usage valide

## Bloquée par
- #98 (plugin_tokens table)""",
         ["phase:10-enrollment", "status:todo", "owner:dev-relay", "type:implementation"], m[9]),

        ("#102 — Agent : RELAY_ENROLLMENT_TOKEN env var + challenge-response OAEP",
         """## Description
Mettre à jour l'agent GO pour utiliser `RELAY_ENROLLMENT_TOKEN` et gérer le challenge-response OAEP.

## Spécifications
- Lire `RELAY_ENROLLMENT_TOKEN` depuis l'env
- Inclure token dans POST `/api/register`
- Déchiffrer challenge OAEP avec sa propre keypair
- Répondre avec `OAEP(nonce+token, server_pubkey)`
- Documenter `RELAY_ENROLLMENT_TOKEN` dans l'unit systemd

## Bloquée par
- #99 (RegisterAgent refactoré)""",
         ["phase:10-enrollment", "status:todo", "owner:dev-agent", "type:implementation"], m[9]),

        ("#103 — CLI : commandes tokens (create, list, revoke, delete, purge)",
         """## Description
Implémenter les commandes CLI de gestion des tokens.

## Commandes
```
tokens create --role enrollment --hostname-pattern "vp.*" [--reusable] [--expires 30d]
tokens create --role plugin --allowed-ips "10.0.0.0/8" --allowed-hostname-pattern "ansible-.*"
tokens list [--role enrollment|plugin]   # affiche MODE one-shot/permanent + USAGES
tokens revoke <id>
tokens delete <id>
tokens purge --expired --used
```

## Références
- `DOC/server/MANAGEMENT_CLI_SPECS.md`

## Bloquée par
- #100 (endpoints admin tokens)""",
         ["phase:10-enrollment", "status:todo", "owner:dev-relay", "type:implementation"], m[9]),

        ("#104 — Tests GO : enrollment tokens (one-shot, permanent, regexp, CIDR)",
         """## Description
Écrire les tests GO couvrant tous les cas d'usage des enrollment et plugin tokens.

## Cas de test
- One-shot : consommé après 1 usage, rejeté au 2ème
- Permanent : N usages, `use_count` incrémenté
- Regexp : match/no-match hostname_pattern
- Token expiré : rejeté
- Token permanent sans expiry : accepté indéfiniment
- CIDR multi-valeurs : match/no-match IP
- Plugin token : CIDR + regexp combinés

## Bloquée par
- #99, #100, #101, #102, #103""",
         ["phase:10-enrollment", "status:todo", "owner:test-writer", "type:test"], m[9]),

        ("#105 — QA Phase 10 : go test ./... 0 fail + smoke test enrollment complet",
         """## Description
Exécuter la suite de tests GO Phase 10 et valider l'enrollment complet en smoke test.

## Critères
- `JWT_SECRET_KEY=test ADMIN_TOKEN=test go test ./... -v` : 0 fail
- Smoke test : enrollment complet depuis container avec token

## Bloquée par
- #104 (tests Phase 10)""",
         ["phase:10-enrollment", "status:todo", "owner:qa", "type:qa"], m[9]),

        ("#106 — Deploy qualif Phase 10 : ré-enrollment des 3 agents avec enrollment tokens",
         """## Description
Déployer et valider Phase 10 : ré-enrollment des 3 agents qualif avec enrollment tokens.

## Spécifications déploiement
- `hostname_pattern = "qualif-host-[0-9]+"` (regexp)
- 3 agents ré-enrôlés via tokens
- Validation one-shot ET permanent
- 0 régression sur les fonctionnalités existantes

## Critères de validation Phase 10
- ✓ `enrollment_tokens` : one-shot ET permanent, TTL optionnel, hostname_pattern regexp
- ✓ One-shot : rejeté au 2ème usage, `use_count` tracé
- ✓ Permanent : N enrollements successifs, `use_count` incrémenté à chaque fois
- ✓ Challenge-response OAEP : token volé sans keypair → challenge échoue
- ✓ `plugin_tokens` : CIDR multi-valeurs + allowed_hostname_pattern regexp
- ✓ CLI : tokens create/list/revoke/delete/purge opérationnels
- ✓ `RELAY_ENROLLMENT_TOKEN` documentée dans le service systemd
- ✓ 3 agents enrôlés via tokens, 0 régression

## Bloquée par
- #105 (QA Phase 10)""",
         ["phase:10-enrollment", "status:todo", "owner:deploy-qualif", "type:deploy"], m[9]),
    ]

    all_tasks = tasks_p1 + tasks_p2 + tasks_p3 + tasks_p4 + tasks_p5 + tasks_p6 + tasks_p7 + tasks_p8 + tasks_p9 + tasks_p10
    return all_tasks


def main():
    print("=== Ansible-SecAgent — Création des issues GitHub ===\n")

    # 1. Create labels
    print("1. Création des labels...")
    for name, color, desc in LABELS:
        create_label(name, color, desc)
    print()

    # 2. Create milestones
    print("2. Création des milestones...")
    milestones = {}
    for i, (title, desc) in enumerate(MILESTONES_DEF):
        num = create_milestone(title, desc)
        milestones[i] = num
        time.sleep(0.5)
    print()

    # 3. Create issues
    print("3. Création des issues...")
    all_tasks = make_issues(milestones)

    issue_map = {}  # backlog_num -> github_issue_num
    for title, body, labels, milestone in all_tasks:
        issue_num = create_issue(title, body, labels, milestone)
        if issue_num:
            issue_map[issue_num] = title
        time.sleep(0.8)  # rate limiting

    # 4. Close completed/suspended/obsolete issues
    print("\n4. Fermeture des issues terminées/suspendues/obsolètes...")
    closed_labels = {"status:completed", "status:suspended", "status:obsolete"}
    for title, body, labels, milestone in all_tasks:
        label_set = set(labels)
        if label_set & closed_labels:
            # Find the issue by title
            pass  # We'll handle this via a separate pass

    # Get all issues and close completed ones
    all_issues = api_request("GET", f"{BASE_URL}/issues?state=open&per_page=100")
    if all_issues:
        for issue in all_issues:
            issue_labels = {l["name"] for l in issue.get("labels", [])}
            if issue_labels & {"status:completed", "status:suspended", "status:obsolete"}:
                close_issue(issue["number"])
                print(f"  ✓ Closed #{issue['number']}: {issue['title'][:50]}")
                time.sleep(0.3)

    print(f"\n=== Terminé ! {len(all_tasks)} issues créées ===")

    # Save issue mapping
    with open("/home/user/Ansible-SecAgent/scripts/issue_map.json", "w") as f:
        json.dump(issue_map, f, indent=2)
    print("Issue map saved to scripts/issue_map.json")


if __name__ == "__main__":
    main()
