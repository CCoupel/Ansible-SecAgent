# /start-session — Démarrage de la team AnsibleRelay

Lance la session de développement du projet **AnsibleRelay** en créant la team complète avec tous ses membres.

## Instructions

Lis d'abord les fichiers de référence du projet :
- `C:/Users/cyril/Documents/VScode/Ansible_Agent/DOC/common/ARCHITECTURE.md` — spécifications techniques complètes
- `C:/Users/cyril/Documents/VScode/Ansible_Agent/DOC/common/HLD.md` — architecture haut niveau, schémas et flux
- `C:/Users/cyril/Documents/VScode/Ansible_Agent/DOC/security/SECURITY.md` — modèle de sécurité complet
- **[GitHub Issues](https://github.com/CCoupel/Ansible-SecAgent/issues)** — état des phases et tâches (source de vérité)

Si un argument est passé (ex: "dans une nouvelle branche"), crée d'abord une branche git avec `git checkout -b session/YYYY-MM-DD` avant de continuer.

Puis exécute les étapes suivantes dans l'ordre :

---

### Étape 1 — Créer la team

Utilise `TeamCreate` pour créer une team nommée `ansible-relay` avec la description :
"Développement du projet AnsibleRelay — système Ansible avec connexions inversées client→serveur et inventaire dynamique."

---

### Étape 2 — Spawner les teammates

Spawne les agents suivants avec l'outil `Agent` en précisant les paramètres `team_name` (valeur retournée par TeamCreate) et `name`. Chaque agent a son propre fichier de spécification dans `.claude/agents/` — utilise le `subagent_type` correspondant.

**RÈGLE ABSOLUE — Démarrage IDLE :** Tous les agents restent en IDLE après initialisation. Aucun n'agit de sa propre initiative. Le CDP attend un ordre explicite de l'utilisateur.

| name               | subagent_type       | rôle                                      |
|--------------------|---------------------|-------------------------------------------|
| `cdp`              | `cdp`               | Chef de Projet, orchestre les phases      |
| `planner`          | `planner`           | Architecte, crée le backlog               |
| `dev-agent`        | `dev-agent`         | relay-agent GO → GO/cmd/agent/            |
| `dev-relay`        | `dev-relay`         | relay-server GO → GO/cmd/server/          |
| `dev-inventory`    | `dev-inventory`     | relay-inventory GO → GO/cmd/inventory/    |
| `dev-connexion`    | `dev-connexion`     | plugin connexion Python → PYTHON/         |
| `test-writer`      | `test-writer`       | Tests GO + Python                         |
| `qa`               | `qa`                | Valide les livrables (go test ./...)      |
| `security-reviewer`| `security-reviewer` | Audite la sécurité                        |
| `deploy-qualif`    | `deploy-qualif`     | Docker Compose → 192.168.1.218            |
| `deploy-prod`      | `deploy-prod`       | Helm chart → Kubernetes                   |

---

### Étape 3 — Briefer le cdp

Envoie un message au `cdp` via `SendMessage` (type: "message") avec le contenu suivant :

```
Bonjour. La team AnsibleRelay est constituée et prête. Voici tes teammates :
- planner : architecte, analyse et crée le backlog TaskList
- dev-agent : développe le relay-agent GO (GO/cmd/agent/)
- dev-relay : développe le relay-server GO (GO/cmd/server/)
- dev-inventory : développe le binaire relay-inventory GO (GO/cmd/inventory/)
- dev-connexion : développe le plugin de connexion Ansible Python (PYTHON/)
- test-writer : écrit les tests GO et Python (en parallèle du dev)
- qa : exécute les tests et valide (JWT_SECRET_KEY=test ADMIN_TOKEN=test go test ./... -v)
- security-reviewer : audite la sécurité avant chaque validation
- deploy-qualif : déploie via Docker Compose sur 192.168.1.218
- deploy-prod : déploie sur Kubernetes via Helm chart, kubeconfig dans C:/Users/cyril/Documents/VScode/kubeconfig.txt

Les spécifications complètes sont dans DOC/common/ (ARCHITECTURE.md, HLD.md), DOC/security/SECURITY.md, et les specs par composant dans DOC/server/, DOC/agent/, DOC/plugins/, DOC/inventory/.
Le backlog est suivi via GitHub Issues : https://github.com/CCoupel/Ansible-SecAgent/issues (issues ouvertes = à faire, fermées = terminées).
Ton workflow est décrit dans ton fichier de spécification — suis-le exactement.

N'engage aucune action pour l'instant. Attends les instructions du leader (l'utilisateur) avant de déléguer quoi que ce soit à l'équipe. Réponds simplement que tu es prêt et résume le workflow de la phase active en 5 lignes.
```

---

### Étape 4 — Confirmer à l'utilisateur

Affiche un résumé structuré de la team créée :

```
Team AnsibleRelay — prête

Membres :
- cdp              (haiku)  — Chef de Projet, orchestre les phases
- planner          (sonnet) — Architecte, analyse et crée le backlog
- dev-agent        (sonnet) — relay-agent GO          → GO/cmd/agent/
- dev-relay        (sonnet) — relay-server GO          → GO/cmd/server/
- dev-inventory    (sonnet) — relay-inventory GO       → GO/cmd/inventory/
- dev-connexion    (sonnet) — plugin connexion Python  → PYTHON/
- test-writer      (sonnet) — Tests GO + Python (en parallèle du dev)
- qa               (haiku)  — Valide les livrables (go test ./...)
- security-reviewer(sonnet) — Audite la sécurité
- deploy-qualif    (sonnet) — Docker Compose → 192.168.1.218
- deploy-prod      (sonnet) — Helm chart → Kubernetes

Workflow : phases dans l'ordre → deploy-qualif après chaque phase → deploy-prod (K8s) en clôture MVP
Condition de passage : qa GO + security 0 CRITIQUE/HAUT + deploy-qualif OK + validation utilisateur
Règle de démarrage : tous les agents sont en IDLE — le cdp attend tes ordres.
```
