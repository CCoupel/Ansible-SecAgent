# MEMORY — Ansible-SecAgent

> Source de vérité au démarrage de session (lue par `/start-session`). Mise à jour par `/end-session`.

## Version et environnements
- **Version produit : v3.0.3 publiée le 2026-10-07** (tag `v3.0.3` sur `cbd4eca`, release GitHub, images `ghcr.io/ccoupel/secagent-server` et `secagent-minion` : tags `3.0.3`, `v3.0.3`, `latest`, paquets publics, provenance + SBOM). Tags existants : v1.0.0, v2.0.0, v3.0.3 (pas de tags v3.0.0 à v3.0.2).
- **`main`** = `a8a0aab` (PR #198 : milestone/v3.0.3 fusionnée en merge commit), CI verte. **Le `schedule` de `failover.yml` est volontairement commenté** : à réactiver par une PR séparée (code v3.0.3 maintenant sur main).
- **Architecture v3.0.3** : relay actif/passif, un seul maître par STATE_DIR partagé (NFS), secondaires sans aucun port ; état = fichier `relay.state` (HMAC, secrets `enc:`) + `relay.lock` ; plus de SQLite, CGO, NATS, Caddy ni Kubernetes (K8s abandonné, #136 fermée). TLS natif (7770/7772), admin 7771 en boucle locale par défaut. Clients multi-adresses (`internal/endpoints`). Détail : `DOC/server/STATE_SPEC.md`, `SERVER_SPEC.md`, `DOC/security/SECURITY.md` (avis 1 à 3).
- **Qualif** : 192.168.1.218 (srv8, Docker 29.2.1, accès `docker -H tcp://192.168.1.218:2375`, API non authentifiée = choix utilisateur sur son LAN). **Chaîne v3.0.3 EN SERVICE** (projet compose `secagent-qualif` : racine actif/passif a/b, enfant pull, minions). L'ancienne qualif v2 (projet `qualif`) est ARRÊTÉE (pas supprimée) et sauvegardée dans `/home/cyril/secagent-qualif-v2-backup-20261007-091343` (contient des secrets : ne jamais commiter). L'hôte héberge MooseFS (projet `chunks`, `/opt/MFS`) : **ne JAMAIS toucher**. Images de qualif par artefact de CI + `docker load` (`chain-test.sh load-images`), sans registre.
- **Prod** : Docker Compose multi-hôtes (`DEPLOYMENT/prod/`), `tag@sha256` obligatoire. Pas encore déployée.
- **Template Claude** : v3.10.0 (`c620b20`, voir `.claude/project-config.json`).

## Milestones GitHub
- v3.0.0 à v3.0.3 fermés (v3.0.3 : 34 issues, #157 épique fermée).
- **v3.0.4 « Confiance et signature des liens »** (ouvert, 11 issues) : #141 signature des tokens par la racine, #146 rôles JWT relay-child/relay-parent, #151 SSRF (restes : DNS rebinding), #156 rate limit snapshots par relay_id, #179, #180, #189, **#194** démarrage serveur sous charge (probe des listeners), **#196** secrets en variables d'environnement (support `*_FILE`, minions root, log `tls=false`), **#197** compléments de qualif (hooks en réel, essai CA négatif, multi-hôtes réel, suite d'intégration ~190 s, somme du CLI Docker statique, tests de temporisation instables). #152 à fermer après vérification.

## Décisions et failles v3.0.3 (à ne pas redécouvrir)
- Failles v1/v2 corrigées en v3.0.3 seulement (pas de hotfix v2, qualif v2 compensée par restriction réseau) : `/ws/agent` sans token, **`POST /api/token/refresh` non authentifiée (route SUPPRIMÉE, 404)**, **`POST /api/register` sans jeton (403 `enrollment_token_required`)**, ré-enrôlement d'un révoqué avec jeton réutilisable (**drapeau `revoked` persistant, 403 `agent_revoked`, levée par `DELETE /api/admin/minions/{h}`**). Retour arrière : un binaire antérieur à #193 refuse un état contenant `revoked:true` ou bascule sur `.prev` (perte silencieuse de révocation) : documenté.
- Plugin Python : classe `Connection` (l'ancien nom `ConnectionPlugin` cassait `get_option`), priorité hostvar > `RELAY_*` > `[secagent_connection]` > défaut, jeton en fichier 0600 propriétaire (pas `/tmp`, pas de lien symbolique/FIFO), stdin en base64.
- CI : `ci.yml` ne publie rien (garde `check_no_publish.py`), `candidate-images.yml` et `failover.yml` manuels (sur main), `release.yml` au tag seulement. Jobs : build+tests, lint, Ansible (opt-in `ANSIBLE_E2E=1`, venv jetable, garde D1-D4), Dockerfiles+Compose, chaîne en conteneurs, sauvegarde/restauration, basculement, archive Compose, reproductibilité, artefact d'images.
- Mesures qualif : arrêt propre 3,2 à 7,2 s, `kill` 277 à 303 s (péremption du maître 5 min), gel `unhealthy` 64 à 76 s. Parc > 3000 hôtes : 3 000 agents enrôlés en 11,8 s, 10 000 agents = fichier 19,7 Mio.

## CI GitHub et outils
- `go` dans `/usr/local/go/bin` (pas dans le PATH). golangci-lint v2.14.0 à télécharger si absent (scratchpad). Tests : `JWT_SECRET_KEY=test ADMIN_TOKEN=test go test -race ./... -timeout 900s` depuis `GO/`. Ansible uniquement dans un venv hors `~/.local` (requirements épinglés `.github/ci/requirements-ansible.txt`, `httpx` inclus).
- Le dépôt est sur `/mnt/c` (NTFS) : `chmod 600` n'y est pas honoré (le plugin refuse alors le jeton) ; lancer les scripts de qualif depuis une copie `git archive` hors `/mnt/c`.
- `docker.exe` (Windows) seul disponible dans WSL ; il ne reçoit pas `DOCKER_HOST` : utiliser `-H`. Le démon Docker local est arrêté : ne pas le démarrer.

## À trancher / suivis
- Réactiver le `schedule` de `failover.yml` (PR séparée). Visibilité des paquets GHCR (publics aujourd'hui).
- Nettoyage qualif : jeton plugin `q4-qa` (8 h) et fichiers `/tmp/q4_*.mark` dans les minions ; `/tmp/qualif-v200` (v2) ; décision sur la suppression des volumes de la v2 (utilisateur).
- Historique git : trois `.exe` obsolètes restent dans l'historique (purge `git filter-repo` = décision utilisateur, destructif).
- Commentaires de code obsolètes (v3.0.4) : `relay.py:7` (FastAPI), `main.go` serveur (`-d`), `secagent-inventory/main.go` (RELAY_TOKEN = ADMIN_TOKEN, faux), aide CLI `relays add` (`--url https://`), `enrollment.go`, `relay_handler.go` (« Phase 12 »), `PYTHON_VS_GO_PLUGINS.md:70`, `MANAGEMENT_CLI_SPECS.md` (`relay health`).
- Labels hérités inutilisés : `phase:1` à `phase:12`, `owner:dev-plugins`.

## Règles / pièges (leçons)
- **Questions à l'utilisateur** : toujours via AskUserQuestion. **Pas de push sans feu vert explicite** (un feu vert vaut pour un lot ; l'utilisateur a donné une autorisation durable bornée pour les corrections de CI sur `milestone/v3.0.3`, éteinte avec la milestone) ; push délégué à `deployer` (SHA complet, jamais `HEAD`, jamais de force, jamais main sauf PR validée) ; je ferme les issues après CI verte.
- **Tâches et retours par fichier** : toute tâche > 3-4 lignes est écrite par le teamleader dans `_work/handoff/<agent>-<date>.md` (le teamleader écrit lui-même ces fichiers de coordination) ; message court avec le chemin ; retour des agents en UNE ligne (SHA, rapport dans `_work/reports/`).
- **Trailer de commit EXACT** : `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>` ; contrôler les 100 % des commits non poussés avant un push (un agent Haiku avait écrit « Haiku 4.5 » ou rien sur 11 commits ; réécriture des seuls messages, arbres identiques prouvés). **Jamais `git commit --amend` en arbre partagé** (un agent a réécrit le commit d'un autre).
- **Vérifier, ne pas croire** : les agents annoncent « 100 % vérifié » avec des erreurs ; les chiffres de « budget de jetons » annoncés par les agents sont inventés ; l'agent `doc-updater` du template tourne sur un petit modèle (Haiku) : toujours passer `model: sonnet` aux agents de documentation. La doc doit être auditée contre le code par `qa` (commandes jouées sur binaires réels) et `security-reviewer`. Les tests d'intrusion réels de QA ont trouvé les failles que les revues ne voyaient pas (`/ws/agent`, `token/refresh`, `register` sans jeton, ré-enrôlement d'un révoqué).
- **Rapports et notifications** : les `idle_notification` répètent le DONE ; ne pas les traiter comme de nouveaux livrables.
- **Environnement de l'utilisateur, push, trailer, agents de doc** : règles permanentes migrées dans `CLAUDE.md` (section Conventions de code) ; ici seulement les incidents : `ansible-core` installé dans `~/.local` par un agent (désinstallé), `failover-test.sh` lancé sans le mode volume sur l'hôte distant (répertoires vides créés puis supprimés), `amend` du commit d'un autre agent.
- **Agents** : noms canoniques sans suffixe ; l'adresse du teamleader est `team-lead` ; `doc-updater`/`infra`/`planner` sont à spawner si absents ; arrêter (`TaskStop`) les agents de documentation terminés.
- **Sécurité** : `become_pass` jamais dans les logs ; fail closed ; pas de `panic` en production ; identifiants externes en `%q`.
- CRLF/LF : `git diff --ignore-space-at-eol`. Plugin Python : `SECAGENT-PYTHON/ansible_plugins/connection_plugins/relay.py`.
