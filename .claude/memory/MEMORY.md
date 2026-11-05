# MEMORY — Ansible-SecAgent

> Source de vérité au démarrage de session (lue par `/start-session`). Mise à jour par `/end-session`.

## État de session (fin 2026-11-03) — v3.0.5 en cours
- **Version** : v3.0.4 publiée, PROD jamais déployée. **v3.0.5 en cours** (milestone 19), branche `milestone/v3.0.5` @ `72bc19e`, poussée, CI verte (run 41622274100), 122 commits d'avance sur main.
- **Travail en cours** :
  - LOT-1 à LOT-5 terminés et poussés ; issues fermées « validé sans QUALIF » à partir de LOT-3.
  - **#237** ouverte jusqu'au GATE 4 : reste gh-pages (`index.html:1192`, PR séparée hors milestone, confirmation dédiée) et `gh api .license` après merge sur main. L'image candidate porte `licenses=MIT`.
  - **LOT-6 EN PAUSE** (décision utilisateur) : #197, #238, #229, #241, #240, #239, tous PRET.
  - Commits test-writer de LOT-6 (`85d02a9`, `2280085` : règles check_compose `*_FILE`/cap_drop, `admission-503.sh`, selftests) **parqués sur la branche locale `lot6-wip`**, à reprendre par cherry-pick ; ne les pousser qu'avec #197 et #238 livrés, sinon CI rouge.
  - Image candidate publiée et attestée (run 41623887845) : serveur `sha256:ceed1549…`, minion `sha256:e84a6283…`.
- **Décisions** :
  - #225 reportée en v3.0.6 (milestone 20) : `relay.failover` aussi au redémarrage (`reason: released`) et propagé au parent. Issues : #244 `host.rerouted`, #245 `relay.up/down`, #246 file amont/`relay.converged`, #247 doc de la perte de `host.down` direct.
  - #239 : second hôte = **srv1 (192.168.1.211)**. Tous les hôtes du labo portent MooseFS et k8s : **ne jamais interférer**, projet isolé.
  - Images GHCR privées : pull sur les hôtes avec un jeton `read:packages` à durée courte, supprimé après usage.
  - Version : `main.Version` (minion, inventory), `internal/cli.Version` (serveur), format `<composant> version <v>`. Seuils `release.yml` : serveur et minion ≥ 3.0.4, inventory ≥ 3.0.5.
  - `docker compose exec` impose `/app/secagent-server` (le PATH de l'image ne contient pas `/app`).
  - Job CI `slow-qa`, en parallèle de `slow-tests`.
- **Pour la prochaine session** :
  - **Secrets et PKI de qualif PERDUS** (redémarrage WSL 2026-11-03) : à régénérer au début de LOT-6, en `*_FILE`. Sur `.218`, `secagent-qualif` tourne encore avec les images de LOT-1 et des secrets perdus.
  - Fichier non suivi `GO/cmd/secagent-server/internal/integration/zz_old_i2_test.go`, à supprimer par l'utilisateur.
  - Suivis : B63 (`pip install --require-hashes` dans 3 jobs CI) ; `~/.cache/go-build` de l'utilisateur a pris 14 Mo, origine inconnue ; 7 PR Dependabot (#199-#205) à fermer au GATE 4 ; Environments GitHub `release`/`candidate` et protection de `main` = réglages utilisateur.
  - **Règle de commit** : `git commit -- <chemins>` après `git diff --cached --stat` (incident `166638e`). Les `.git/index.lock` orphelins se suppriment avec l'accord du CDP.
- **Issues v3.0.5** : ouvertes #237, #197, #238, #229, #241, #240, #239. Fermées pendant la session : #234, #215, #218, #216, #222 (LOT-3) ; #233, #219, #220, #221 (LOT-4) ; #223, #236, #228, #231 (LOT-5).

## Version et environnements
- **Version produit : v3.0.4 publiée le 2026-10-08** (release GitHub « Latest », site gh-pages à jour). v3.0.3 publiée le 2026-10-07 (`cbd4eca`). Tags : v1.0.0, v2.0.0, v3.0.3, v3.0.4.
- **`main`** = `3571cfe` : PR #242 `milestone/v3.0.4` → `main` mergée en **squash** le 2026-11-01 (1 parent `ef553d4`, arbre identique à `e36243e`, checks 23 verts / 1 ignoré). Les commits `af901d3`, `d8fb7b7`, `099eb6e`, `e36243e` sont dans main via ce squash (plus aucun « non poussé »). Branche distante `milestone/v3.0.4` supprimée. Le dev de v3.0.5 se fait sur `milestone/v3.0.5` (voir « État de session »). **Le `schedule` de `failover.yml` est volontairement commenté** : à réactiver par une PR séparée.
- **Architecture v3.0.3** : relay actif/passif, un seul maître par STATE_DIR partagé (NFS), secondaires sans aucun port ; état = fichier `relay.state` (HMAC, secrets `enc:`) + `relay.lock` ; plus de SQLite, CGO, NATS, Caddy ni Kubernetes (K8s abandonné, #136 fermée). TLS natif (7770/7772), admin 7771 en boucle locale par défaut. Clients multi-adresses (`internal/endpoints`). Détail : `DOC/server/STATE_SPEC.md`, `SERVER_SPEC.md`, `DOC/security/SECURITY.md` (avis 1 à 3).
- **Qualif** : 192.168.1.218 (srv8, Docker 29.2.1, accès `docker -H tcp://192.168.1.218:2375`, API non authentifiée = choix utilisateur sur son LAN). Projet compose `secagent-qualif` (racine actif/passif a/b, enfant pull, minions) **encore en service avec les images de LOT-1 et des secrets/PKI perdus** (WSL redémarré le 2026-11-03) : à régénérer. L'ancienne qualif v2 (projet `qualif`) est ARRÊTÉE (pas supprimée) et sauvegardée dans `/home/cyril/secagent-qualif-v2-backup-20261007-091343` (contient des secrets : ne jamais commiter). L'hôte héberge MooseFS (projet `chunks`, `/opt/MFS`) : **ne JAMAIS toucher**. Images de qualif par artefact de CI + `docker load` (`chain-test.sh load-images`), sans registre (jusqu'à v3.0.5 LOT-1 ; décision 2026-11-03 : pull GHCR avec jeton `read:packages` court).
- **Prod** : Docker Compose (`DEPLOYMENT/prod/`), `tag@sha256` obligatoire. **Hôte = 192.168.1.218** (même hôte que la qualif, choix utilisateur 2026-10-31), projet compose `secagent-prod-*` distinct, collisions de ports à vérifier. **Jamais déployée.** Accès enregistré dans `project-config.json` → `infrastructure.environments[].access`.
- **Template Claude** : v3.30.1 (`0977a3a`, synchro 2026-11-01, voir `.claude/project-config.json` → `template_version`).

## Milestones GitHub
- v3.0.0 à v3.0.3 fermés (v3.0.3 : 34 issues, #157 épique fermée).
- **v3.0.4 « Confiance et signature des liens » : CLOS le 2026-11-01** (milestone n° 17, clôture manuelle, 10 issues fermées, implémentées dans `main`, label `DONE`). **#197 reportée en v3.0.5.** **v3.0.5 « Durcissement et dettes issues de v3.0.4 »** (milestone n° 19) = milestone actif, LOT-1 à LOT-5 faits, LOT-6 en pause (voir « État de session »). Aucun label `LOT-*` utilisé sur v3.0.4. Historique v3.0.4 (11 issues) : #141 signature des tokens par la racine, #146 rôles JWT relay-child/relay-parent, #151 SSRF (restes : DNS rebinding), #156 rate limit snapshots par relay_id, #179, #180, #189, **#194** démarrage serveur sous charge (probe des listeners), **#196** secrets en variables d'environnement (support `*_FILE`, minions root, log `tls=false`), **#197** compléments de qualif (hooks en réel, essai CA négatif, multi-hôtes réel, suite d'intégration ~190 s, somme du CLI Docker statique, tests de temporisation instables). #152 vérifiée et fermée. #189 livrée par l'alternative « drapeau `revoked` persistant » (#193), pas par le 409 `no_token_jti`.
- **#197 reportée en v3.0.5 (ouverte, commentaire posté)** ; conditions de clôture inchangées : déploiement PROD de v3.0.4 sur 192.168.1.218 + secrets de la chaîne de qualif en `*_FILE` (commentaire du 2026-11-01). Points restants suivis par **#238** (minions qualif cap_drop/non-root), **#239** (stockage partagé 2 hôtes réels), **#240** (empreinte du CLI Docker statique), **#241** (503 `memory_budget_exhausted` en réel). Le jeton `chain-smoke` 2 h est corrigé (`plugin_token()` frais dans `chain-test.sh`).
- Écart doc `token_hash` pull (SERVER_SPEC §9.6 vs `admin_relays.go:222`) ajouté à #231.

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
- Écart CI C11 partiel : `scripts/ci.sh` (`commands.ci`) = jobs Go de `ci.yml`, pas encore appelé par `ci.yml` → alignement par `infra` en v3.0.5.
- Branches résiduelles (2026-11-01) : seules restent les 7 branches dependabot (PR ouvertes, #227). Supprimées : `backup/pre-trailer-1e310aa`, `site-v304`, `fix/admission-release-order`, `backup/milestone-v3.0.4-pre-merge-20261101`. Branche locale `milestone/v3.0.4` à supprimer au nettoyage de fin de session (décision en cours).
- Template : références `context/PROJECT_CONTEXT.md` corrigées par le template v3.30.1 (sync 2026-11-01). Compagnon `security-reviewer` corrigé (`model: sonnet`, chemins relatifs, `af901d3`).
- Réactiver le `schedule` de `failover.yml` (PR séparée). Paquets GHCR **privés** (pull refusé sur .218 le 2026-11-03) : à garder en tête pour la visibilité.
- Nettoyage qualif : jeton plugin `q4-qa` (8 h) et fichiers `/tmp/q4_*.mark` dans les minions ; `/tmp/qualif-v200` (v2) ; décision sur la suppression des volumes de la v2 (utilisateur).
- Historique git : trois `.exe` obsolètes restent dans l'historique (purge `git filter-repo` = décision utilisateur, destructif).
- Labels hérités inutilisés : `phase:1` à `phase:12`, `owner:dev-plugins`.

## Règles / pièges (leçons)
- **Questions à l'utilisateur** : toujours via AskUserQuestion. **Pas de push sans feu vert explicite** (un feu vert vaut pour un lot ; l'utilisateur a donné une autorisation durable bornée pour les corrections de CI sur `milestone/v3.0.3`, éteinte avec la milestone) ; push délégué à `deployer` (SHA complet, jamais `HEAD`, jamais de force, jamais main sauf PR validée) ; je ferme les issues après CI verte.
- **Tâches et retours par fichier** : toute tâche > 3-4 lignes est écrite par le teamleader dans `_work/tasks/<agent>-<YYYYMMDD-HHmmss>.md` (le teamleader écrit lui-même ces ordres, seule exception à la délégation) ; message court avec le chemin ; retour des agents en UNE ligne (SHA, rapport dans `_work/reports/`).
- **Trailer de commit EXACT** : `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>` ; contrôler les 100 % des commits non poussés avant un push (un agent Haiku avait écrit « Haiku 4.5 » ou rien sur 11 commits ; réécriture des seuls messages, arbres identiques prouvés). **Jamais `git commit --amend` en arbre partagé** (un agent a réécrit le commit d'un autre).
- **Vérifier, ne pas croire** : les agents annoncent « 100 % vérifié » avec des erreurs ; les chiffres de « budget de jetons » annoncés par les agents sont inventés ; l'agent `doc-updater` du template tourne sur un petit modèle (Haiku) : toujours passer `model: sonnet` aux agents de documentation. La doc doit être auditée contre le code par `qa` (commandes jouées sur binaires réels) et `security-reviewer`. Les tests d'intrusion réels de QA ont trouvé les failles que les revues ne voyaient pas (`/ws/agent`, `token/refresh`, `register` sans jeton, ré-enrôlement d'un révoqué).
- **Merge avec conflits** : `git merge --no-edit` laisse des lignes `# Conflicts:` après le trailer ; écrire le message dans un fichier et `git commit -F <fichier> --cleanup=verbatim` (merge refait le 2026-11-01, arbre identique, sans `--amend`).
- **Interruption (Échap)** : une interruption utilisateur pendant un tour arrête tous les teammates → relancer la team (respawn complet) avant de dispatcher.
- **Rapports et notifications** : les `idle_notification` répètent le DONE ; ne pas les traiter comme de nouveaux livrables.
- **Environnement de l'utilisateur, push, trailer, agents de doc** : règles permanentes migrées dans `CLAUDE.md` (section Conventions de code) ; ici seulement les incidents : `ansible-core` installé dans `~/.local` par un agent (désinstallé), `failover-test.sh` lancé sans le mode volume sur l'hôte distant (répertoires vides créés puis supprimés), `amend` du commit d'un autre agent.
- **Agents** : noms canoniques sans suffixe ; l'adresse du teamleader est `team-lead` ; `doc-updater`/`infra`/`planner` sont à spawner si absents ; arrêter (`TaskStop`) les agents de documentation terminés.
- **Sécurité** : `become_pass` jamais dans les logs ; fail closed ; pas de `panic` en production ; identifiants externes en `%q`.
- CRLF/LF : `git diff --ignore-space-at-eol`. Plugin Python : `SECAGENT-PYTHON/ansible_plugins/connection_plugins/relay.py`.
