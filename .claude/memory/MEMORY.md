# MEMORY — Ansible-SecAgent

> Source de vérité au démarrage de session (lue par `/start-session`). Mise à jour par `/end-session`.

## État de session (fin 2026-11-06)
- **Version : v3.0.5 publiée et déployée en PROD le 2026-11-06** (premier déploiement PROD du projet). Tag `v3.0.5` sur `654afdc` (merge PR #251, `--no-ff`) ; release.yml run 42186254744 vert 8/8 ; images attestées `secagent-server@sha256:6029905ebaae90bddcf8c7d106e834c9e2154775de6c057faae55ea0f97c46ee`, `secagent-minion@sha256:407f4d49e6ccc2fa0bbad4205d19125593fc77a8d1115f5b5b7daf42dcae1869`. Paquets GHCR **publics** (pull anonyme).
- `main` @ `67f680a` (PR #252 doc post-déploiement). Branche `milestone/v3.0.5` supprimée. Milestone v3.0.5 (n° 19) **clos** (29 issues). Site gh-pages publié (PR #257) : licence AGPL-3.0-or-later.
- **Travail en cours : aucun** (workflow v3.0.5 `completed`). Prochain milestone : **v3.0.6** (n° 20) — #225, #244-#247, #249, #253 (auth API Docker PROD + rotation secrets/cert), #254 (Environment `release` + protection `main`), #255 (retirer la connexion révoquée avant close 4001), #256 (scripts qualif : cert avant démarrage, bruit DIAGNOSTIC).

## Version et environnements
- **Tags** : v1.0.0, v2.0.0, v3.0.3, v3.0.4, v3.0.5. Template Claude : v4.2.1 (`ba78d41`, synchro 2026-11-05).
- **Architecture v3.0.3+** : relay actif/passif, un seul maître par STATE_DIR partagé, secondaires sans aucun port ; état = fichier `relay.state` (HMAC, secrets `enc:`) + `relay.lock` ; plus de SQLite, CGO, NATS, Caddy ni Kubernetes. TLS natif (7770/7772), admin 7771 en boucle locale par défaut. Détail : `DOC/server/STATE_SPEC.md`, `SERVER_SPEC.md`, `DOC/security/SECURITY.md`.
- **Qualif** : 192.168.1.218 (srv8, Docker 29.2.1, accès `docker -H tcp://192.168.1.218:2375`, API non authentifiée = choix utilisateur sur son LAN). Projet compose `secagent-qualif` (racine a/b, enfant pull, minions), vert sur v3.0.5. L'hôte héberge MooseFS (projet `chunks`, `/opt/MFS`) : **ne JAMAIS toucher** (idem srv1 192.168.1.211, MooseFS et k8s). Ancienne qualif v2 ARRÊTÉE, sauvegardée dans `/home/cyril/secagent-qualif-v2-backup-20261007-091343` (secrets : ne jamais commiter).
- **PROD** : hôte 192.168.1.218 (srv8), projet compose `secagent-prod-root` (nœud unique), ports 17770 / 17772, admin `127.0.0.1:17771` ; état local `/var/lib/secagent/prod/state` ; config `/etc/secagent/prod/` (secrets 10001:10001 0400, `tls.key` 10001:10001 **0600** — 0640 déclenche un `[SECURITY WARNING]`). Compose exécuté **sur l'hôte** dans `docker:29-cli@sha256:4d742ab934c2149b628bf26369ac3ec51cb91e2e28fe6722a0e86a6d6efc4bd5` (démon distant sans SSH : `secrets: file:` résolus sur l'hôte). Accès : `project-config.json` → `infrastructure.environments[].access`.
- **PKI PROD** : CA RSA-4096 10 ans `pathlen:0`, feuille `CN=secagent-prod-root` SAN `IP:192.168.1.218,DNS:srv8.local`, valable jusqu'au 2027-12-08. Administration par `srv8.local` ou l'IP, **jamais `localhost`** (hors SAN).
- **Secrets PROD : référence `~/secagent-private/prod/` (ext4, 0700) — `ca.key` n'en sort jamais.** `PRIVATE/prod/` (NTFS) = public uniquement (`pki/ca.crt`, `.env`, `README.txt`). Sauvegarde hors poste de `ca.key`/`rsa_master_key` faite par l'utilisateur ; sauvegarde initiale de `relay.state` dans `~/secagent-private/prod/backup/` (à copier hors poste par l'utilisateur). **Aucun secret PROD réel sur NTFS** (`/mnt/c` : chmod sans effet, lisible par tout le poste).
- Risque accepté (Q6) : API Docker `tcp:2375` non authentifiée → durcissement + rotation en #253. `/etc/secagent/prod/.branch-compose-bak/` conservé sur l'hôte (décision utilisateur).

## Décisions (à ne pas redécouvrir)
- **Failles v1/v2 corrigées en v3.0.3 seulement** : `/ws/agent` sans token, `POST /api/token/refresh` (route supprimée, 404), `POST /api/register` sans jeton (403 `enrollment_token_required`), ré-enrôlement d'un révoqué (drapeau `revoked` persistant, 403 `agent_revoked`, levée par `DELETE /api/admin/minions/{h}`). Retour arrière vers v3.0.3 impossible (liens Ed25519 v3.0.4) ; un binaire antérieur à #193 perd silencieusement les révocations.
- **#197** (compléments de qualif) : clôturée avec le déploiement PROD de v3.0.5 (milestone clos).
- **#250 / LOT-9 — `PRIVATE/`** : racine `SECAGENT_PRIVATE_DIR` (absolue obligatoire, défaut `<dépôt>/PRIVATE`), scripts fail-closed (ne créent jamais la racine). Secrets et PKI de qualif sous `PRIVATE/qualif/{secrets,pki,ci-tls}`. **Jetons de chaîne volatils sur `/tmp/secagent-qualif-chain-<uid>`** (NTFS 0777 refusé par le plugin), garde 0700/propriétaire/lien, nettoyés par `chain-test.sh down`. CI : `PRIVATE` jetable sous `$RUNNER_TEMP`. `.env.example` racine supprimé. Les secrets de l'ancien `.env.qualif` (historique poussé) ne sont plus en service.
- `failover.yml` teste par défaut le commit du workflow (`github.sha`, input `ref` vide). Le `schedule` de `failover.yml` reste commenté (PR séparée).
- Test `TestWiring_ARevocationBetweenTheCheckAndTheRegistrationClosesTheLink` déterministe (`36c8523`) : la close 4001 part avant `unregisterIfCurrent` (fenêtre de µs, pas de défaut de sécurité) → #255.
- **CLA** : branche `cla-signatures` (non protégée, registre `signatures/cla.json`, à conserver). Sur PR #252 le check a exigé la signature du co-auteur `claude` (absent de l'allowlist `CCoupel,dependabot[bot]`), puis est passé après `recheck` ; cause non établie, `cla.yml` non modifié — à surveiller (piste : ajouter `claude` à l'allowlist).
- Version : `main.Version` (minion, inventory), `internal/cli.Version` (serveur). `docker compose exec` impose `/app/secagent-server`.
- Plugin Python : classe `Connection`, priorité hostvar > `RELAY_*` > `[secagent_connection]` > défaut, jeton en fichier 0600 propriétaire, stdin en base64.
- CI : `ci.yml` ne publie rien (garde `check_no_publish.py`), `candidate-images.yml` et `failover.yml` manuels, `release.yml` au tag seulement.
- Mesures : arrêt propre 3,2 à 7,2 s, `kill` ~5 min (péremption du verrou), 3 000 agents enrôlés en 11,8 s.

## CI et outils
- `go` dans `/usr/local/go/bin` (pas dans le PATH) ; bloc d'environnement Go : `.claude/outillage_go.md`. Tests : `JWT_SECRET_KEY=test ADMIN_TOKEN=test go test -race ./... -timeout 900s` depuis `GO/`. Ansible uniquement dans un venv hors `~/.local`.
- Le dépôt est sur `/mnt/c` (NTFS) : `chmod 600` non honoré ; lancer les scripts de qualif depuis une copie `git archive` hors `/mnt/c` ou avec `PRIVATE/` configuré.
- `docker.exe` (Windows) seul dans WSL, sans `DOCKER_HOST` : utiliser `-H`. Démon Docker local arrêté : ne pas le démarrer.

## Suivis / à trancher
- Branche locale `lot6-wip` (redondante, commits déjà intégrés) et worktree `wt9` : conservés par décision utilisateur.
- B63 (`pip install --require-hashes` dans 3 jobs CI) ; Environments GitHub `release`/`candidate` et protection de `main` = réglages utilisateur (#254).
- Historique git : trois `.exe` obsolètes (purge `git filter-repo` = décision utilisateur) ; secrets de l'ancien `.env.qualif` lisibles dans l'historique poussé (rotation conseillée si réutilisés).
- Labels hérités inutilisés : `phase:1` à `phase:12`, `owner:dev-plugins`.

## Règles / pièges (leçons)
- **Questions à l'utilisateur** : toujours via AskUserQuestion. **Pas de push sans feu vert explicite** ; push délégué à `deployer` (SHA complet, jamais `HEAD`, jamais de force, jamais main sauf PR validée) ; un tag publie : confirmation dédiée.
- **Tâches et retours par fichier** : tout ordre > 3 lignes dans `_work/tasks/<agent>-<YYYYMMDD-HHmmss>.md` ; retour des agents en UNE ligne (SHA, rapport dans `_work/reports/`).
- **Trailer de commit EXACT** : `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>` ; contrôler tous les commits non poussés avant un push. **Jamais `git commit --amend` en arbre partagé**. Règle : `git commit -- <chemins>` après `git diff --cached --stat` (incident `166638e`).
- **Vérifier, ne pas croire** : les « vérifié à 100 % » des agents contiennent des erreurs ; les budgets de jetons annoncés sont inventés ; agents de documentation en `model: sonnet`. Les tests d'intrusion réels de QA trouvent ce que les revues ne voient pas.
- **Merge avec conflits** : `git merge --no-edit` laisse des lignes `# Conflicts:` ; écrire le message dans un fichier et `git commit -F <fichier> --cleanup=verbatim`.
- **Interruption (Échap)** : arrête tous les teammates → respawn complet de l'effectif avant de dispatcher.
- `/mnt/c` (WSL 9p) peut tomber en `Input/output error` en cours de session : tout s'arrête (agents compris) ; remède `wsl --shutdown`. Un `.git/index.lock` vide peut rester après l'arrêt d'un agent : le supprimer seulement si aucun processus git ne tourne.
- Les teammates peuvent passer en IDLE sans avoir pris un ordre envoyé juste après leur spawn : renvoyer l'ordre. Les `idle_notification` répètent le DONE : pas de nouveau livrable.
- Incidents passés : `ansible-core` installé dans `~/.local` par un agent (désinstallé), `failover-test.sh` lancé sans le mode volume sur l'hôte distant, `amend` du commit d'un autre agent.
- **Agents** : noms canoniques sans suffixe ; adresse du teamleader `team-lead` ; arrêter (`TaskStop`) les agents de documentation terminés.
- **Sécurité** : `become_pass` jamais dans les logs ; fail closed ; pas de `panic` en production ; identifiants externes en `%q`.
- CRLF/LF : `git diff --ignore-space-at-eol`. Plugin Python : `SECAGENT-PYTHON/ansible_plugins/connection_plugins/relay.py`.
