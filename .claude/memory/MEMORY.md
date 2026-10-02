# MEMORY — Ansible-SecAgent

> Source de vérité au démarrage de session (lue par `/start-session`). Mise à jour par `/end-session`.

## Version et environnements
- **Dernière release** : `v2.0.0` (tag annoté sur `259fd13`, release GitHub publiée le 2026-10-02) — Phase 12 Proxy/Gateway multi-zone. La release n'a aucun asset (pas de binaires).
- **Images GHCR v2.0.0** : publiées le 2026-10-02 via le workflow Release lancé à la demande (`tag=v2.0.0`, `skip_tests=true`) : `ghcr.io/ccoupel/secagent-server` et `secagent-minion` (tags `v2.0.0`, `2.0.0`, `latest`, paquets publics).
- **Qualif** : 192.168.1.218 (Docker Compose, `DEPLOYMENT/qualif/docker-compose.proxy.yml`) — v2.0.0 validée sur be17cee (smoke 8/8, exec via proxy OK une fois les relay nodes enregistrés sur le port 7770 avec un token plugin).
- **Prod Kubernetes** : hors périmètre v2.0.0 (pas de Helm chart, kubeconfig Rancher expiré, voir #136).
- **Template Claude** : v3.9.0 (`cf187ca7`), synchronisé le 2026-10-02.

## CI GitHub (créée le 2026-10-02, issue #133 encore ouverte)
- `.github/workflows/ci.yml` : build + `go test ./...` sur push/PR `main|master` — verte sur `1a7b963`.
- `.github/workflows/release.yml` : tag `vX.Y.Z` ou `workflow_dispatch` (inputs `tag`, `skip_tests`) ; tests, images GHCR, release GitHub (notes du CHANGELOG + binaires linux/amd64 + SHA256SUMS) ; ne recrée jamais une release existante.
- Manque : lint golangci-lint (config non vérifiée), tests Python (`SECAGENT-PYTHON/tests` vide), badge README, `version_file`.
- Les tests sont bloquants, jamais masqués : un tag ne publie rien si les tests échouent.

## Travail en cours
- Branche `main`, alignée sur `origin/main` (`1a7b963`), arbre propre.
- Milestone **v3.0 — repeater-client/server** (#13) : 1/16 fermée (#100 corrigée par `1a7b963`). Ouvertes : #122-#130, #131-#136.
- Le correctif #100 (become/stdin non vide, timeout) est dans `main` mais PAS dans v2.0.0 : il sortira avec v3.0 (décision utilisateur, pas de v2.0.1).
- Milestone v2.0 (#12) : fermé, 13/13, réellement implémenté (audit planner 2026-10-02).

## Décisions de la session 2026-10-02
- v2.0.0 taguée sur le dernier commit de doc (code Go identique à e9672dc et be17cee ; be17cee ne change que la config compose + docs).
- A4 (auto-seed `PROXY_RELAYS`) absorbé par #124/#125 (auto-enregistrement du repeater-client).
- Une CI rouge se corrige, elle ne se contourne pas (consigne explicite de l'utilisateur) : ne jamais masquer un test.

## À trancher (prochaine session)
- **PushManager (#123)** : suppression du mode push et de `PROXY_RELAYS` livrés en v2.0 — à rediscuter avec l'utilisateur (rupture de compatibilité à documenter).
- Ordre de v3.0 avec les 7 nouvelles issues (#131-#136, #124/#125 enrichies).
- Fermer ou garder #133 (lint, tests Python).
- Qualif : nettoyer le worktree `/tmp/qualif-v200` et décider du sort de `DEPLOYMENT/qualif/docker-compose.override.yml`.
- `.gitattributes` (`* text=auto eol=lf`) et ajout de `MARKETING/` au `.gitignore` (template v3.9.0, site sur `gh-pages` uniquement).

## Règles / pièges
- Le CRLF/LF fait apparaître des fichiers « modifiés » sans diff réelle (WSL/Windows) : vérifier avec `git diff --ignore-space-at-eol` avant de commiter.
- Vérifier le code avant d'affirmer dans un CHANGELOG (des affirmations non vérifiées ont dû être retirées de la v2.0.0).
- Le teamleader délègue : `doc-updater` et `infra` ne sont pas dans les 10 agents permanents, à lancer manuellement ; `/team-delete` arrête tous les teammates en fin de session.
- `go` n'est pas dans le PATH du shell du teamleader : les tests Go passent par les agents dev ou par la CI.
- `become_pass` ne doit jamais apparaître dans les logs (test `TestRunBecomePassNotInLogs`).
