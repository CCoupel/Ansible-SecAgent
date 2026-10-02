# MEMORY — Ansible-SecAgent

> Source de vérité au démarrage de session (lue par `/start-session`). Mise à jour par `/end-session`.

## Version et environnements
- **Dernière release** : `v2.0.0` (tag annoté sur `259fd13`, release GitHub publiée le 2026-10-02) — Phase 12 Proxy/Gateway multi-zone.
- **Qualif** : 192.168.1.218 (Docker Compose, `DEPLOYMENT/qualif/docker-compose.proxy.yml`) — v2.0.0 validée sur be17cee (smoke 8/8, exec via proxy OK).
- **Prod Kubernetes** : hors périmètre v2.0.0 (pas de Helm chart, kubeconfig Rancher expiré, voir #136).
- **Images GHCR v2.0.0** : NON publiées — reportées à la CI (#133). Le workflow devra pouvoir être lancé à la demande (`workflow_dispatch`) sur un tag existant.

## Travail en cours
- Branche `main`, alignée sur `origin/main` (`259fd13`), arbre propre.
- Milestone **v3.0 — repeater-client/server** (#13) : 0/16 issues fermées. Issues #122-#130 + #100, #131-#136 (créées le 2026-10-02).
- Milestone v2.0 (#12) : fermé, 13/13, réellement implémenté (audit planner 2026-10-02).

## Décisions de la session 2026-10-02
- v2.0.0 taguée sur le dernier commit de doc (code Go identique à e9672dc et be17cee ; be17cee ne change que la config compose + docs).
- Bugs executor (#100) reportés en v3.0 : `bytesReader` renvoie `fmt.Errorf("EOF")` (stdin non vide et `become` => rc=1), timeout ne tue que `/bin/sh`. Limites connues documentées dans le CHANGELOG.
- A4 (auto-seed `PROXY_RELAYS`) absorbé par #124/#125 (auto-enregistrement du repeater-client).
- La CI GitHub n'existait pas (`.github/workflows` absent) : releases et images étaient manuelles. #133 la crée (build, tests, images GHCR, release sur tag).

## À trancher (prochaine session)
- **PushManager (#123)** : suppression du mode push et de `PROXY_RELAYS` livrés en v2.0 — à rediscuter avec l'utilisateur (rupture de compatibilité à documenter).
- Ordre de v3.0 avec les 7 nouvelles issues (#100 critique en premier).
- Qualif : nettoyer le worktree `/tmp/qualif-v200` et décider du sort de `DEPLOYMENT/qualif/docker-compose.override.yml`.

## Règles / pièges
- Le CRLF/LF fait apparaître des fichiers « modifiés » sans diff réelle (WSL/Windows) : vérifier avec `git diff --ignore-space-at-eol` avant de commiter ; ajouter un `.gitattributes` (`* text=auto eol=lf`) reste à décider.
- Vérifier le code avant d'affirmer dans un CHANGELOG (des affirmations non vérifiées ont dû être retirées de la v2.0.0).
- Le teamleader délègue : `doc-updater` n'est pas dans les 10 agents permanents, à lancer manuellement.
- `become_pass` ne doit jamais apparaître dans les logs.
