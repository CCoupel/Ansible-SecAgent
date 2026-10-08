# Deploy PROD — adaptations projet Ansible-SecAgent

> Compagnon de `deploy.prod.template.md` (mécanisme `docker-compose`) — à lire après le template.
> Ne contient que le spécifique projet. Le CODE fait foi : `DEPLOYMENT/prod/` et `DEPLOYMENT/prod/README.md`.

Installation de l'artefact déjà publié par PUBLISH PROD (tag `vX.Y.Z`, images buildées par la CI : `release.yml`) via
Docker Compose. Pas de Kubernetes/Helm, pas de Swarm, pas de NATS, pas de Caddy, pas de SQLite.

## Cible de déploiement
- Hôtes : N hôtes de prod (actif/passif), le MÊME Compose et le MÊME stockage partagé (`STATE_HOST_DIR` → `STATE_DIR`) sur chacun. Si un hôte de prod héberge aussi la QUALIF, vérifier avant `up` l'absence de collision de ports publiés (`docker ps --format '{{.Names}} {{.Ports}}'`) et alerter le teamleader sans arrêter la QUALIF.
- Méthode : Docker sur chaque hôte (adresses fournies par le teamleader / l'utilisateur ; ne jamais supposer 192.168.1.218, c'est la QUALIF).
- Fichier Compose : `DEPLOYMENT/prod/docker-compose.server.yml` (service `secagent-server`) ; relay enfant : ajouter `-f DEPLOYMENT/prod/docker-compose.child.yml` (`REPEATER_*` obligatoires).
- Projet compose dédié : `docker compose -p secagent-prod-<relay_id> ...` — jamais un projet de QUALIF.
- Variables non secrètes : `DEPLOYMENT/prod/.env` (modèle `.env.example` : `SECAGENT_VERSION`, `STATE_HOST_DIR`, `TLS_CERT_DIR`, `ADMIN_PUBLISH_ADDR`, `SECAGENT_MEM_LIMIT`, `GOMEMLIMIT`).
- Secrets (v3.0.4, #196) : FICHIERS dans `DEPLOYMENT/prod/secrets/` (`jwt_secret_key`, `admin_token`, `rsa_master_key`, + `repeater_upstream_token` pour un enfant ; mode d'emploi `prod.env.example`, mode 0400, hors dépôt, montés en `secrets:` et lus par `*_FILE`) : `JWT_SECRET_KEY`, `ADMIN_TOKEN`, `RSA_MASTER_KEY` IDENTIQUES sur tous les nœuds d'un relay, propres à PROD, jamais les valeurs de qualification. `RSA_MASTER_KEY` se sauvegarde HORS hôte et hors du partage.
- `.claude/agents/environments/prod.env` (jamais commité, modèle `prod.env.example` de ce dossier) ne porte que les accès registre/SSH de l'agent.

## Artefact
- Images `linux/amd64`, `ghcr.io/ccoupel/secagent-server:vX.Y.Z@sha256:<digest>`. L'archive de release `secagent-compose-<version>.tar.gz` contient les Compose avec `image:` réécrite en `tag@sha256` (jamais `latest`, jamais `build:`) ; vérifier `SHA256SUMS` avant usage.
- Sans archive : `SECAGENT_VERSION` dans `.env` fixe le tag.

## Références
- `DEPLOYMENT/prod/README.md` (stockage partagé, vérification, sauvegarde/restauration), `DEPLOYMENT/README.md`
- SERVER_SPEC.md : DOC/server/SERVER_SPEC.md §2 — 7770 (API), 7771 (admin), 7772 (WS) ; ARCHITECTURE.md §19 ; HLD.md §4

## Spécificités PROD
- 7771 n'est publié que sur `ADMIN_PUBLISH_ADDR` (boucle locale par défaut, jamais 0.0.0.0) ; `ADMIN_TLS=true` ; `TLS_DISABLE` et `RELAY_INSECURE_TLS` jamais définis.
- Stockage partagé non testé avec `DEPLOYMENT/prod/tools/test_shared_storage.py` = non supporté.
- Ne jamais lancer `docker compose down -v` ni supprimer un volume ou le stockage d'état sans ordre explicite.

## Processus (sur demande du teamleader)
1. Vérifier que `DEPLOYMENT/prod/docker-compose.server.yml` existe, que `.env` et le répertoire `secrets/` sont en place (enfant : aussi `REPEATER_ROOT_ID` et `ROOT_LINK_KEY_FILE`) et que l'image/tag publié est présent. Sinon `BLOQUE` au teamleader (le scaffold est du ressort de l'agent `infra`).
2. Première installation uniquement, depuis UN seul hôte : `docker compose -p secagent-prod-<relay_id> -f docker-compose.server.yml run --rm --no-deps secagent-server state init`.
3. Sur chaque hôte : `docker compose -p secagent-prod-<relay_id> -f docker-compose.server.yml pull` puis `up -d`.
4. Vérifier `ps` et `logs --tail=50` : une instance maître (ports ouverts), les autres secondaires (aucun port) ; `exec secagent-server secagent-server status --local` code 0 sur chaque hôte (healthy).
5. Smoke : `/health` du maître (`https://<hôte>:7770/health` → `"role":"master"`, TLS natif, sans proxy) et `/api/inventory` avec un jeton plugin (le jeton admin est refusé).
6. Rapport : services + statut (maître / secondaires), URL accessible oui/non, logs d'erreur, `RÉSULTAT : OK / ÉCHEC`.

## Outils
`MSYS_NO_PATHCONV=1` requis pour les `docker exec` avec chemins Unix ; `docker cp` avec chemins Windows.

## Règles absolues
- Ne jamais modifier le code source ni rebuilder : déployer l'artefact publié (principe BORE).
- En cas d'échec, fournir les logs complets et proposer le rollback au tag précédent sans l'exécuter sans accord. Un retour arrière de version ne dispense pas de la restauration d'état (`state verify` / `state restore`, voir le README prod).
