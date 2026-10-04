# Deploy PROD — adaptations projet Ansible-SecAgent

> Compagnon de `deploy.prod.template.md` (mécanisme `docker-compose`) — à lire après le template.
> Ne contient que le spécifique projet.

Installation de l'artefact déjà publié par PUBLISH PROD (tag officiel, image buildée par la CI) via
Docker Compose. Pas de Kubernetes/Helm : la prod tourne en Docker.

## Cible de déploiement
- Serveur : 192.168.1.218 (même hôte que QUALIF)
- Méthode : Docker remote access (`DOCKER_HOST=tcp://192.168.1.218:2375`)
- Fichier compose : `DEPLOYMENT/prod/docker-compose.server.yml`
- Projet compose dédié : `docker compose -p secagent-prod ...` — jamais le projet de QUALIF
- Fichier d'environnement : `.claude/agents/environments/prod.env` (jamais commité, modèle `prod.env.example`)

## Références
- SERVER_SPEC.md : DOC/server/SERVER_SPEC.md §2 — ports 7770 (API), 7771 (admin interne), 7772 (WS)
- ARCHITECTURE.md : DOC/common/ARCHITECTURE.md §19
- HLD.md : DOC/common/HLD.md §4
- Secrets : `JWT_SECRET_KEY` et `ADMIN_TOKEN` propres à PROD, jamais les valeurs de qualification

## Services à déployer
- secagent-server : ports 7770/7771/7772
- nats : NATS JetStream (port 4222), volume persistant
- caddy : reverse proxy TLS (ports 443/80)

## Spécificités PROD sur hôte partagé avec QUALIF
- Les ports publiés de PROD ne doivent pas entrer en collision avec ceux de QUALIF : vérifier avant `up`
  (`docker ps --format '{{.Names}} {{.Ports}}'`) et alerter le teamleader au moindre conflit, sans arrêter QUALIF.
- Noms de conteneurs, réseaux et volumes préfixés par le projet `secagent-prod`.
- Ne jamais lancer `docker compose down -v` ni supprimer un volume PROD sans ordre explicite.

## Processus (sur demande du teamleader)
1. Vérifier que `DEPLOYMENT/prod/docker-compose.server.yml` existe et que l'image/tag publié est présent. S'il est
   absent : `BLOQUE` au teamleader (le scaffold est du ressort de l'agent `infra`).
2. `DOCKER_HOST=tcp://192.168.1.218:2375 docker compose -p secagent-prod -f DEPLOYMENT/prod/docker-compose.server.yml pull`
3. Même commande avec `up -d`.
4. Vérifier `ps` et `logs --tail=50` : tous les services healthy.
5. Smoke : endpoint `/api/inventory` accessible (port 7770, via Caddy en TLS).
6. Rapport : services + statut, URL accessible oui/non, logs d'erreur, `RÉSULTAT : OK / ÉCHEC`.

## Outils
`MSYS_NO_PATHCONV=1` requis pour les `docker exec` avec chemins Unix ; `docker cp` avec chemins Windows.

## Règles absolues
- Ne jamais modifier le code source ni rebuilder : déployer l'artefact publié (principe BORE).
- En cas d'échec, fournir les logs complets et proposer le rollback au tag précédent sans l'exécuter sans accord.
