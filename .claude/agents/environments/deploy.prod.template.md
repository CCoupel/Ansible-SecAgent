# Deploy — PROD (mecanisme : docker-compose)

> Genere depuis `TEMPLATE_claude/templates/environments/deploy-docker-compose.md` — selectionne
> car `infrastructure.environments[].deploy.mechanism = "docker-compose"` pour PROD dans
> `.claude/project-config.json`. Charge par `agents/deploy.md`, Tache DEPLOY PROD, etape
> [2. MECANISME]. Fichier compose : `docker-compose.prod.yml`.

Installation pure de l'artefact deja publie par PUBLISH PROD — aucun build, aucune
publication ici (principe BORE, `agents/infra.md` section 3).

## Variables attendues

| Variable | Usage |
|----------|-------|
| `REGISTRY_USER` / `REGISTRY_PASSWORD` | `docker login` avant `docker pull`, si le registre est prive |
| `SSH_HOST` / `SSH_USER` / `SSH_KEY_PATH` | Uniquement si le service tourne sur un hote distant (variante rsync/scp) |

```bash
# 1. Verification
docker image inspect "git-tag:$VERSION" >/dev/null 2>&1 \
  || { echo "Aucune publication trouvee pour PROD — executer /publish prod d'abord"; exit 1; }

# 2. Install
[ -n "$REGISTRY_USER" ] && echo "$REGISTRY_PASSWORD" | docker login git-tag -u "$REGISTRY_USER" --password-stdin
docker pull "git-tag:$VERSION" && docker-compose -f docker-compose.prod.yml up -d
# ou (artefact fichier plutot qu'image) : rsync/scp de l'artefact vers le serveur cible, puis
# restart du service via docker-compose

# 3. Smoke tests
curl -f "https://prod.example.com/health"

# 4. Notification
echo "Deploiement PROD termine - $VERSION"
```

## Echec

```bash
docker-compose -f docker-compose.prod.yml logs --tail=50
```

Un echec ici est toujours un echec d'installation — le build (BUILD) et la publication (PUBLISH
PROD) ont deja reussi. Rapport a `main`, jamais de correction autonome.

## Rollback

```bash
docker-compose -f docker-compose.prod.yml up -d --force-recreate --no-deps app  # relance l'image precedente si $VERSION n'a pas ete change en place
# ou, si la version precedente a ete ecrasee localement :
docker pull "git-tag:$PREVIOUS_VERSION" && docker-compose -f docker-compose.prod.yml up -d
```
