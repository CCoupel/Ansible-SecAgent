# Deploy — QUALIF (mecanisme : docker-compose)

> Genere depuis `TEMPLATE_claude/templates/environments/deploy-docker-compose.md` — selectionne
> car `infrastructure.environments[].deploy.mechanism = "docker-compose"` pour QUALIF dans
> `.claude/project-config.json`. Charge par `agents/deploy.md`, Tache DEPLOY QUALIF, etape
> [2. MECANISME]. Fichier compose : `docker-compose.qualif.yml`.

Installation pure de l'artefact deja publie par PUBLISH QUALIF — aucun build, aucune
publication ici (principe BORE, `agents/infra.md` section 3).

## Variables attendues

| Variable | Usage |
|----------|-------|
| `REGISTRY_USER` / `REGISTRY_PASSWORD` | `docker login` avant `docker pull`, si le registre est prive |
| `SSH_HOST` / `SSH_USER` / `SSH_KEY_PATH` | Uniquement si le service tourne sur un hote distant (variante rsync/scp) |

```bash
# 1. Verification
docker image inspect "build/qualif_v{X.Y.Z}/:$VERSION" >/dev/null 2>&1 \
  || { echo "Aucune publication trouvee pour QUALIF — executer /publish qualif d'abord"; exit 1; }

# 2. Install
[ -n "$REGISTRY_USER" ] && echo "$REGISTRY_PASSWORD" | docker login build/qualif_v{X.Y.Z}/ -u "$REGISTRY_USER" --password-stdin
docker pull "build/qualif_v{X.Y.Z}/:$VERSION" && docker-compose -f docker-compose.qualif.yml up -d
# ou (artefact fichier plutot qu'image) : rsync/scp de l'artefact vers le serveur cible, puis
# restart du service via docker-compose

# 3. Smoke tests
curl -f "https://qualif.example.com/health"

# 4. Notification
echo "Deploiement QUALIF termine - $VERSION"
```

## Echec

```bash
docker-compose -f docker-compose.qualif.yml logs --tail=50
```

Un echec ici est toujours un echec d'installation — le build (BUILD) et la publication (PUBLISH
QUALIF) ont deja reussi. Rapport a `main`, jamais de correction autonome.

## Rollback

```bash
docker-compose -f docker-compose.qualif.yml up -d --force-recreate --no-deps app  # relance l'image precedente si $VERSION n'a pas ete change en place
# ou, si la version precedente a ete ecrasee localement :
docker pull "build/qualif_v{X.Y.Z}/:$PREVIOUS_VERSION" && docker-compose -f docker-compose.qualif.yml up -d
```
