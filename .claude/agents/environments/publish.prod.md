# publish.prod — adaptations Ansible-SecAgent

> Compagnon de `publish.prod.template.md` (lire après le template).

## Barrière de pré-validation (étape 1quater)

- Le workflow de pré-validation du projet est **`.github/workflows/ci.yml`** (déclenché sur push
  `milestone/**`), pas `ci-branch.yml` : remplacer `ci-branch.yml` par `ci.yml` dans les commandes
  `gh run list` / `gh workflow run` de la barrière.
- Script CI unique : `commands.ci` = `scripts/ci.sh` (C11 partiel : jobs Go de `ci.yml` seulement ; `ci.yml`
  ne l'appelle pas encore, alignement à faire par `infra` en v3.0.5).

## Version

- `version_file` n'est pas défini dans `project-config.json` : la version vient du tag `vX.Y.Z` et de la
  branche `milestone/vX.Y.Z` ; ignorer les étapes de lecture/écriture du fichier de version.
- Push et tag : jamais sans feu vert explicite de l'utilisateur, tag = confirmation dédiée (CLAUDE.md).
