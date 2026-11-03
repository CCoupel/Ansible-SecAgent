# publish.prod — adaptations Ansible-SecAgent

> Compagnon de `publish.prod.template.md` (lire après le template).

## Barrière de pré-validation (étape 1quater)

- Le workflow de pré-validation du projet est **`.github/workflows/ci.yml`** (déclenché sur push
  `milestone/**`), pas `ci-branch.yml` : remplacer `ci-branch.yml` par `ci.yml` dans les commandes
  `gh run list` / `gh workflow run` de la barrière.
- Script CI unique : `commands.ci` = `scripts/ci.sh` (C11 partiel : jobs Go de `ci.yml` seulement ; `ci.yml`
  ne l'appelle pas encore, alignement à faire par `infra` en v3.0.5).

## Version

- `version_file` = **`VERSION`** (racine, une ligne `X.Y.Z` + LF, v3.0.5, D-P3) : il porte la version du milestone
  dès l'ouverture du cycle, **sans compteur de build `.a`** (les candidats QUALIF sont identifiés par `sha-<commit>`,
  pas par `X.Y.Z.a`) ; `VERSION=$(cat VERSION)`. La CI le vérifie, jamais ne l'écrit : format + égalité à la branche
  `milestone/vX.Y.Z` (`ci.yml`, job lint), égalité au tag avant tout build (`release.yml`, `check_version_file.sh`).
  Les binaires prennent toujours leur version du tag (`-ldflags -X`). Tant que le template n'est pas resynchronisé
  (`/init-project` d6), la ligne générée `DEV_VERSION=$(cat )` du template est à remplacer par `cat VERSION`.
- Push et tag : jamais sans feu vert explicite de l'utilisateur, tag = confirmation dédiée (CLAUDE.md).
