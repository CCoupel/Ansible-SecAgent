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

## Merge sur `main` par PR (surcharge, #254)

`main` est protégée par un ruleset **sans contournement admin** (PR obligatoire, ni force-push ni suppression) :
les étapes du template qui font `merge --no-ff` puis `git push origin HEAD:main` sont **remplacées** par :

```bash
git push origin milestone/vX.Y.Z    # état exact de la branche (inchangé)
gh pr create --base main --head milestone/vX.Y.Z --title "Release v$VERSION" --body "<résumé du milestone>"
# attendre la CI verte et la validation de la PR, puis :
gh pr merge <n> --merge --delete-branch=false    # commit de merge (pas de squash/rebase) ; branche supprimée plus tard par /end-session
git fetch origin main
SHA=$(gh pr view <n> --json mergeCommit -q .mergeCommit.oid)   # commit de merge de la PR
[ -n "$SHA" ] && [ "$(git rev-parse origin/main)" = "$SHA" ] || { echo "REFUS : origin/main != commit de merge de la PR"; exit 1; }
git tag -a "v$VERSION" "$SHA" -m "Release v$VERSION"
git push origin "v$VERSION"                      # tag = confirmation dédiée ; Environment `release` : reviewer requis
```

- Plus de worktree de release ni de `push origin HEAD:main`.
- Les PR vers `main` n'acceptent que la méthode **merge** (`--merge`) : ni squash ni rebase.
- **Rollback** : PR de revert (branche `revert/vX.Y.Z` depuis `origin/main`, `git revert -m 1 <merge>`, `gh pr create`,
  `gh pr merge --merge`), jamais de push direct ni de force.
- **Suppression exceptionnelle d'un tag erroné** (les tags sont protégés par le ruleset 26864482) : uniquement après
  **confirmation utilisateur dédiée** (`AskUserQuestion`), puis :
  ```bash
  gh api -X PUT repos/CCoupel/Ansible-SecAgent/rulesets/26864482 -f enforcement=disabled
  git push origin --delete "v$VERSION" && git tag -d "v$VERSION"
  gh api -X PUT repos/CCoupel/Ansible-SecAgent/rulesets/26864482 -f enforcement=active
  gh api repos/CCoupel/Ansible-SecAgent/rulesets/26864482 -q .enforcement   # doit afficher « active »
  ```
  La réactivation est obligatoire même si la suppression échoue ; sa vérification fait partie du compte rendu.

## Poste (Linux natif depuis 2026-11-09)

- `gh` du poste en **2.46.0**, authentifié par `GH_TOKEN` : suffisant pour la barrière (`gh run list`, `gh workflow run`,
  `gh run view`) et pour le tag ; `gh attestation verify` exige `gh` ≥ 2.49 téléchargé dans le scratchpad (`deploy.qualif.md`).
- Pas de client Docker ni de `ssh` sur le poste : PUBLISH PROD n'en a pas besoin (merge + tag, rebuild par `release.yml`).
