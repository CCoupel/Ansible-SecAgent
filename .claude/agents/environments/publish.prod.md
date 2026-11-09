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
tag_release() {   # return 1 (jamais exit : ne tue pas un shell interactif) si le commit de merge n'est pas origin/main
  local SHA; SHA=$(gh pr view "$1" --json mergeCommit -q .mergeCommit.oid)   # commit de merge de la PR
  if [ -z "$SHA" ] || [ "$(git rev-parse origin/main)" != "$SHA" ]; then
    echo "REFUS : origin/main != commit de merge de la PR"; return 1
  fi
  git tag -a "v$VERSION" "$SHA" -m "Release v$VERSION"
}
# pas de tag ni de push si le contrôle échoue ; tag = confirmation dédiée ; Environment `release` : reviewer requis
tag_release <n> && git push origin "v$VERSION"
```

- Plus de worktree de release ni de `push origin HEAD:main`.
- Les PR vers `main` n'acceptent que la méthode **merge** (`--merge`) : ni squash ni rebase.
- **Rollback** : PR de revert (branche `revert/vX.Y.Z` depuis `origin/main`, `git revert -m 1 <merge>`, `gh pr create`,
  `gh pr merge --merge`), jamais de push direct ni de force.
- **Suppression exceptionnelle d'un tag erroné** (les tags sont protégés par le ruleset 26864482) : uniquement après
  **confirmation utilisateur dédiée** (`AskUserQuestion`), puis :
  ```bash
  RS=repos/CCoupel/Ansible-SecAgent/rulesets/26864482
  set_enforcement() {   # GET complet -> jq (seul .enforcement change) -> PUT --input -> relecture
    local E=$1 T; T=$(mktemp)
    gh api "$RS" > "$T.orig" || return 1
    jq --arg e "$E" '{name,target,enforcement:$e,conditions,rules,bypass_actors}' "$T.orig" > "$T.new" || return 1
    gh api -X PUT "$RS" --input "$T.new" > /dev/null || return 1
    gh api "$RS" > "$T.after" || return 1
    # rules, conditions et bypass_actors doivent être identiques à l'original ; seul enforcement change
    [ "$(jq -S '{rules,conditions,bypass_actors}' "$T.orig")" = "$(jq -S '{rules,conditions,bypass_actors}' "$T.after")" ] \
      && [ "$(jq -r .enforcement "$T.after")" = "$E" ] || { echo "ECART ruleset après PUT $E"; return 1; }
    rm -f "$T" "$T.orig" "$T.new" "$T.after"
  }
  delete_tag() {   # la réactivation s'exécute TOUJOURS, quel que soit le résultat de la suppression
    local rc=0
    set_enforcement disabled || return 1          # rien n'a été désactivé de façon sûre : on s'arrête
    git push origin --delete "v$VERSION" && git tag -d "v$VERSION" || rc=1
    set_enforcement active || { echo "ALERTE : ruleset tags NON réactivé — réactiver à la main"; rc=1; }
    gh api "$RS" -q .enforcement                  # doit afficher « active »
    return $rc
  }
  delete_tag
  ```
  Toute modification d'un ruleset suit ce schéma (GET complet, `jq` ne changeant que le champ visé, sans
  `id`/`_links`/`created_at`…, `PUT --input`, relecture et comparaison de `rules`/`conditions`/`bypass_actors`) : jamais
  de `PUT -f champ=valeur` partiel. Si `set_enforcement disabled` échoue après son PUT, vérifier l'état et réactiver.
  La vérification finale fait partie du compte rendu.

## Poste (Linux natif depuis 2026-11-09)

- `gh` du poste en **2.46.0**, authentifié par `GH_TOKEN` : suffisant pour la barrière (`gh run list`, `gh workflow run`,
  `gh run view`) et pour le tag ; `gh attestation verify` exige `gh` ≥ 2.49 téléchargé dans le scratchpad (`deploy.qualif.md`).
- Pas de client Docker ni de `ssh` sur le poste : PUBLISH PROD n'en a pas besoin (merge + tag, rebuild par `release.yml`).
