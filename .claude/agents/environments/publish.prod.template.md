# Publish — PROD (mecanisme : rebuild-ci)

> Genere depuis `TEMPLATE_claude/templates/environments/publish-rebuild-ci.md` — selectionne car
> `infrastructure.environments[].publish.mode = "rebuild-ci"` pour PROD dans
> `.claude/project-config.json`. Charge par `agents/deploy.md`, Tache PUBLISH PROD, etape
> [2. MECANISME]. Pipeline CI : `.github/workflows/release.yml`.

Merge vers `main` + tag officiel, qui declenche la CI. La CI reconstruit depuis exactement la
meme source figee (le tag), en suivant l'unique pipeline — reproductible, mais recalcule, jamais
un build ad hoc (voir principe BORE, `agents/infra.md` section 3, mecanisme "rebuild
deterministe").

## Variables attendues

Aucune dans `.env`/`<env>.env` — les commandes `git`/`gh` ci-dessous utilisent l'authentification
ambiante du poste (`gh auth login` deja fait). Les secrets consommes PAR LA CI elle-meme
(`.github/workflows/release.yml`) sont geres separement, dans les secrets du systeme CI/CD (ex. GitHub Actions
repo secrets), jamais dans ces fichiers `.env` locaux.

```bash
# 1. Verification
# Prerequis confirmes par le teamleader avant cet ordre. Une publication validee sur l'environnement
# precedent de la chaine doit exister — sauf hotfix ou ordre portant `Cadrage : sans QUALIF`
# (agents/context/MILESTONE_CADRAGE.md section 5), ou ce candidat vient directement de BUILD.

# 1bis. Determination de la version cible
# X.Y.Z est fixe integralement par le milestone (regle complete : commands/context/COMMON.md
# section 5.7).  porte deja ce X.Y.Z depuis l'ouverture du cycle — aucun calcul,
# on retire uniquement le compteur de build "a" pour obtenir la version officielle.
DEV_VERSION=$(cat )       # ex: 1.4.0.3 — c'est l'artefact deja publie et valide
VERSION=$(echo "$DEV_VERSION" | cut -d. -f1-3)   # X.Y.Z, ex: 1.4.0
# Ecrire $VERSION dans  avant le merge

# 1ter. Verification documentation (avant merge)
# En orchestration teamleader : DOC FINALIZE fait par doc-updater, ou CHANGELOG tenu par les agents DEV
# (cadrage `doc: dev`) — verifier juste la reception du DONE. Standalone : verifier manuellement, sinon STOP.
# Recherche sur X.Y.Z (section de release du CHANGELOG), jamais sur X.Y.Z.a : `a` est incremente au BUILD,
# apres l'ecriture du CHANGELOG.
grep -q "$VERSION" CHANGELOG.md || {
  echo "CHANGELOG.md sans section $VERSION — STOP, retour doc-updater (ou agent DEV si cadrage doc: dev)."
  exit 1
}
# README/docs concernes : verifier manuellement qu'ils refletent les changements de ce release.

# 1quater. BARRIERE — pre-validation verte sur le SHA exact (un tag ne sert JAMAIS de test)
# Le workflow de pre-validation (`.github/workflows/ci-branch.yml`, infra.md §3bis C10, qui ne lance
# que `commands.ci`) doit etre vert sur le commit exact de la branche milestone qui va etre merge.
# Sinon : STOP — pas de merge dans main, pas de tag.
git push origin milestone/vX.Y.Z
SHA=$(git rev-parse milestone/vX.Y.Z)
gh run list --workflow ci-branch.yml --commit "$SHA" --json status,conclusion,databaseId \
  --jq '.[0]'    # attendu : status=completed, conclusion=success
# Aucun run sur ce SHA -> le declencher : gh workflow run ci-branch.yml --ref milestone/vX.Y.Z
#   puis `gh run watch <id> --exit-status`. Run rouge/absent -> PUBLISH FAILED (categorie CODE/FLAKY,
#   voir Echec) ; ne rien merger, ne rien taguer.

# 2. Promotion (sans supprimer la branche de travail) — la branche de travail est la branche
# milestone (milestone/vX.Y.Z), qui a accueilli tout le cycle FEATURE/BUGFIX/REFACTOR ;
# ce merge est le SEUL moment ou ce travail rejoint main.
#
# Securite : pousser d'abord l'etat local exact de la branche milestone — un commit local peut
# exister depuis la derniere publication (ex: fix mineur post-validation, suivi d'un nouveau
# /build) sans avoir encore ete pousse (voir context/COMMON.md section 7.1). Garantit que le
# rollback en cas d'echec (ci-dessous) dispose de l'etat exact merge, avant la suppression de la
# branche distante en cas de succes (voir `agents/deploy.md`, Tache DEPLOY PROD, Etape 6).
git push origin milestone/vX.Y.Z
# Merge dans un worktree detache sur origin/main — le HEAD du checkout principal reste sur la branche
# milestone (il appartient au teamleader, voir context/COMMON.md « Branche Courante et Historique »)
REL=.claude/worktrees/release
git fetch origin main
git worktree add --detach "$REL" origin/main
git -C "$REL" merge --no-ff milestone/vX.Y.Z -m "Release v$VERSION"
git -C "$REL" push origin HEAD:main

# 3. Tag officiel — LE declencheur du rebuild deterministe. Le pipeline CI (`.github/workflows/release.yml`) est
# configure sur `tags: ['v*']` : ce push de tag lance le job de build, qui reconstruit depuis ce
# commit fige et publie le resultat (registre / GitHub Release).
git -C "$REL" tag -a "v$VERSION" -m "Release v$VERSION"   # tag sur le commit de merge
git push origin "v$VERSION"
git worktree remove "$REL"

sleep 5
RUN_ID=$(gh run list --limit 1 --json databaseId --jq '.[0].databaseId')
gh run watch "$RUN_ID" --exit-status
CI_STATUS=$?
```

**CI_STATUS = 0 → continuer vers Notification.**

**CI_STATUS ≠ 0 → executer le protocole d'echec ci-dessous.**

## Echec

Le deployer ne corrige rien lui-même. Il identifie l'agent responsable et remonte au teamleader.

**Classifier :**

```bash
gh run view "$RUN_ID" --log-failed
```

| Catégorie | Indicateurs dans les logs | Build fiable ? | Agent responsable |
|-----------|--------------------------|------------------------|-------------------|
| **CODE** | Compilation échoue, tests régressent, lint | Non | `dev` |
| **FLAKY** | Timeout réseau, service tiers, race condition | Oui (retry) | `qa` |
| **CONFIG** | Secret manquant, variable absente, mauvais path | Oui | `infra` |
| **INFRA** | Registry inaccessible, runner hors ligne, quota | Oui | `infra` |

**Rapport au teamleader :**

```
SendMessage({
  to: "team-lead",
  content: "PUBLISH FAILED
Environnement : PROD
Version  : v[X.Y.Z]
Catégorie: [CODE|FLAKY|CONFIG|INFRA]
Run CI   : #[RUN_ID] — gh run view [RUN_ID] --log-failed"
})
```

**Politique de reprise** : apres un echec, le deployer **corrige sur la branche milestone** (via l'agent
responsable) et rejoue la pre-validation ; il ne **retague jamais** pour « retester » (le tag ne sert pas de
test). Un echec **FLAKY** se relance **une fois au plus** ; au deuxieme echec, analyse (traiter comme CODE).
L'ordre PROD de l'utilisateur n'autorise pas a retaguer sans limite (`CDP_WORKFLOWS.md` §7).

Le teamleader analyse le rapport et décide du routing et de la suite. En cas d'echec, le merge/tag sont
annules (voir Rollback ci-dessous) — aucun artefact partiellement publié ne doit rester
référençable.

```bash
# 4. Notification
echo "Publication PROD terminee - v$VERSION (tag pousse, CI OK)"
```

## Rollback

```bash
# Worktree detache sur origin/main (jamais de checkout dans le checkout principal)
git fetch origin main && git worktree add --detach .claude/worktrees/rollback origin/main
git -C .claude/worktrees/rollback revert HEAD --no-edit
git -C .claude/worktrees/rollback push origin HEAD:main
git worktree remove .claude/worktrees/rollback
git tag -d v[X.Y.Z]
git push origin --delete v[X.Y.Z]
# Correction : agent responsable (voir Echec ci-dessus), puis /publish prod a nouveau
```
