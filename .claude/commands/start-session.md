# Commande /start-session

Demarrage de session : lecture de la memoire projet et creation de la team de travail.

## Argument recu

$ARGUMENTS

## Instructions

### Etape 1 — Verification des mises a jour du template

**Premiere action, avant tout le reste.**

Si `TEMPLATE_claude/.template-source.json` existe :

```bash
TEMPLATE_REPO=$(cat TEMPLATE_claude/.template-source.json | jq -r '.repo')
TEMPLATE_BRANCH=$(cat TEMPLATE_claude/.template-source.json | jq -r '.branch')
KNOWN_COMMIT=$(cat TEMPLATE_claude/.template-source.json | jq -r '.commit // ""')
SYNCED_AT=$(cat TEMPLATE_claude/.template-source.json | jq -r '.synced_at // ""')

LATEST_COMMIT=$(gh api repos/$TEMPLATE_REPO/commits/$TEMPLATE_BRANCH --jq '.sha' 2>/dev/null || echo "")
```

| Resultat | Action |
|----------|--------|
| `LATEST_COMMIT` vide (pas de reseau / gh non auth) | Continuer silencieusement |
| `LATEST_COMMIT` = `KNOWN_COMMIT` | Template a jour — continuer |
| `LATEST_COMMIT` ≠ `KNOWN_COMMIT` | **Avertir et demander confirmation** (via `AskUserQuestion`) |

Si mise a jour disponible, afficher **avant de continuer** :

```
⚠️  Mise a jour du template disponible

   Template  : $TEMPLATE_REPO
   Sync local : $SYNCED_AT ($KNOWN_COMMIT)
   Disponible : $LATEST_COMMIT

   Il est recommande de synchroniser avant de demarrer la session.
   Lancez /init-project (option d) pour mettre a jour commandes et agents.

```

Puis poser la question via `AskUserQuestion` (jamais en texte) :
`"Mise a jour du template disponible — comment proceder ?"` — options : **Continuer quand meme** /
**Stopper et lancer /init-project** (Recommande).

- Si **stopper** → stopper ici, l'utilisateur lance `/init-project`
- Si **continuer** → continuer avec les etapes suivantes

### Etape 2 — Détection d'un workflow interrompu, puis purge

**Jamais de purge avant cette détection** : un terminal tué (crash, coupure, fermeture) laisse un workflow en cours
dont l'avancement vit dans `.claude/workflow-state.json`, `.claude/workflow/` et `_work/`.

```bash
STATE=.claude/workflow-state.json
# status absent (etat anterieur a ce champ) : termine si toutes les phases sont completed/skipped
DONE_Q='(.status // (if ([.phases[]?.status] | length > 0 and all(. == "completed" or . == "skipped"))
          then "completed" else "in_progress" end)) | IN("completed","abandoned")'
INTERRUPTED=""
if [ -f "$STATE" ] && ! jq -e "$DONE_Q" "$STATE" >/dev/null; then
  INTERRUPTED=1
fi
```

| Résultat | Action |
|----------|--------|
| `INTERRUPTED` vide | Purge complète : `rm -rf _work/` — continuer |
| `INTERRUPTED=1` | Afficher le résumé ci-dessous, puis demander via `AskUserQuestion` |

Résumé (lu depuis `$STATE`) :

```
⚠️  Workflow interrompu détecté
   Type / version : <type> — <version> (branche <branch>)
   Phase          : <phase en cours>   Cycle : <cycles>
   Lots           : <lots.current> en <phase du lot> — terminés : <liste> — restants : <liste>   (si lots)
   Plan validé    : <plan>   (absent → « plan perdu, re-planification nécessaire »)
   Dernière maj   : <updated_at>
```

Question : `"Workflow <type> <version> interrompu en phase <phase> — reprendre ?"` — options :
**Reprendre le workflow** (Recommandé) : purge sélective, reprise à l'étape 4bis /
**Abandonner et repartir de zéro** : `$STATE` passe à `status: "abandoned"`, purge complète. Les commits, la branche,
les labels GitHub et le plan copié dans `.claude/workflow/` sont conservés.

- **Reprendre** → purge sélective (seuls les fichiers temporaires et les ordres déjà consommés) :
  ```bash
  rm -rf _work/tmp/ _work/tasks/
  ```
  `_work/reports/`, `_work/handoff/`, `_work/tests-ledger.md` et `_work/mockup/` sont conservés. Mémoriser
  `RESUME=1` pour l'étape 4bis.
- **Abandonner** → `rm -rf _work/`.

> `_work/` est gitignored : la purge complète est sans risque une fois l'état du workflow écarté.

### Etape 3 — Lecture de la memoire projet

Lire `.claude/memory/MEMORY.md` (source de verite unique).

Extraire :
- Version courante et environnements
- Travail en cours (branche, phase, issues actives)
- Regles critiques du projet
- Corrections de comportement a appliquer

### Etape 3bis — Modele et effort du teamleader

Resoudre les valeurs attendues (`TEAMMATES_PROTOCOL.md` section 7) : frontmatter de `.claude/agents/teamleader.md`
s'il existe, sinon de `.claude/agents/teamleader.template.md`. Les comparer a `.claude/settings.json`
(`model`, `effortLevel`) et au modele de la session courante :

- `settings.json` differe des valeurs resolues → afficher une ligne « settings.json en retard — relancer
  `/init-project` (mises a jour) » et continuer ;
- la session ne tourne pas avec le modele/effort attendus (ou ne peut pas le verifier pour l'effort) → afficher une
  seule fois les commandes a taper : `/model <modele>` et `/effort <effort>`, puis continuer. Ne jamais tenter de
  changer soi-meme le modele.

### Etape 4 — Creation de la TEAM et spawn de tous les teammates

**Sans demander confirmation** :

1. **TeamCreate** avec le nom `ansible-secagent-team` (defini dans CLAUDE.md)

2. **Resoudre modele et effort de chaque teammate** (`TEAMMATES_PROTOCOL.md` section 7) : frontmatter du compagnon
   `.claude/agents/<nom>.md` (instance generique : `generic.<nom>.md` puis `generic.md`) s'il en a un, sinon
   frontmatter de `.claude/agents/<nom>.template.md`. Les passer **explicitement** au spawn — sans cela le teammate
   herite du modele et de l'effort de la session du teamleader.

3. **Spawner les teammates permanents en parallèle** — lire la liste dans CLAUDE.md section "Agents Disponibles", colonne `Spawn = permanent` :

```
Pour chaque agent avec Spawn = permanent :
Task({
  name: "<nom-canonique>",
  subagent_type: "<nom-canonique>",
  model: <modele resolu>,
  effort: <effort resolu>,
  prompt: "Lis .claude/agents/context/TEAMMATES_PROTOCOL.template.md puis .claude/agents/<nom>.template.md
           (et .claude/agents/<nom>.md s'il existe — adaptations projet).
           Tu fais partie de ansible-secagent-team sur Ansible-SecAgent.
           Mets-toi en IDLE après avoir envoyé ACTIF — le teamleader t'enverra ta tâche."
})
```

Pour une **instance générique** (fichier = `generic.template.md` + `generic.<nom>.md`) :

```
Task({
  name: "<nom>",
  subagent_type: "generic",
  model: <modele resolu>,
  effort: <effort resolu>,
  prompt: "Lis .claude/agents/context/TEAMMATES_PROTOCOL.template.md, puis .claude/agents/generic.template.md
           puis ta spécification .claude/agents/generic.<nom>.md (obligatoire).
           Tu es l'instance `<nom>` et fais partie de ansible-secagent-team sur Ansible-SecAgent.
           Mets-toi en IDLE après avoir envoyé ACTIF — le teamleader t'enverra ta tâche."
})
```

> Les agents `ponctuel` (ex: `security`, `infra`) sont spawned à la demande par leur commande dédiée — ne pas les inclure ici.

4. **Attendre les ACTIF de tous les teammates** avant de continuer.

> Après cette étape, le teamleader n'utilise plus que `SendMessage` — aucun nouveau spawn pendant la session.

### Etape 4bis — Reprise du workflow interrompu (si `RESUME=1`)

Les teammates viennent d'être respawnés : ils n'ont **aucun** souvenir du workflow. Le teamleader reconstitue l'état
avant tout ordre, puis reprend comme `/<type> resume <phase>` (`context/CDP_WORKFLOWS.md` §12 « Reprise après
interruption ») :

1. **Rapprocher les trois sources** — en cas de désaccord, git et GitHub priment sur le fichier d'état :
   - `$STATE` : phase, lot courant, SHA enregistrés, chemins de rapports/handoffs ;
   - git (ordre à `deployer`) : branche courante = `branch` de l'état, commits depuis le dernier SHA enregistré,
     `git status --short` (travail non commité des teammates tués) ;
   - GitHub (ordre à `deployer`) : labels des issues du milestone (`PRET` / `EN COURS` / `DONE`, lot de chaque issue).
2. **Travail non commité** (arbre sale) : présenter le diff résumé (fichiers + agent probable), puis
   `AskUserQuestion` : `"Modifications non commitées laissées par l'interruption — que faire ?"` — options :
   **Commiter en WIP** (Recommandé) : commit `wip(<scope>): reprise après interruption` par `deployer` /
   **Stasher** / **Jeter** (`git restore`/`git clean` par `deployer`, après confirmation).
3. **Plan absent** (`plan` nul ou fichier manquant — ex. workflow lancé avant ce mécanisme) : utiliser
   `phases.plan.report` s'il existe encore dans `_work/reports/` (et le copier dans `.claude/workflow/`) ; sinon
   reprise à la phase PLAN — le planner repart des issues, de leurs labels de lot et des commits existants, le lot
   courant et les lots terminés lui sont indiqués.
4. **Reprendre la phase interrompue depuis son début** : une phase `in_progress` est rejouée entièrement (le travail
   d'un teammate tué n'est fiable que s'il a été commité ; chaque ordre indique les commits déjà présents). Les phases
   et les lots `completed` ne sont jamais rejoués ; `_work/tests-ledger.md` évite de relancer un scope de tests déjà
   VALIDATED sur un arbre inchangé.
5. **Sous-agents orphelins** : aucun `sub-planner-*` / `sub-reviewer-*` / `sub-qa-*` ne survit au terminal ; les
   délégations en cours sont relancées avec la phase.

Afficher la ligne de reprise dans la confirmation (étape 6) : `**Reprise** : <type> <version> — <lot> en <phase>`.

### Etape 5 — Etat du backlog GitHub

Executer les deux requetes en parallele :

**Milestone actif :**
```bash
gh api repos/{owner}/{repo}/milestones \
  --jq '[.[] | select(.state=="open")] | sort_by(.due_on) | .[0] | {title, open_issues, closed_issues, due_on}'
```
Calculer : `progress = closed_issues / (open_issues + closed_issues) * 100`
Si aucun milestone actif → ne pas afficher le bloc milestone.

**Issues ouvertes :**
```bash
gh issue list --state open --limit 50 \
  --json number,title,labels,milestone,assignees,updatedAt \
  --jq 'sort_by(.milestone.title, .number) | .[] | [.number, .title, ([.labels[].name] | join(",")), (.milestone.title // "—"), ([.assignees[].login] | join(",") | if . == "" then "-" else . end), .updatedAt[:10]] | @tsv'
```

### Etape 6 — Confirmation a l'utilisateur



```markdown
## Session demarree — Ansible-SecAgent

**Team** : ansible-secagent-team
**Version** : [lue depuis MEMORY.md]
**Branche** : [lue depuis MEMORY.md]
**Travail en cours** : [lu depuis MEMORY.md]
**Reprise** : [type version — lot en phase, si workflow repris a l'etape 4bis ; ligne omise sinon]

---

**Milestone actif** : <version>  ████████░░  <X>%  (<closed>/<total> issues)
**Echeance** : <date ou "non definie">

### Backlog — Issues ouvertes

| # | Titre | Labels | Milestone | Assignee | Maj |
|---|-------|--------|-----------|----------|-----|
| 42 | ... | feature | v1.2.0 | - | 2026-01-10 |
| 38 | ... | bug | v1.2.0 | @user | 2026-01-08 |
| 35 | ... | refactor | — | - | 2026-01-05 |

_(Si aucune issue ouverte : "Aucune issue ouverte.")_

---

**Team** : tous les teammates sont en IDLE et prêts à recevoir des tâches

**Commandes disponibles** :
- `/feature <description>` — Nouvelle feature complete
- `/bugfix <description>` — Correction de bug
- `/backlog [description]` — Consulter ou traiter les GitHub Issues
- `/milestone status` — Progression du milestone actif
- `/review [scope] [mode]` — Revue de code
- `/secu [scope]` — Audit securite
- `/build`, `/publish qualif|prod`, `/deploy qualif|prod` — Deployer
- `/context-audit [scope]` — Audit doc projet (doublons, refs cassées, optimisation contexte agents)
- `/team-status` — État de la team et fermeture des agents inactifs
- `/end-session` — Cloturer la session
```

## Regles

- La MEMORY projet est la **seule source de verite** au demarrage — sauf pour un workflow interrompu, dont l'etat
  vient de `.claude/workflow-state.json` rapproche de git et GitHub (etape 4bis)
- **Jamais de purge de `_work/` sans avoir verifie l'absence de workflow interrompu** (etape 2)
- La TEAM est **toujours creee** sans demander confirmation
- Le nom de la TEAM est **toujours** `ansible-secagent-team` (defini dans CLAUDE.md)
- Tous les teammates sont spawned au démarrage et passent en IDLE
- Pendant la session : **uniquement SendMessage** — aucun nouveau spawn
- Les teammates attendent un ordre explicite du teamleader via SendMessage
