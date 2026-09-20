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
| `LATEST_COMMIT` ≠ `KNOWN_COMMIT` | **Avertir et demander confirmation** |

Si mise a jour disponible, afficher **avant de continuer** :

```
⚠️  Mise a jour du template disponible

   Template  : $TEMPLATE_REPO
   Sync local : $SYNCED_AT ($KNOWN_COMMIT)
   Disponible : $LATEST_COMMIT

   Il est recommande de synchroniser avant de demarrer la session.
   Lancez /init-project (option d) pour mettre a jour commandes et agents.

   Continuer quand meme ? [O/n]
```

- Si **non** → stopper ici, l'utilisateur lance `/init-project`
- Si **oui** → continuer avec les etapes suivantes

### Etape 2 — Purge et réinitialisation

```bash
rm -rf _work/
```

> Supprime les rapports et handoffs d'une session précédente éventuellement non clôturée.
> Sans risque : `_work/` est gitignored et jamais lu avant le démarrage d'un workflow.

### Etape 3 — Lecture de la memoire projet

Lire `.claude/memory/MEMORY.md` (source de verite unique).

Extraire :
- Version courante et environnements
- Travail en cours (branche, phase, issues actives)
- Regles critiques du projet
- Corrections de comportement a appliquer

### Etape 4 — Creation de la TEAM et spawn de tous les teammates

**Sans demander confirmation** :

1. **TeamCreate** avec le nom `ansible-secagent-team` (defini dans CLAUDE.md)

2. **Spawner les teammates permanents en parallèle** — lire la liste dans CLAUDE.md section "Agents Disponibles", colonne `Spawn = permanent` :

```
Pour chaque agent avec Spawn = permanent :
Task({
  name: "<nom-canonique>",
  prompt: "Lis .claude/agents/context/TEAMMATES_PROTOCOL.md puis .claude/agents/<nom>.template.md
           (et .claude/agents/<nom>.md s'il existe — adaptations projet).
           Tu fais partie de ansible-secagent-team sur Ansible-SecAgent.
           Mets-toi en IDLE après avoir envoyé ACTIF — le teamleader t'enverra ta tâche."
})
```

> Les agents `ponctuel` (ex: `security`, `infra`) sont spawned à la demande par leur commande dédiée — ne pas les inclure ici.

3. **Attendre les ACTIF de tous les teammates** avant de continuer.

> Après cette étape, le teamleader n'utilise plus que `SendMessage` — aucun nouveau spawn pendant la session.

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

- La MEMORY projet est la **seule source de verite** au demarrage
- La TEAM est **toujours creee** sans demander confirmation
- Le nom de la TEAM est **toujours** `ansible-secagent-team` (defini dans CLAUDE.md)
- Tous les teammates sont spawned au démarrage et passent en IDLE
- Pendant la session : **uniquement SendMessage** — aucun nouveau spawn
- Les teammates attendent un ordre explicite de `main` via SendMessage
