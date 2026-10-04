# Commande /marketing

Mettre a jour le site marketing Github Pages apres une release. Le site est gere **uniquement sur la branche
`gh-pages`** — jamais commite sur la branche de code. `MARKETING/` est le **worktree git de `gh-pages`**
(pas un dossier de `main`, pas une publication de `main`).

## Usage

```
/marketing [version]
```

## Argument recu

$ARGUMENTS

## Mots-cles de controle

**Reference :** Voir `context/COMMON.md` section 12

| Mot-cle | Action |
|---------|--------|
| `help` | Affiche l'aide et les mots-cles disponibles |
| `status` | Affiche l'etat du workflow en cours |
| `plan` | Affiche le plan sans executer |
| `skip <section>` | Saute une section du site |

Si `$ARGUMENTS` commence par un mot-cle -> executer l'action correspondante.
Sinon -> workflow normal.

## Exemples

```
/marketing               # Met a jour le site avec la derniere release
/marketing v1.3.0        # Force la version a documenter
/marketing plan          # Affiche ce qui sera mis a jour sans modifier
```

## Role

Generer ou mettre a jour le site statique publie sur la branche `gh-pages`.
Le site est **bilingue (FR/EN)** avec un commutateur de langue.
La version affichee est recuperee dynamiquement depuis les **tags Git** du repo.

## Recuperation de la version

Si aucune version n'est passee en argument, recuperer le dernier tag semantique :

```bash
git tag --sort=-version:refname | head -1
```

Si le repo est GitHub, on peut aussi utiliser l'API :

```bash
gh api repos/CCoupel/Ansible-SecAgent/tags --jq '.[0].name'
```

La version recuperee est utilisee dans toutes les sections du site (Hero, Features, Roadmap).

## Prerequis

**Reference** : Voir `context/GITHUB.md` sections 1 (auth), 3 (milestones), 5 (releases/tags)

- [ ] Un tag Git existe sur le repo (`git tag --list`)
- [ ] `CHANGELOG.md` a jour
- [ ] `README.md` a jour avec le positionnement produit
- [ ] Issues GitHub ouvertes/fermees (pour la Roadmap)
- [ ] Milestone GitHub correspondant a la version (recommande)

## Workflow

```
/marketing [version]
    |
    v
[COLLECTE] --> Lire CHANGELOG, README, releases GitHub, issues GitHub, milestone GitHub
    |
    v
[DETECTION] --> Site existant sur gh-pages (worktree MARKETING/ cree si absent) ? Sinon : INITIALISATION (questions de cadrage
    |           a l'utilisateur + maquette avant toute generation — voir agents/marketing-release.md)
    v
[GENERATION] --> Generer ou mettre a jour les sections du site
    |
    v
[TRADUCTION] --> Produire les fichiers locales/fr.json et locales/en.json
    |
    v
[COMMIT gh-pages] --> Commiter et pousser depuis le worktree MARKETING/ (= directement sur gh-pages)
    |
    v
[RAPPORT] --> Confirmer les sections mises a jour
```

## Collecte du milestone

Dans la phase COLLECTE, recuperer les donnees du milestone correspondant a la version :

```bash
# Milestone cloture correspondant a la version — matching par PREFIXE, jamais par titre exact
# (le titre reel peut porter un nom descriptif apres un separateur non garanti — convention
# " — " via /milestone new, mais milestones plus anciens/manuels parfois en " - " ou autre,
# voir context/COMMON.md section 5.7)
TITLE=$(gh api repos/{owner}/{repo}/milestones \
  --jq '.[] | select(.title == "<version>" or ((.title | ltrimstr("<version>")) as $rest
        | $rest != .title and ($rest == "" or ($rest[0:1] | test("[0-9.]") | not)))) | .title')

# Issues fermees dans ce milestone (= ce qui a ete livre)
gh issue list --milestone "$TITLE" --state closed \
  --json number,title,labels \
  --jq '.[] | [.number, .title, (.labels | map(.name) | join(", "))] | @tsv'

# Issues ouvertes dans le prochain milestone (= roadmap "a venir")
NEXT_TITLE=$(gh api repos/{owner}/{repo}/milestones \
  --jq '[.[] | select(.state=="open")] | sort_by(.due_on) | .[0].title')
gh issue list --milestone "$NEXT_TITLE" --state open \
  --json number,title,labels
```

Si aucun milestone n'existe pour la version → fallback sur CHANGELOG.md et issues GitHub classiques.

## Emplacement du site — worktree `MARKETING/`

Le site vit uniquement sur `gh-pages`. Si `MARKETING/` est absent, le creer avant toute generation :
`git worktree add MARKETING gh-pages` (ou, si `gh-pages` n'existe pas encore, `git worktree add --orphan -b gh-pages MARKETING`).
`MARKETING/` est ignore par la branche de code (`.gitignore`). **Ne jamais commiter `MARKETING/` sur la
branche de code.** Release notes et posts restent sur la branche de code, dans `docs/releases/`.
Detail du cycle de vie : `agents/marketing-release.md`, "Emplacement du site".

## Structure du site genere

Racine de `gh-pages` (visible via `MARKETING/`) :

```
MARKETING/                  # = racine de gh-pages
├── CADRAGE.md              # Cadrage valide a l'initialisation (public, valeur, identite, sections, liens)
├── index.html              # Page principale (FR par defaut)
├── assets/
│   ├── style.css           # Styles communs
│   └── lang.js             # Gestion commutateur FR/EN
└── locales/
    ├── fr.json             # Textes FR
    └── en.json             # Textes EN
```

## Sections obligatoires

### Hero / Accroche (`id="hero"`)

- Nom du projet et baseline en FR et EN
- **Version courante recuperee dynamiquement** via `git tag --sort=-version:refname | head -1`
- Bouton "Voir les releases" pointant vers `https://github.com/CCoupel/Ansible-SecAgent/releases`
- Call-to-action principal (ex : "Installer", "Voir la doc")

### Problematiques (`id="problems"`)

Decrire les problemes concrets que le projet resout :
- Contexte et situation actuelle (avant le projet)
- Pain points identifies, illustres avec icones
- Public cible concerne

Source : extraire depuis `README.md` section probleme/contexte et `CLAUDE.md` si disponible.

### Solutions (`id="solutions"`)

Presenter les reponses apportees :
- Correspondance probleme → solution (format avant/apres)
- Benefices mesurables (gain de temps, fiabilite, securite...)
- Fonctionnalites cles de la version courante (depuis `CHANGELOG.md`)

### Fonctionnalites (`id="features"`)

Liste des fonctionnalites principales :
- Icone + titre + description courte pour chaque fonctionnalite
- Badge "Nouveau" sur les fonctionnalites de la derniere version
- Distinguer fonctionnalites stables et experimentales si applicable

### Installation (`id="install"`)

Couvrir les 3 scenarios :

**Depuis les sources**
```bash
git clone https://github.com/CCoupel/Ansible-SecAgent.git
cd Ansible-SecAgent
<commande d'installation specifique au projet>
<commande de demarrage>
```

**Depuis les releases binaires**

| Plateforme | Fichier | Commande |
|------------|---------|----------|
| Windows | `.exe` | Double-cliquer sur l'installeur |
| Linux (Debian) | `.deb` | `sudo dpkg -i {project}_X.Y.Z.deb` |
| macOS | `.dmg` | Ouvrir et suivre l'installeur |

**Configuration**
- Variables d'environnement ou fichier de config principal
- Ports par defaut
- Permissions systeme si applicable

### Roadmap (`id="roadmap"`)

Generer automatiquement en privilegiant les milestones GitHub (source la plus precise) :

**Source prioritaire — milestones** :
- **Milestone cloture** correspondant a la version → colonne "Livre" (issues fermees du milestone)
- **Milestone(s) ouvert(s)** → colonnes "En cours" et "A venir" selon les labels des issues

**Fallback sans milestone** :
- Issues fermees recentes → colonne "Livre"
- Issues ouvertes avec label `roadmap` ou `enhancement` → colonne "A venir"
- Issues ouvertes avec label `EN COURS` → colonne "En cours"

Format :
```
[ Livre ✓ ]                    [ En cours ⚙ ]           [ A venir ○ ]
- #42 Auth OAuth2 (v1.2.0)    - #51 Export PDF (#v1.3)  - #60 API v2 (#v2.0)
- #38 Fix crash iOS (v1.2.0)  - #47 Perf dashboard      - #61 Mode offline
```

Si aucune issue ni milestone disponible : afficher les elements du `CHANGELOG.md` comme historique.

## Commutateur de langue

Integrer dans le `<header>` un toggle visible sur toutes les sections :

```html
<div class="lang-switcher">
  <button class="lang-btn active" data-lang="fr">FR</button>
  <span>|</span>
  <button class="lang-btn" data-lang="en">EN</button>
</div>
```

Tous les textes du site portent l'attribut `data-i18n="cle"`.
Le fichier `lang.js` charge `locales/fr.json` ou `locales/en.json` et remplace
dynamiquement les valeurs au changement de langue. La preference est sauvegardee
en `localStorage`.

## Mise a jour du site existant

Si le site existe deja sur `gh-pages` (worktree `MARKETING/` ; lire d'abord `CADRAGE.md` : identite, public et sections deja
arbitres — ne pas les re-questionner) :
1. Mettre a jour la version dans le Hero
2. Ajouter les nouvelles fonctionnalites dans la section Features (badge "Nouveau")
3. Mettre a jour la section Solutions avec les apports de la version
4. Regenerer la Roadmap depuis les issues courantes
5. Verifier que les commandes d'installation sont toujours valides

## Rapport final

```
Site marketing mis a jour — vX.Y.Z

Sections mises a jour :
- [x] Hero (version dynamique : vX.Y.Z)
- [x] Problematiques
- [x] Solutions (N nouvelles fonctionnalites)
- [x] Fonctionnalites (N badges "Nouveau")
- [x] Installation
- [x] Roadmap (N issues ouvertes, N livrees)

Traductions :
- [x] locales/fr.json
- [x] locales/en.json

Commit pousse sur gh-pages (depuis le worktree MARKETING/).
URL : https://CCoupel.github.io/Ansible-SecAgent/

Voulez-vous :
a) Valider — le site est en ligne
b) Modifier une section specifique
c) Regenerer la roadmap uniquement
```

## Agent

Agent ponctuel — non spawné au `/start-session`, spawné à la demande. Orchestré par le CDP
en deux dispatches distincts (`PREPARE` puis `PUBLISH`), en parallèle du déploiement PROD —
voir `agents/cdp.template.md` Phase 6 et `agents/marketing-release.template.md` pour le détail du protocole :

```
Task({
  name: "marketing-release",
  prompt: "Lis .claude/agents/context/TEAMMATES_PROTOCOL.md puis .claude/agents/marketing-release.template.md (et .claude/agents/marketing-release.md s'il existe — adaptations projet). Tu fais partie de ansible-secagent-team sur Ansible-SecAgent. Mets-toi en IDLE après avoir envoyé ACTIF — le teamleader t'enverra ta tâche."
})
```

Attendre ACTIF, puis envoyer la tâche de préparation :
`SendMessage({to: "marketing-release", content: "PREPARE vX.Y.Z"})`

À réception de `MARKETING RIEN A PUBLIER` → `TaskStop("marketing-release")`, terminé.

À réception de `MARKETING PRET` → relayer le rapport à l'utilisateur (GATE 4d). Une fois la
maquette validée **et** le déploiement PROD confirmé réussi, envoyer la publication :
`SendMessage({to: "marketing-release", content: "PUBLISH"})`

À réception du `MARKETING TERMINE`, fermer l'agent :
`TaskStop("marketing-release")`

Spec : `.claude/agents/marketing-release.template.md` (+ `.claude/agents/marketing-release.md` si présent)
