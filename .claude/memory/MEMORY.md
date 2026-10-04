# MEMORY — Ansible-SecAgent

> Source de vérité au démarrage de session (lue par `/start-session`). Mise à jour par `/end-session`.

## Version et environnements
- **Dernière release** : `v2.0.0` (tag sur `259fd13`, 2026-10-02), Phase 12 Proxy/Gateway multi-zone. Images GHCR `ghcr.io/ccoupel/secagent-server` et `secagent-minion` publiées.
- **`main` (au 2026-10-04)** : milestone v3.0 « Fondations » **terminé, non taggé** (10 issues fermées). HEAD `c14cea5`, aligné sur `origin/main`, CI verte (run 37192729367). CHANGELOG : section `[Unreleased]` ajoutée.
- **Qualif** : 192.168.1.218 (Docker Compose). **La topologie multi-zone v2 n'est plus fonctionnelle** depuis la suppression de `PROXY_RELAYS` (#123) : 5 checks du smoke échouent jusqu'à v3.1 (#124, #125, #140). Aucun déploiement v2.0 en production, donc pas de migration.
- **Prod Kubernetes** : hors périmètre (Helm chart = #136, milestone v3.4).
- **Template Claude** : v3.9.1 (`dc3d230f`).

## CI GitHub
- `.github/workflows/ci.yml` : job `Build + tests Go` (bloquant) et job `Lint Go` **bloquant** (`gofmt -l .` + golangci-lint v2.14.0, action v7, config `GO/.golangci.yml` au format v2, plafonds à 0, **sans exclusion sur les `_test.go`**, module entier). 0 issue mesurée. `release.yml` : tag `vX.Y.Z` ou `workflow_dispatch` (images GHCR + release).
- Pas de golangci-lint local : télécharger le binaire v2.14.0 depuis la release GitHub (qa l'a fait dans son scratchpad). `go` est dans `/usr/local/go/bin` (pas dans le PATH).
- Manque : tests Python (`SECAGENT-PYTHON/tests/` vide), `-race` en CI (courses connues #145).

## Modèle v3 (spec validée, issue #122 fermée)
- Topologie en **arbre** : un relay = un seul parent ; plusieurs sous-relays ; un agent = un seul relay ; un seul chemin par hôte, pas de redondance.
- Lien ouvert par l'enfant (`REPEATER_UPSTREAM_URL` / `REPEATER_UPSTREAM_TOKEN` / `REPEATER_ID`, env simples) **ou** par le parent (enfant enregistré via API admin, `relay_nodes.mode=push`). `mode=pull` : le relay ouvre vers ce serveur.
- Handshake : `relay_hello` (celui qui ouvre, `relay_id == jwt.sub`, `ancestors`) → `relay_ack` → `topology_snapshot` (toujours envoyé par l'enfant) → connexion établie ; puis `event_forward` (`host.*`, `relay.*`).
- Refus de boucle : un lien « C enfant de P » est refusé ssi `C ∈ {P} ∪ ancêtres(P)`.
- Deux rôles JWT : `relay-child` (créé sur le parent, signé par le secret du parent) et `relay-parent` (créé sur l'enfant, signé par le secret de l'enfant) ; `sub` = identifiant du porteur. JWT_SECRET_KEY, RELAY_PLUGIN_TOKEN et NATS propres à chaque relay, jamais partagés.
- Inventaire d'un relay = **toute sa descendance** ; groupe Ansible = nom exact du relay, sans préfixe, sans contrôle de collision avec les hostnames ; group vars via `RELAY_GROUP_VARS` (env).
- Routage : clé `hostname` seule ; en cas de déclaration par deux relays, le dernier arrivé gagne + event `host.conflict`.
- Signature des tokens par la racine : reportée (#141, milestone v3.3).

## Milestones GitHub (au 2026-10-04)
- v3.0 Fondations : 0 ouverte / 10 fermées.
- **v3.1 Chaîne de relais** : #124 (config enfant), #125 (repeater-client, l'enfant ouvre), #140 (le parent ouvre / dial-out), #127 (routage), #129 (tests), #138 (doc), #145 (courses sous `-race`, sleeps fixes, `handlers` non rejouable en `-count>1`) : 7 ouvertes.
- v3.2 Events et inventaire : #126, #128, #130, #137, #139 (5 ouvertes). v3.3 Confiance et signature des liens : #141. v3.4 Packaging K8s : #136.
- **Aucun développement de v3.1 lancé.** Ordre prévu : #124 → #125 → #140 → #127.

## À trancher / suivis
- Lancer v3.1 (dev-relay sur #124 avec la spec #122) ; décider du sort de #145.
- Suivis mineurs de qa sur #144 : 3 mutations survivantes (dont un test d'échec d'écriture pour `FileExecutor`), `os.Pipe()` ignoré dans les tests de l'inventory, 5 `//nolint:gosec` morts préexistants.
- Labels hérités inutilisés : `phase:1` à `phase:12`, `owner:dev-plugins` (l'agent s'appelle `dev-connexion`).
- Qualif : nettoyer `/tmp/qualif-v200`, décider du sort de `DEPLOYMENT/qualif/docker-compose.override.yml` (contournement `store.go`, devrait être inutile depuis #131).
- Tag `v3.0.0` : à décider (la v3.0 « Fondations » ne contient pas encore le repeater).

## Règles / pièges
- **Questions à l'utilisateur** : toujours via l'outil AskUserQuestion (règle des templates), jamais en texte libre.
- **Labels** : le CDP maintient les labels de phase du template (`EN COURS` → `EN QA` → `DONE`, puis `status:completed` à la fermeture en retirant `status:todo`) ; le planner pose `status:todo`, `owner:*`, `type:*`. Pas de label `status:in-progress`.
- **Trailer de commit** : exactement `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>`. Les agents mettent souvent `Sonnet 4.6` : le contrôler à CHAQUE commit (`git show -s --format=%B HEAD | tail -2`). Correction locale possible par `git filter-branch --msg-filter` sur `origin/main..HEAD` seulement si l'arbre est propre et non poussé.
- **Vérifier, ne pas croire** : les agents annoncent parfois des résultats faux (gofmt « 0 fichier » par erreur de syntaxe, rapport cité avec un mauvais chemin, DONE sans rapport, tests absents). Vérifier par `git`, `gh` et lecture des rapports ; qa recompte et refait des mutations.
- Pas de push sans feu vert explicite de l'utilisateur ; le CDP délègue les commits (dev-*, deploy-qualif, doc-updater) avec liste de fichiers explicite (`git add` fichier par fichier, plusieurs agents partagent le même arbre).
- Le CRLF/LF fait apparaître des fichiers « modifiés » sans diff réelle : `git diff --ignore-space-at-eol`.
- `become_pass` ne doit jamais apparaître dans les logs (test `TestRunBecomePassNotInLogs` côté agent, `TestLogExecSafe_*` côté serveur) ; pas de `panic` en production.
- Le plugin Python est dans `SECAGENT-PYTHON/` (pas `PYTHON/`).
- `doc-updater` et `infra` ne sont pas dans les 10 agents permanents (spawn manuel) ; `/team-delete` arrête tous les teammates en fin de session.
