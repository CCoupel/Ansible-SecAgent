# Outillage Go des agents — confiné au scratchpad (#226)

Document commun, référencé par les compagnons `dev-*`, `security-reviewer` et par `CLAUDE.md` (donc aussi
`test-writer`, `qa`, `deployer`). Règle de fond (`CLAUDE.md`, « Environnement de l'utilisateur ») : **aucun agent
n'écrit hors du scratchpad** — rien dans `~/go`, `~/.cache`, `~/.local`, pas de `go env -w`, pas de `~/.bashrc`.
Le nettoyage des caches existants de l'utilisateur ne regarde pas les agents.

## Faits à connaître

- Le binaire est `/usr/local/go/bin/go`, **absent du PATH**. Il est en Go 1.24.2.
- `GO/go.work` exige `go 1.25.5` (`GO/go.mod` : `go 1.24.0`). Avec `GOTOOLCHAIN=local` et le Go 1.24.2 installé,
  toute commande échoue : `go: go.work requires go >= 1.25.5 (running go 1.24.2; GOTOOLCHAIN=local)`.
  **Ne pas** fixer `GOTOOLCHAIN=local` sans pointer `GOROOT`/`PATH` vers un Go 1.25.5 (voir le bloc ci-dessous).
  Laisser `GOTOOLCHAIN=auto` avec le Go 1.24.2 provoque le téléchargement de `golang.org/toolchain` dans le cache de
  modules : c'est la cause de l'écriture hors scratchpad constatée en v3.0.4.
- Le Go 1.25.5 existe déjà dans le cache de modules de l'utilisateur
  (`~/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.25.5.linux-amd64`) : on l'**utilise en lecture seule**, on ne
  le re-télécharge pas et on n'y écrit pas.
- Les modules du dépôt sont dans ce même cache (`~/go/pkg/mod/cache/download`) : exposé comme proxy fichier
  (`GOPROXY=file://…`), `go` copie dans le scratchpad uniquement les modules nécessaires (quelques Mio, 2,6 Mio mesurés par qa pour
  `go build ./...`) sans rien écrire côté utilisateur et **sans réseau**. `GOFLAGS=-mod=mod` est refusé en mode
  workspace (`go.work`) : ne pas l'ajouter.
- Si ce toolchain n'est plus dans le cache : le télécharger (`GOTOOLCHAIN=go1.25.5`) avec `GOMODCACHE` **dans le
  scratchpad**, jamais dans `~/go`.

## Bloc d'environnement (à copier tel quel avant toute commande `go`)

```bash
S=<scratchpad de l'agent>            # chemin absolu fourni par l'environnement
T=$HOME/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.25.5.linux-amd64   # lecture seule
mkdir -p "$S/go"/{path,mod,cache,bin,lint}
export GOROOT="$T" GOTOOLCHAIN=local
export PATH="$S/go/bin:$T/bin:$PATH"
export GOPATH="$S/go/path" GOMODCACHE="$S/go/mod" GOCACHE="$S/go/cache" GOBIN="$S/go/bin"
export GOLANGCI_LINT_CACHE="$S/go/lint"
export GOPROXY="file://$HOME/go/pkg/mod/cache/download" GOSUMDB=off GOFLAGS=-modcacherw
```

> **Avertissement** : `GOSUMDB=off` et le proxy fichier sont réservés à la compilation et aux tests. Cet
> environnement **interdit d'ajouter ou de mettre à jour une dépendance** (`go get`, `go mod tidy`) : sans base de
> sommes, une dépendance altérée ne serait pas détectée. Tout changement de `go.mod` ou `go.sum` est relu à la main
> en revue.

`GOFLAGS=-modcacherw` rend le cache du scratchpad supprimable sans `chmod`. `GOSUMDB=off` est sans risque ici :
`go.sum` reste vérifié, seule la base de sommes publique est désactivée (le proxy est local).

## Commandes

- Tests, depuis `GO/` : `JWT_SECRET_KEY=test ADMIN_TOKEN=test go test -race ./... -timeout 900s`.
  `-race` exige CGO (gcc présent : `/usr/bin/gcc`) ; la CI l'utilise (`.github/workflows/ci.yml`).
  Écart de timeout : 900 s est la valeur consignée dans la mémoire projet (`MEMORY.md`, « CI GitHub et outils »),
  prévue comme marge pour un poste d'agent (WSL sur NTFS, `-race`, CPU partagé) ; `scripts/ci.sh`, `GO/Makefile`
  et le job `build-test` de la CI utilisent 300 s. Un dépassement à 300 s sur un poste d'agent ne prouve donc pas
  un test bloqué : relancer avec 900 s avant de conclure. Les scripts ne sont pas modifiés.
- Tag de build `testhelpers` : les tests d'intégration compilent eux-mêmes un nœud avec
  `go test -c -tags testhelpers` (`internal/integration/jwt_renewal_spec_test.go:65`,
  `internal/server/agent_jwt_testhelpers.go`). Il abaisse les durées minimales de JWT : **jamais dans un binaire
  de release**. Pour compiler/vérifier à la main : `go build -tags testhelpers ./cmd/secagent-server/...`.
- Tests lents : tag `slow` (voir `.github/workflows/ci.yml`, job `slow-tests`).
- `gofmt -l .` depuis `GO/` doit être vide (la CI échoue sinon).
- Build : `go build ./...` et `CGO_ENABLED=0 go build ./...` (`scripts/ci.sh`).

## golangci-lint v2.14.0 (version de la CI, `.github/workflows/ci.yml`)

Ne **pas** faire `go install` (télécharge un toolchain et les modules du linter). Télécharger le binaire dans le
scratchpad et **vérifier sa somme SHA-256** :

```bash
V=2.14.0; B=https://github.com/golangci/golangci-lint/releases/download/v$V
mkdir -p "$S/dl" && cd "$S/dl"
curl -fsSL -O $B/golangci-lint-$V-linux-amd64.tar.gz -O $B/golangci-lint-$V-checksums.txt
# vérification sur la somme ÉPINGLÉE ici (pas sur le fichier téléchargé avec l'archive) ; attendu : OK
echo "ab90aeb7b066f92a33415b638a50fe5344bbb75a0d32ad30cc248d88f81032ab  golangci-lint-$V-linux-amd64.tar.gz" | sha256sum -c -
tar -xzf golangci-lint-$V-linux-amd64.tar.gz -C "$S/dl" --strip-components=1 golangci-lint-$V-linux-amd64/golangci-lint
mv "$S/dl/golangci-lint" "$S/go/bin/"
cd <racine>/GO && golangci-lint run --timeout=5m
```

La somme épinglée a été relevée dans le fichier de sommes publié avec la release (`curl -O …-checksums.txt` pour
la recontrôler lors d'une montée de version). Même principe pour tout autre outil Go
(`actionlint`…) : binaire vérifié par somme, ou `go install` avec `GOBIN`, `GOMODCACHE` et `GOCACHE` du bloc.

## Piège `/mnt/c` (NTFS)

Le dépôt est sur `/mnt/c` : `chmod 600` n'y est **pas honoré** (le plugin refuse alors le jeton). Pour les scripts de
qualif, travailler sur une copie `git archive` hors `/mnt/c` (dans le scratchpad).

## Vérification (qa)

Comparer tailles et dates de `~/go`, `~/.cache/go-build` et `~/.cache/golangci-lint` avant/après une session
build + tests + lint : elles ne doivent pas bouger (`du -sb` ; relevé initial 2026-11-02 : 3 988 255 140 /
1 196 241 222 / 549 067 octets).
