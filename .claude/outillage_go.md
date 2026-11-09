# Outillage Go des agents — confiné au scratchpad (#226)

Document commun, référencé par les compagnons `dev-*`, `security-reviewer` et par `CLAUDE.md` (donc aussi
`test-writer`, `qa`, `deployer`). Règle de fond (`CLAUDE.md`, « Environnement de l'utilisateur ») : **aucun agent
n'écrit hors du scratchpad** — rien dans `~/go`, `~/.cache`, `~/.local`, pas de `go env -w`, pas de `~/.bashrc`.
Le nettoyage des caches existants de l'utilisateur ne regarde pas les agents.

## Faits à connaître

Poste de travail depuis 2026-11-09 : **Linux natif** (Ubuntu 26.04, conteneur ; plus de WSL ni de `/mnt/c`). Le
`$HOME` (`/home/cyril`, overlay du conteneur) est **recréé au démarrage du poste** : ne rien y considérer comme durable.

- Le Go du poste est **`~/.local/go`** (Go **1.27.3**, distribution officielle), **dans le PATH** via `~/.local/bin/go`.
  C'est la version exigée par `GO/go.work` (`go 1.27.3`, alignée sur l'image de build `golang:1.27-alpine` ;
  `GO/go.mod` : `go 1.24.0`, version minimale du langage). On l'**utilise en lecture seule** avec `GOTOOLCHAIN=local`.
  L'ancien `/usr/local/go` (1.24.2) et les toolchains de `~/go/pkg/mod/golang.org/` n'existent plus.
- Sans le bloc ci-dessous, `go` écrit dans `~/go` et `~/.cache/go-build` de l'utilisateur (règle de fond enfreinte) ;
  si un jour `~/.local/go` n'est plus en 1.27.3, `GOTOOLCHAIN=auto` téléchargerait le toolchain dans `~/go` : c'est
  la cause de l'écriture hors scratchpad constatée en v3.0.4. Le bloc le télécharge alors **dans le scratchpad**
  (`GOTOOLCHAIN=go1.27.3`, amorce = le `go` du PATH, base de sommes ACTIVE : toolchain vérifié par sum.golang.org).
- **Pas de compilateur C sur le poste** (`gcc`/`cc` absents, `go env CGO_ENABLED` = 0) : **`go test -race` est
  impossible en local**. Le détecteur de course n'est rejoué que par la CI (`.github/workflows/ci.yml`) ; un rapport
  local le dit explicitement (« `-race` non rejoué localement »), jamais « vert ». Aucune installation de `gcc`.
- Le cache de modules de l'utilisateur (`~/go/pkg/mod/cache/download`) ne contient que quelques modules : il reste
  exposé en premier comme proxy fichier, `proxy.golang.org` sert le reste. `go` ne copie que les modules nécessaires
  dans le scratchpad et `go.sum` vérifie chaque module. `GOFLAGS=-mod=mod` est refusé en mode workspace (`go.work`) :
  ne pas l'ajouter.
- Autres outils du poste : `jq` 1.8.1, `gh` **2.46.0** (< 2.49 : `gh attestation verify` exige un `gh` récent
  téléchargé dans le scratchpad, voir `deploy.qualif.md`), `python3` 3.14 **sans `yaml`** (`scripts/ci/check_actions_pinned.py`
  et `check_compose_selftest.py` l'importent : venv du scratchpad avec `pip install pyyaml`), **ni client Docker ni `ssh`**.

## Bloc d'environnement (à copier tel quel avant toute commande `go`)

```bash
S=<scratchpad de l'agent>            # chemin absolu fourni par l'environnement
mkdir -p "$S/go"/{path,mod,cache,bin,lint}
T=$HOME/.local/go                    # Go 1.27.3 du poste, lecture seule
[ "$(head -1 "$T/VERSION" 2>/dev/null)" = go1.27.3 ] || T="$S/go/mod/golang.org/toolchain@v0.0.1-go1.27.3.linux-amd64"
# 1. seulement si le Go du poste n'est pas en 1.27.3 : Go 1.27.3 dans le scratchpad (verifie par la base de sommes)
[ -x "$T/bin/go" ] || env GOTOOLCHAIN=go1.27.3 GOPATH="$S/go/path" GOMODCACHE="$S/go/mod" GOCACHE="$S/go/cache" \
  GOFLAGS=-modcacherw GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org go version
# 2. environnement de travail
export GOROOT="$T" GOTOOLCHAIN=local
export PATH="$S/go/bin:$T/bin:$PATH"
export GOPATH="$S/go/path" GOMODCACHE="$S/go/mod" GOCACHE="$S/go/cache" GOBIN="$S/go/bin"
export GOLANGCI_LINT_CACHE="$S/go/lint"
export GOPROXY="file://$HOME/go/pkg/mod/cache/download,https://proxy.golang.org" GOSUMDB=sum.golang.org GOFLAGS=-modcacherw
```

Vérifié par infra le 2026-11-09 : `go version` → `go1.27.3 linux/amd64`, `go vet ./cmd/secagent-inventory/...` OK,
`~/go` inchangé (`du -sb`).

> **Avertissement** : cet environnement sert à compiler et tester. **Ajouter ou monter une dépendance** (`go get`,
> `go mod tidy`) reste réservé à un ordre explicite (infra ou dev), base de sommes active (jamais `GOSUMDB=off` pour
> cela), et tout changement de `go.mod` / `go.sum` est relu à la main en revue.

`GOFLAGS=-modcacherw` rend le cache du scratchpad supprimable sans `chmod`. La base de sommes n'est interrogée que pour un
module absent de `go.sum` ; pour les modules du dépôt, `go.sum` suffit (aucune requête).

## Commandes

- Tests, depuis `GO/` : `JWT_SECRET_KEY=test ADMIN_TOKEN=test go test ./... -timeout 900s` (sans `-race` en local :
  pas de CGO sur le poste, voir « Faits à connaître » ; la CI, elle, lance `-race`).
  Écart de timeout : 900 s est la valeur consignée dans la mémoire projet (`MEMORY.md`, « CI GitHub et outils »),
  prévue comme marge pour un poste d'agent (dépôt sur partage réseau MooseFS, CPU partagé) ; `scripts/ci.sh`,
  `GO/Makefile` et le job `build-test` de la CI utilisent 300 s. Un dépassement à 300 s sur un poste d'agent ne
  prouve donc pas un test bloqué : relancer avec 900 s avant de conclure. Les scripts ne sont pas modifiés.
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

## Système de fichiers du dépôt (MooseFS)

Le dépôt est sur `/share/MFS/...`, un **partage réseau MooseFS** (FUSE, maître 192.168.1.231, `allow_other`). Les
modes POSIX y sont conservés (`chmod 600`/`700` constatés le 2026-11-09) : le contournement `git archive` hors `/mnt/c`
n'est plus nécessaire pour les permissions. Mais c'est un partage : tout client MooseFS monté en root peut lire les
fichiers, quels que soient leurs modes. Conséquences : aucun secret PROD sous le dépôt (`PRIVATE/prod/` = public
seulement), jetons volatils toujours dans `${TMPDIR:-/tmp}` (local au poste), et des E/S plus lentes que sur un disque
local (d'où la marge de 900 s).

## Vérification (qa)

Comparer tailles et dates de `~/go`, `~/.cache/go-build` et `~/.cache/golangci-lint` avant/après une session
build + tests + lint : elles ne doivent pas bouger (`du -sb` ; relevé 2026-11-09, poste Linux : `~/go` 4 340 780
octets, `~/.cache/go-build` et `~/.cache/golangci-lint` absents). `$HOME` étant recréé au démarrage du poste, refaire
le relevé initial en début de session plutôt que de comparer à ces valeurs.
