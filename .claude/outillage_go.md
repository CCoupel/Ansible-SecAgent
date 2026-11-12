# Outillage Go des agents — confiné au scratchpad (#226)

Document commun, référencé par les compagnons `dev-*`, `security-reviewer` et par `CLAUDE.md` (donc aussi
`test-writer`, `qa`, `deployer`). Règle de fond (`CLAUDE.md`, « Environnement de l'utilisateur ») : **aucun agent
n'écrit hors du scratchpad** — rien dans `~/go`, `~/.cache`, `~/.local`, pas de `go env -w`, pas de `~/.bashrc`.
Le nettoyage des caches existants de l'utilisateur ne regarde pas les agents.

## Faits à connaître

Poste de travail depuis 2026-11-09 : **Linux natif** (Ubuntu 26.04, conteneur ; plus de WSL ni de `/mnt/c`). Le
`$HOME` (`/home/cyril`, overlay du conteneur) est **recréé au démarrage du poste** : ne rien y considérer comme durable.

- Le Go du poste est **`~/.local/go`** (Go **1.27.4**, distribution officielle), **dans le PATH** via `~/.local/bin/go` ;
  il est installé par le bootstrap du conteneur (`.claude-launcher/env-template.yaml`, étape `setup`, puis relevé en 1.27.4 avec
  vérification SHA256 par l'étape de `.claude-launcher/env.yaml` tant que le template n'est pas resynchronisé), pas par un agent.
  C'est la version exigée par `GO/go.work` (`go 1.27.4`, alignée sur l'image de build `golang:1.27.4-alpine` épinglée par digest ;
  `GO/go.mod` : `go 1.24.0`, version minimale du langage). On l'**utilise en lecture seule** avec `GOTOOLCHAIN=local`.
  L'ancien `/usr/local/go` (1.24.2) et les toolchains de `~/go/pkg/mod/golang.org/` n'existent plus.
- Sans le bloc ci-dessous, `go` écrit dans `~/go` et `~/.cache/go-build` de l'utilisateur (règle de fond enfreinte) ;
  si un jour `~/.local/go` n'est plus en 1.27.4, `GOTOOLCHAIN=auto` téléchargerait le toolchain dans `~/go` : c'est
  la cause de l'écriture hors scratchpad constatée en v3.0.4. Le bloc le télécharge alors **dans le scratchpad**
  (`GOTOOLCHAIN=go1.27.4`, amorce = le `go` du PATH, base de sommes ACTIVE : toolchain vérifié par sum.golang.org).
- **Téléchargement d'office au démarrage du poste (constaté le 2026-11-12, palliatif dans `env.yaml`)** : le `setup` du
  conteneur joue, dans un seul script `bash -e`, les étapes du launcher, puis du template, puis du projet
  (Claude-Launcher NG2 : `backend.go:189`, `bootstrap.sh:110-118`). L'étape Go de `env-template.yaml` (`V=1.27.3`
  codé en dur) réinstalle la 1.27.3, puis `(cd GO && go mod download)` tourne avec elle : `GO/go.work` exigeant 1.27.4
  et `GOTOOLCHAIN` valant `auto`, Go **télécharge d'office la toolchain 1.27.4** dans `~/go/pkg/mod` (~250 Mo). Ensuite
  seulement, l'étape d'`env.yaml` relève `~/.local/go` en 1.27.4. Le launcher ne permet ni de remplacer une étape du
  template, ni de passer avant elle, ni de lui fournir une variable : la même étape d'`env.yaml` **supprime donc, en fin
  de setup, cette toolchain et elle seule** (`~/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.27.*`, rendue inscriptible
  puis retirée, et `cache/download/golang.org/toolchain/@v/v0.0.1-go1.27.*`). C'est idempotent, et rien d'autre n'est
  touché. Le téléchargement réseau (~75 Mo) a encore lieu à chaque démarrage. **Ce n'est pas une violation de la règle du
  scratchpad** : l'écriture est faite par le bootstrap du poste (étape du template), pas par un agent, et le palliatif ne
  fait que la défaire. `GOTOOLCHAIN=local` n'est **pas** posé : il ferait échouer ce `go mod download` (1.27.3) et donc
  tout le setup. Correction durable, hors de ce dépôt : clé `env:` ou étapes nommées dans le launcher, ou étape Go du
  template lisant la version dans `go.work` (`_work/reports/infra-gotoolchain-local-20261112.md` §5) ; le palliatif sera
  alors à retirer.
- **CGO / `-race`** : `go test -race` exige un compilateur C. Le 2026-11-09 le poste n'en avait pas (`gcc` absent,
  `go env CGO_ENABLED` = 0) ; `gcc` et les en-têtes libc (`libc6-dev` sous apt) sont désormais **déclarés dans
  `.claude-launcher/env.yaml`** (`packages`, `packages_by_manager`). **`-race` local disponible une fois le poste
  reconstruit avec ce bootstrap.** Vérifier avant de lancer : `command -v gcc && go env CGO_ENABLED` (→ `1`). Sans gcc,
  le rapport dit « `-race` non rejoué localement » (la CI le lance toujours), jamais « vert ». Aucun agent n'installe gcc.
- Le cache de modules de l'utilisateur (`~/go/pkg/mod/cache/download`) ne contient que quelques modules : il reste
  exposé en premier comme proxy fichier, `proxy.golang.org` sert le reste. `go` ne copie que les modules nécessaires
  dans le scratchpad et `go.sum` vérifie chaque module. `GOFLAGS=-mod=mod` est refusé en mode workspace (`go.work`) :
  ne pas l'ajouter.
- Autres outils du poste : `jq` 1.8.1, `gh` **2.46.0** (< 2.49 : `gh attestation verify` exige un `gh` récent
  téléchargé dans le scratchpad, voir `deploy.qualif.md`), `python3` 3.14 système **sans `yaml`** (`scripts/ci/check_actions_pinned.py`
  et `check_compose_selftest.py` l'importent : utiliser le venv du projet `.github/ci/.venv`, construit par le bootstrap, qui l'a), **ni client Docker ni `ssh`**.

## Bloc d'environnement (à copier tel quel avant toute commande `go`)

```bash
S=<scratchpad de l'agent>            # chemin absolu fourni par l'environnement
mkdir -p "$S/go"/{path,mod,cache,bin,lint}
T=$HOME/.local/go                    # Go 1.27.4 du poste, lecture seule
[ "$(head -1 "$T/VERSION" 2>/dev/null)" = go1.27.4 ] || T="$S/go/mod/golang.org/toolchain@v0.0.1-go1.27.4.linux-amd64"
# 1. seulement si le Go du poste n'est pas en 1.27.4 : Go 1.27.4 dans le scratchpad (verifie par la base de sommes)
[ -x "$T/bin/go" ] || env GOTOOLCHAIN=go1.27.4 GOPATH="$S/go/path" GOMODCACHE="$S/go/mod" GOCACHE="$S/go/cache" \
  GOFLAGS=-modcacherw GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org go version
# 2. environnement de travail
export GOROOT="$T" GOTOOLCHAIN=local
export PATH="$S/go/bin:$T/bin:$PATH"
export GOPATH="$S/go/path" GOMODCACHE="$S/go/mod" GOCACHE="$S/go/cache" GOBIN="$S/go/bin"
export GOLANGCI_LINT_CACHE="$S/go/lint"
export GOPROXY="file://$HOME/go/pkg/mod/cache/download,https://proxy.golang.org" GOSUMDB=sum.golang.org GOFLAGS=-modcacherw
```

Vérifié par infra le 2026-11-09 : `go version` → `go1.27.3 linux/amd64`, `go vet ./cmd/secagent-inventory/...` OK,
`~/go` inchangé (`du -sb`). Le 2026-11-11 (montée 1.27.4, GO-2026-6859) : repli de l'étape 1 rejoué (`go1.27.4` téléchargé
dans le scratchpad, `toolchain@v0.0.1-go1.27.4.linux-amd64`), `go build`/`go vet`/`govulncheck ./...` OK, `~/go` inchangé.

> **Avertissement** : cet environnement sert à compiler et tester. **Ajouter ou monter une dépendance** (`go get`,
> `go mod tidy`) reste réservé à un ordre explicite (infra ou dev), base de sommes active (jamais `GOSUMDB=off` pour
> cela), et tout changement de `go.mod` / `go.sum` est relu à la main en revue.

`GOFLAGS=-modcacherw` rend le cache du scratchpad supprimable sans `chmod`. La base de sommes n'est interrogée que pour un
module absent de `go.sum` ; pour les modules du dépôt, `go.sum` suffit (aucune requête).

## Commandes

- Tests, depuis `GO/` : `JWT_SECRET_KEY=test ADMIN_TOKEN=test go test -race ./... -timeout 900s` si `gcc` est présent
  (`CGO_ENABLED=1`), sinon sans `-race` en le signalant (voir « Faits à connaître ») ; la CI lance toujours `-race`.
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
fichiers, quels que soient leurs modes. Conséquences : les secrets PROD de `PRIVATE/PROD/` (référence depuis le
2026-11-09, décision utilisateur) sont exposés à ce risque résiduel, jetons volatils toujours dans `${TMPDIR:-/tmp}` (local au poste), et des E/S plus lentes que sur un disque
local (d'où la marge de 900 s).

## Vérification (qa)

Comparer tailles et dates de `~/go`, `~/.cache/go-build` et `~/.cache/golangci-lint` avant/après une session
build + tests + lint : elles ne doivent pas bouger (`du -sb` ; relevé 2026-11-09, poste Linux : `~/go` 4 340 780
octets, `~/.cache/go-build` et `~/.cache/golangci-lint` absents). `$HOME` étant recréé au démarrage du poste, refaire
le relevé initial en début de session plutôt que de comparer à ces valeurs.
