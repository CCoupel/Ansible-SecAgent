# secagent-minion — GO implementation

Daemon client Ansible-SecAgent en Go. Maintient une connexion WSS persistante vers le relay server
et exécute les tâches Ansible reçues.

## Project layout

```
GO/cmd/agent/
├── main.go                          # Entrypoint : config, enrollment, dispatch loop
└── internal/
    ├── enrollment/
    │   ├── enrollment.go            # POST /api/register + déchiffrement RSA + persist JWT
    │   └── keys.go                  # GenerateRSAKey, PublicKeyPEM, PrivateKeyPEM
    ├── ws/
    │   └── dispatcher.go            # Connexion WSS, ReconnectManager, dispatch messages
    ├── executor/
    │   └── executor.go              # Exec subprocess, timeout, stdin become, troncature 5MB
    ├── files/
    │   └── files.go                 # PutFile, FetchFile, path traversal validation
    ├── registry/
    │   └── registry.go              # Registre async JSON persisté (write-through, atomique)
    └── facts/
        ├── facts.go                 # Collect(), getHostname/OS/CPU/RAM/disk/network
        ├── disk_linux.go            # syscall.Statfs (Linux)
        ├── disk_windows.go          # GetDiskFreeSpaceExW (Windows)
        └── disk_other.go            # Stub pour autres OS
```

## Module Go

Les packages agent sont dans le même module `secagent-server` (défini dans `GO/go.mod`).
Les imports utilisent le préfixe `secagent-server/cmd/agent/internal/...`.

Pas de module séparé pour l'agent — justification : un seul `go.sum`, dépendances partagées
avec le serveur (gorilla/websocket, jwt), build unifié dans le même `Makefile`.

## Dépendances principales

| Package | Rôle |
|---|---|
| `github.com/gorilla/websocket` | Connexion WSS (déjà dans go.mod) |
| `crypto/rsa` (stdlib) | Déchiffrement JWT enrollment |
| `crypto/tls` (stdlib) | TLS strict (CERT_REQUIRED, MinVersion TLS 1.2) |
| `os/exec` (stdlib) | Spawn subprocesses par tâche |
| `encoding/json` (stdlib) | Sérialisation messages WS |
| `syscall` (stdlib) | kill(pid, 0) pour check PID vivant, Statfs Linux |

Pas de dépendance `gopsutil` dans cette version — stdlib uniquement pour les facts (décision
d'architecture : zéro dépendance externe non déjà présente dans go.mod pour les facts de base).

## Décisions architecturales

### Même module que le serveur (`secagent-server`)
- Un seul `go.mod` / `go.sum` évite la gestion de multi-modules.
- `gorilla/websocket` et `golang-jwt/jwt` sont partagés.
- Build cible différente : `go build ./cmd/server` vs `go build ./cmd/agent`.

### Package `internal/` par responsabilité
- `enrollment` : isolation du flow HTTP + RSA, testable indépendamment.
- `ws` : dispatcher pur, indépendant des handlers (interface `MessageHandler`).
- `executor` : isolation OS/exec, facile à mocker en tests.
- `files` : isolation path traversal, testable sans WS.
- `registry` : persistence JSON, testable sans subprocess.
- `facts` : collecte système, build tags par OS.

### Interface `ws.MessageHandler`
Le dispatcher WS est découplé des handlers via l'interface :
```go
type MessageHandler interface {
    HandleExec(ctx, ExecMsg, SendFunc) error
    HandlePutFile(ctx, PutFileMsg, SendFunc) error
    HandleFetchFile(ctx, FetchFileMsg, SendFunc) error
}
```
Permet de mocker les handlers en tests sans lancer de vrais subprocesses.

### Goroutine par tâche exec, sémaphore `MaxConcurrentTasks=10`
- Chaque message `exec` lance une goroutine.
- Un channel buffered (capacité 10) fait office de sémaphore.
- Le read loop WebSocket ne bloque jamais : si l'agent est plein → réponse immédiate `agent_busy`.

### Reconnexion backoff exponentiel
- `ReconnectManager` : délai initial 1s, max 60s, facteur 2.
- Code close `4001` (révocation) → pas de reconnexion → erreur fatale.
- Code `4002` (token expiré) → reconnexion avec nouvel enrollment (v2).

### Sécurité
- TLS : `MinVersion = TLS 1.2`, vérification certificat obligatoire, InsecureSkipVerify=false.
- Enrollment : déchiffrement RSA obligatoire — jamais de fallback token brut.
- JWT stocké avec `os.OpenFile(O_CREATE, 0600)` — création atomique 0600 (pas de TOCTOU).
- Path traversal : `filepath.Clean` + vérification préfixe `ALLOWED_WRITE/READ_PREFIXES`.
- become : stdin (become_pass) masqué dans tous les logs.
- stdout : troncature à 5 MB avant envoi.

### Facts : stdlib uniquement
Les facts système utilisent uniquement la stdlib Go :
- `os.Hostname()`, `runtime.GOOS`, `/proc/meminfo`, `net.Interfaces()`, `syscall.Statfs`.
- Pas de `gopsutil` dans cette version (réduction des dépendances, scope MVP).
- Build tags `//go:build linux|windows|!linux&&!windows` pour `diskTotalBytesOS`.

## Compilation et exécution

```bash
# Build depuis GO/
cd GO/
go build -o bin/secagent-minion ./cmd/agent

# Run (Linux)
RELAY_SERVER_URL=https://relay.example.com \
RELAY_WS_URL=wss://relay.example.com/ws/agent \
RELAY_PRIVATE_KEY=/etc/secagent-minion/id_rsa \
RELAY_JWT_PATH=/etc/secagent-minion/token.jwt \
./bin/secagent-minion
```

## Variables d'environnement

| Variable | Défaut | Description |
|---|---|---|
| `RELAY_SERVER_URL` | `https://localhost:7770` | URL HTTPS du relay server |
| `RELAY_WS_URL` | `wss://localhost:7772/ws/agent` | URL WSS WebSocket |
| `RELAY_AGENT_HOSTNAME` | `os.Hostname()` | Hostname de l'agent |
| `RELAY_PRIVATE_KEY` | `/etc/secagent-minion/id_rsa` | Chemin clef privée RSA |
| `RELAY_JWT_PATH` | `/etc/secagent-minion/token.jwt` | Chemin JWT persisté |
| `RELAY_CA_BUNDLE` | `` (store système) | CA bundle custom |
| `RELAY_ASYNC_DIR` | `/var/lib/secagent-minion/async` | Répertoire registre async |
