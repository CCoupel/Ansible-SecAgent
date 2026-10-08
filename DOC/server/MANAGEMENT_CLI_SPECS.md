# Spécifications — Management CLI (Phase 6)

> **Document de conception historique (Phase 6, CLI Python `relay`).** La CLI réelle est `secagent-server` (GO, cobra,
> `GO/cmd/secagent-server/internal/cli`) ; les exemples `relay …` ci-dessous sont des maquettes de conception.
> Commandes réelles (v3.0.3) : `minions` (list, get, set-state, suspend, resume, revoke, authorize, vars get/set/delete),
> `tokens` (create, list, revoke, delete, purge), `relays` (list, add, remove, status), `security` (keys status/rotate,
> tokens list, blacklist list/purge), `hooks` (status, log), `inventory list`, `server` (status, stats), `status --local`,
> `state` (init, verify, restore, link-trust reset, rekey). Il n'existe **pas** de `minions refresh`, de login/refresh de jeton ni de composant NATS :
> l'authentification se fait par jeton admin (`ADMIN_TOKEN`), sans renouvellement automatique côté CLI.
> Voir `DOC/server/SERVER_SPEC.md`.

## Vue d'ensemble

CLI de management pour administrer les minions (agents) et l'inventaire Ansible dans Ansible-SecAgent.

**Utilisateurs cibles** :
- Administrateurs système (gestion minions, revoke, delete)
- Utilisateurs Ansible (édition inventaire, gestion hosts)
- DevOps / infrastructure engineers

**Distribution** :
- PyPI package : `pip install ansiblerelay-cli`
- Bin : `/usr/local/bin/relay` (symlink ou entry point)
- Bash completion : `relay --help`, `_relay` completion script
- Man pages : `man relay`, `man relay-minion`, `man secagent-inventory`

**Authentification** :
- File local : `~/.config/ansiblerelay/credentials.json` (chmod 600)
- Format : `{ "server": "https://relay.example.com", "token": "<JWT>", "expires_at": "2026-03-15T...Z" }`
- Pas de renouvellement automatique de jeton (le refresh de jeton est supprimé en v3.0.3 : jeton à re-émettre)

---

## Commands principale

### 1. Auth Management

```bash
# Login
relay auth login
  # Prompt: Server URL, username, password
  # Output: ✅ Logged in as admin@example.com (token expires in 1h)
  # Stores: ~/.config/ansiblerelay/credentials.json

# Logout
relay auth logout
  # Output: ✅ Logged out

# Status
relay auth status
  # Output:
  # Server: https://relay.example.com
  # User: admin@example.com
  # Token expires: in 55 minutes
  # Last login: 2026-03-05 10:00:00

# Context / Server switching
relay auth context list
relay auth context add prod https://relay-prod.example.com
relay auth context switch prod
relay auth context remove staging
```

### 2. Minions Management

```bash
# List minions
relay minions list [OPTIONS]
  # Options:
  #   --status connected|disconnected|expired
  #   --last-seen <N> days ago
  #   --output text|json|yaml|table
  #   --sort hostname|status|last-seen
  #   --watch (live refresh, like `watch`)

  # Output (default):
  # HOSTNAME       STATUS       LAST SEEN       FACTS
  # qualif-01      ✅ connected  30s ago         Ubuntu 22.04, 4 CPU, 8GB
  # qualif-02      ✅ connected  2m ago          Ubuntu 22.04, 4 CPU, 8GB
  # qualif-03      ⏹️  disconn    5m ago          Ubuntu 22.04, 4 CPU, 8GB
  #
  # CONNECTED: 2/3, DISCONNECTED: 1/3

# Show minion details
relay minions detail <hostname> [OPTIONS]
  # Options:
  #   --output text|json|yaml
  #   --show-logs (derniers 20 événements)
  #   --show-facts

  # Output (default):
  # Minion: qualif-01
  # Status: CONNECTED
  # Last seen: 30s ago
  # Enrolled: 2026-03-01 10:15:00
  #
  # Facts:
  #   OS: Ubuntu 22.04 (Jammy)
  #   Kernel: Linux 5.15.0-56-generic
  #   CPU: 4 vCPUs
  #   Memory: 8 GB
  #   Uptime: 45 days 3 hours
  #
  # Token:
  #   JTI: 3d7a...9f2c
  #   Status: active
  #   Issued: 2026-03-05 10:00:00
  #   Expires: 2026-03-05 11:00:00
  #
  # Recent Activity:
  #   [20:15] exec: hostname → rc=0
  #   [20:10] put_file: /tmp/test.txt → rc=0
  #   [20:05] fetch_file: /tmp/test.txt → rc=0

# Revoke minion token (force re-enrollment)
relay minions revoke <hostname> [OPTIONS]
  # Options:
  #   --force (skip confirmation)

  # Output:
  # ⚠️  Revoking token for qualif-01
  # This will force the minion to re-enroll on next connection.
  # Continue? [y/N]: y
  # ✅ Token revoked for qualif-01
  # ⚠️  Minion will be disconnected immediately

# Delete minion (unregister completely)
relay minions delete <hostname> [OPTIONS]
  # Options:
  #   --force (skip confirmation)

  # Output:
  # ⚠️  DELETING minion: qualif-01
  # This action is PERMANENT and cannot be undone.
  # The minion will NOT be able to reconnect.
  # Continue? [y/N]: y
  # ✅ Minion qualif-01 deleted from database
  # 📝 Audit log entry created

# Authorize minion (pre-register public key)
relay minions authorize <hostname> [OPTIONS]
  # Options:
  #   --public-key-file <path>
  #   --public-key <PEM string>
  #   --approved-by <email>
  #   --output json

  # Output:
  # ✅ Public key authorized for qualif-04
  # Hostname can now enroll using POST /api/register

# (la commande `relay minions refresh` n'existe pas : retirée)

# Forget minion (remove from cache, not DB)
relay minions forget <hostname>
  # Output:
  # ✅ Minion qualif-01 removed from local cache
```

### 3. Inventory Management

```bash
# View inventory (current state)
relay inventory view [OPTIONS]
  # Options:
  #   --output yaml|json|ini
  #   --hosts-only
  #   --vars-only

  # Output (default YAML):
  # all:
  #   hosts:
  #     qualif-01:
  #       ansible_connection: relay
  #       ansible_secagent_server: http://192.168.1.218:7771
  #     qualif-02:
  #       ansible_connection: relay
  #       ansible_secagent_server: http://192.168.1.218:7771
  #   vars:
  #     ansible_secagent_token_file: /etc/ansible/secagent_plugin.jwt

# Edit inventory (opens $EDITOR)
relay inventory edit [OPTIONS]
  # Options:
  #   --validate-only (no save)
  #   --no-backup

  # Flow:
  # 1. $EDITOR opens on current inventory
  # 2. User edits YAML
  # 3. On save: validate, show diff, ask confirm
  # 4. Save to DB, keep backup, log audit

# Validate inventory YAML (without saving)
relay inventory validate <file>
  # Output:
  # ✅ Valid YAML syntax
  # ✅ All hosts are registered minions
  # ✅ All variables recognized
  # ⚠️  3 hosts unreachable (disconnected)

# Show inventory diff vs last saved version
relay inventory diff [OPTIONS]
  # Options:
  #   --version <N> (vs older backup)

  # Output (color diff):
  # --- inventory (saved version)
  # +++ inventory (working version)
  # @@ -5,3 +5,5 @@
  #  qualif-02:
  #    ansible_connection: relay
  # -qualif-03:
  # +qualif-04:
  #    ansible_connection: relay
  # +  ansible_secagent_timeout: 45

# Show inventory history (backups)
relay inventory history [OPTIONS]
  # Options:
  #   --limit <N> (default: 10)
  #   --output json

  # Output:
  # VERSION  TIMESTAMP           EDITED BY    DESCRIPTION
  # 1 (cur)  2026-03-05 10:00:00 admin        Added qualif-04
  # 2        2026-03-04 15:30:00 devops       Modified ansible_secagent_timeout
  # 3        2026-03-04 10:15:00 admin        Initial setup

# Rollback inventory to previous version
relay inventory rollback <version|timestamp> [OPTIONS]
  # Options:
  #   --force (skip confirm)
  #   --keep-backup

  # Output:
  # ⚠️  Rolling back to version 3 (2026-03-04 10:15:00)
  # Continue? [y/N]: y
  # ✅ Inventory rolled back
  # 📝 Previous version backed up as v1-2026-03-05-100000.yml

# Add host to inventory
relay inventory add <hostname> [OPTIONS]
  # Options:
  #   --ansible-var <key=value> (repeatable)
  #   --group <group>

  # Output:
  # ✅ Host qualif-05 added to inventory
  # Next: relay inventory edit

# Remove host from inventory
relay inventory remove <hostname> [OPTIONS]
  # Options:
  #   --force

  # Output:
  # ⚠️  Removing host qualif-05
  # Continue? [y/N]: y
  # ✅ Host qualif-05 removed

# Export inventory (for backup/external use)
relay inventory export <output-file> [OPTIONS]
  # Options:
  #   --format yaml|json|ini

  # Output:
  # ✅ Inventory exported to inventory-2026-03-05.yml (1.2 KB)
```

### 4. Logs & Audit

```bash
# Show audit trail (all management actions)
relay audit log [OPTIONS]
  # Options:
  #   --limit <N> (default: 50)
  #   --user <username>
  #   --action revoke|delete|edit-inventory|authorize
  #   --since <date>
  #   --output json|table

  # Output:
  # TIMESTAMP            USER  ACTION           RESOURCE      DETAILS
  # 2026-03-05 10:15:00  admin revoke           qualif-01      Token JTI 3d7a...
  # 2026-03-05 10:10:00  admin edit-inventory  all.hosts      Added qualif-04
  # 2026-03-04 15:30:00  devops edit-inventory all.vars       Updated timeout
  # 2026-03-04 14:00:00  admin delete          qualif-03      Permanent delete

# Show minion activity log
relay minions log <hostname> [OPTIONS]
  # Options:
  #   --limit <N> (default: 20)
  #   --output json

  # Output:
  # TIMESTAMP      TASK_TYPE    COMMAND/FILE         RC  STDOUT (truncated)
  # 20:15:00       exec         hostname             0   qualif-01
  # 20:10:00       put_file     /tmp/test.txt        0   written 256 bytes
  # 20:05:00       fetch_file   /tmp/test.txt        0   read 256 bytes
```

### 5. Configuration & Info

```bash
# Show configuration
relay config show
  # Output:
  # Configuration file: ~/.config/ansiblerelay/config.yaml
  # Server: https://relay.example.com
  # User: admin@example.com
  # Timeout: 30 seconds
  # Output format: table
  # Verify TLS: true

# Set configuration option
relay config set <key> <value>
  # relay config set output json
  # relay config set timeout 45
  # relay config set verify-tls false

# Show version & info
relay version
  # Output:
  # ansiblerelay-cli version 1.0.0
  # compatible with secagent-server >= 1.0.0
  # Python 3.11.0
  # Built: 2026-03-05

# Show health (server status)
relay health
  # Output:
  # Server: https://relay.example.com
  # Status: ✅ healthy
  # Database: ✅ ok
  # Last sync: 2s ago
```

---

### 6. Commandes réelles v3.0.4 : `keys` et `state link-trust reset`

> Les exemples ci-dessus sont des maquettes historiques ; cette section décrit la CLI réelle `secagent-server` (sources : `cli/keys.go`, `cli/state_tools.go`, `handlers/admin_link.go`, `state/linktrust_reset.go`). Détail du modèle : `DOC/security/SECURITY.md` §7, `DOC/server/STATE_SPEC.md`.

#### `secagent-server keys …` — clé de signature des liens (racine, via l'API admin)

Toutes les sous-commandes passent par l'API admin (`ADMIN_TOKEN`, `RELAY_API_URL`) et répondent `409 not_root` sur un relay qui a un parent ou une ancre épinglée, `503 master_key_required` sans `RSA_MASTER_KEY` (`cli/keys.go:15-17`, `handlers/admin_link.go:36-52`). La clé privée n'est jamais affichée ni exportée.

| Commande | Effet | Route | Erreurs notables |
|---|---|---|---|
| `keys link-pubkey` | écrit sur stdout la clé **publique** PEM (`PUBLIC KEY`) à épingler sur les enfants (`REPEATER_ROOT_LINK_KEY_FILE`) ; `root_id=… kid=…` sur stderr ; génère la clé si elle n'existe pas encore | `GET /api/admin/link/pubkey` | `cli/keys.go:40-58` |
| `keys rotate-link` | la clé courante devient `previous`, nouvelle courante, `link_keys` poussé aux enfants ; affiche `current`, `previous`, `seq` | `POST /api/admin/link/keys/rotate` | `409 previous_key_not_retired` si une rotation est déjà ouverte (`handlers/admin_link.go:43-44`) |
| `keys retire-link-previous [--force]` | ferme la fenêtre de double acceptation ; les jetons signés par l'ancienne clé sont ensuite refusés | `POST /api/admin/link/keys/retire-previous` `{"force":bool}` | `409 rotation_unconfirmed` + liste `unconfirmed` tant que des relays n'ont pas confirmé (`handlers/admin_link.go:221-225`) ; `409 no_previous_key` (`:45-46`) ; `--force` passe outre, `[SECURITY WARNING]` côté serveur, la CLI affiche les relays non confirmés |
| `keys link-status` | `root_id`, `seq`, `kid` courant/précédent, puis tableau `RELAY / LINK_SEQ / KID / CONFIRMED` | `GET /api/admin/link/status` | `cli/keys.go:101-120` |

Codes de sortie de ces commandes (`cli/client.go:188-209`, `cli/keys.go:25-32`) : `0` succès ; `1` toute erreur HTTP (dont 409 et 503, message `Error: <code> (HTTP <n>)` sur stderr) ou `401/403` (`unauthorized — check ADMIN_TOKEN`) ; `2` sur `404`. Il n'y a pas de code de sortie dédié à `rotation_unconfirmed`.

#### `secagent-server state link-trust reset [--state-dir D] [--yes] [--i-know-no-instance-is-running]`

Commande **hors ligne** (elle ouvre `STATE_DIR` directement, pas l'API) qui efface **uniquement** l'ancre de confiance persistée (`link_trust`) d'un relay **non racine** arrêté, pour le ré-épingler après une rotation manquée ou une re-racine. Exige `RSA_MASTER_KEY` (ou `_FILE`). Spécification complète, garde de verrou et sauvegarde : `STATE_SPEC.md` § `state link-trust reset`.

| Option | Rôle |
|---|---|
| `--state-dir` | répertoire d'état (défaut `$STATE_DIR`, sinon `/data`) |
| `--yes` | confirme sans invite ; **obligatoire** hors terminal interactif |
| `--i-know-no-instance-is-running` | passe outre un `relay.lock` orphelin (stockage figé) ; `[SECURITY WARNING]` |

Sans `--yes` en terminal, la commande demande de taper `reset`. Avant toute écriture : copie de `relay.state` dans `relay.state.linktrust-reset.<UTC>.bak` (0600) ; si elle échoue, rien n'est modifié. Une ligne est ajoutée à `state-restore.log` (`source: link-trust-reset`).

| Code | Signification | Preuve |
|---|---|---|
| 0 | ancre effacée, ou rien à effacer (aucune écriture) | `cli/state_tools.go:341-345` |
| 2 | HMAC invalide / clé maître incorrecte / `sha256` falsifié | `:25,53,55` |
| 3 | `schema_version` inconnue | `:26,51` |
| 4 | invariant violé | `:27,59` |
| 5 | fichier illisible, absent ou pas un état | `:28,61` |
| 6 | `RSA_MASTER_KEY` absente | `:29,331` |
| 8 | `relay.lock` frais : une instance est active (aussi si un nœud démarre pendant la commande : abandon, état intact, sauvegarde conservée) | `:31,213,375` |
| 9 | refusé, rien n'est modifié : nœud **racine** (clé de signature de lien présente), état issu de `relay.state.prev`, confirmation absente en mode non interactif (`--yes` manquant) ou réponse différente de `reset` | `:276-278,359,365,389-394` |

#### `secagent-server state rekey [--state-dir D] [--yes] [--i-know-no-instance-is-running]`

Commande **hors ligne** (ouvre `STATE_DIR` directement) qui fait la rotation de `RSA_MASTER_KEY` : rechiffre **tous** les champs `enc:` de `relay.state` avec une nouvelle clé maître et recalcule le HMAC. Les deux clés passent par l'environnement, **jamais** en argument : `RSA_MASTER_KEY_FILE` / `RSA_MASTER_KEY` (actuelle) et `NEW_RSA_MASTER_KEY_FILE` / `NEW_RSA_MASTER_KEY` (nouvelle ; fichier 0600, **à préférer** aux variables saisies au shell) ; la nouvelle clé doit faire **au moins 32 octets** (`openssl rand -base64 48`). Ne change ni `JWT_SECRET_KEY` ni les clés de signature. Détail, ordre des opérations et procédure actif/passif : `STATE_SPEC.md` (§ `state rekey`) et `SECURITY.md` §11.

| Option | Rôle |
|---|---|
| `--state-dir` | répertoire d'état (défaut `$STATE_DIR`, sinon `/data`) |
| `--yes` | confirme sans invite ; **obligatoire** hors terminal interactif |
| `--i-know-no-instance-is-running` | passe outre un `relay.lock` orphelin (stockage figé) ; `[SECURITY WARNING]` |

Sans `--yes` en terminal, la commande demande de taper `rekey`. Avant toute écriture : `relay.state.rekey.<UTC>.bak` (0600, **lisible avec l'ancienne clé** : à détruire une fois la nouvelle clé en service). Un état encore en schéma 1 est accepté et migré en schéma 2 par la même écriture (`relay.state.v1.bak` = copie de l'original, en plus de la sauvegarde `rekey`). Après l'écriture : relecture avec la nouvelle clé et comparaison des clairs ; échec = original remis en place.

| Code | Signification |
|---|---|
| 0 | clé maître remplacée |
| 2-6 | idem `state verify` (ancienne clé incorrecte, état falsifié, invariant, clé absente…) |
| 8 | `relay.lock` frais (ou apparu pendant la commande) : une instance est active, état intact |
| 9 | refusé, rien n'est modifié : nouvelle clé absente ou identique à l'ancienne, champ `enc:` non couvert, état issu de `relay.state.prev`, confirmation absente (`--yes` manquant) ou réponse ≠ `rekey` |
| 10 | vérification après écriture échouée (l'original a été remis en place, sauf message contraire) |
| 11 | nouvelle clé de moins de 32 octets, rien n'est modifié (l'ancienne clé n'est pas contrôlée) |

Le code 7 (`--min-write-seq`) n'existe que pour `state verify` / `state restore`.

---

## Global Options

```bash
relay [OPTIONS] COMMAND [ARGS]

Options:
  -h, --help              Show help
  -v, --version           Show version
  -q, --quiet             Suppress output (errors still shown)
  -j, --json              Output in JSON format
  --config <path>         Use alternate config file
  --server <url>          Override server URL
  --token <jwt>           Override token (env: RELAY_TOKEN)
  --context <name>        Use specific context
  --verbose               Verbose logging (debug)
  --no-verify-tls         Skip TLS verification (dev only)
  --timeout <seconds>     API request timeout (default: 30)

Environment variables:
  RELAY_SERVER           Server URL
  RELAY_TOKEN            JWT token
  RELAY_CONFIG           Config file path
  RELAY_CONTEXT          Context name
```

---

## Output Formats

### Table (default for list commands)
```
HOSTNAME       STATUS      LAST SEEN
qualif-01      connected   30s ago
qualif-02      connected   2m ago
qualif-03      disconnected 5m ago
```

### JSON
```json
{
  "minions": [
    {
      "hostname": "qualif-01",
      "status": "connected",
      "last_seen": "2026-03-05T10:15:30Z"
    }
  ]
}
```

### YAML
```yaml
minions:
  - hostname: qualif-01
    status: connected
    last_seen: 2026-03-05T10:15:30Z
```

---

## Stack technique

| Composant | Détail |
|-----------|--------|
| Framework CLI | Python `typer` (modern, async-ready) ou `click` |
| HTTP client | `httpx` (async, supports streaming) |
| Table formatting | `rich` (colored tables, progress bars) |
| YAML parsing | `pyyaml` |
| Diff display | `difflib` ou `rich.compare` |
| Config storage | TOML ou JSON (XDG compliant) |
| Bash completion | Dynamique via `shell_complete` |
| Packaging | setuptools + pyproject.toml |
| Distribution | PyPI + GitHub releases |

---

## Sécurité

| Aspect | Mesure |
|--------|--------|
| Credentials | Fichier local `~/.config/ansiblerelay/credentials.json` (chmod 600) |
| Renouvellement de jeton | Aucun (supprimé en v3.0.3) |
| Token masking | Affichage masqué dans output (3d7a...9f2c) |
| TLS | Obligatoire par défaut (--no-verify-tls = dev only) |
| Input validation | YAML parsing, regex pour hostnames, SQL injection protection |
| Command injection | Pas d'exec() ou shell=True, args passés comme liste |
| Audit logs | Tous changements loggés côté serveur |
| Rate limiting | Côté API (éviter brute-force) |

---

## Exemples d'utilisation

```bash
# Login
$ relay auth login
Server URL: https://relay.example.com
Username: admin@example.com
Password: ••••••••
✅ Logged in as admin@example.com

# List minions
$ relay minions list
HOSTNAME      STATUS       LAST SEEN    FACTS
qualif-01     ✅ connected  30s ago      Ubuntu 22.04, 4 CPU, 8GB
qualif-02     ✅ connected  2m ago       Ubuntu 22.04, 4 CPU, 8GB
qualif-03     ⏹️  disconn    5m ago       Ubuntu 22.04, 4 CPU, 8GB
TOTAL: 3 minions, 2 connected, 1 disconnected

# View minion detail
$ relay minions detail qualif-01
Minion: qualif-01
Status: CONNECTED
Last seen: 30s ago
Enrolled: 2026-03-01 10:15:00

Facts:
  OS: Ubuntu 22.04 (Jammy)
  Kernel: Linux 5.15.0-56-generic
  CPU: 4 vCPUs
  Memory: 8 GB

Token: 3d7a...9f2c (expires in 45 minutes)

Recent Activity:
  [20:15] exec: hostname → rc=0
  [20:10] put_file: /tmp/test.txt → rc=0

# Edit inventory
$ relay inventory edit
# Opens editor with current inventory
# After save: shows diff and audit entry

# Revoke minion (force re-enrollment)
$ relay minions revoke qualif-03
⚠️  Revoking token for qualif-03
This will force the minion to re-enroll on next connection.
Continue? [y/N]: y
✅ Token revoked for qualif-03

# Delete minion (permanent)
$ relay minions delete qualif-03 --force
⚠️  DELETING minion: qualif-03
✅ Minion qualif-03 deleted from database
📝 Audit log entry created

# Show audit trail
$ relay audit log --limit 10
TIMESTAMP            USER   ACTION            RESOURCE
2026-03-05 10:15:00  admin  revoke            qualif-03
2026-03-05 10:10:00  admin  edit-inventory    all.hosts

# Check server health
$ relay health
Server: https://relay.example.com
Status: ✅ healthy
Database: ✅ ok
Last sync: 2s ago
```

---

## Dépendances

- **Phase 4** : déploiement Docker Compose actif/passif (Kubernetes/Helm retirés)
- **Phase 5** : Monitoring/alerting infrastructure
- **Backend ready** : DB schema (minions + inventory + audit logs)
- **Auth system** : JWT generation/validation (routes_register.py)

---

## Métriques de succès

- ✅ Installation : `pip install ansiblerelay-cli`
- ✅ Login/logout avec JWT
- ✅ Minions list/detail/revoke/delete opérationnels
- ✅ Inventory view/edit/diff/rollback opérationnels
- ✅ Audit trail complet (tous les changements loggés)
- ✅ Bash completion fonctionne (`relay <TAB>`)
- ✅ Help output cohérent (`relay --help`, `relay minions --help`)
- ✅ Sécurité : tokens masqués, TLS obligatoire, audit logs
- ✅ Performance : API response < 500ms, CLI latency < 1s
- ✅ Tests : 80%+ coverage (unitaire + E2E)
