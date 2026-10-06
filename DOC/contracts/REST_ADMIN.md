# Contrat d'interface — REST Admin (CLI → secagent-server)

> Interface d'administration entre le CLI cobra et le secagent-server.
> Endpoint : port admin **7771** (`ADMIN_ADDR`), réservé à l'administration — ne jamais l'exposer au réseau public.
> Sources : `DOC/server/SERVER_SPEC.md` §7 · `DOC/server/MANAGEMENT_CLI_SPECS.md` · `DOC/security/SECURITY.md` §8

---

## 1. Accès et authentification

```
Port    : 7771 (ADMIN_ADDR, défaut ":7771" = toutes les interfaces)
Auth    : Authorization: Bearer <ADMIN_TOKEN>   (aucune exemption loopback)
```

Le port admin ne démarre que dans une configuration sûre (`server/tls.go` `adminExposure`) : soit TLS (`ADMIN_TLS=true`, avec `TLS_CERT`/`TLS_KEY`), soit une adresse **loopback** (`ADMIN_ADDR=127.0.0.1:7771`), soit la dérogation explicite `ADMIN_INSECURE_HTTP=true` + `ADMIN_INSECURE_HTTP_ACK=i-understand-the-risk` (avertissement `[SECURITY WARNING]`, jeton admin en clair sur le réseau). Sinon, avec le défaut `:7771` et sans TLS admin, le serveur **refuse de démarrer**.

Le CLI `secagent-server` lit `ADMIN_TOKEN` dans l'environnement et appelle l'API admin (`/api/admin/*`, plus `GET /api/inventory`).

## 2. Minions

### `GET /api/admin/minions` — Liste des agents

```http
GET /api/admin/minions?format=json
Authorization: Bearer <ADMIN_TOKEN>
```

**Réponse 200 :**
```json
[
  {
    "hostname": "host-A",
    "status": "connected",
    "last_seen": "2026-03-06T10:00:00Z",
    "suspended": false,
    "enrolled_at": "2026-03-01T10:00:00Z"
  }
]
```

`status` vaut `connected` si l'agent a une WebSocket ouverte sur cette instance, sinon la valeur enregistrée (`handlers/admin.go` `MinionSummary`, `AdminListMinions`). Il n'y a pas de paramètre `format` : la réponse est toujours du JSON.

---

### `GET /api/admin/minions/{hostname}` — Détail d'un agent

**Réponse 200 :** `hostname`, `status`, `last_seen`, `suspended`, `enrolled_at`, `key_fingerprint` (début de la clef publique, 16 caractères + `...`) et `vars` (variables Ansible de l'hôte) — `MinionDetail`, `handlers/admin.go`. La clef publique complète n'est pas renvoyée.

**Codes d'erreur :**

| HTTP | Signification |
|---|---|
| `404` | Hostname non enregistré |

---

### `POST /api/admin/authorize` — Mémoriser une clef publique (sans droit d'enrôlement)

Enregistre une clef publique dans les `authorized_keys` de l'état et répond `201`. **Cela ne donne aucun droit d'enrôlement** : depuis la v3.0.3 (#192), `POST /api/register` ne consulte plus `authorized_keys` et refuse toute requête sans jeton d'enrôlement (`403 enrollment_token_required`, voir `REST_ENROLLMENT.md` §4b). La route (et la commande `secagent-server minions authorize <hostname> --key-file`) subsiste uniquement pour la compatibilité des scripts existants ; elle ne génère aucun jeton. Pour enrôler un hôte : créer un jeton avec `POST /api/admin/tokens` (`role: "enrollment"`, §3) ou `secagent-server tokens create --role enrollment`, puis le donner au minion (`RELAY_ENROLLMENT_TOKEN`). La route est servie sur 7771 et, par compatibilité, aussi sur 7770 (`server/routers.go`).

```http
POST /api/admin/authorize
Authorization: Bearer <ADMIN_TOKEN>
Content-Type: application/json
```

```json
{
  "hostname": "host-A",
  "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...",
  "approved_by": "ci-pipeline"
}
```

**Réponse 201 :** `{ "hostname": "host-A", "status": "authorized" }`

| HTTP | Signification |
|---|---|
| `400` | JSON invalide (`invalid_request`) ou champ vide (`missing_fields` : `hostname`, `public_key_pem` et `approved_by` sont tous obligatoires) |
| `401` | `missing_authorization` / `invalid_admin_token` |

(`handlers/register.go` `AdminAuthorize`.)

---

### `POST /api/admin/revoke/{hostname}` — Révoquer un agent

Blackliste le JTI du JWT actif, ferme la connexion WS avec le code `4001` et marque l'agent déconnecté.

```http
POST /api/admin/revoke/{hostname}
Authorization: Bearer <ADMIN_TOKEN>
```

**Réponse 200 :**
```json
{ "status": "revoked", "hostname": "host-A", "ws_disconnected": true }
```

`404 agent_not_found` si le hostname est inconnu. L'agent reçoit `close(4001)` et s'arrête définitivement (pas de reconnexion). Si l'écriture dans la blacklist échoue, la réponse est une erreur et la WS **n'est pas** fermée (voir §6, mode lecture seule). (`handlers/admin.go` `AdminRevokeMinion`.)

---

### `DELETE /api/admin/minions/{hostname}` — Supprimer un agent

Ferme la WS (code `4000`), supprime l'agent de l'état et émet l'événement `host.deleted`. Réponse 200 : `{ "hostname", "status": "deleted", "ws_disconnected" }` ; `404 agent_not_found`. Différent de la révocation, qui blackliste sans supprimer.

---

### `POST /api/admin/minions/{hostname}/set-state` — Forcer le statut

Corps `{ "status": "connected" | "disconnected" }` (autre valeur : `400 invalid_status`). Modifie le statut enregistré sans toucher à la WebSocket. Réponse 200 : `{ "hostname", "status" }`.

---

### `POST /api/admin/minions/{hostname}/suspend` — Suspendre

Marque l'agent suspendu (conservé en DB). **La WS reste ouverte** (pas de close `4001`) : seule l'exécution est refusée. `exec`, `upload` et `fetch` répondent `503 {"error": "agent_suspended"}` **avant tout envoi à l'agent** ; si l'état ne peut pas être lu : `503 {"error": "agent_state_unavailable"}` (fail closed). La suspension est évaluée par le relay qui détient l'agent ; un relay parent relaie le refus. L'inventaire liste l'agent avec `secagent_suspended: true`. Chaque tentative journalise un `[SECURITY WARNING]`.

---

### `POST /api/admin/minions/{hostname}/resume` — Reprendre

Retire la suspension : `exec`/`upload`/`fetch` sont de nouveau acceptés immédiatement, sans reconnexion.

---

### `GET /api/admin/minions/{hostname}/vars` — Variables hôte

```http
GET /api/admin/minions/{hostname}/vars
Authorization: Bearer <ADMIN_TOKEN>
```

**Réponse 200 :**
```json
{
  "ansible_user": "deploy",
  "ansible_become": true
}
```

---

### `POST /api/admin/minions/{hostname}/vars` — Définir des variables

```http
POST /api/admin/minions/{hostname}/vars
Authorization: Bearer <ADMIN_TOKEN>
Content-Type: application/json
```

Le corps est un objet clef → valeur ; chaque paire est ajoutée ou mise à jour :

```json
{ "ansible_user": "deploy", "ansible_become": true }
```

Réponse 200 : `{ "hostname": "host-A", "status": "updated" }` ; `404 agent_not_found`. Il n'existe pas de route `PUT …/vars/{key}`.

---

### `DELETE /api/admin/minions/{hostname}/vars/{key}` — Supprimer une variable

Réponse 200 : `{ "hostname", "key", "status": "deleted" }` ; `404 agent_not_found` ou `404 key_not_found`.

---

## 3. Tokens plugin

### `GET /api/admin/tokens` — Liste des tokens

```http
GET /api/admin/tokens?role=plugin
Authorization: Bearer <ADMIN_TOKEN>
```

**Paramètres :**
- `role` : `plugin` | `enrollment` | `relay-parent` | `all` (défaut: `all`) ; autre valeur : `400 invalid_role`

**Réponse 200 :**
```json
[
  {
    "id": "tok-uuid",
    "description": "ansible-control-prod",
    "role": "plugin",
    "allowed_ips": "192.168.1.10/32",
    "allowed_hostname_pattern": "ansible-control-[0-9]+",
    "created_at": "2026-03-01T10:00:00Z",
    "last_used_at": "2026-03-06T10:00:00Z",
    "last_used_ip": "192.168.1.10",
    "last_used_approximate": true,
    "revoked": false
  }
]
```

`expires_at`, `last_used_*` et `description` sont omis quand ils sont vides. `last_used_at` / `last_used_ip` sont gardés en mémoire et ne sont persistés qu'avec la prochaine écriture de l'état : ils peuvent retarder de plusieurs minutes (`last_used_approximate: true`), et un jeton utilisé juste avant un crash peut apparaître « jamais utilisé » — ne pas s'en servir pour un audit. Chaque entrée porte aussi `token_hash` (jamais le jeton en clair). Les jetons `enrollment` et `relay-parent` ont leurs propres champs (`hostname_pattern`, `reusable`, `use_count` ; `sub`, `jti`) — `handlers/admin_tokens.go`.

---

### `POST /api/admin/tokens` — Créer un token (plugin, enrôlement ou relay-parent)

```http
POST /api/admin/tokens
Authorization: Bearer <ADMIN_TOKEN>
Content-Type: application/json
```

```json
{
  "description": "ansible-control-prod",
  "role": "plugin",
  "allowed_ips": "192.168.1.10/32",
  "allowed_hostname_pattern": "ansible-control-[0-9]+",
  "expires_at": "2027-03-01T00:00:00Z"
}
```

`role` : `plugin`, `enrollment` ou `relay-parent` (sinon `400 invalid_role`). L'expiration est `expires_at` en **RFC 3339** (pas de durée `expires_in` ; format invalide : `400 invalid_expires_at`). Vide = jeton sans expiration, sauf `relay-parent` pour lequel elle est obligatoire (maximum 365 jours, `400 expires_exceeds_maximum_365d`). Le CLI `tokens create --expires <durée>` convertit la durée en `expires_at`. Champs propres au rôle : `enrollment` → `hostname_pattern` (obligatoire), `reusable` (0 = usage unique, 1 = permanent) ; `plugin` → `description`, `allowed_ips`, `allowed_hostname_pattern` ; `relay-parent` → `sub` (relay_id du parent).

**Réponse 201 :**
```json
{
  "id": "tok-uuid",
  "token": "secagent_plg_<64 hex>",
  "role": "plugin",
  "created_at": "2026-03-01T10:00:00Z"
}
```

Le token en clair n'est retourné **qu'une seule fois** à la création. Ensuite, seul le hash est stocké. Les jetons `plugin` et `enrollment` sont des chaînes **opaques** préfixées `secagent_plg_` / `secagent_enr_` (suivies de 64 caractères hexadécimaux), **pas des JWT** ; seul le jeton `relay-parent` est un JWT (`handlers/admin_tokens.go:163`).

#### Note sur `allowed_hostname_pattern`

Le champ `allowed_hostname_pattern` est une **regexp Go** (pas un glob shell). Le serveur valide le pattern à la **création du token** — si la regexp ne compile pas, l'API retourne HTTP `400 {"error":"invalid_hostname_pattern"}`.

**Ancrage automatique** : Le serveur applique l'ancrage `^(?:pattern)$` (groupe non-capturant) pour éviter les bypasses d'alternation. Le pattern doit correspondre au **nom d'hôte complet**.

**Exemples valides** :
- `ansible-control-[0-9]+` → matche `ansible-control-1`, `ansible-control-42` (classe `[0-9]+`)
- `ansible-.*` → matche `ansible-prod`, `ansible-staging-01`, mais PAS `notansible-prod` (ancrage début)
- `.*-prod-.*` → matche `app-prod-01`, `db-prod-web` (dot-star `.*` = 0+ caractères)
- `ansiblecent-0[1-3]` → matche `ansiblecent-01`, `ansiblecent-02`, `ansiblecent-03` (classe `[1-3]`)
- `web1|db` → matche **exactement** `web1` ou `db` (pas `web1-evil` ni `xdb` — l'alternation est ancrée)
- `(?i)web1|(?i)db` → case-insensitive pour les deux alternatives

**Erreur classique** :
- `web-*` n'est **pas** un glob shell — c'est une regexp Go cherchant un tiret littéral suivi d'une étoile. Utiliser `web-[0-9]+` ou `web-.*` à la place.

**Sécurité** :
- Un pattern invalide (ex: `[`) est rejeté à la création : `400 invalid_hostname_pattern`.
- Un pattern trop large (ex: `.*`) accepte n'importe quel hostname. À utiliser avec précaution et préférer une restriction IP (`allowed_ips`).
- L'alternation `web1|db` (enveloppe automatique `^(?:web1|db)$`) accepte exactement "web1" ou "db", pas les prefixes/suffixes.

---

### `POST /api/admin/tokens/{id}/revoke` — Révoquer un token

Révoque un jeton **plugin** (ou `relay-parent`). Les jetons d'enrôlement ne se révoquent pas : utiliser `DELETE`. Réponse 200 : `{ "revoked": true, "id": "...", "updated_at": "..." }` ; `404 token_not_found` si l'id n'existe pas.

---

### `DELETE /api/admin/tokens/{id}` — Supprimer un token

---

### `POST /api/admin/tokens/purge` — Purger les tokens expirés ou consommés

Paramètres de requête : `expired=1` (jetons d'enrôlement expirés) et/ou `used=1` (jetons d'enrôlement à usage unique consommés) ; aucun des deux : `400 specify_at_least_one_param_expired_or_used`. Réponse 200 : `{ "deleted_count": N, "purged_at": "..." }`. Les jetons plugin ne sont pas purgés.

---

## 4. Sécurité — rotation des clefs JWT

### `GET /api/admin/security/keys/status` — État des clefs

**Réponse 200 :**
```json
{
  "current_key_sha256": "<sha256 hex>",
  "previous_key_sha256": "<sha256 hex ou vide>",
  "deadline": "2026-03-07T10:00:00Z",
  "rotation_active": true,
  "agents_total": 42
}
```

Les clefs sont identifiées par leur empreinte SHA-256 (pas d'identifiant `key-…`). `agents_total` = agents actuellement connectés. (`handlers/security.go` `KeysStatusResponse`.)

---

### `POST /api/admin/keys/rotate` — Déclencher une rotation

```http
POST /api/admin/keys/rotate
Authorization: Bearer <ADMIN_TOKEN>
Content-Type: application/json
```

```json
{
  "grace": "24h"
}
```

Corps facultatif ; `grace` est une durée Go (`24h`, `2h30m`), défaut `24h` ; durée invalide : `400 invalid_grace_duration`.

**Réponse 200 :**
```json
{
  "current_key_sha256": "<sha256 hex>",
  "previous_key_sha256": "<sha256 hex>",
  "deadline": "2026-03-08T10:00:00Z",
  "agents_migrated": 41,
  "agents_total": 42
}
```

`agents_migrated` = agents connectés à qui le nouveau JWT a pu être envoyé ; `agents_total` = agents connectés (`handlers/security.go` `RotateKeysResponse`). La rotation renouvelle aussi la paire RSA du serveur.

Pendant `grace_period`, les deux clefs (`jwt_secret_current` + `jwt_secret_previous`) sont valides.
Après `rotation_deadline`, `jwt_secret_previous` est invalidé et les JTIs pré-rotation sont blacklistés.

Les agents connectés reçoivent un message WS `{type: "rekey"}` et ré-enrollment automatiquement.

---

### `GET /api/admin/security/blacklist` — Consulter la blacklist JTI

**Réponse 200 :**
```json
[
  {
    "jti": "uuid-v4",
    "hostname": "host-A",
    "revoked_at": "2026-03-06T10:00:00Z",
    "reason": "manual_revoke",
    "expires_at": "2026-03-07T10:00:00Z"
  }
]
```

---

### `POST /api/admin/security/blacklist/purge` — Purger les JTIs expirés

Réponse 200 : `{ "deleted": N }`.

---

### `GET /api/admin/security/tokens` — JTI actifs des agents

Réponse 200 : tableau de `{ hostname, jti, enrolled_at, last_seen, status }`, un par agent ayant un JTI courant.

---

## 5. Inventaire

### `GET /api/inventory` (port 7771) — Inventaire complet, jeton admin

Sur le port admin 7771 la route est `GET /api/inventory` (il n'existe pas de `/api/admin/inventory`) ; elle exige l'`ADMIN_TOKEN`. Sur 7770, la même route exige un **jeton plugin** (voir `DOC/contracts/REST_PLUGIN.md` §2) : un `ADMIN_TOKEN` y est refusé (`server/routers.go:40,71`, `handlers/inventory.go` `GetInventory` / `AdminGetInventory`).

```http
GET /api/inventory?only_connected=false
Authorization: Bearer <ADMIN_TOKEN>
```

Format de réponse identique à `GET /api/inventory` (voir `DOC/contracts/REST_PLUGIN.md` §2).

---

## 5b. Journal des hooks

### `GET /api/admin/hooks/log` — Journal d'exécution des actions de hooks

```http
GET /api/admin/hooks/log?limit=50&event=host.new&hostname=web01
Authorization: Bearer <ADMIN_TOKEN>
```

Lu dans le journal append-only `actions.log` (#161). `limit` : 1–200 (défaut 50), sinon `400 invalid_limit`. Réponse `200` : tableau, du plus récent au plus ancien, de `{id, event, hostname, action_type, action_index, config_snapshot, success, error, duration_ms, executed_at}`.

- `config_snapshot` et `error` sont **masqués** : seuls restent le type, la méthode, `cmd`, `path`, les délais et, pour une URL, schéma + hôte + port (le chemin devient `/***` et la query string `?***` — le secret d'un webhook Slack/Discord/Teams est dans le chemin) ; noms des en-têtes conservés, valeurs masquées ; tout autre champ est masqué.
- Journal inexistant ou vide : `200 []`.
- Journal existant mais illisible : `503 {"error":"journal_unavailable"}` (jamais un `[]` trompeur).
- Journal non configuré : `500 {"error":"action_log_not_initialized"}`.

---

## 6. Statut serveur

### `GET /api/admin/status`

**Réponse 200 :** `db`, `ws_connections`, `uptime`, `links` (relay hiérarchique, si câblé) et, depuis #183, la file des hooks :

```json
{ "db": "ok", "ws_connections": 3, "uptime": "7200s",
  "hooks_queue_depth": 4, "hooks_queue_capacity": 10000, "hooks_inflight": 2,
  "hooks_dropped_events": 0, "hooks_dropped_actions": 0 }
```

`hooks_dropped_events` : événements rejetés (file pleine ou arrêt) ; `hooks_dropped_actions` : actions perdues avec des événements en file lors d'un arrêt brutal (doit rester 0). `secagent-server server status` les affiche.

**Mode d'écriture de l'état (#163)** : `state_mode` (`read_write` | `read_only`), `state_mode_reason` quand il est `read_only` (`no write guard`, `lock lost`, `ownership not confirmed`), `role` (`master`), `instance_id`, `write_seq` (de l'état détenu), `beat` et `last_beat_at` (dernier battement réussi du verrou, RFC 3339). `secagent-server server status` les affiche ; `secagent-server status --local` donne le même mode d'écriture sans passer par l'API.

**Écriture refusée parce que l'instance est en lecture seule (#163)** : toute route qui écrit répond **`503 {"error":"state_read_only","reason":"<no write guard|lock lost|ownership not confirmed>"}`** (et non plus un `500 db_error` générique) quand, au moment de la réponse, l'état est réellement en lecture seule (aucune garde, verrou perdu ou non confirmé). Un vrai échec de base reste un `500 db_error`. Le refus est journalisé une fois par minute. Une révocation d'agent (`POST …/revoke`) dont l'écriture dans la blacklist est refusée **ne ferme plus** le lien en `4001` : elle répond 503 et le client réessaie.

---

### `GET /api/admin/stats`

**Réponse 200 :**
```json
{ "agents_connected": 3, "agents_total": 15, "tasks_active": 2 }
```

`tasks_active` = tâches en attente de réponse d'un agent (`handlers/admin.go` `AdminStats`). Il n'existe pas de routes `/api/admin/server/status` ni `/api/admin/server/stats` ; `secagent-server server status` appelle `GET /api/admin/status`.

---

## 6b. Relays

| Route | Rôle |
|---|---|
| `POST /api/admin/relays` | Enregistre un relay enfant (`relay_id`, `mode` `pull` (défaut) ou `push`, `urls`, `token`, `description`). Mode pull : renvoie `jwt_token` **une seule fois**. |
| `GET /api/admin/relays` | Liste des relays |
| `GET /api/admin/relays/status` | État des relays : `{ "relays": [...], "timestamp": "..." }` |
| `DELETE /api/admin/relays/{id}` | Supprime un relay |
| `POST /api/admin/relays/{id}/revoke` | Révoque un relay (c'est la seule forme de révocation : il n'y a pas de sous-commande CLI `relays revoke`) |

(`server/routers.go:91-95`, `handlers/admin_relays.go`.)

---

## 7. Codes d'erreur communs

| HTTP | Signification |
|---|---|
| `401` | ADMIN_TOKEN absent ou invalide (`missing_authorization`, `invalid_admin_token`) — y compris depuis une boucle locale : il n'y a aucune exemption loopback |
| `404` | Ressource introuvable |
| `409` | Conflit (ex: hostname déjà existant) |
| `500` | Erreur interne |
| `503` | Ressource temporairement indisponible (ex. `journal_unavailable`) |
