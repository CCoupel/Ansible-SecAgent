# Event Hooks — Spécifications techniques

> Composant : `secagent-server`  
> Milestone : Phase 11 — Webhooks & Events  
> Issues : #98, #101–#108

---

## 1. Vue d'ensemble

Le système d'**event hooks** permet d'exécuter des actions automatiques lorsque l'état d'un agent change. Les actions sont définies dans un fichier de configuration JSON et exécutées de façon **asynchrone** — elles ne bloquent pas l'opération déclenchante.

### Principe

```
Événement agent                   Fichier hooks.json
(host.new, host.up...)    ──►    ┌─────────────────────┐
        │                        │ hook host.new        │
        │                        │  - action webhook    │
        ▼                        │  - action shell      │
  Dispatcher                     │  - action file       │
  (queue async)     ──────────►  └─────────────────────┘
        │
        ▼
  Executor (par type)
  webhook │ shell │ file │ api
        │
        ▼
  actions.log (JSON Lines, STATE_DIR/actions.log)
```

---

## 2. Fichier de configuration

### Emplacement

Défini par la variable d'environnement `RELAY_HOOKS_CONFIG` (défaut : `/etc/secagent-server/hooks.json`).

Si le fichier est absent, le serveur démarre normalement sans hooks (message de log informatif, pas d'erreur fatale).

### Hot-reload

Envoyer `SIGHUP` au processus recharge la configuration sans redémarrage :

```bash
kill -HUP $(pidof secagent-server)
```

### Format

```json
{
  "hooks": [
    {
      "event": "<event_type>",
      "actions": [
        { "type": "<action_type>", ... }
      ]
    }
  ]
}
```

### Événements disponibles

| Événement | Déclencheur |
|-----------|-------------|
| `host.new` | Enrollment réussi (phase 2 challenge-response) |
| `host.up` | Agent WebSocket connecté |
| `host.down` | Agent WebSocket déconnecté |
| `host.revoked` | Agent révoqué (`/api/admin/revoke/{hostname}`) |
| `host.deleted` | Agent supprimé (`DELETE /api/admin/minions/{hostname}`) |

---

## 3. Types d'actions

### 3.1 `webhook` — HTTP POST vers une URL externe

```json
{
  "type":            "webhook",
  "url":             "https://mon-cmdb.internal/hooks/secagent",
  "secret":          "hmac-signing-key",
  "max_retries":     3,
  "timeout_seconds": 10
}
```

| Champ | Requis | Défaut | Description |
|-------|--------|--------|-------------|
| `url` | ✅ | — | URL cible. Doit commencer par `http://` ou `https://` |
| `secret` | ❌ | `""` | Clef HMAC-SHA256. Si défini, ajoute le header `X-Signature` |
| `max_retries` | ❌ | `3` | Tentatives supplémentaires après échec (0–10) |
| `timeout_seconds` | ❌ | `10` | Timeout HTTP par tentative (1–60) |

**Body envoyé** : JSON standardisé (voir §5).

**Headers** :
```
Content-Type:  application/json
User-Agent:    secagent-server/1.0
X-Event:       host.new
X-Signature:   sha256=<hex(HMAC-SHA256(secret, body))>   ← si secret défini
```

**Retry** : backoff exponentiel (0s, 1s, 2s, 4s… max 60s). Pas de retry sur réponse 4xx.

---

### 3.2 `shell` — Exécution d'un script ou commande

```json
{
  "type":            "shell",
  "cmd":             "/opt/secagent/hooks/register.sh",
  "args":            ["{{hostname}}", "{{event}}"],
  "timeout_seconds": 30
}
```

| Champ | Requis | Défaut | Description |
|-------|--------|--------|-------------|
| `cmd` | ✅ | — | Chemin absolu de la commande ou script |
| `args` | ❌ | `[]` | Arguments (template supporté) |
| `timeout_seconds` | ❌ | `30` | Timeout d'exécution |
| `env` | ❌ | `{}` | Variables supplémentaires (nom → valeur, template supporté, 64 max) ; valeurs masquées dans le journal |

**Environnement du processus (liste blanche, #185)** : le processus **n'hérite jamais** de l'environnement du serveur
(`ADMIN_TOKEN`, `JWT_SECRET_KEY`, `RSA_MASTER_KEY`, `REPEATER_UPSTREAM_TOKEN`… ne lui sont pas visibles). Il reçoit uniquement :

- `PATH` fixe (`/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`) ;
- `HOME` (celui du serveur, sinon `/nonexistent`), `LANG`, `LC_*`, `TZ` (valeurs du serveur, si définies) ;
- les variables déclarées dans `env` de l'action ;
- les variables d'événement, qui l'emportent sur tout le reste :
```
SECAGENT_EVENT=host.new
SECAGENT_HOSTNAME=my-server-01
SECAGENT_TIMESTAMP=2026-05-22T14:30:00Z
SECAGENT_STATUS=disconnected
SECAGENT_ENROLLED_AT=2026-05-22T14:30:00Z   ← host.new uniquement
SECAGENT_RELAY_CHAIN / SECAGENT_RELAY_ORIGIN ← événement venu d'un relay enfant
```

Règles de validation de `env` (la configuration entière est refusée sinon) : réservé à `type: "shell"` ; noms
`[A-Za-z_][A-Za-z0-9_]*` ; préfixe `SECAGENT_` réservé ; **`ADMIN_TOKEN`, `JWT_SECRET_KEY`, `RSA_MASTER_KEY`,
`REPEATER_UPSTREAM_TOKEN` et `RELAY_ENROLLMENT_TOKEN` interdits** (insensible à la casse). Une valeur sensible dans `env`
(ex. jeton d'une API tierce) doit être un secret **propre au hook**, jamais une copie d'un secret du serveur. Aucun réglage
ne permet de désactiver la liste blanche.

**Succès** : code de retour 0. Toute autre valeur → success=false ; seul le statut de sortie (`exit status N`) est journalisé : le stderr est ignoré (il peut citer des secrets, #161).

---

### 3.3 `file` — Écriture dans un fichier

```json
{
  "type":   "file",
  "path":   "/var/log/secagent/events.log",
  "append": "{{timestamp}} {{event}} {{hostname}} {{status}}\n"
}
```

| Champ | Requis | Description |
|-------|--------|-------------|
| `path` | ✅ | Chemin du fichier (créé si absent, répertoires créés si nécessaires) |
| `append` | ✅ | Contenu à ajouter à la fin du fichier (template supporté) |

Mode : toujours append (`O_APPEND|O_CREATE`). Permissions : `0644`.

---

### 3.4 `api` — Appel HTTP avec méthode configurable

```json
{
  "type":            "api",
  "method":          "PATCH",
  "url":             "http://monitoring.internal/api/hosts/{{hostname}}",
  "headers":         { "X-Api-Key": "secret123" },
  "body":            { "status": "{{status}}", "last_seen": "{{timestamp}}" },
  "max_retries":     1,
  "timeout_seconds": 5
}
```

| Champ | Requis | Défaut | Description |
|-------|--------|--------|-------------|
| `url` | ✅ | — | URL cible (template supporté) |
| `method` | ❌ | `GET` | Méthode HTTP (`GET`, `POST`, `PATCH`, `PUT`, `DELETE`) |
| `headers` | ❌ | `{}` | Headers additionnels |
| `body` | ❌ | `null` | Corps de la requête (sérialisé JSON, template appliqué sur la valeur JSON) |
| `max_retries` | ❌ | `0` | Retry sur échec réseau |
| `timeout_seconds` | ❌ | `10` | Timeout |

Différences vs `webhook` : méthode configurable, pas de HMAC, body libre.

---

## 4. Moteur de template

Les variables suivantes sont disponibles dans les champs `url`, `args`, `append`, `body` de toutes les actions :

| Variable | Valeur | Présent pour |
|----------|--------|-------------|
| `{{hostname}}` | Nom de l'agent | Tous les événements |
| `{{event}}` | Type d'événement (`host.new`...) | Tous |
| `{{timestamp}}` | RFC3339 UTC de l'événement | Tous |
| `{{status}}` | État agent (`connected`, `revoked`...) | Tous |
| `{{enrolled_at}}` | Date d'enrollment RFC3339 | `host.new` uniquement |

Variables inconnues (`{{foo}}`) sont laissées telles quelles.

---

## 5. Payload standardisé (type `webhook`)

```json
{
  "event":     "host.new",
  "timestamp": "2026-05-22T14:30:00Z",
  "host": {
    "hostname":    "my-server-01",
    "status":      "disconnected",
    "enrolled_at": "2026-05-22T14:30:00Z"
  }
}
```

### Valeurs par événement

| Événement | `host.status` | `host.enrolled_at` |
|-----------|---------------|--------------------|
| `host.new` | `"disconnected"` | ✅ présent |
| `host.up` | `"connected"` | absent |
| `host.down` | `"disconnected"` | absent |
| `host.revoked` | `"revoked"` | absent |
| `host.deleted` | `"deleted"` | absent |

---

## 6. Exemples de configuration

### Exemple complet

```json
{
  "hooks": [
    {
      "event": "host.new",
      "actions": [
        {
          "type":        "webhook",
          "url":         "https://cmdb.internal/api/assets",
          "secret":      "hmac-key-prod",
          "max_retries": 3
        },
        {
          "type": "shell",
          "cmd":  "/opt/secagent/hooks/on-new-host.sh",
          "args": ["{{hostname}}"]
        },
        {
          "type":   "file",
          "path":   "/var/log/secagent/events.log",
          "append": "{{timestamp}} NEW     {{hostname}}\n"
        }
      ]
    },
    {
      "event": "host.up",
      "actions": [
        {
          "type":    "api",
          "method":  "PATCH",
          "url":     "http://monitoring.internal/hosts/{{hostname}}",
          "headers": { "Authorization": "Bearer mon-token" },
          "body":    { "status": "online", "seen_at": "{{timestamp}}" }
        },
        {
          "type":   "file",
          "path":   "/var/log/secagent/events.log",
          "append": "{{timestamp}} UP      {{hostname}}\n"
        }
      ]
    },
    {
      "event": "host.down",
      "actions": [
        {
          "type":    "api",
          "method":  "PATCH",
          "url":     "http://monitoring.internal/hosts/{{hostname}}",
          "headers": { "Authorization": "Bearer mon-token" },
          "body":    { "status": "offline", "seen_at": "{{timestamp}}" }
        },
        {
          "type":   "file",
          "path":   "/var/log/secagent/events.log",
          "append": "{{timestamp}} DOWN    {{hostname}}\n"
        }
      ]
    },
    {
      "event": "host.revoked",
      "actions": [
        {
          "type": "shell",
          "cmd":  "/opt/secagent/hooks/on-revoke.sh",
          "args": ["{{hostname}}"]
        }
      ]
    },
    {
      "event": "host.deleted",
      "actions": [
        {
          "type":    "api",
          "method":  "DELETE",
          "url":     "http://cmdb.internal/api/assets/{{hostname}}",
          "headers": { "Authorization": "Bearer mon-token" }
        }
      ]
    }
  ]
}
```

### Exemple minimal — log fichier uniquement

```json
{
  "hooks": [
    {
      "event": "host.new",
      "actions": [
        { "type": "file", "path": "/var/log/secagent/events.log", "append": "{{timestamp}} NEW {{hostname}}\n" }
      ]
    },
    {
      "event": "host.up",
      "actions": [
        { "type": "file", "path": "/var/log/secagent/events.log", "append": "{{timestamp}} UP  {{hostname}}\n" }
      ]
    },
    {
      "event": "host.down",
      "actions": [
        { "type": "file", "path": "/var/log/secagent/events.log", "append": "{{timestamp}} DOWN {{hostname}}\n" }
      ]
    }
  ]
}
```

---

## 7. Log d'exécution (journal `actions.log`)

Toutes les exécutions sont tracées dans un journal JSON Lines append-only (`actions.log`, défaut `STATE_DIR/actions.log`), consultable via CLI. **Les secrets (HMAC, tokens, en-têtes) sont masqués** dans le journal (ils n'apparaissent jamais, contrairement aux versions v1.0.0/v2.0.0 qui exposaient les secrets en clair dans `action_log.config_snapshot`). Rotation par taille (10 Mio × 5).

| Colonne | Description |
|---------|-------------|
| `event` | Événement déclenchant |
| `hostname` | Agent concerné |
| `action_type` | `webhook` / `shell` / `file` / `api` |
| `action_index` | Position dans la liste `actions` du hook |
| `config_snapshot` | JSON de l'`ActionDef` au moment de l'exécution |
| `success` | `true` si l'action a réussi |
| `error` | Message d'erreur si échec |
| `duration_ms` | Durée d'exécution en millisecondes |
| `executed_at` | Horodatage RFC3339 |

---

## 8. CLI

### `secagent-server hooks status`

Affiche la configuration active :

```
Hooks config : /etc/secagent-server/hooks.json
Dernière lecture : 2026-05-22T14:30:00Z

EVENT           ACTIONS
host.new        webhook(https://cmdb/...), shell(/opt/hooks/register.sh), file(/var/log/...)
host.up         api(PATCH http://monitoring/...)
host.down       api(PATCH http://monitoring/...), file(/var/log/...)
host.revoked    shell(/opt/hooks/on-revoke.sh)
host.deleted    api(DELETE http://cmdb/...)
```

### `secagent-server hooks log`

```bash
secagent-server hooks log [--limit 50] [--event host.new] [--hostname my-server] [--format table|json]
```

```
EXECUTED_AT           EVENT       HOSTNAME       TYPE     SUCCESS  DURATION  ERROR
2026-05-22T14:30:01   host.new    my-server-01   webhook  ✓        42ms
2026-05-22T14:30:01   host.new    my-server-01   shell    ✓        120ms
2026-05-22T14:31:00   host.up     my-server-01   api      ✗        5001ms    connection refused
```

---

## 9. Variable d'environnement

| Variable | Défaut | Description |
|----------|--------|-------------|
| `RELAY_HOOKS_CONFIG` | `/etc/secagent-server/hooks.json` | Chemin du fichier de configuration des hooks |
| `RELAY_HOOKS_MAX_CONCURRENT_ACTIONS` | `64` | Nombre de workers (événements traités en parallèle) |
| `RELAY_HOOKS_QUEUE_SIZE` | `10000` | Nombre d'événements en file, tous workers confondus (voir §9b) |

### 9b. Traitement des événements : file, ordre, contre-pression (#183)

Le dispatcher est un **pool de workers** (`RELAY_HOOKS_MAX_CONCURRENT_ACTIONS`, défaut 64), chacun avec sa file FIFO bornée.
Un événement est confié au worker désigné par un **hachage du hostname** ; ce worker exécute les actions de l'événement **l'une après l'autre**.

- **Contre-pression, pas de perte** : une action n'est plus abandonnée parce que « trop d'actions tournent » : elle attend dans la file.
- **Ordre** : FIFO par hostname (`host.up` puis `host.down` d'un même hôte ne s'inversent jamais) ; **aucune garantie d'ordre entre hôtes**.
- **Isolation** : un webhook lent ne bloque que son worker (borné par `timeout_seconds`, défaut 10 s, plus les retries) ; les hôtes des autres workers progressent. Les hôtes du même worker attendent.
- **Dimensionnement** : la file contient `RELAY_HOOKS_QUEUE_SIZE` événements (défaut 10 000, réparti sur les workers : `ceil(taille/workers)` chacun, au moins 1) pour absorber plusieurs événements par hôte d'un parc de plus de 3 000 hôtes qui se reconnecte (bascule actif/passif, redémarrage). Mémoire : environ 200 octets + chaînes par événement, soit quelques Mo au défaut. Budget de débit : avec 64 workers et le pire timeout (10 s), 3 000 actions lentes se rattrapent en environ 470 s, toutes conservées.
- **Au-delà de la file** : l'événement est rejeté et **compté** (`hooks_dropped_events`) ; un seul `[WARN] hooks: N event(s) …` agrégé par minute, et une entrée **`dropped`** agrégée dans le journal des actions (`action_type:"dropped"`, `event:"*"`, le message donne les comptes). Jamais une ligne par événement.
- **Compteurs** (`GET /api/admin/status`, `secagent-server server status`) : `hooks_queue_depth` (+ `hooks_queue_capacity`), `hooks_inflight`, `hooks_dropped_events`, `hooks_dropped_actions` (actions perdues avec des événements en file lors d'un arrêt brutal : doit rester 0 en marche).
- **Arrêt propre** (signal d'arrêt) : les serveurs HTTP s'arrêtent, puis la file est vidée pendant 10 s au plus ; le reste est compté et loggué (`[SHUTDOWN] hooks: N event(s) still pending`). **Arrêt brutal** (perte du verrou actif/passif, #163) : sortie immédiate, les événements en file sont perdus, comptés et loggués (`Dispatcher stopped: N queued event(s) not processed`). Le nouveau maître reçoit de toute façon les `host.up` des reconnexions.
- **Budgets séparés avec #179** : les actions de hook ne consomment pas de slot de tâche `exec` ; une action `api` qui appellerait l'API exec du serveur serait soumise à #179 comme n'importe quel client.

---

## 10. Cas limites

| Situation | Comportement |
|-----------|-------------|
| Fichier absent | Démarrage normal, log info `hooks config not found`, 0 hook actif |
| JSON invalide au chargement | Log error, config précédente conservée (ou vide si premier chargement) |
| Queue pleine (`RELAY_HOOKS_QUEUE_SIZE`, 10 000 par défaut) | Événement rejeté et compté (`hooks_dropped_events`), un `[WARN]` agrégé par minute + entrée `dropped` dans le journal (§9b) |
| Type d'action inconnu | Log `WARN unknown action type`, action ignorée |
| `shell` : commande introuvable | success=false, erreur dans action_log |
| `file` : permissions insuffisantes | success=false, erreur OS dans action_log |
| `webhook`/`api` : URL non joignable | Retry selon max_retries, dernier échec loggué |
| `webhook`/`api` : réponse 4xx | Pas de retry (erreur permanente côté consommateur) |
| `ctx` annulé (shutdown) | Dispatcher s'arrête, jobs en queue droppés |
| SIGHUP pendant une exécution | Les exécutions en cours terminent, nouvelle config pour les suivantes |
