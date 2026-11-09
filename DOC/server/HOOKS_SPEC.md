# Event Hooks — Spécifications techniques

> Composant : `secagent-server`  
> Milestone : Phase 11 — Webhooks & Events  
> Issues : #98, #101–#108 ; v3.0.6 : #225, #245, #265

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

### Un seul hook s'exécute par événement

Pour un événement donné, **seul le premier hook de la liste `hooks` qui correspond s'exécute** (même nom d'événement et, s'il y en a un, `filter` satisfait) ; ses actions tournent l'une après l'autre, puis la recherche s'arrête (`hooks/dispatcher.go:569-580`, `// first matching HookDef wins`). Les hooks suivants visant le même événement sont **ignorés en silence à l'exécution** : pour plusieurs actions sur un événement, les mettre dans la liste `actions` d'**un seul** hook. Deux hooks du même événement ne coexistent que s'ils ont des `filter` différents qui ne se recouvrent pas (`relay_chain_contains`).

Au chargement de la configuration, le serveur journalise un `[WARN]` quand plusieurs hooks visent le même événement (ajout v3.0.6). *(À confirmer à la livraison : ce contrôle n'est pas dans le code de `hooks/config.go` à la date de rédaction.)* **L'exécution de tous les hooks correspondants est prévue en v3.0.7** ; d'ici là, regrouper les actions.

### Événements disponibles

**Événements d'hôte** (clé d'ordre : le hostname)

| Événement | Déclencheur |
|-----------|-------------|
| `host.new` | Enrollment réussi (phase 2 challenge-response) |
| `host.up` | **Première** connexion WebSocket d'un process minion (démarrage ou redémarrage du service ou de l'hôte), ou connexion d'un minion antérieur à la v3.0.6. Voir « `up` ou `reconnect` » ci-dessous |
| `host.reconnect` | (v3.0.6) Connexion suivante du **même process** minion ≥ 3.0.6 (coupure réseau, bascule du relais, keepalive) : exclusif avec `host.up` |
| `host.down` | Agent WebSocket déconnecté |
| `host.suspended` | Agent suspendu (`POST /api/admin/minions/{hostname}/suspend`) ; remonte aux ancêtres (#180) |
| `host.resumed` | Suspension levée (`POST /api/admin/minions/{hostname}/resume`) ; remonte aux ancêtres (#180) |
| `host.revoked` | Agent révoqué (`/api/admin/revoke/{hostname}`) |
| `host.deleted` | Agent supprimé (`DELETE /api/admin/minions/{hostname}`) |
| `host.conflict` | Hôte revendiqué par un second relay alors qu'il est déjà routé vers un autre : émis une fois par changement de propriétaire, statut `ancien->nouveau` (`server/server.go:496` ; accepté en `event_forward` par `ws/relay_handler.go:1789` ; SERVER_SPEC §9.5a) |
| `host.discover`, `host.rerouted`, `host.removed` | **À venir (LOT-3.2/3.3), jamais émis en v3.0.6.** Le nom est déjà accepté dans `hooks.json` (pas d'avertissement) et la forme déjà acceptée sur le fil (SERVER_SPEC §9.2) |

**Événements de relais** (v3.0.6 ; **sans hostname**, clé d'ordre : le `relay_id` ; `{{hostname}}` et `{{status}}` y sont vides)

| Événement | Déclencheur | Émis par |
|-----------|-------------|----------|
| `relay.failover` | Cette instance vient de devenir le **maître** du `STATE_DIR` : `cause` = `takeover` (verrou périmé d'un maître disparu supprimé, `previous_instance_id` renseigné si connu) ou `start` (verrou libre : premier démarrage ou arrêt propre du maître précédent). Émis **avant** l'ouverture de tout port (`server/instance.go:249`, `server/server.go:786`) | le nouveau maître ; un nœud non racine le remonte à son parent (mis en file avant que le lien amont existe) |
| `relay.up` | Premier `topology_snapshot` accepté d'un lien relais dont le process enfant annonce sa première connexion (`conn_seq` ≤ 1 ou absent) ; un snapshot de **remplacement** sur un lien déjà établi n'émet rien (`ws/relay_handler.go:1770`) | le parent direct du lien ; remonte aux ancêtres |
| `relay.reconnect` | Idem, mais `conn_seq` > 1 : même process enfant qui revient. Exclusif avec `relay.up` | le parent direct ; remonte |
| `relay.down` | Fin d'un lien dont le snapshot avait été accepté. **Aucun** événement quand ce nœud ferme lui-même ses liens en s'arrêtant (`CloseAllLinks`, dialer arrêté) : c'est le nouveau maître qui s'annonce par `relay.failover` (`ws/relay_handler.go:1228`) | le parent direct ; remonte |
| `relay.discover`, `relay.rerouted`, `relay.removed`, `relay.converged` | **À venir (LOT-3.2/3.3), jamais émis en v3.0.6** ; noms acceptés dans `hooks.json`, formes acceptées sur le fil | — |

`relay.updated` (changement de `group_vars`) circule dans l'arbre mais **ne déclenche aucun hook** : un hook déclaré sur ce nom ne se déclenche jamais et le chargement journalise un `[WARN]` (`hooks/config.go:61`, comme pour toute faute de frappe).

#### `up` ou `reconnect` — **[CHANGED] `host.up` n'est plus émis à chaque reconnexion**

Le client compte les connexions réussies de son process : le minion envoie l'en-tête `X-SecAgent-Conn-Seq`, un relais enfant le champ `conn_seq` (`relay_hello` en pull, `relay_ack` en push). `1` = première connexion du process ⇒ `*.up` ; `> 1` ⇒ `*.reconnect`. Le serveur ne garde **aucune mémoire** : après une bascule actif/passif, le nouveau maître lit `conn_seq > 1` et émet `*.reconnect`. Une valeur absente, non numérique ou hors de 1..2³¹ vaut 1 (fail-safe : `*.up`) ; un minion ou un relais antérieur à la v3.0.6 n'envoie rien ⇒ toujours `*.up`.

- **Conséquence pour les hooks existants** : un hook `host.up` ne voit plus les reconnexions d'un même process minion ≥ 3.0.6. Pour agir à **toute** connexion, déclarer deux hooks : `host.up` **et** `host.reconnect`.
- `conn_seq` est **déclaratif** (annoncé par le pair) : un `reconnect` n'est pas une preuve d'instabilité (SECURITY.md §10). Un redémarrage du minion repart à 1 (`host.up`).

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

Pour les événements de relais et `host.up` / `host.reconnect` (v3.0.6), s'ajoutent, **seulement quand elles ont une valeur** (`hooks/shellenv.go`, `hooks/event.go`) : `SECAGENT_RELAY_ID`, `SECAGENT_CONN_SEQ`, `SECAGENT_MODE`, `SECAGENT_HOSTS_ROUTED`, `SECAGENT_RELAYS_BELOW`, `SECAGENT_RELAYS_BELOW_IDS`, `SECAGENT_REASON`, `SECAGENT_CAUSE`, `SECAGENT_INSTANCE_ID`, `SECAGENT_PREVIOUS_INSTANCE_ID` (voir §4 pour le sens). Pour un `relay.*`, `SECAGENT_HOSTNAME` et `SECAGENT_STATUS` existent mais sont **vides**. Les valeurs sont assainies (les caractères de contrôle deviennent `_`) ; elles viennent d'un pair authentifié mais sont bornées par liste ou regex avant d'arriver ici (SERVER_SPEC §9.2). **Ne jamais mettre une variable d'événement en tête d'un argument ou dans un chemin sans la contrôler dans le script.**

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
| `{{hostname}}` | Nom de l'agent (**vide pour un `relay.*`**) | Tous les événements d'hôte |
| `{{event}}` | Type d'événement (`host.new`...) | Tous |
| `{{timestamp}}` | RFC3339 UTC de l'événement | Tous |
| `{{status}}` | État agent (`connected`, `revoked`...) (vide pour un `relay.*`) | Tous les événements d'hôte |
| `{{enrolled_at}}` | Date d'enrollment RFC3339 | `host.new` uniquement |
| `{{relay_chain}}` | Relais traversés, séparés par des virgules, **origine en premier** (ex. `zone-a,dmz1`) ; vide pour un événement local de ce nœud (dont `relay.failover`) | Événement venu d'un relay enfant ; `relay.up`/`reconnect`/`down` (chaîne = le relais décrit) |
| `{{relay_origin}}` | Premier élément de la chaîne (relais d'où vient l'événement) | idem |

Variables de relais et de connexion (v3.0.6), présentes quand elles ont une valeur (entiers en décimal) :

| Variable | Sens | Présent pour |
|----------|------|-------------|
| `{{relay_id}}` | Relais décrit par l'événement | `relay.*` |
| `{{conn_seq}}` | Numéro de connexion annoncé par le client (1 = première du process) | `host.up`, `host.reconnect`, `relay.up`, `relay.reconnect` (quand le client l'a annoncé ; absent pour un minion ou relais < 3.0.6 reçu d'un enfant) |
| `{{mode}}` | `pull` ou `push` | `relay.up`, `relay.reconnect` |
| `{{hosts_routed}}` | À `relay.up`/`reconnect` : agents du snapshot accepté ; à `relay.down` : agents du **dernier** snapshot accepté (ce que le lien portait, pas un comptage du store). Toujours présent (0 compris) | `relay.up`, `relay.reconnect`, `relay.down` |
| `{{relays_below}}`, `{{relays_below_ids}}` | Nombre et ids (virgules, ≤ 256, triés) des relais déclarés sous ce lien | `relay.up`, `relay.reconnect` |
| `{{reason}}` | `revoked` (jeton révoqué ou relais supprimé : lien coupé par ce nœud) \| `rejected:<code>` (ce nœud a fermé le lien, 4010/4012) \| `peer_closed:<code>` (le pair a fermé, 1000..4999) \| `idle_timeout` (rien lu pendant 120 s) \| `read_error` | `relay.down` |
| `{{cause}}` | `takeover` \| `start` | `relay.failover` |
| `{{instance_id}}`, `{{previous_instance_id}}` | Identité de l'instance devenue maître ; de l'ancien maître (absent après un arrêt propre ou si inconnu) | `relay.failover` |

Variables inconnues (`{{foo}}`) sont laissées telles quelles. Les variables du premier tableau sont toujours définies (chaîne vide quand elles ne s'appliquent pas). Celles du second tableau n'existent que pour les événements indiqués : sur un autre événement, `{{conn_seq}}` (par exemple) reste **littéral** dans la sortie (`hooks/event.go`, `Detail.vars`).

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
| `host.reconnect` (v3.0.6) | `"connected"` | absent |
| `host.down` | `"disconnected"` | absent |
| `host.suspended` | `"suspended"` | absent |
| `host.resumed` | `"resumed"` | absent |
| `host.revoked` | `"revoked"` | absent |
| `host.deleted` | `"deleted"` | absent |

### Événements de relais (v3.0.6)

Un `relay.*` n'a pas d'hôte : l'objet **`host` est absent** (jamais un `host` vide) et un objet **`relay`** le remplace. `relay_chain` / `relay_origin` figurent quand la chaîne n'est pas vide (voir §4). Les compteurs sont des entiers, `0` compris.

```json
{
  "event":     "relay.down",
  "timestamp": "2026-11-09T14:30:00Z",
  "relay": {
    "relay_id":     "zone-a",
    "reason":       "idle_timeout",
    "hosts_routed": 12
  },
  "relay_chain":  ["zone-a"],
  "relay_origin": "zone-a"
}
```

Champs de `relay` (omis quand ils ne s'appliquent pas) : `relay_id` (toujours), `mode`, `reason`, `cause`, `instance_id`, `previous_instance_id`, `conn_seq`, `hosts_routed`, `relays_below`, `relays_below_ids` (voir §4 pour le sens). `relay.failover` d'un nœud racine n'a pas de `relay_chain` :

```json
{ "event": "relay.failover", "timestamp": "…", "relay": { "relay_id": "root", "cause": "takeover", "instance_id": "…", "previous_instance_id": "…" } }
```

Pour `host.up` et `host.reconnect`, `host.conn_seq` porte le numéro de connexion annoncé ; `host.reconnect` a `host.status` = `"connected"`.

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
- **Arrêt propre** (signal d'arrêt) : les serveurs HTTP s'arrêtent, puis la file est vidée pendant 10 s au plus ; le reste est compté et loggué (`[SHUTDOWN] hooks: N event(s) still pending`). **Arrêt brutal** (perte du verrou actif/passif, #163) : sortie immédiate, les événements en file sont perdus, comptés et loggués (`Dispatcher stopped: N queued event(s) not processed`). Voir « Bascule actif/passif » ci-dessous pour ce que voit le nouveau maître.
- **Budgets séparés avec #179** : les actions de hook ne consomment pas de slot de tâche `exec` ; une action `api` qui appellerait l'API exec du serveur serait soumise à #179 comme n'importe quel client.


### Bascule actif/passif : ce que voit le nouveau maître (v3.0.6, #225)

Dans l'ordre :

1. **`relay.failover`** : émis par le nouveau maître dès qu'il tient le verrou, **avant** l'ouverture de tout port (`server/instance.go:249`). `cause` = `takeover` si le verrou d'un maître disparu était périmé (`previous_instance_id` = son identité, quand elle est connue), `start` si le verrou était libre. Après un arrêt **propre** du maître précédent, le verrou est libre : `cause=start`. Un nœud non racine le remonte à son parent, même avant que son lien amont soit rétabli.
2. **Agents directs** : ils se reconnectent avec leur compteur de process (`conn_seq > 1`) ⇒ **`host.reconnect`**, et non `host.up`.
3. **Relais enfants** : leurs liens se rétablissent et chaque premier `topology_snapshot` donne **`relay.reconnect`** (même process enfant) ou `relay.up` (enfant redémarré). Le maître sortant n'émet pas de `relay.down` pour les liens qu'il ferme lui-même en s'arrêtant.
4. **Hôtes derrière un relais enfant** : ils sont re-routés par le `topology_snapshot` **sans aucun événement `host.*`** (`ws/relay_handler.go`, `handleTopologySnapshot` n'émet que `relay.up|reconnect` ; test `TestFailoverChildHosts_NewMasterRoutesTheLeafWithoutAnEvent`). Pour savoir que leurs routes ont changé, s'abonner à `relay.failover` puis `relay.up|reconnect` ; l'inventaire reste la source de vérité de l'état.

Un snapshot de **remplacement** sur un lien déjà établi (changement de topologie) n'émet ni `relay.up` ni `relay.reconnect`.

Ordre : clé FIFO = `relay_id` pour les `relay.*` ; l'émission locale est synchrone, donc `relay.failover` puis `relay.reconnect` d'un même nœud gardent leur ordre dans la file. Pas d'ordre entre clés différentes.

---

## 10. Cas limites

| Situation | Comportement |
|-----------|-------------|
| Fichier absent | Démarrage normal, log info `hooks config not found`, 0 hook actif |
| JSON invalide au chargement | Log error, config précédente conservée (ou vide si premier chargement) |
| Queue pleine (`RELAY_HOOKS_QUEUE_SIZE`, 10 000 par défaut) | Événement rejeté et compté (`hooks_dropped_events`), un `[WARN]` agrégé par minute + entrée `dropped` dans le journal (§9b) |
| Plusieurs hooks pour le même événement | Seul le premier correspondant s'exécute, les autres sont ignorés ; `[WARN]` au chargement (v3.0.6) ; tous exécutés en v3.0.7 (§2) |
| Type d'action inconnu | Log `WARN unknown action type`, action ignorée |
| `shell` : commande introuvable | success=false, erreur dans action_log |
| `file` : permissions insuffisantes | success=false, erreur OS dans action_log |
| `webhook`/`api` : URL non joignable | Retry selon max_retries, dernier échec loggué |
| `webhook`/`api` : réponse 4xx | Pas de retry (erreur permanente côté consommateur) |
| `ctx` annulé (shutdown) | Dispatcher s'arrête, jobs en queue droppés |
| SIGHUP pendant une exécution | Les exécutions en cours terminent, nouvelle config pour les suivantes |
| Hook sur un nom d'événement inconnu (`relay.updated`, faute de frappe) | `[WARN] hooks: … which this server never emits` au chargement ; le fichier reste accepté, le hook ne se déclenche jamais |
| Hook sur `host.discover`, `host.rerouted`, `host.removed`, `relay.discover/rerouted/removed/converged` | Accepté, aucun avertissement ; **jamais déclenché en v3.0.6** (à venir) |
| `relay.down` à l'arrêt propre du maître | Aucun : le nouveau maître s'annonce par `relay.failover` |
| Parent < 3.0.6 recevant les nouveaux événements d'un enfant 3.0.6 | Événement jeté avec `[SECURITY WARNING] … unsupported event kind`, lien conservé ; `host.reconnect` ignoré jusqu'au prochain snapshot (DEPLOYMENT.md : parents d'abord) |
| `conn_seq` absent, invalide ou hors 1..2³¹ (en-tête, `relay_hello`, `relay_ack`) | Traité comme 1 : `host.up` / `relay.up` |
| Webhook d'un `relay.*` | Pas d'objet `host`, objet `relay` (§5) |
