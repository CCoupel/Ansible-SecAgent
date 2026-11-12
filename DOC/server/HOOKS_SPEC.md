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

Au chargement de la configuration (démarrage et `SIGHUP`), le serveur journalise, pour chaque événement visé par plusieurs hooks : `[WARN] hooks: N hooks listen to event "<événement>": only the first matching one runs, the others never do` (`hooks/config.go:86-95`, v3.0.6). Le compte est fait sur le nom d'événement seul, **sans tenir compte des `filter`** : deux hooks aux filtres disjoints déclenchent donc aussi cet avertissement, sans conséquence. Le fichier reste accepté. **L'exécution de tous les hooks correspondants est prévue en v3.0.7** ; d'ici là, regrouper les actions.

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
| `host.deleted` | **[DEPRECATED]** Agent supprimé (`DELETE /api/admin/minions/{hostname}`) : toujours émis en v3.0.6, **juste après `host.removed`**, mais **déprécié depuis la v3.0.6 et retiré en v3.0.7 ([BREAKING] annoncé)**. Un hook qui s'y abonne produit au chargement `[WARN] … host.deleted: deprecated since v3.0.6, removed in v3.0.7, use host.removed` (`hooks/config.go`). Migrer vers `host.removed` (#277) |
| `host.conflict` | Hôte revendiqué par un second relay alors qu'il est déjà routé vers un autre : émis une fois par changement de propriétaire, statut `ancien->nouveau` (`server/server.go:530` ; accepté en `event_forward` par `ws/relay_handler.go:1789` ; SERVER_SPEC §9.5a) |
| `host.rerouted` | (v3.0.6, #244) La **route** d'un hôte a changé, vue de ce nœud. `cause` = `moved` (la route est passée d'un relais ou d'un chemin à un autre) \| `direct` (un hôte routé par un relais se connecte maintenant à ce nœud) \| `indirect` (un hôte qui était connecté à ce nœud revient par un relais). Variables `old_relay`, `new_relay`, `old_chain`, `new_chain`, `cause` (§4). La route précédente est celle que **ce process** a vue : une première route, une route identique, un redémarrage ou une bascule actif/passif n'émettent rien. Un conflit donne `host.conflict` **puis** `host.rerouted`. **Un seul événement par changement le long de l'arbre** : un nœud n'émet le sien que s'il est l'ancêtre commun des deux routes, sinon il distribue et remonte celui de son pair ; les chaînes émises par un enfant sont relatives à cet enfant ; **limite** : si l'enfant redémarre, le `host.rerouted` est perdu pour tout l'arbre (détail sous « Pertes à la bascule »). Un hôte dont l'agent vit sur le nœud n'est jamais re-routé (`ws/relay_reroute.go`, `snapshotDiff`, `rerouteCause`, `noteLocalConnect` ; test `ws/relay_reroute_test.go`) |
| `host.discover` | (v3.0.6, #266) **Première** connexion d'un hôte : émis **une seule fois** dans la vie de l'hôte, au premier handshake `/ws/agent` réussi, **avant** `host.up` (même hostname : FIFO). La date est persistée (`first_seen_at`, `relay.state`) : jamais à une reconnexion, un redémarrage ou une bascule actif/passif (état partagé) ; un `DELETE` puis un ré-enrôlement en redonnent un, un ré-enrôlement sans suppression non. Variables `enrolled_at`, `first_seen_at`. **Au moins une fois** : l'événement part avant la persistance (écriture groupée au plus `RELAY_FIRST_SEEN_FLUSH` = 1 s plus tard) ; un arrêt brutal dans cette fenêtre peut en donner **un de plus**. Les hôtes **indirects** ne sont pas marqués par le parent : leur `discover` est celui de leur relais direct, propagé (`ws/handler.go`, `RegisterConnection` ; `storage/store_first_seen.go`, `MarkFirstSeen`) |
| `host.removed` | (v3.0.6, #266) Un administrateur **supprime** l'hôte (`DELETE /api/admin/minions/{hostname}`) : `cause` = `deleted`, `enrolled_at`, `first_seen_at` (absent si l'hôte ne s'est jamais connecté). Propagé aux ancêtres. Une **révocation** n'en émet jamais. Remplace `host.deleted` (`handlers/admin.go`, `AdminDeleteMinion` ; `TestAdminRevokeMinion_EmitsNoRemoved`) |

**Événements de relais** (v3.0.6 ; **sans hostname**, clé d'ordre : le `relay_id` ; `{{hostname}}` et `{{status}}` y sont vides)

| Événement | Déclencheur | Émis par |
|-----------|-------------|----------|
| `relay.failover` | Cette instance vient de devenir le **maître** du `STATE_DIR` : `cause` = `takeover` (verrou périmé d'un maître disparu supprimé, `previous_instance_id` renseigné si connu) ou `start` (verrou libre : premier démarrage ou arrêt propre du maître précédent). Émis **avant** l'ouverture de tout port (`server/instance.go:249`, `server/server.go:816`) | le nouveau maître ; un nœud non racine le remonte à son parent (mis en file avant que le lien amont existe) |
| `relay.up` | Premier `topology_snapshot` accepté d'un lien relais dont le process enfant annonce sa première connexion (`conn_seq` ≤ 1 ou absent) ; un snapshot de **remplacement** sur un lien déjà établi n'émet rien (`ws/relay_handler.go:1770`) | le parent direct du lien ; remonte aux ancêtres |
| `relay.reconnect` | Idem, mais `conn_seq` > 1 : même process enfant qui revient. Exclusif avec `relay.up` | le parent direct ; remonte |
| `relay.down` | Fin d'un lien dont le snapshot avait été accepté. **Aucun** événement quand ce nœud ferme lui-même ses liens en s'arrêtant (`CloseAllLinks`, dialer arrêté) : c'est le nouveau maître qui s'annonce par `relay.failover` (`ws/relay_handler.go:1228`) | le parent direct ; remonte |
| `relay.rerouted` | (v3.0.6, #244) Un `topology_snapshot` montre qu'un **relais** a changé de chaîne (reparent, y compris le passage de descendant d'un pair à pair direct). **Un seul événement par relais déplacé**, jamais un `host.rerouted` par hôte sur un snapshot. Variables : `relay_id`, `old_relay`, `new_relay`, `old_chain`, `new_chain`, `hosts_routed` (hôtes du snapshot dont la chaîne passe par ce relais, ceux derrière ses enfants compris). Un relais jamais vu n'émet rien | le parent qui reçoit le snapshot ; remonte |
| `relay.converged` | (v3.0.6, #246) **Un seul** par promotion : émis après `relay.failover`, quand tous les relais enfants déclarés sont revenus (lien direct, ou relais déclaré sous un lien), ou, sinon, au délai `RELAY_CONVERGENCE_TIMEOUT` (§9). Un nœud sans enfant déclaré l'émet aussitôt. Variables : `relay_id` (le nœud), `relays_connected`, `relays_missing`, `hosts_direct`, `hosts_routed`, `upstream_dropped_events_total`. Jamais réémis ; rien n'est émis pendant l'arrêt du nœud. Un relais mort pour de bon n'apparaît que dans `relays_missing` au délai (`server/convergence.go`) | le nœud promu ; remonte comme `relay.failover` |
| `relay.discover` | (v3.0.6, #266) **Premier** snapshot accepté d'un relais **déclaré** (`POST /api/admin/relays`, pull ou push), vu par son **parent direct**, **avant** `relay.up`/`relay.reconnect`. Une seule fois (marque `first_seen_at` du `relay_nodes`) : jamais à une reconnexion, un redémarrage de l'enfant, un snapshot de remplacement ni une bascule du parent. Variables `relay_id`, `mode`, `hosts_routed` (hôtes du snapshot), `first_seen_at`. Un `relay.discover` **reçu** d'un enfant ne marque rien ; un relais reparenté vers un ancêtre qui ne l'a jamais tenu directement donne un second `relay.discover` chez cet ancêtre ; les descendants appris seulement par la topologie ne sont pas marqués (`ws/relay_handler.go`, `emitRelayUp` ; `TestRelayDiscover_BeforeUpOnlyOnceForADeclaredRelay`) | le parent direct ; remonte |
| `relay.removed` | (v3.0.6, #266) Un administrateur **supprime** la déclaration d'un relais (`DELETE /api/admin/relays/{id}`) : `cause` = `deleted`, `mode`, `first_seen_at` (absent si jamais connecté), `hosts_routed` **à titre informatif** (hôtes routés par ce relais au moment de la suppression). Émis **avant** le `relay.down reason=revoked` que la coupure du lien provoque. **Pas de cascade** : un seul événement, aucun `relay.removed`/`host.removed` pour le sous-arbre. Une révocation n'en émet jamais. Un `DELETE` d'un relais **sans JTI suivi** (relais **push**, ou déclaré avant #153) **non révoqué** est refusé en **409 `relay_not_revoked`** : le révoquer d'abord (`POST /api/admin/relays/{id}/revoke`) (`handlers/admin_relays.go:377-390`, `AdminDeleteRelay` ; `TestAdminDeleteRelay_EmitsOneRelayRemoved`) | le nœud qui supprime ; remonte |

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
| `{{enrolled_at}}` | Date d'enrollment RFC3339 | `host.new`, `host.discover`, `host.removed` (v3.0.6) |
| `{{first_seen_at}}` | (v3.0.6, #266) Date RFC3339 du **premier handshake** de l'hôte, ou du premier snapshot accepté d'un relais ; vide si l'hôte ou le relais ne s'est jamais connecté (`hooks/event.go`) | `host.discover`, `host.removed`, `relay.discover`, `relay.removed` |
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

Variables de re-routage et de convergence (v3.0.6, #244 #246) :

| Variable | Sens | Présent pour |
|----------|------|-------------|
| `{{old_relay}}`, `{{new_relay}}` | Le relais qui **portait** l'hôte (ou le relais déplacé), avant / après : le **dernier** élément de `old_chain` / `new_chain` (`Detail.OldRelay()`/`NewRelay()`, `hooks/event.go:35-40`). Vide s'il n'y a pas de chaîne | `host.rerouted`, `relay.rerouted` |
| `{{old_chain}}`, `{{new_chain}}` | Chaîne **descendante** (virgules) : du pair direct de ce nœud jusqu'au relais qui porte l'hôte ; ≤ 32 ids | idem |
| `{{cause}}` | `moved` \| `direct` \| `indirect` | `host.rerouted` (et `takeover` \| `start` pour `relay.failover`, `deleted` pour `host.removed` et `relay.removed`) |
| `{{relays_connected}}`, `{{relays_missing}}` | Relais enfants déclarés revenus / encore absents à l'émission | `relay.converged` |
| `{{hosts_direct}}`, `{{hosts_routed}}` | Agents connectés à ce nœud / routes du nœud | `relay.converged` |
| `{{upstream_dropped_events_total}}` | Compteur cumulé des événements ascendants perdus (§9b « File amont ») | `relay.converged` |

En variable d'environnement (action `shell`) : `SECAGENT_OLD_RELAY`, `SECAGENT_NEW_RELAY` (`hooks/event.go`, `eventEnvKeys`).

**Règle de rendu (`Render`, v3.0.6, #246)** : un jeton `{{variable}}` d'une variable **connue** mais absente de l'événement (par exemple `{{cause}}` dans l'URL d'un hook `host.up`, ou `{{conn_seq}}` pour un minion < 3.0.6) est rendu **vide** ; un jeton **inconnu** (`{{foo}}`, faute de frappe) est laissé **tel quel** (`hooks/template.go`, `KnownVars()` ; tests `hooks/template_test.go`). Cela vaut pour tous les champs rendus : arguments et environnement `shell`, URL, corps et en-têtes `webhook`/`api`, ligne `file`. Avant la v3.0.6, un jeton de variable connue mais absente restait littéral dans la sortie : une URL de webhook devait donc ne contenir que des variables présentes pour l'événement.

**Ordre de `relay_chain`** : dans les **événements** (`{{relay_chain}}`, `relay_chain` d'un webhook, `event_forward`), l'**origine est en premier** (`dmz2,dmz1` : dmz2 est le relais d'où vient l'événement, dmz1 son parent) ; dans les **routes** et les chaînes `old_chain` / `new_chain` des re-routages, l'ordre est **descendant** (du pair direct du nœud au relais qui porte l'hôte). Ne pas comparer les deux sans les inverser.

Les variables du premier tableau sont toujours définies (chaîne vide quand elles ne s'appliquent pas).

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
| `host.deleted` (déprécié, retiré en v3.0.7) | `"deleted"` | absent |

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

Champs de `relay` (omis quand ils ne s'appliquent pas) : `relay_id` (toujours), `mode`, `reason`, `cause`, `instance_id`, `previous_instance_id`, `conn_seq`, `hosts_routed`, `relays_below`, `relays_below_ids`, et (v3.0.6) `old_chain`, `new_chain`, `relays_connected`, `relays_missing`, `hosts_direct`, `upstream_dropped_events_total` (voir §4 pour le sens ; `hooks/executor.go:93-115`).

**Re-routage** : `host.rerouted` et `relay.rerouted` ajoutent un objet **`change`** (`hooks/executor.go:149-160`), `cause` seulement pour `host.rerouted` :

```json
{
  "event": "host.rerouted",
  "timestamp": "2026-11-11T10:00:00Z",
  "host":   { "hostname": "web-01", "status": "connected" },
  "change": { "old_relay": "dmz1", "new_relay": "dmz2", "old_chain": ["dmz1"], "new_chain": ["dmz2"], "cause": "moved" },
  "relay_chain": ["dmz2"], "relay_origin": "dmz2"
}
```

`relay.converged` porte ses compteurs dans `relay` : `{ "relay_id": "root", "relays_connected": 2, "relays_missing": 0, "hosts_direct": 14, "hosts_routed": 3000, "upstream_dropped_events_total": 0 }`. `relay.failover` d'un nœud racine n'a pas de `relay_chain` :

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
      "event": "host.removed",
      "actions": [
        {
          "type":    "api",
          "method":  "DELETE",
          "url":     "http://cmdb.internal/api/assets/{{hostname}}",
          "headers": { "Authorization": "Bearer mon-token" }
        }
      ]
    },
    {
      "event": "host.rerouted",
      "actions": [
        {
          "type":   "file",
          "path":   "/var/log/secagent/events.log",
          "append": "{{timestamp}} REROUTE {{hostname}} {{cause}} {{old_relay}}->{{new_relay}}\n"
        }
      ]
    },
    {
      "event": "relay.rerouted",
      "actions": [
        {
          "type":   "file",
          "path":   "/var/log/secagent/events.log",
          "append": "{{timestamp}} RELAY-REROUTE {{relay_id}} {{old_chain}}->{{new_chain}} hosts={{hosts_routed}}\n"
        }
      ]
    },
    {
      "event": "relay.converged",
      "actions": [
        {
          "type":   "webhook",
          "url":    "https://monitoring.internal/api/failover-done",
          "secret": "hmac-key-prod"
        },
        {
          "type":   "file",
          "path":   "/var/log/secagent/events.log",
          "append": "{{timestamp}} CONVERGED {{relay_id}} connected={{relays_connected}} missing={{relays_missing}} direct={{hosts_direct}} dropped={{upstream_dropped_events_total}}\n"
        }
      ]
    },
    {
      "event": "host.discover",
      "actions": [
        {
          "type":   "file",
          "path":   "/var/log/secagent/events.log",
          "append": "{{timestamp}} DISCOVER {{hostname}} enrolled={{enrolled_at}} first_seen={{first_seen_at}}\n"
        }
      ]
    },
    {
      "event": "relay.discover",
      "actions": [
        {
          "type":   "file",
          "path":   "/var/log/secagent/events.log",
          "append": "{{timestamp}} RELAY-DISCOVER {{relay_id}} mode={{mode}} hosts={{hosts_routed}}\n"
        }
      ]
    },
    {
      "event": "relay.removed",
      "actions": [
        {
          "type":   "file",
          "path":   "/var/log/secagent/events.log",
          "append": "{{timestamp}} RELAY-REMOVED {{relay_id}} cause={{cause}} hosts={{hosts_routed}}\n"
        }
      ]
    }
  ]
}
```

Après une bascule, un hook sur `relay.converged` est le bon déclencheur d'une resynchronisation par `GET /api/inventory` (voir « Pertes à la bascule »).

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
host.removed    api(DELETE http://cmdb/...)
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
| `RELAY_UPSTREAM_QUEUE_SIZE` | `10000` | (v3.0.6, #246) Capacité de la **file amont** d'un relais enfant : événements gardés tant que le lien vers le parent est coupé. Bornes **256 à 100 000** ; hors bornes ou non entier : défaut + `[WARN]` (`server/upstream_queue.go:20-25`). Voir « File amont » ci-dessous, y compris la mémoire |
| `RELAY_UPSTREAM_RATE` | `150` | (v3.0.6, #246) Cadence de rejeu vers le parent, en événements par seconde. Bornes **10 à 1000** ; hors bornes : défaut + `[WARN]` ; au-delà de 200, `[WARN]` : le parent refusera l'excédent (quota de 200/s par relais) |
| `RELAY_CONVERGENCE_TIMEOUT` | `60s` | (v3.0.6, #246) Délai maximal d'attente des relais enfants avant d'émettre `relay.converged`. Durée Go (`30s`, `2m`) ou nombre de secondes ; bornes **5 s à 10 min** ; hors bornes : défaut + `[WARN]` (`server/convergence.go:20-22,41-43`) |

### 9b. Traitement des événements : file, ordre, contre-pression (#183)

Le dispatcher est un **pool de workers** (`RELAY_HOOKS_MAX_CONCURRENT_ACTIONS`, défaut 64), chacun avec sa file FIFO bornée.
Un événement est confié au worker désigné par un **hachage du hostname** ; ce worker exécute les actions de l'événement **l'une après l'autre**.

- **Contre-pression, pas de perte** : une action n'est plus abandonnée parce que « trop d'actions tournent » : elle attend dans la file.
- **Ordre** : FIFO par hostname (`host.up` puis `host.down` d'un même hôte ne s'inversent jamais) ; **aucune garantie d'ordre entre hôtes**.
- **Isolation** : un webhook lent ne bloque que son worker (borné par `timeout_seconds`, défaut 10 s, plus les retries) ; les hôtes des autres workers progressent. Les hôtes du même worker attendent.
- **Dimensionnement** : la file contient `RELAY_HOOKS_QUEUE_SIZE` événements (défaut 10 000, réparti sur les workers : `ceil(taille/workers)` chacun, au moins 1) pour absorber plusieurs événements par hôte d'un parc de plus de 3 000 hôtes qui se reconnecte (bascule actif/passif, redémarrage). Mémoire : environ 200 octets + chaînes par événement, soit quelques Mo au défaut. Budget de débit : avec 64 workers et le pire timeout (10 s), 3 000 actions lentes se rattrapent en environ 470 s, toutes conservées.
- **Au-delà de la file** : l'événement est rejeté et **compté** (`hooks_dropped_events`) ; un seul `[WARN] hooks: N event(s) …` agrégé par minute, et une entrée **`dropped`** agrégée dans le journal des actions (`action_type:"dropped"`, `event:"*"`, le message donne les comptes). Jamais une ligne par événement.
- **Compteurs** (`GET /api/admin/status`, `secagent-server server status`) : `hooks_queue_depth` (+ `hooks_queue_capacity`), `hooks_inflight`, `hooks_dropped_events`, `hooks_dropped_actions` (actions perdues avec des événements en file lors d'un arrêt brutal : doit rester 0 en marche).
- **Arrêt propre** (signal d'arrêt) : les serveurs HTTP s'arrêtent, puis la file est vidée pendant 10 s au plus ; le reste est compté et loggué (`[SHUTDOWN] hooks: N event(s) still pending`). **Arrêt brutal** (perte du verrou actif/passif, #163) : sortie immédiate, les événements en file sont perdus, comptés et loggués (`Dispatcher stopped: N queued event(s) not processed`). Les `host.down` des agents directs que cet arrêt déconnecte ne sont **ni exécutés ni remontés** : le dispatcher est annulé avant la fermeture des liens (`server.go:791-806`). Voir « Bascule actif/passif » ci-dessous, tableau « Pertes à la bascule », pour ce que voit le nouveau maître.
- **Budgets séparés avec #179** : les actions de hook ne consomment pas de slot de tâche `exec` ; une action `api` qui appellerait l'API exec du serveur serait soumise à #179 comme n'importe quel client.


### Cycle de vie : `discover` et `removed` (v3.0.6, #266)

`host.discover` / `relay.discover` sont émis à la **première connexion** persistée, `host.removed` / `relay.removed` à la **suppression** par un administrateur (tableau des événements, §2).

- **Bascule actif/passif : 0 `discover`.** La marque `first_seen_at` est dans `relay.state`, que les deux nœuds partagent : le nouveau maître sait que l'hôte ou le relais a déjà été vu et émet `host.reconnect` / `relay.reconnect`, jamais `discover`. De même pour un redémarrage de l'enfant, un snapshot de remplacement ou une reconnexion.
- **Livraison au moins une fois** : l'événement `discover` est émis **avant** la persistance de la marque, qui est écrite par lots (`RELAY_FIRST_SEEN_FLUSH`, 1 s par défaut, bornes 100 ms à 10 s ; hors bornes : défaut + `[WARN]`). Pendant l'écriture groupée, un second handshake du même hôte ne redonne **pas** de `discover` (les marques en cours d'écriture sont consultées jusqu'à la fin de la mutation) : **seul un arrêt brutal** (crash) dans cette seconde peut redonner **un** `discover` de plus ; l'écriture est refusée sans verrou maître (garde #163) et les marques en attente sont conservées et réessayées. Au-delà de 100 000 marques en attente, la marque (donc l'événement) est abandonnée (fail-safe).
- **Aucune écriture déclenchée par un événement reçu** : seul un handshake local réussi (`RegisterConnection`) ou le premier snapshot d'un relais déclaré marque. Un `discover` propagé par un enfant ne modifie pas l'état de l'ancêtre.
- **`late` sans effet** : un événement `discover` / `removed` rejoué depuis la file amont (marqueur `late`, « File amont ») est traité **normalement**, et son **horodatage d'origine** est conservé jusqu'aux hooks du récepteur (`{{timestamp}}` = l'heure de l'événement, pas celle du rejeu ; `TestHookEvent_CarriesTheOriginTimestamp`). **Borné** (`originTimestamp`) : un horodatage **postérieur à maintenant + 5 min**, ou **antérieur à maintenant − 7 jours pour un événement non `late`**, est **remplacé par l'heure d'arrivée** ; le remplacement est compté et loggué **une fois par minute** (`[RELAY]`). Un événement `late` peut donc être plus ancien que 7 jours.
- **Vague de `discover` à la montée** : les hôtes et relais **déjà enrôlés** n'ont pas de marque : **chacun** émet **un** `discover` à sa première connexion après la montée en v3.0.6 (aucun rattrapage). Prévoir une rafale (voir `DEPLOYMENT.md`) ; la file des hooks (`RELAY_HOOKS_QUEUE_SIZE`) absorbe 10 000 événements.
- **Hôtes inactifs** : il n'y a **pas** d'événement `host.stale` ; la surveillance des hôtes inactifs est à la charge de l'administrateur, à partir de l'inventaire : `GET /api/admin/minions` (liste et détail) expose `status` et `last_seen` (RFC 3339, dernier contact vu ; valeur approximative, en retard d'au plus une écriture d'état), ainsi que `first_seen_at`.

### Règle du sous-arbre (v3.0.6, #266, T34)

Un relais ne remonte et ne distribue d'événements que pour les hôtes de **son sous-arbre**. Pour `host.down`, `host.discover`, `host.removed`, `host.rerouted`, `host.suspended`, `host.resumed` et `host.conflict` reçus d'un enfant (`host.up`, `host.new` et `host.reconnect` créent la route : le conflit existant reste la règle), `hostSubtreeRefusal` (`ws/relay_reroute.go`, appelée par `applyEventRouting`) refuse l'événement, **ni distribué ni remonté**, quand :

1. l'hôte est **connecté sur ce nœud** : `[SECURITY WARNING] … is connected locally` ;
2. le propriétaire de la route n'est **ni le pair ni un de ses descendants déclarés** : `[SECURITY WARNING] … is routed through another relay`, **sauf** l'**écho d'un déplacement légitime récent** : si le relais émetteur (ou un de ses descendants) est le **porteur que l'hôte vient de quitter** (mémoire `leftCarriers`, 10 min, alimentée aux changements de porteur et aux connexions locales), le refus est loggué au niveau **`[RELAY]`**, sans alarme de sécurité ;
3. il n'y a **aucune route connue** : `[RELAY] … has no route`, **sans alarme de sécurité** (état transitoire normal : parent redémarré avant son snapshot, reparentage).

**Exceptions sans route** : `host.discover` (il précède `host.up`, donc la route) et `host.conflict` sont acceptés pour un hôte sans route, si la `relay_chain` est cohérente avec le pair ; un hôte local ou routé ailleurs reste refusé. Les événements `late` suivent la **même** règle.

**Journalisation** : la **première** occurrence par (relais, kind, raison) est journalisée aussitôt, les suivantes agrégées en **une ligne par minute** (`dropreport`, table bornée à **256 triplets vivants par minute** ; au-delà, un refus est **compté** (`rerouteRefuseOverflow`) et rapporté : `[SECURITY WARNING] N refused event(s) … beyond the 256 tracked triplets`). **Nouveau descendant** : l'uplink de l'intermédiaire **retient** un événement dont la chaîne cite un relais **jamais déclaré sur la session du lien** (remise à zéro à chaque connexion ; ensemble alimenté par chaque snapshot envoyé, borné à 100 000), et ce **une seule fois par relais** : à sa libération, les relais de sa chaîne entrent dans l'ensemble. **Libération dès l'envoi d'un snapshot** (qu'il liste ou non le relais : le parent décide), ou au bout de **5 s** par retenue ; **plafond de 30 s de retenue cumulée par session**, au-delà de quoi plus rien n'est retenu. Un événement retenu à la fin de la session est **perdu et compté** (`upstream_dropped_events`). Un `relay.removed` d'un enfant supprimé ou un `host.down` d'un relais tombé citent un relais déjà déclaré : jamais retenus (`HoldEventsForSnapshotAfter`, `repeater/uplink.go` ; `TestUplink_EventForAnUndeclaredRelayWaitsForItsSnapshot`, test des 200 événements < 3 s). Un événement qui part sans que son relais soit déclaré est refusé par le parent. Avant la v3.0.6, un hôte sans route était accepté (**[CHANGED]**).

**Limite connue : un parent qui vient de démarrer** (mémoire des routes vide, aucune route encore dans le store) refuse avec `[RELAY] … has no route` — et **perd** — les `host.down` et `host.removed` qu'un enfant lui envoie pour des hôtes qu'il ne connaît pas encore ; il ne relaie pas les événements d'hôtes inconnus (`host.discover` et `host.conflict` font exception). L'état converge aux snapshots suivants ; resynchroniser par `GET /api/inventory` (revue LOT-3.3, mineur 6).

**Limite connue (#278)** : un `host.up` d'un enfant peut **réécrire la route d'un hôte annoncé par un autre pair** ; cela n'est qu'**alerté** (`host.conflict`), pas refusé.

### File amont : événements d'un relais enfant vers son parent (v3.0.6, #246)

Un relais enfant remonte ses événements (et ceux de son sous-arbre) à son parent par une **file bornée** (`RELAY_UPSTREAM_QUEUE_SIZE`, défaut 10 000, bornes 256 à 100 000), puis un **rejeu cadencé** (`RELAY_UPSTREAM_RATE`, défaut 150/s, bornes 10 à 1000). Elle ne bloque jamais un producteur (`upstreamQueue.Offer`, `server/upstream_queue.go:93`).

- **Lien coupé** : les événements s'accumulent dans la file ; à la reconnexion ils sont rejoués à la cadence configurée, sans coupure de la boucle du lien (les pings et snapshots restent servis : `repeater/uplink.go:194`). Rejouer 10 000 événements à 150/s prend environ **67 s** (1/150 s entre deux événements ; `TestUplink_ReplayIsPacedAtEventRate`).
- **Quota du parent** : le parent accepte au plus **200 `event_forward` par seconde et par `relay_id`** en **seau à jetons** : débit soutenu 200/s, **rafale de 400** (2 s de débit) acceptée après un silence, aucune exemption pour un rejeu (`ws/event_quota.go`, `eventQuotaBurst`). La cadence par défaut (150/s) reste sous ce débit ; une pause du parent suivie d'un rattrapage en rafale ne provoque plus de refus tant que la rafale tient dans le seau. Si `RELAY_UPSTREAM_RATE` dépasse 200, le serveur le signale au démarrage (`[WARN] RELAY_UPSTREAM_RATE=… exceeds the parent's event quota`) : l'excédent sera refusé par le parent, loggué une fois par minute et par identité, sans fermer le lien.
- **File pleine** : l'événement est **rejeté et compté**. Même un événement retiré de la file mais non envoyé (écriture en échec, chaîne en boucle) est compté. Compteur : `upstream_dropped_events` (`GET /api/admin/status`, `secagent-server server status`, avec `upstream_queue_depth` et `upstream_queue_capacity` ; une racine sans parent renvoie `0`, `0`, la capacité). **Un seul** `[WARN] … event(s) dropped in the last minute` par minute et **une seule** entrée `action_type:"upstream_dropped"` (`event:"*"`) dans le journal des actions (`GET /api/admin/hooks/log?event=*`), jamais une ligne par événement. Le rapport arrive après la première minute de pertes et est vidé à l'arrêt du nœud.
- **Lien coupé ou pas encore établi (pull comme push, T24)** : un nœud **non racine** met **tous** ses événements locaux, `host.*` compris, dans la file amont (`queueLocalEvent`, `server/upstream_queue.go:118-121`, `server/server.go:476-490`) ; ils sont rejoués, cadencés, dans la limite de la file, chacun gardant son horodatage d'origine. Un **débordement** est compté (`upstream_dropped_events`, un `[WARN]` et une entrée `upstream_dropped` par minute). Une **racine sans parent** ne met rien en file (`server.go:459-463`, `queueLocalEvent`).
- **Ordre de rejeu** : à la reconnexion, l'enfant envoie d'abord le `topology_snapshot`, puis les liens et états, puis l'`agent_list`, **puis** la file rejouée.
- **Marqueur `late`** : un événement resté plus de **10 s** dans la file (`LateEventAfter`, `repeater/uplink.go:395,405-406`) part avec `late:true` (champ additif de `event_forward`). Pour le parent, un `host.up` / `host.new` / `host.reconnect` tardif est de l'**historique** : il ne met pas la route à jour, ne crée ni conflit ni `host.rerouted` ; il est distribué et remonté seulement si l'hôte n'appartient pas à un autre pair ou à ce nœud, sinon il est **refusé**, compté et loggué une fois par minute (`[RELAY] … late event for a host owned elsewhere`) (`ws/relay_handler.go:2148`, `ws/relay_reroute.go:271` ; tests `TestLateHostUp_IsHistoryOnly`, `TestUplink_ReplayedEventIsMarkedLate`). Un `host.up` tardif d'un hôte reparti n'efface aucune route : le `host.down` rejoué le suit (FIFO). **Limite** : une coupure de moins de 10 s avec peu d'événements n'est pas marquée tardive (traitée comme vivante).
- **Livraison au plus une fois** : tant que l'enfant croit son lien vivant, il écrit sur la socket sans garder l'événement ; si le parent **gèle sans couper la connexion TCP** (processus figé, gel de conteneur), les écritures continuent d'être acquittées par le noyau jusqu'à la détection de la perte, **jusqu'à 90 s** (`PingInterval` 30 s × `readTimeoutFactor` 3, `repeater/client.go:52,54`, `uplink.go:158`). Les événements écrits dans cette fenêtre sont **perdus** et **non comptés** dans `upstream_dropped_events`. La file amont ne protège que les coupures **déjà détectées**. Mesuré en QUALIF : 23 événements perdus sur 24 pendant un gel du parent, aucun `dropped` (`_work/reports/dev-relay-qualif-upstream-queue-20261112.md`). Une correction (accusé `event_ack`, rejeu des non acquittés, déduplication par le parent) est prévue en **v3.0.7** ; d'ici là, resynchroniser par `GET /api/inventory`.
- **Mémoire** : la file est un canal de `RELAY_UPSTREAM_QUEUE_SIZE` événements ; **10 000 événements pleins ≈ 4,2 Mio de tas** (hostname et chaîne typiques ; mesure `TestUpstreamQueue_MemoryOfAFullQueue`). La taille d'un événement est bornée par la taille maximale d'un message WebSocket : une file à 100 000 événements peut donc occuper bien davantage dans le pire cas. **Quand on relève `RELAY_UPSTREAM_QUEUE_SIZE`, adapter `GOMEMLIMIT` (et la limite mémoire du conteneur) en conséquence.**

### Bascule actif/passif : ce que voit le nouveau maître (v3.0.6, #225)

Dans l'ordre :

1. **`relay.failover`** : émis par le nouveau maître dès qu'il tient le verrou, **avant** l'ouverture de tout port (`server/instance.go:249`). `cause` = `takeover` si le verrou d'un maître disparu était périmé (`previous_instance_id` = son identité, quand elle est connue), `start` si le verrou était libre. Après un arrêt **propre** du maître précédent, le verrou est libre : `cause=start`. Un nœud non racine le remonte à son parent, même avant que son lien amont soit rétabli.
2. **Agents directs** : ils se reconnectent avec leur compteur de process (`conn_seq > 1`) ⇒ **`host.reconnect`**, et non `host.up`.
3. **Relais enfants** : leurs liens se rétablissent et chaque premier `topology_snapshot` donne **`relay.reconnect`** (même process enfant) ou `relay.up` (enfant redémarré). Le maître sortant n'émet pas de `relay.down` pour les liens qu'il ferme lui-même en s'arrêtant.
4. **Hôtes derrière un relais enfant** : ils sont re-routés par le `topology_snapshot` **sans aucun événement `host.*`** (`ws/relay_handler.go`, `handleTopologySnapshot` n'émet que `relay.up|reconnect` ; test `TestFailoverChildHosts_NewMasterRoutesTheLeafWithoutAnEvent`). Pour savoir que leurs routes ont changé, s'abonner à `relay.failover` puis `relay.up|reconnect` ; l'inventaire reste la source de vérité de l'état.

Un snapshot de **remplacement** sur un lien déjà établi (changement de topologie) n'émet ni `relay.up` ni `relay.reconnect`.

#### Pertes à la bascule, par type d'hôte et d'arrêt (#247, option A)

**Décision du 2026-11-09 : option A, sans registre persistant.** Le relais ne garde aucune liste des hôtes connectés d'un process à l'autre : le nouveau maître ne peut donc pas déduire ce qui s'est passé pendant la fenêtre sans maître. Les pertes ci-dessous sont **connues et documentées**, pas corrigées.

| Hôtes | Arrêt **propre** du maître sortant | Arrêt **brutal** (perte du verrou, #163) |
|---|---|---|
| Agents directs, **vivants** à la bascule | Ils se reconnectent au nouveau maître : `host.reconnect` (`host.up` si le minion est < 3.0.6, `ws/handler.go:197-203`). | Idem. |
| Agents directs **connectés à l'ancien maître** | Le maître sortant ferme **tous** leurs WebSockets (`CloseAllLinks`, `server.go:766`) : chaque handler émet `host.down` (`ws/handler.go:212,232`), **y compris pour les agents qui se reconnectent aussitôt** au nouveau maître (`host.reconnect`). Ces `host.down` sont émis en pratique avant le drain (10 s au plus, `server.go:766-781`), sans garantie : un `host.down` tardif est **rejeté et compté** (`hooks_dropped_events`). L'ordre entre le `host.down` de l'ancien maître et le `host.reconnect` du nouveau n'est pas garanti. | **Tous** les `host.down` de l'ancien maître sont perdus (`Abort` annule le dispatcher avant `CloseAllLinks`, `server.go:795` puis `:802`). |
| Agents directs **tombés pendant la fenêtre** (jamais revenus) | **Aucun `host.down`**, ni du maître sortant (déjà parti) ni du nouveau (qui ne les a jamais vus connectés). C'est la vraie perte de l'option A. | Idem. |
| Hôtes **indirects** (derrière un relais enfant) | Le premier `topology_snapshot` du lien rétabli les re-route **sans aucun événement `host.*`** (`ws/relay_handler.go`, `handleTopologySnapshot`). Leurs connexions et déconnexions survenues pendant la fenêtre (lien coupé) sont **mises en file par l'enfant puis rejouées** après son snapshot, marquées `late` au-delà de 10 s (« File amont »), **dans la limite de sa file** (`RELAY_UPSTREAM_QUEUE_SIZE`, défaut 10 000, bornes 256 à 100 000 ; rejeu à `RELAY_UPSTREAM_RATE`, défaut 150/s : voir « File amont » ci-dessus) ; au-delà, elles sont perdues et comptées (`upstream_dropped_events`). Un événement `late` ne met pas la route à jour. | Idem. |
| **Parent gelé sans coupure TCP** (cause autre qu'une bascule) | Les événements d'un enfant écrits pendant la détection (jusqu'à 90 s) sont **perdus, non comptés** : livraison au plus une fois (« File amont »). Correction prévue en v3.0.7. | Idem. |
| **Parent qui vient de démarrer** (redémarrage, bascule : mémoire des routes vide) | `host.down` / `host.removed` d'un enfant pour un hôte que le parent ne connaît pas encore : refusés (`[RELAY] … has no route`), **perdus** (« Règle du sous-arbre »). | Idem. |
| **Re-routage** d'un hôte (`host.rerouted`) dont l'**enfant** qui l'émet **redémarre** | Sa mémoire des routes est vide : il n'émet rien, l'ancêtre (même premier saut des deux routes) reste silencieux : le `host.rerouted` est **perdu pour tout l'arbre**. | Idem. |

Un seul `host.rerouted` par changement le long de l'arbre : un nœud n'émet **le sien** que s'il est l'**ancêtre commun** des deux routes (l'ancienne et la nouvelle sortent par des pairs directs **différents**, ou l'hôte revient de local = `indirect`). Quand les deux routes passent par le **même** pair direct, le changement a eu lieu dans son sous-arbre : le nœud met sa mémoire à jour en silence et **distribue puis remonte** le `host.rerouted` que ce pair lui fait suivre (validé comme tout re-route d'un enfant, §10). Les chaînes d'un `host.rerouted` émis par un enfant sont **relatives à cet enfant** : elles commencent à son pair direct (pour un `direct`, `new_chain` = `[l'enfant]`), sans préfixe. **Limite connue** : si l'enfant **redémarre**, sa mémoire des routes est vide : il n'émet rien, l'ancêtre reste silencieux, et ce `host.rerouted` est **perdu pour tout l'arbre** (même cause que les pertes de la bascule : pas de registre persistant). Resynchroniser par `GET /api/inventory`. Source : `ws/relay_reroute.go` (`noteRoute`) ; `TestNoteRoute_OneEventPerChangeAlongTheTree`, `TestIntermediateNode_NoDuplicateHostRerouted`.

**Recommandation** : ne pas déduire l'état du parc des seuls événements `host.*` après une bascule. Sur `relay.failover`, puis une fois les liens rétablis (`relay.up` / `relay.reconnect` de chaque enfant attendu, et `relay.converged`, émis au plus tard après `RELAY_CONVERGENCE_TIMEOUT`), **resynchroniser par `GET /api/inventory`**, qui reste la source de vérité. Les trois variables `RELAY_UPSTREAM_QUEUE_SIZE`, `RELAY_UPSTREAM_RATE` et `RELAY_CONVERGENCE_TIMEOUT` sont décrites au §9 et dans « File amont » ci-dessus.

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
| Hook sur `host.deleted` | Accepté, mais `[WARN] … deprecated since v3.0.6, removed in v3.0.7, use host.removed` au chargement ; toujours déclenché en v3.0.6 |
| `host.discover` / `host.removed` / `relay.discover` / `relay.removed` rejoué (`late`) | Traité normalement ; horodatage d'origine conservé (« Cycle de vie ») |
| `host.*` d'un enfant pour un hôte hors de son sous-arbre | Refusé ; `[SECURITY WARNING]`, ou `[RELAY]` pour l'écho d'un déplacement récent ou un hôte sans route (« Règle du sous-arbre ») |
| Horodatage d'origine hors bornes (> now + 5 min, ou < now − 7 j hors `late`) | Remplacé par l'heure d'arrivée, compté, `[RELAY]` une fois par minute |
| `DELETE /api/admin/relays/{id}` d'un relais sans JTI suivi (push, ancien) **non révoqué** | **409 `relay_not_revoked`** ; aucun `relay.removed` ; révoquer d'abord |
| `DELETE` d'un relais ayant des descendants | Un seul `relay.removed` (`hosts_routed` informatif), pas de cascade |
| `host.rerouted` / `relay.rerouted` reçu d'un enfant et **incohérent avec son sous-arbre** (T16b) | Ni distribué ni remonté ; refus compté par (relais, kind, raison) et loggué **une fois par minute** (`[SECURITY WARNING] re-route event refused`). Règles : `old_relay`/`new_relay` = dernier élément de `old_chain`/`new_chain` ; chaque élément des chaînes est le pair ou un relais qu'il a déclaré ; `relay.rerouted` : `new_chain` = inverse de `relay_chain` ; `host.rerouted` : l'hôte a une route connue du nœud (`ws/relay_reroute.go`, `reroutedRefusal` ; test `TestReroutedRefusal`) |
| Arrêt ordonné d'un relais enfant (pull ou push) | Trame de fermeture **1001 going away** avant la fermeture de la socket : le parent journalise `relay.down reason=peer_closed:1001` et non `1006` (coupure réelle) (`repeater/uplink.go`, `Uplink.goingAway` ; test `uplink_goingaway_test.go`) |
| Variable connue absente / inconnue dans un modèle | Connue : rendue vide ; inconnue : laissée telle quelle (§4, `Render`) |
| File amont pleine ; `event_forward` au-delà du quota du parent | Perte comptée (`upstream_dropped_events`), un `[WARN]` et une entrée `upstream_dropped` par minute ; refus de quota loggué une fois par minute et par identité (« File amont ») |
| `relay.down` à l'arrêt propre du maître | Aucun : le nouveau maître s'annonce par `relay.failover` |
| Parent < 3.0.6 recevant les nouveaux événements d'un enfant 3.0.6 | Événement jeté avec `[SECURITY WARNING] … unsupported event kind`, lien conservé ; `host.reconnect` ignoré jusqu'au prochain snapshot (DEPLOYMENT.md : parents d'abord) |
| `conn_seq` absent, invalide ou hors 1..2³¹ (en-tête, `relay_hello`, `relay_ack`) | Traité comme 1 : `host.up` / `relay.up` |
| Webhook d'un `relay.*` | Pas d'objet `host`, objet `relay` (§5) |
