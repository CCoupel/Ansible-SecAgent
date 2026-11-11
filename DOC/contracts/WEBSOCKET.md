# Contrat d'interface — WebSocket (secagent-server ↔ secagent-minion)

> Interface opérationnelle entre le secagent-server et le secagent-minion.
> Canal bidirectionnel multiplexé par `task_id`.
> Sources : `DOC/common/ARCHITECTURE.md` §4 · `DOC/agent/AGENT_SPEC.md` §4-§6

---

## 1. Connexion

```
Endpoint  : WSS /ws/agent  (port 7770 ou 7772, TLS natif v3.0.3)
Initiateur: secagent-minion (sortant uniquement)
Auth      : Authorization: Bearer <JWT HMAC-HS256>
TLS       : obligatoire (TLS natif, version minimale TLS 1.2 — `server/tls.go:169`)
```

Handshake HTTP → upgrade WebSocket :
```http
GET /ws/agent HTTP/1.1
Host: relay.example.com
Upgrade: websocket
Connection: Upgrade
Authorization: Bearer eyJhbGci...
```

Le serveur valide le JWT (signature + expiration + JTI blacklist) avant d'accepter l'upgrade, puis vérifie l'agent : un hostname inconnu, un JTI remplacé ou un agent **révoqué** (drapeau persistant `revoked`, même si l'entrée de blacklist a expiré, #193) est refusé en `401` avant l'upgrade (`server/helpers.go:205-218`). Seul le rôle `agent` est accepté sur `/ws/agent` (un JWT d'un autre rôle, ou un jeton plugin, est refusé : `ws/handler.go:409`).

### En-tête `X-SecAgent-Conn-Seq` (v3.0.6, additif)

```http
X-SecAgent-Conn-Seq: 3
```

Posé par le minion à côté de `Authorization` : nombre de connexions que **ce process** a ouvertes vers le serveur depuis son démarrage (1 = première). Règle : **seuls les handshakes RÉUSSIS comptent** : la valeur annoncée au dial est le nombre de handshakes réussis du process + 1 ; une tentative échouée (dial, upgrade refusé, ack refusé) n'incrémente pas, donc `1` = première connexion réussie depuis le démarrage, même après N échecs. Entier décimal `1..2³¹` ; **absent, vide, nul, négatif, non décimal ou hors borne ⇒ traité comme 1** (fail-safe). Le serveur n'en garde rien : `1` ⇒ événement `host.up` (nouveau process : démarrage du service ou de l'hôte), `> 1` ⇒ `host.reconnect` (même process qui revient : coupure, bascule du relais, keepalive), jamais les deux. Un minion v3.0.5 n'envoie pas l'en-tête ⇒ toujours `host.up`. Un serveur v3.0.5 l'ignore. Le JWT ne peut pas porter cette valeur (claims signés par le serveur).

---

## 2. Format d'enveloppe

Tous les messages (dans les deux sens) sont du JSON texte :

```json
{
  "task_id": "uuid-v4",
  "type": "<type>",
  ...champs spécifiques au type
}
```

`task_id` identifie la tâche et permet au serveur de router la réponse vers la future HTTP bloquante correspondante.

---

## 3. Messages Serveur → Agent

### `exec` — Exécution de commande

```json
{
  "task_id": "t-001",
  "type": "exec",
  "cmd": "python3 /tmp/.ansible/tmp-xyz/module.py",
  "stdin": "<base64 | null>",
  "timeout": 30,
  "become": false,
  "become_method": "sudo",
  "expires_at": 1234567890
}
```

| Champ | Type | Description |
|---|---|---|
| `task_id` | string | UUID-v4 généré par le plugin |
| `cmd` | string | Commande shell à exécuter |
| `stdin` | string\|null | Données stdin en base64 (become_pass, pipelining) |
| `timeout` | int | Secondes avant SIGTERM du subprocess |
| `become` | bool | Élévation de privilèges — masquer `stdin` dans les logs |
| `become_method` | string | `sudo`, `su`, `pbrun`... |
| `expires_at` | int | Timestamp UNIX — l'agent **refuse** si dépassé |

**Contrainte sécurité :** si `become: true`, le champ `stdin` est masqué dans tous les logs. Ne jamais loguer son contenu.

---

### `put_file` — Transfert de fichier vers l'agent

```json
{
  "task_id": "t-002",
  "type": "put_file",
  "dest": "/tmp/.ansible/tmp-xyz/module.py",
  "data": "<base64 du contenu>",
  "mode": "0700"
}
```

| Champ | Type | Description |
|---|---|---|
| `dest` | string | Chemin absolu de destination sur l'agent |
| `data` | string | Contenu du fichier encodé en base64 |
| `mode` | string | Permissions octal (`0700`, `0644`...) |

**Limite : 500 KB décodé.** Si dépassé, l'agent répond `rc: 1, error: "payload_too_large"`.

---

### `fetch_file` — Récupération de fichier depuis l'agent

```json
{
  "task_id": "t-003",
  "type": "fetch_file",
  "src": "/etc/myapp/config.yml"
}
```

---

### `cancel` — Annulation de tâche

```json
{
  "task_id": "t-001",
  "type": "cancel"
}
```

L'agent envoie `SIGTERM` au subprocess associé au `task_id`. Le mapping `task_id → subprocess` est **interne à l'agent**, jamais exposé.

---

### Keepalive de `/ws/agent` (v3.0.5)

Le relais envoie un **ping WebSocket** à chaque agent connecté toutes les `AGENT_WS_PING_INTERVAL` (défaut `30s`, entre 5 s et 60 s ; borne haute liée aux réessais du minion sur un 401, ~84 s : la règle N1 ne juge une connexion morte qu'après un intervalle de silence) et ferme la connexion (puis la désenregistre : `host.down`, tâches en cours en erreur `agent_disconnected`) si **rien** n'arrive (ni pong, ni trame) pendant `2 × AGENT_WS_PING_INTERVAL`. Un agent qui lit sa socket répond par un pong automatiquement (gorilla, côté minion : aucun changement requis, à condition que sa boucle de lecture ne reste pas bloquée). Avant v3.0.5 le relais n'avait ni ping ni délai (coupure franche détectée par le keepalive TCP, ~150 s).

**Sonde (N1)** : une reconnexion qui présente le JWT *précédent* (JTI remplacé, voir `rekey`) alors qu'une connexion paraît vivante pour l'hôte déclenche un ping de sonde ; l'ancienne connexion n'est jugée morte que si son dernier signe de vie (pong ou trame) date d'au moins un `AGENT_WS_PING_INTERVAL` **et** qu'elle ne répond pas au ping de sonde sous `AGENT_WS_PROBE_TIMEOUT` (défaut `5s`, entre 1 s et 30 s) : elle est alors fermée et la reconnexion acceptée. Sinon (signe de vie récent, réponse, ou plus de 64 sondes simultanées sur le relais) la reconnexion reçoit un 401 sans remplacer la connexion. Une sonde à la fois par hôte ; le handshake attend au plus ce délai.

### `rekey` — Nouveau JWT pour l'agent

```json
{
  "type": "rekey",
  "token_encrypted": "<base64 RSA-OAEP(SHA-256) du JWT, chiffré avec la clé publique de l'agent>"
}
```

Pas de `task_id`. L'agent déchiffre le JWT, le persiste (`token.jwt`, 0600) et l'utilise pour ses reconnexions ; la connexion en cours est maintenue. Le JTI précédent est remplacé : refusé en HTTP 401 à toute reconnexion (corps générique `unauthorized` ; le motif `token_replaced` n'apparaît que dans le journal du relay). Une trame `rekey` sans `token_encrypted` (repli du serveur quand le chiffrement échoue) demande à l'agent de se ré-enrôler.

**Émissions** (format identique, un minion antérieur à v3.0.5 les traite déjà) :

1. rotation de `JWT_SECRET_KEY` (`security keys rotate`) ;
2. reconnexion d'un agent avec le JWT signé par l'ancien secret ;
3. **[CHANGED v3.0.5, #217] renouvellement périodique** : le relay envoie un JWT frais à chaque agent connecté avant l'expiration du sien, toutes les `AGENT_JWT_RENEW_INTERVAL` (défaut `AGENT_JWT_TTL`/3, gigue ±10 %). `AGENT_JWT_TTL` : 24 h par défaut (1 h avant v3.0.5), entre 5 min et 7 jours. Un agent révoqué ne reçoit rien ; un état en lecture seule non plus. Voir `DOC/security/SECURITY.md` §5.

`/ws/agent` : la sémantique du 401 (JTI remplacé, révoqué ou expiré) est inchangée.

---

## 4. Messages Agent → Serveur

### `ack` — Prise en compte

```json
{
  "task_id": "t-001",
  "type": "ack",
  "status": "running"
}
```

Envoyé **immédiatement** après le démarrage du subprocess, avant tout stdout.

---

### `stdout` — Streaming sortie standard

```json
{
  "task_id": "t-001",
  "type": "stdout",
  "data": "ligne de sortie...\n"
}
```

Buffer max : **5 MB total** par tâche. Au-delà, tronqué + `truncated: true` dans le `result` final.

---

### `result` — Résultat final

#### Pour `exec`

```json
{
  "task_id": "t-001",
  "type": "result",
  "rc": 0,
  "stdout": "<stdout complet accumulé>",
  "stderr": "<stderr>",
  "truncated": false
}
```

| `rc` | Signification |
|---|---|
| `0` | Succès |
| `1+` | Erreur applicative |
| `-15` | Annulé (SIGTERM reçu) |
| `-1` | Agent busy (`max_concurrent_tasks` atteint) |

#### Pour `put_file`

```json
{
  "task_id": "t-002",
  "type": "result",
  "rc": 0
}
```

Erreur `payload_too_large` :
```json
{
  "task_id": "t-002",
  "type": "result",
  "rc": 1,
  "error": "payload_too_large"
}
```

#### Pour `fetch_file`

```json
{
  "task_id": "t-003",
  "type": "result",
  "rc": 0,
  "data": "<base64 du contenu du fichier>"
}
```

---

## 5. Codes de fermeture WebSocket

| Code | Émis par le serveur ? | Signification | Comportement de l'agent |
|---|---|---|---|
| `4000` | Oui — uniquement à la suppression d'un agent (`DELETE /api/admin/minions/{hostname}`, `handlers/admin.go:644`) | Fermeture normale | Reconnexion avec backoff exponentiel : 1s → 2s → 4s → … → 60s |
| `4001` | Oui — révocation (`POST /api/admin/revoke/{hostname}`) | Token révoqué | **Arrêt définitif — NE PAS reconnecter** ; le minion sort avec le code **77** |
| `4002` | **Non** — constante définie (`ws/handler.go:24`) mais jamais émise | Token expiré (réservé) | Aucun traitement dédié : l'agent reconnecte comme pour tout code autre que `4001` |
| `1001` | Oui — arrêt propre du serveur, perte du verrou maître (`server/server.go:566,602`) | Going Away | Reconnexion avec backoff exponentiel (jamais `4001`, pour ne pas interdire la reconnexion au nouveau maître) |
| réseau | — | Déconnexion réseau | Backoff exponentiel |

Seul `4001` arrête l'agent (`ReconnectManager.ShouldReconnect`, `secagent-minion/internal/ws/dispatcher.go:159`). Les codes `4003` (« re-enrollment requis ») et `4004` (« conflit hostname ») **n'existent pas** : le serveur ne les émet jamais et l'agent ne les traite pas. Le ré-enrôlement est déclenché par un `401` sur l'upgrade WebSocket (JWT rejeté), pas par un code de fermeture. Les codes `4010` et `4012` appartiennent au lien relay ↔ relay (`/ws/relay`), pas à `/ws/agent`.

---

## 6. Gestion de la concurrence (agent)

```
MAX_CONCURRENT_TASKS = 10  (variable d'environnement MAX_CONCURRENT_TASKS du minion)
```

Si le sémaphore est saturé, l'agent répond immédiatement :
```json
{
  "task_id": "...",
  "type": "result",
  "rc": -1,
  "stdout": "",
  "stderr": "agent_busy",
  "truncated": false
}
```
→ Le minion Go n'émet pas de champ `error` dans ce message : le serveur le relaie à l'appelant comme un résultat ordinaire (`rc: -1`, `stderr: "agent_busy"`). Le serveur sait traduire un résultat portant `error: "agent_busy"` en HTTP `429` (`handlers/exec.go:237`), mais le minion Go ne produit pas ce champ aujourd'hui.

---

## 7. Invariants

- Une seule connexion WebSocket par agent (identifié par `hostname` extrait du JWT)
- Toutes les tâches d'un même agent sont multiplexées sur cette connexion unique
- Le serveur stocke `ws_connections[hostname]` en mémoire — perte sur restart node. La HA est assurée par l'état fichier (v3.0.3, voir DEPLOYMENT.md)
- Heartbeat : ping WebSocket standard (pas de message applicatif dédié)

---

## 8. Liens relais (`/ws/relay`) — renvoi

Le contrat complet des liens enfant ↔ parent (handshake, `topology_snapshot`, `event_forward`) est dans `DOC/server/SERVER_SPEC.md` §9.2. Ajouts v3.0.6 (additifs) :

- `relay_hello.conn_seq` (pull) et `relay_ack.conn_seq` (push, renvoyé par l'enfant) : entier décimal `1..2³¹`, nombre de connexions du process enfant vers son parent ; **seuls les handshakes RÉUSSIS comptent** : la valeur annoncée au dial est le nombre de handshakes réussis du process + 1 ; une tentative échouée (dial, upgrade refusé, ack refusé) n'incrémente pas, donc `1` = première connexion réussie depuis le démarrage, même après N échecs. Même règle en pull et en push ; absent/invalide ⇒ traité comme 1. Le parent en déduit `relay.up` (≤ 1) ou `relay.reconnect` (> 1) au premier `topology_snapshot`.
- `event_forward` : kinds `relay.failover`, `relay.up`, `relay.reconnect`, `relay.down`, `relay.discover`, `relay.rerouted`, `relay.removed`, `relay.converged`, `host.reconnect`, `host.discover`, `host.rerouted`, `host.removed` ; les `relay.*` n'ont **pas** de `hostname` (clé `relay_id`). Un parent v3.0.5 jette les kinds inconnus sans fermer le lien.

- `host.rerouted` (#244) : `hostname`, `cause` = `moved` (la route d'un hôte a changé de relais ou de chemin) | `direct` (un hôte routé par un relais se connecte maintenant à ce nœud) | `indirect` (un hôte qui était connecté à ce nœud revient par un relais), `old_chain`, `new_chain` (chaînes **descendantes** : elles commencent au pair direct du nœud et finissent au relais qui porte l'hôte ; ≤ 32 identifiants), `old_relay` / `new_relay` (identifiants de relais valides : le **dernier** élément de `old_chain` / `new_chain`), `relay_chain` comme les autres événements d'hôte (origine en premier). Une première route, une route identique ou une bascule actif/passif n'émettent rien. Un conflit est annoncé par `host.conflict` **puis** `host.rerouted`. Un hôte dont l'agent vit sur le nœud n'est jamais re-routé (`host.conflict` seul).
- `relay.rerouted` (#244) : `relay_id` (le relais déplacé), `old_chain`, `new_chain` (descendantes, dernier élément = le relais), `hosts_routed` (hôtes du snapshot routés par ce relais) ; émis **une fois par relais** dont la chaîne connue du nœud diffère de celle d'un `topology_snapshot` (reparent, y compris le passage de descendant d'un pair à pair direct) ; **aucun** `host.rerouted` par hôte sur un snapshot. Un relais jamais vu n'émet rien.
- Hooks : variables `old_relay`, `new_relay` (`SECAGENT_OLD_RELAY`, `SECAGENT_NEW_RELAY`) pour les deux kinds ; corps de webhook : objet `change` `{old_relay, new_relay, old_chain, new_chain, cause}` (`cause` seulement pour `host.rerouted`).
- `relay.converged` (#246) : émis **une seule fois** par un nœud promu (racine ou non), juste après son `relay.failover`, quand tous les relais enfants déclarés sont revenus (lien direct, ou relais déclaré sous un lien) ou, sinon, au délai `RELAY_CONVERGENCE_TIMEOUT` (défaut 60 s, bornes 1 s..10 min, durée Go ou nombre de secondes). Champs : `relay_id` (le nœud), `relays_connected`, `relays_missing`, `hosts_direct` (agents connectés au nœud), `hosts_routed` (routes du nœud), `upstream_dropped_events_total` (compteur de la file amont). Un nœud sans enfant déclaré l'émet aussitôt (`0`/`0`). Jamais réémis ; rien n'est émis pendant l'arrêt du nœud. Propagé vers le parent comme `relay.failover`. Un relais mort pour de bon n'est visible que par `relays_missing` au délai.
