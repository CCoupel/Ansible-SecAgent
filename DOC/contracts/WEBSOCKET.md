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

Le serveur valide le JWT (signature + expiration + JTI blacklist) avant d'accepter l'upgrade. Seul le rôle `agent` est accepté sur `/ws/agent` (un JWT d'un autre rôle, ou un jeton plugin, est refusé : `ws/handler.go:409`).

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

### `rekey` — Rotation des clefs serveur

```json
{
  "type": "rekey"
}
```

Pas de `task_id`. Déclenche un ré-enrollment automatique côté agent (voir `DOC/contracts/REST_ENROLLMENT.md`).

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
