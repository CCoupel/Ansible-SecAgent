# secagent-minion — Spécifications techniques

> Référence complète pour le composant secagent-minion (GO).
> Source canonique : `DOC/common/ARCHITECTURE.md` §2, §4, §9-§13, §16, §18
> Sécurité : `DOC/security/SECURITY.md` §3 (enrollment), §4 (connexion WS)
> **Contrats d'interface** : `DOC/contracts/REST_ENROLLMENT.md` · `DOC/contracts/WEBSOCKET.md`

---

## 1. Rôle et périmètre

Le secagent-minion est un **daemon** déployé sur chaque hôte géré. Il initie et maintient
une connexion WebSocket sortante vers le secagent-server. Il n'écoute sur aucun port.

```
Ansible Control Node ──REST──▶ Relay Server ◀──WSS── secagent-minion (hôte cible)
```

**L'agent ne connaît pas NATS.** Il parle uniquement WebSocket avec le serveur.

### Blocs internes (GO)

```
GO/cmd/agent/
├── main.go                     — point d'entrée, chargement config + keypair
├── internal/enrollment/
│   ├── keys.go                 — génération RSA-4096, sérialisation PEM, stockage 0600
│   └── enroll.go               — POST /api/register, challenge OAEP, decrypt JWT
├── internal/ws/
│   └── dispatcher.go           — connexion WSS, backoff, sémaphore concurrence, code 4001
├── internal/executor/
│   └── executor.go             — subprocess, 5MB buffer, become stdin masqué
├── internal/registry/
│   ├── registry.go             — async JSON persisté sur disque
│   ├── alive_unix.go           — vérification PID via /proc (Linux)
│   └── alive_windows.go        — vérification PID via OpenProcess (Windows)
└── internal/facts/
    └── facts.go                — hostname, OS, IP, version (stdlib uniquement)
```

---

## 2. Fichiers de l'agent sur le système

| Chemin (défaut) | Variable d'env | Contenu | Permissions |
|---|---|---|---|
| `/etc/secagent-minion/id_rsa` | `RELAY_PRIVATE_KEY` | Clef privée RSA-4096 PEM | 0600 |
| `/etc/secagent-minion/token.jwt` | `RELAY_JWT_PATH` | JWT courant (réécrit à chaque enrollment) | 0600 |
| `/var/lib/secagent-minion/async_jobs.json` | — | Registre jobs async persisté | 0644 |
| `/var/log/secagent-minion/agent.log` | — | Logs (become_pass masqué) | 0644 |

---

## 3. Enrollment (premier démarrage)

> Protocole complet : `DOC/security/SECURITY.md` §3

```
1. Génère RSA-4096 si absent → stocke à RELAY_PRIVATE_KEY (mode 0600)
2. POST /api/register {hostname, pubkey_pem, enrollment_token}
3. Server répond : {challenge: OAEP(nonce, agent_pubkey)}
4. Agent déchiffre nonce → répond : {response: OAEP(nonce+token, server_pubkey)}
5. Server valide → répond : {jwt: OAEP(jwt, agent_pubkey)}
6. Agent déchiffre JWT → stocke à RELAY_JWT_PATH
7. Ouvre WSS /ws/agent avec Authorization: Bearer <JWT>
```

**Sur 403 :** token invalide ou expiré → log + retry selon politique backoff.
**Sur 401 après rotation clefs :** ré-enrollment automatique.

---

## 4. Protocole WebSocket — messages reçus (Server → Agent)

### `exec` — Exécution de commande

```json
{
  "task_id": "uuid-v4",
  "type": "exec",
  "cmd": "python3 /tmp/.ansible/tmp-xyz/module.py",
  "stdin": "<base64|null>",
  "timeout": 30,
  "become": false,
  "become_method": "sudo",
  "expires_at": 1234567890
}
```

- Refuser si `expires_at` dépassé (tâche périmée)
- `stdin` masqué dans les logs si `become: true` (**CRITIQUE sécurité**)

### `put_file` — Transfert de fichier vers l'agent

```json
{
  "task_id": "t-002",
  "type": "put_file",
  "dest": "/tmp/.ansible/tmp-xyz/module.py",
  "data": "<base64>",
  "mode": "0700"
}
```

Limite : **500KB** décodé. Retourner `rc: 1, error: "payload_too_large"` si dépassé.

### `fetch_file` — Récupération de fichier

```json
{
  "task_id": "t-003",
  "type": "fetch_file",
  "src": "/etc/myapp/config.yml"
}
```

### `cancel` — Annulation

```json
{ "task_id": "t-001", "type": "cancel" }
```

`SIGTERM` sur le subprocess associé au `task_id`. Le mapping `task_id → subprocess` est **interne à l'agent**, jamais exposé.

### `rekey` — Rotation des clefs serveur

```json
{ "type": "rekey" }
```

Déclenche un ré-enrollment automatique : génère un nouvel enrollment token (via admin si possible) ou utilise le mécanisme de refresh token.

---

## 5. Protocole WebSocket — messages envoyés (Agent → Server)

### `ack` — Prise en compte

```json
{ "task_id": "t-001", "type": "ack", "status": "running" }
```
Envoyé immédiatement après démarrage du subprocess, avant tout stdout.

### `stdout` — Streaming

```json
{ "task_id": "t-001", "type": "stdout", "data": "ligne...\n" }
```

### `result` — Résultat final

```json
{
  "task_id": "t-001",
  "type": "result",
  "rc": 0,
  "stdout": "<stdout accumulé>",
  "stderr": "<stderr>",
  "truncated": false
}
```

| `rc` | Signification |
|---|---|
| `0` | Succès |
| `1+` | Erreur applicative |
| `-15` | Annulé (SIGTERM) |
| `-1` | Agent busy (max_concurrent_tasks atteint) |

---

## 6. Codes de fermeture WebSocket

| Code | Signification | Comportement **obligatoire** |
|---|---|---|
| `4001` | Token révoqué | **Arrêt définitif — NE PAS reconnecter** |
| `4002` | Token expiré | Refresh token → reconnecter |
| `4003` | Re-enrollment requis | Ré-enrollment complet → reconnecter |
| `1001` / réseau | Restart / coupure | Backoff exponentiel : 1s→2s→4s→…→60s max |

---

## 7. Gestion de la concurrence

```
MAX_CONCURRENT_TASKS = 10  (configurable via RELAY_MAX_TASKS)

Si dépassé → répondre immédiatement :
  { "task_id": "...", "type": "result", "rc": -1, "error": "agent_busy" }
  → HTTP 429 retourné au plugin Ansible

Un subprocess par tâche (jamais de thread pool).
Isolation complète par task_id.
```

---

## 8. Tâches async (Ansible async/poll)

**Phase 1 — Lancement (`poll: 0`) :**

Server envoie `exec` avec `"async": true, "async_timeout": 3600`.
Agent daemonise le subprocess, répond immédiatement :

```json
{
  "task_id": "t-async-001",
  "type": "result",
  "rc": 0,
  "stdout": "{\"ansible_job_id\": \"jid-uuid\", \"started\": 1, \"finished\": 0}"
}
```

Job persisté dans `async_jobs.json` :
```json
{
  "jid-uuid": {
    "pid": 4521,
    "cmd": "./deploy.sh",
    "started_at": 1234567890,
    "timeout": 3600,
    "stdout_path": "/tmp/.ansible-secagent/jid-uuid.stdout"
  }
}
```

**Phase 2 — Vérification (`async_status`) :**

Ansible envoie `exec` avec `async_status.py --jid jid-uuid`.
L'agent intercepte et consulte le registre :

```json
// En cours :
{ "ansible_job_id": "jid-uuid", "finished": 0, "stdout": "<partiel>" }
// Terminé :
{ "ansible_job_id": "jid-uuid", "finished": 1, "rc": 0, "stdout": "<complet>" }
```

**Reprise après restart :**
- PID actif (`/proc/{pid}` existe) → job en cours
- PID mort → job terminé avec `rc: -1, error: "agent_restarted"`

---

## 9. become (élévation de privilèges)

```
Sans become :
  cmd = "python3 /tmp/module.py"
  stdin = null

Avec become_pass :
  cmd = "sudo -H -S -n -u root python3 /tmp/module.py"
  stdin = base64("monmotdepasse\n")
  become = true   ← flag pour masquage des logs (OBLIGATOIRE)
```

```go
// Subprocess GO — become via stdin
proc := exec.Command("bash", "-c", cmd)
if stdinData != nil {
    proc.Stdin = bytes.NewReader(stdinData)
}
// CRITIQUE : masquer stdin dans les logs si become=true
```

---

## 10. Gestion des erreurs

| Situation | Comportement agent |
|---|---|
| Timeout tâche | `SIGTERM` subprocess → `rc: -15` |
| Agent busy | `rc: -1, error: "agent_busy"` immédiat |
| Fichier > 500KB | `rc: 1, error: "payload_too_large"` |
| WS close 4001 | Arrêt définitif |
| WS close 4002/4003 | Ré-enrollment puis reconnexion |
| Réseau coupé | Backoff expo (1s→60s) |

---

## 11. Configuration (variables d'environnement)

| Variable | Défaut | Description |
|---|---|---|
| `RELAY_SERVER_URL` | `wss://localhost:7772/ws/agent` | URL WSS du relay server |
| `RELAY_API_URL` | `https://localhost:7770` | URL HTTPS pour enrollment |
| `RELAY_PRIVATE_KEY` | `/etc/secagent-minion/id_rsa` | Chemin clef privée RSA-4096 |
| `RELAY_JWT_PATH` | `/etc/secagent-minion/token.jwt` | Chemin token JWT |
| `RELAY_MAX_TASKS` | `10` | Tâches simultanées max |
| `RELAY_STDOUT_MAX` | `5242880` | Buffer stdout max (5MB) |
| `RELAY_INSECURE_TLS` | `false` | Désactiver vérif TLS (tests uniquement) |

---

## 12. Déploiement systemd

```ini
# /etc/systemd/system/secagent-minion.service
[Unit]
Description=Ansible-SecAgent Agent
After=network.target

[Service]
Type=simple
User=secagent-minion
Group=secagent-minion
ExecStart=/usr/local/bin/secagent-minion
Restart=on-failure
RestartSec=5s
Environment=RELAY_SERVER_URL=wss://relay.example.com/ws/agent
Environment=RELAY_API_URL=https://relay.example.com
EnvironmentFile=-/etc/secagent-minion/env

[Install]
WantedBy=multi-user.target
```

```bash
# Installation
useradd -r -s /sbin/nologin secagent-minion
mkdir -p /etc/secagent-minion && chown secagent-minion: /etc/secagent-minion && chmod 700 /etc/secagent-minion
cp secagent-minion /usr/local/bin/ && chmod 755 /usr/local/bin/secagent-minion
systemctl daemon-reload && systemctl enable --now secagent-minion
```
