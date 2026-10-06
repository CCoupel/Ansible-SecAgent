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
GO/cmd/secagent-minion/
├── main.go                     — point d'entrée, chargement config + keypair
├── internal/enrollment/
│   ├── keys.go                 — génération RSA-4096, sérialisation PEM, stockage 0600
│   ├── enrollment.go           — POST /api/register, challenge OAEP, decrypt JWT
│   └── reenroll.go             — ré-enrôlement (401) et déchiffrement du rekey
├── internal/ws/
│   └── dispatcher.go           — connexion WSS, backoff, sémaphore concurrence, code 4001 (exit 77), codes de sortie 77/78
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
2. POST /api/register {hostname, public_key_pem, enrollment_token}
3. Server répond : {challenge: OAEP(nonce, agent_pubkey), server_public_key_pem}
4. Agent déchiffre nonce → POST /api/register {hostname, public_key_pem, enrollment_token, challenge_response: OAEP(nonce+token, server_pubkey)}
5. Server valide → répond : {token_encrypted / jwt_encrypted: OAEP(jwt, agent_pubkey), server_public_key_pem}
6. Agent déchiffre JWT → stocke à RELAY_JWT_PATH
7. Ouvre WSS /ws/agent avec Authorization: Bearer <JWT>
```

**Sur 403 :** token invalide, expiré ou déjà consommé → refus permanent, aucun retry, sortie avec le code 78.
**Sur 401 à l'upgrade WebSocket (JWT rejeté, par ex. après rotation des clefs) :** ré-enrollment automatique. Autre échec (réseau, 5xx) : retry avec backoff.

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

| Code | Émis par le serveur | Comportement **obligatoire** |
|---|---|---|
| `4001` | Oui (révocation admin) | **Arrêt définitif — NE PAS reconnecter** (code de sortie 77) |
| `4000` | Oui (agent supprimé par l'admin) | Reconnexion avec backoff |
| `1001` / réseau | Oui (arrêt propre du serveur, perte du verrou) / coupure | Backoff exponentiel : 1s→2s→4s→…→60s max |

Tout code autre que `4001` provoque une reconnexion (`ShouldReconnect`, `internal/ws/dispatcher.go:159`). `4002` est défini côté serveur mais jamais émis ; `4003` et `4004` n'existent pas. Un JWT expiré ou invalide est refusé par un **HTTP 401** à l'upgrade WebSocket, ce qui déclenche le ré-enrôlement (§12). Voir `DOC/contracts/WEBSOCKET.md` §5.

---

## 7. Codes de sortie du processus

L'agent quitte avec un code de sortie distinctif dans les cas critiques (enrôlement/révocation) :

| Code | Cause | Comportement container/systemd |
|---|---|---|
| 0 | Shutdown propre (coupure de WS normale) | Redémarrage par policy |
| 1 | Erreur générique ou état critique | Redémarrage par policy |
| 77 | **Agent révoqué** (token JTI blacklisté, close 4001) | **NE PAS redémarrer** — état terminal, l'opérateur doit intervenir |
| 78 | **Enrôlement refusé définitivement** (403 persistant, enrollment_token expiré/invalide) | **NE PAS redémarrer** — état terminal, l'opérateur doit créer un nouveau jeton d'enrôlement |

**Configuration systemd recommandée** (pour éviter les redémarrages inutiles) :
```ini
Restart=on-failure
RestartSec=30s
StartLimitIntervalSec=600
StartLimitBurst=5
RestartPreventExitStatus=77 78
```

Avec cette config, l'unité s'arrête définitivement (passe en état `failed`) après 5 redémarrages en 10 min, ou immédiatement si le code est 77/78, forçant l'intervention manuelle.

---

## 8. Gestion de la concurrence

```
MAX_CONCURRENT_TASKS = 10  (variable d'environnement MAX_CONCURRENT_TASKS ; entier > 0, sinon 10)

Si dépassé → répondre immédiatement :
  { "task_id": "...", "type": "result", "rc": -1, "stdout": "", "stderr": "agent_busy", "truncated": false }
  → relayé à l'appelant comme un résultat ordinaire (le serveur ne traduit en HTTP 429
    qu'un résultat portant `error: "agent_busy"`, que le minion Go n'émet pas)

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
| Agent busy | `rc: -1, stderr: "agent_busy"` immédiat |
| Fichier > 500KB | `rc: 1, error: "payload_too_large"` |
| WS close 4001 | Arrêt définitif |
| HTTP 401 à l'upgrade WS | Ré-enrollment puis reconnexion |
| Réseau coupé | Backoff expo (1s→60s) |

---

## 11. Configuration (variables d'environnement)

| Variable | Défaut | Description |
|---|---|---|
| `RELAY_SERVER_URL` | `https://localhost:7770` | URL(s) HTTPS du relay server pour l'API d'enrollment — liste séparée par virgules pour failover (ex: `https://relay1:7770,https://relay2:7770`). Appairé par position avec `RELAY_WS_URL` (mêmes longueurs imposées) |
| `RELAY_WS_URL` | `wss://localhost:7772/ws/agent` | URL(s) WSS du relay server pour le WebSocket agent — liste séparée par virgules, pairées par position avec `RELAY_SERVER_URL` (ex: 2 serveurs = 2 WS URLs : `wss://relay1:7772/ws/agent,wss://relay2:7772/ws/agent`) |
| `RELAY_PRIVATE_KEY` | `/etc/secagent-minion/id_rsa` | Chemin clef privée RSA-4096 |
| `RELAY_JWT_PATH` | `/etc/secagent-minion/token.jwt` | Chemin token JWT |
| `RELAY_ENROLLMENT_TOKEN` | — (obligatoire tant que le minion n'a pas de JWT) | Jeton d'enrôlement `secagent_enr_…` ; jamais journalisé. Absent et pas de JWT → arrêt avec le code 78 |
| `RELAY_AGENT_HOSTNAME` | `os.Hostname()` | Hostname déclaré à l'enrôlement |
| `RELAY_CA_BUNDLE` | système | Bundle CA PEM personnalisé pour vérifier le serveur |
| `RELAY_ASYNC_DIR` | `/var/lib/secagent-minion/async` | Répertoire du registre des tâches async |
| `MAX_CONCURRENT_TASKS` | `10` | Tâches simultanées max (entier > 0) |
| `RELAY_INSECURE_TLS` | `false` | Désactiver vérif TLS (tests uniquement) |

Il n'existe pas de variable pour la taille du buffer stdout : la limite de 5 MiB est une constante (`executor.StdoutBufferMax`). Le minion n'a pas de fichier de configuration : uniquement des variables d'environnement (`loadConfig`, `main.go:398`).

---

## 11b. Environnement des tâches (liste blanche)

Les tâches Ansible **ne reçoivent PAS** l'environnement complet du minion. Une liste blanche stricte prévient les fuites de secrets :

**Variables **toujours interdites**:**
- `RELAY_*` (tous) : enrollment token, JWT, clefs, URLs
- Suffixes `*_TOKEN`, `*_KEY`, `*_SECRET`, `*_PASSWORD`, `*_PASS` (defense in depth)

**Variables **autorisées**:**
- `PATH`, `HOME`, `TZ`, `USER`, `LOGNAME`, `SHELL`, `TMPDIR`, `LANG`
- Préfixe `LC_*` (locale settings)
- **Aucune autre** — pas de variables utilisateur custom directement

**Mécanisme :**
- Ansible utilise `environment:` dans les playbooks → les variables sont écrites dans la command-line (`VAR=value cmd`), interprétées par le shell, pas passées via l'environnement du processus
- `become_pass` voyage en `stdin`, jamais en environnement
- Cette isolation empêche une playbook d'accéder aux secrets de la minion (enrollment token, JWT, etc.)

---

## 12. Ré-enrôlement et reconnexa

Le minion gère automatiquement le ré-enrôlement en cas de token JWT expiré ou révoqué :

1. **HTTP 401 à l'upgrade WebSocket** (JWT expiré, invalide ou rejeté) → le JWT local est supprimé, appel à `POST /api/register` (enrollment, avec `RELAY_ENROLLMENT_TOKEN`) → nouveau JWT → reconnexion WS. Aucun code de fermeture WebSocket ne déclenche un ré-enrôlement
2. **Message `rekey`** → le minion déchiffre `token_encrypted`, remplace son JWT et garde la connexion ouverte (pas de ré-enrôlement)
3. **Échec corrigible d'enrôlement** (réseau, 400, 5xx, coupure après envoi de la requête) → nouveau tour après un backoff exponentiel : **1 s → 2 s → 4 s → … → 60 s max**, en passant à l'adresse suivante de `RELAY_SERVER_URL`
   - Un jeton à usage unique n'est jamais rejoué sur une autre adresse une fois la requête partie
   - Si le serveur accepte le ré-enrôlement mais refuse encore le JWT à l'upgrade, un message `[ERROR] N consecutive authentication cycles without a working WebSocket…` est journalisé et le minion continue avec backoff
4. **HTTP 403 à l'enrôlement** (jeton invalide, expiré ou déjà consommé) ou **absence de `RELAY_ENROLLMENT_TOKEN`** → **refus permanent, aucun retry** : sortie avec le code **78**. **NE PAS redémarrer** (voir codes sortie §7) ; l'opérateur crée un nouveau jeton d'enrôlement

---

## 13. Déploiement systemd

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
Environment=RELAY_SERVER_URL=https://relay.example.com:7770
Environment=RELAY_WS_URL=wss://relay.example.com:7772/ws/agent
RestartPreventExitStatus=77 78
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
