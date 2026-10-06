# Contrat d'interface — REST Plugin (Ansible → secagent-server)

> Interface entre les plugins Ansible (connection plugin, inventory plugin, secagent-inventory binary)
> et le secagent-server.
> Endpoint : HTTPS :7770 (TLS natif v3.0.3)
> Sources : `DOC/plugins/PLUGINS_SPEC.md` · `DOC/inventory/INVENTORY_SPEC.md` · `DOC/server/SERVER_SPEC.md` §3

---

## 1. Authentification

Tous les endpoints de cette interface requièrent :

```http
Authorization: Bearer <PLUGIN_TOKEN>
```

Le `PLUGIN_TOKEN` est un token statique créé par l'admin :
```bash
secagent-server tokens create --role plugin --description "ansible-control-prod" \
  --allowed-ips "192.168.1.10/32" --allowed-hostname-pattern "ansible-control-[0-9]+"
```

Validation serveur à chaque requête :
1. Token hash vérifié contre table `plugin_tokens`
2. IP source vérifiée contre `allowed_ips` (CIDR)
3. Header `X-Relay-Client-Host` vérifié contre `allowed_hostname_pattern` (regexp Go ancrée `^(?:pattern)$`, si configuré)
4. Token non révoqué (`revoked = 0`)

Header optionnel pour le binding hostname (utile derrière NAT) :
```http
X-Relay-Client-Host: ansible-control-prod
```

---

## 2. `GET /api/inventory` — Inventaire dynamique Ansible (v3.0.2+)

### Requête

```http
GET /api/inventory?only_connected=false&relay=<relay_id>
Authorization: Bearer <PLUGIN_TOKEN>
```

| Paramètre | Type | Défaut | Description |
|---|---|---|---|
| `only_connected` | bool | `false` | `true` = exclure les agents déconnectés |
| `relay` | string | (absent) | ID d'un relay (optionnel, v3.0.2+) — limite l'inventaire à la descendance de ce relay |

### Réponse 200

```json
{
  "all": {
    "hosts": ["host-C"],
    "children": ["dmz1", "zone2"]
  },
  "dmz1": {
    "hosts": ["host-A", "host-B"],
    "children": ["zone-a"],
    "vars": {"region": "dmz"}
  },
  "zone-a": {
    "hosts": ["host-D"],
    "children": [],
    "vars": {"zone": "a"}
  },
  "zone2": {
    "hosts": ["host-C"],
    "children": [],
    "vars": {}
  },
  "_meta": {
    "hostvars": {
      "host-A": {
        "ansible_connection": "relay",
        "ansible_host": "host-A",
        "secagent_status": "connected",
        "secagent_last_seen": "2026-03-06T10:00:00Z",
        "secagent_relay_chain": ["dmz1"],
        "secagent_next_hop": "dmz1"
      },
      "host-D": {
        "ansible_connection": "relay",
        "ansible_host": "host-D",
        "secagent_status": "connected",
        "secagent_last_seen": "2026-03-06T10:00:00Z",
        "secagent_relay_chain": ["zone-a", "dmz1"],
        "secagent_next_hop": "zone-a"
      }
    }
  }
}
```

**Format hiérarchique (v3.0.2+)** :
- Groupes (`all`, `dmz1`, `zone-a`, `zone2`) = noms exacts des relays dans la descendance
- `children` = relays enfants directs (hiérarchie récursive)
- `vars` = `RELAY_GROUP_VARS` du relay (JSON)
- Chaînes `secagent_relay_chain` = ordre **origine en premier** (relay le plus proche de l'agent d'abord)
- `secagent_next_hop` = relay enfant direct vers lequel router la tâche

Les agents `disconnected` sont inclus par défaut. Ansible les marquera `UNREACHABLE` lors de l'exécution.

### Codes d'erreur

| HTTP | Signification |
|---|---|
| `400` | Paramètre `relay` mal formé (voir format `relayIDShape` : `^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$`) |
| `401` | Token invalide ou révoqué |
| `403` | IP source non autorisée ou hostname non autorisé |

---

## 3. `POST /api/exec/{hostname}` — Exécution de commande (bloquant)

Appel **synchrone bloquant**. Le plugin attend la réponse HTTP (contrainte Ansible : `exec_command()` est synchrone).

### Requête

```http
POST /api/exec/{hostname}
Authorization: Bearer <PLUGIN_TOKEN>
Content-Type: application/json
```

```json
{
  "task_id": "uuid-v4",
  "cmd": "python3 /tmp/.ansible/tmp-xyz/AnsiballZ_command.py",
  "stdin": "<base64 | null>",
  "timeout": 30,
  "become": false,
  "become_method": "sudo"
}
```

| Champ | Type | Description |
|---|---|---|
| `task_id` | string | UUID-v4 généré par le plugin (idempotence) |
| `cmd` | string | Commande à exécuter sur l'hôte cible |
| `stdin` | string\|null | Données stdin en base64 (become_pass, pipelining) |
| `timeout` | int | Timeout en secondes (défaut 30) |
| `become` | bool | Élévation de privilèges |
| `become_method` | string | `sudo` (défaut), `su`, `pbrun`... |

**Note pipelining :** si `ANSIBLE_PIPELINING=true`, Ansible injecte le module Python via `stdin`. Le plugin le transmet via ce champ.

### Réponse 200

```json
{
  "rc": 0,
  "stdout": "output de la commande...",
  "stderr": "",
  "truncated": false
}
```

| Champ | Description |
|---|---|
| `rc` | Code retour du subprocess sur l'agent |
| `stdout` | Sortie standard (max 5MB, tronquée si `truncated: true`) |
| `stderr` | Sortie d'erreur |
| `truncated` | `true` si stdout dépasse 5MB |

### Codes d'erreur

| HTTP | Corps JSON | Exception Ansible |
|---|---|---|
| `503` | `{"error": "agent_offline"}` | `AnsibleConnectionError` (UNREACHABLE) |
| `503` | `{"error": "agent_suspended"}` | `AnsibleConnectionError` (agent suspendu par l'admin, #173) |
| `503` | `{"error": "agent_state_unavailable"}` | `AnsibleConnectionError` (état de suspension illisible, fail closed) |
| `504` | `{"error": "timeout"}` | `AnsibleConnectionError` (timeout) |
| `500` | `{"error": "agent_disconnected"}` | `AnsibleConnectionError` |
| `429` | `{"error": "agent_busy"}` | `AnsibleConnectionError` |
| `401` | `{"error": "unauthorized"}` | `AnsibleAuthenticationFailure` |
| `403` | `{"error": "forbidden"}` | `AnsibleAuthenticationFailure` |

---

## 4. `POST /api/upload/{hostname}` — Transfert de fichier

### Requête

```http
POST /api/upload/{hostname}
Authorization: Bearer <PLUGIN_TOKEN>
Content-Type: application/json
```

```json
{
  "task_id": "uuid-v4",
  "dest": "/tmp/.ansible/tmp-xyz/module.py",
  "data": "<base64 du contenu du fichier>",
  "mode": "0700"
}
```

**Limite : 500 KB** (taille du fichier décodé). Si dépassé → `413`.

### Réponse 200

```json
{ "rc": 0 }
```

### Codes d'erreur

| HTTP | Corps JSON | Exception Ansible |
|---|---|---|
| `413` | `{"error": "payload_too_large"}` | `AnsibleError` |
| `503` | `{"error": "agent_offline"}` | `AnsibleConnectionError` |
| `504` | `{"error": "timeout"}` | `AnsibleConnectionError` |

---

## 5. `POST /api/fetch/{hostname}` — Récupération de fichier

### Requête

```http
POST /api/fetch/{hostname}
Authorization: Bearer <PLUGIN_TOKEN>
Content-Type: application/json
```

```json
{
  "task_id": "uuid-v4",
  "src": "/etc/myapp/config.yml"
}
```

### Réponse 200

```json
{
  "rc": 0,
  "data": "<base64 du contenu du fichier>"
}
```

### Codes d'erreur

| HTTP | Corps JSON | Exception Ansible |
|---|---|---|
| `503` | `{"error": "agent_offline"}` | `AnsibleConnectionError` |
| `504` | `{"error": "timeout"}` | `AnsibleConnectionError` |
| `500` | `{"error": "file_not_found"}` | `AnsibleError` |

---

## 6. Tableau récapitulatif

| Endpoint | Méthode | Auth | Bloquant | Usage |
|---|---|---|---|---|
| `/api/inventory` | GET | PLUGIN_TOKEN | Non | Inventaire Ansible |
| `/api/exec/{host}` | POST | PLUGIN_TOKEN | Oui | Exécution commande |
| `/api/upload/{host}` | POST | PLUGIN_TOKEN | Oui | put_file |
| `/api/fetch/{host}` | POST | PLUGIN_TOKEN | Oui | fetch_file |

---

## 7. Configuration côté plugin

### Variables d'environnement

| Variable | Défaut | Description |
|---|---|---|
| `RELAY_SERVER_URL` | `https://localhost:7770` | URL du secagent-server |
| `RELAY_TOKEN` | — | PLUGIN_TOKEN (Bearer) |
| `RELAY_CA_BUNDLE` | — | CA custom (certificat auto-signé) |
| `RELAY_INSECURE_TLS` | `false` | Désactiver vérif TLS (tests uniquement) |
| `RELAY_ONLY_CONNECTED` | `false` | Filtrer inventaire sur agents connectés |

### Variables hôte Ansible (`host_vars/my-host.yml`)

```yaml
ansible_connection: relay
ansible_host: my-host
ansible_secagent_server_url: https://relay.example.com
ansible_secagent_timeout: 60
```
