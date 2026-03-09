# Contrat d'interface — REST Plugin (Ansible → secagent-server)

> Interface entre les plugins Ansible (connection plugin, inventory plugin, secagent-inventory binary)
> et le secagent-server.
> Endpoint : HTTPS :7770 (via Caddy)
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
  --allowed-ips "192.168.1.10/32" --allowed-hostname "ansible-control-prod"
```

Validation serveur à chaque requête :
1. Token hash vérifié contre table `plugin_tokens`
2. IP source vérifiée contre `allowed_ips` (CIDR)
3. Header `X-Relay-Client-Host` vérifié contre `allowed_hostname` (si configuré)
4. Token non révoqué (`revoked = 0`)

Header optionnel pour le binding hostname (utile derrière NAT) :
```http
X-Relay-Client-Host: ansible-control-prod
```

---

## 2. `GET /api/inventory` — Inventaire dynamique Ansible

### Requête

```http
GET /api/inventory?only_connected=false
Authorization: Bearer <PLUGIN_TOKEN>
```

| Paramètre | Type | Défaut | Description |
|---|---|---|---|
| `only_connected` | bool | `false` | `true` = exclure les agents déconnectés |

### Réponse 200

```json
{
  "all": {
    "hosts": ["host-A", "host-B", "host-C"]
  },
  "_meta": {
    "hostvars": {
      "host-A": {
        "ansible_connection": "relay",
        "ansible_host": "host-A",
        "secagent_status": "connected",
        "secagent_last_seen": "2026-03-06T10:00:00Z"
      },
      "host-B": {
        "ansible_connection": "relay",
        "ansible_host": "host-B",
        "secagent_status": "disconnected",
        "secagent_last_seen": "2026-03-05T08:00:00Z"
      }
    }
  }
}
```

Les agents `disconnected` sont inclus par défaut. Ansible les marquera `UNREACHABLE` lors de l'exécution.

### Codes d'erreur

| HTTP | Signification |
|---|---|
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
