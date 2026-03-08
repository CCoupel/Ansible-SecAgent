# Plugins Ansible — Spécifications techniques

> Référence pour les plugins Ansible du projet AnsibleRelay (Python).
> Source canonique : `DOC/common/ARCHITECTURE.md` §2, §6, §8, §11, §12, §13, §14, §16
> Sécurité : `DOC/security/SECURITY.md` §6 (auth plugin tokens)
> **Contrat d'interface** : `DOC/contracts/REST_PLUGIN.md`
> **Inventaire GO** : `DOC/inventory/INVENTORY_SPEC.md` (alternative binaire)

---

## 1. Vue d'ensemble

Les plugins tournent sur l'**Ansible Control Node** (machine de confiance).
Ils remplacent SSH par des appels REST HTTPS vers le relay-server.

```
Ansible Control Node
  ├── connection_plugins/relay.py   — remplace SSH (exec, upload, fetch) — OBLIGATOIRE PYTHON
  └── inventory_plugins/relay.py   — inventaire dynamique (GET /api/inventory) — OPTIONNEL (voir §1b)
          │
          │ HTTPS bloquant (requests/httpx)
          ▼
      Relay Server :7770
          │
          │ WebSocket
          ▼
      relay-agent (hôte cible)
```

### 1a. Contrainte Ansible : Python uniquement

**Les plugins Ansible ne peuvent pas être en GO.**

- `ConnectionBase` : API Python uniquement (définit `exec_command()`, `put_file()`, `fetch_file()`)
- `InventoryModule` : API Python uniquement (définit `parse()`, `verify_file()`)
- Ansible charge dynamiquement les `.py` depuis `connection_plugins/` et `inventory_plugins/`
- Impossible d'écrire un plugin natif GO — ce n'est pas une limitation de l'architecture, c'est une contrainte d'Ansible

→ **Conséquence** : `connection_plugins/relay.py` reste **obligatoirement Python**

### 1b. Inventaire : Plugin Python OU binaire GO

Deux approches pour l'inventaire Ansible :

| Approche | Fichier | Langage | Contrainte | Usage |
|----------|---------|---------|-----------|-------|
| **Plugin Ansible** | `inventory_plugins/relay_inventory.py` | Python | Ansible API Python | Natif, zéro config |
| **Binaire GO** | `relay-inventory` | GO (Phase 9) | Ansible external inventory protocol | Docker, CI/CD, restrictions env |

**Recommandation** : Utiliser le **binaire GO** (`relay-inventory`) en production :
- ✅ Déjà implémenté (Phase 9, 19 tests PASS)
- ✅ Moins de dépendances Python à gérer
- ✅ Performance identique
- ✅ Compatible Ansible `--list` / `--host` protocol

**Contrainte fondamentale :** `exec_command()` d'Ansible est synchrone.
Les plugins utilisent `requests` ou `httpx` (HTTP bloquant), jamais `asyncio`.

---

## 2. Authentification

Les plugins s'authentifient avec un **PLUGIN_TOKEN** statique :

```
Authorization: Bearer $RELAY_PLUGIN_TOKEN
X-Relay-Client-Host: <hostname du control node>  ← optionnel, pour le binding
```

Ce token est créé par l'admin via :
```bash
relay-server tokens create --role plugin --description "ansible-control-prod" \
  --allowed-ips "192.168.1.10/32" --allowed-hostname "ansible-control-prod"
```

> Voir `DOC/security/SECURITY.md` §6 pour le modèle complet (IP binding, hostname binding).

---

## 3. Connection Plugin (`relay.py`)

### Classe et méthodes

```python
class Connection(ConnectionBase):
    transport = 'relay'

    def _connect(self) -> None
    def exec_command(self, cmd: str, in_data=None, sudoable=True) -> tuple[int, bytes, bytes]
    def put_file(self, in_path: str, out_path: str) -> None
    def fetch_file(self, in_path: str, out_path: str) -> None
    def close(self) -> None
```

### `exec_command()`

```python
POST /api/exec/{hostname}
Authorization: Bearer $RELAY_PLUGIN_TOKEN

{
  "task_id": "uuid-v4",           # généré par le plugin
  "cmd": "<commande>",
  "stdin": "<base64|null>",       # pipelining ou become_pass
  "timeout": 30,                  # depuis ansible.cfg ou variable hôte
  "become": bool,
  "become_method": "sudo"
}

# Mapping retour → Ansible
200 { rc, stdout, stderr } → (rc, stdout_bytes, stderr_bytes)
503                        → AnsibleConnectionError("UNREACHABLE: agent offline")
504                        → AnsibleConnectionError("TIMEOUT")
500                        → AnsibleConnectionError("agent_disconnected")
429                        → AnsibleConnectionError("agent_busy")
```

### `put_file()`

```python
POST /api/upload/{hostname}
{
  "task_id": "uuid-v4",
  "dest": out_path,
  "data": base64.b64encode(open(in_path, 'rb').read()).decode(),
  "mode": "0644"
}
```

**Limite : 500KB**. Si `os.path.getsize(in_path) > 500*1024` → lever `AnsibleError`.

### `fetch_file()`

```python
POST /api/fetch/{hostname}
{ "task_id": "uuid-v4", "src": in_path }

# Réponse :
{ "rc": 0, "data": "<base64>" }
# Écrire base64.b64decode(data) → out_path
```

### Pipelining

Si `ANSIBLE_PIPELINING=true`, Ansible injecte le module Python via `stdin` (pas de `put_file`).
Le plugin supporte cela via le champ `stdin` de `exec_command`.

```ini
# ansible.cfg
[defaults]
pipelining = true
```

### Configuration plugin

```ini
# ansible.cfg
[relay_connection]
relay_server_url = https://relay.example.com   # ou var RELAY_SERVER_URL
plugin_token     = <token>                     # ou var RELAY_PLUGIN_TOKEN
ca_bundle        = /etc/ssl/certs/ca.pem       # ou var RELAY_CA_BUNDLE
verify_tls       = true
timeout          = 30
```

Variables hôte (`host_vars/my-host.yml`) :
```yaml
ansible_connection: relay
ansible_relay_server_url: https://relay.example.com
ansible_relay_timeout: 60
```

---

## 4. Inventaire Ansible : Binaire GO recommandé

### ⚠️ DÉPRÉCIÉE : Plugin Python `relay_inventory.py`

La tâche Phase 3 #36 (plugin Python inventory) ne sera **pas implémentée**. À la place, utilisez le **binaire GO** (`relay-inventory`, Phase 9) qui fournit une interface identique via le protocole Ansible `--list` / `--host`.

**Raison** : Le binaire GO (Phase 9, complet + testé) remplace fonctionnellement le plugin Python sans ajouter de dépendances Python.

---

### 4a. Approche recommandée : Binaire GO (`relay-inventory`)

L'exécutable `relay-inventory` (Phase 9) interroge `GET /api/inventory` et retourne le format JSON Ansible standard.

**Endpoint serveur** :
```http
GET /api/inventory?only_connected={bool}
Authorization: Bearer $RELAY_PLUGIN_TOKEN
X-Relay-Client-Host: <hostname>  (optionnel, pour binding)
```

**Réponse** :
```json
{
  "all": { "hosts": ["host-A", "host-B"] },
  "_meta": {
    "hostvars": {
      "host-A": {
        "ansible_connection": "relay",
        "ansible_host": "host-A",
        "relay_status": "connected",
        "relay_last_seen": "2026-03-06T10:00:00Z"
      }
    }
  }
}
```

**Usage Ansible** :
```bash
# En ligne de commande
ansible-playbook -i relay-inventory site.yml

# Ou dans ansible.cfg
[defaults]
inventory = /usr/local/bin/relay-inventory
```

**Configuration via variables d'environnement** :
```bash
export RELAY_SERVER_URL=https://relay.example.com
export RELAY_PLUGIN_TOKEN=relay_plugin_xxxxx
export RELAY_CA_BUNDLE=/etc/ssl/certs/ca.pem     # optionnel
export RELAY_INSECURE_TLS=false                  # true = tests uniquement
export RELAY_ONLY_CONNECTED=false                # true = hôtes connectés uniquement
```

Voir `DOC/inventory/INVENTORY_SPEC.md` pour spécifications complètes.

---

### 4b. Alternative (non recommandée) : Plugin Python `relay_inventory.py`

Si vous devez utiliser un plugin Python (cas exceptionnel), implémentez une classe `InventoryModule` suivant le modèle ci-dessous (référence, non produite) :

```python
class InventoryModule(BaseInventoryPlugin):
    NAME = 'relay'

    def verify_file(self, path: str) -> bool
    def parse(self, inventory, loader, path, cache=True) -> None
```

**Note** : Cette approche ajoute une dépendance Python non nécessaire. Le binaire GO (4a) est recommandé.

---

## 5. Gestion des erreurs

| Code HTTP | Signification | Exception Ansible |
|---|---|---|
| `503` | Agent offline | `AnsibleConnectionError` (UNREACHABLE) |
| `504` | Timeout | `AnsibleConnectionError` (timeout) |
| `500` | Déconnexion mid-task | `AnsibleConnectionError` |
| `429` | Agent busy | `AnsibleConnectionError` |
| `413` | Fichier > 500KB | `AnsibleError` |
| `401` | Token invalide | `AnsibleAuthenticationFailure` |
| `403` | IP/hostname non autorisé | `AnsibleAuthenticationFailure` |

---

## 6. Flow complet (référence)

Exemple avec `ansible-playbook -i relay_inventory.py site.yml` :

```
1. Inventory plugin → GET /api/inventory → [host-A(connected), host-B(disconnected)]
2. Ansible prépare les workers

Pour host-A :
  gather_facts → POST /api/exec/host-A { cmd: "python3 -c <setup>" }
  task: copy   → POST /api/upload/host-A { dest: "/tmp/module.py" }
               → POST /api/exec/host-A { cmd: "python3 /tmp/module.py" }
  task: shell  → POST /api/exec/host-A { cmd: "sudo systemctl restart x",
                                          stdin: base64(pass), become: true }

Pour host-B :
  POST /api/exec/host-B → 503 agent_offline → UNREACHABLE
```

---

## 7. Installation

```bash
# Dans ansible.cfg
[defaults]
connection_plugins = /usr/lib/ansible-relay/connection_plugins
inventory_plugins  = /usr/lib/ansible-relay/inventory_plugins

# Variables d'environnement du control node
export RELAY_SERVER_URL=https://relay.example.com
export RELAY_PLUGIN_TOKEN=relay_plugin_xxxxx
export RELAY_CA_BUNDLE=/etc/ssl/certs/relay-ca.pem    # si CA custom
```
