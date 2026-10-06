# Plugins Ansible — Spécifications techniques

> Référence pour les plugins Ansible du projet Ansible-SecAgent (Python).
> Source canonique : `DOC/common/ARCHITECTURE.md` §2, §6, §8, §11, §12, §13, §14, §16
> Sécurité : `DOC/security/SECURITY.md` §6 (auth plugin tokens)
> **Contrat d'interface** : `DOC/contracts/REST_PLUGIN.md`
> **Inventaire GO** : `DOC/inventory/INVENTORY_SPEC.md` (alternative binaire)

---

## 1. Vue d'ensemble

Les plugins tournent sur l'**Ansible Control Node** (machine de confiance).
Ils remplacent SSH par des appels REST HTTPS vers le secagent-server.

```
Ansible Control Node
  ├── connection_plugins/relay.py      — remplace SSH (exec, upload, fetch) — OBLIGATOIRE PYTHON
  └── inventory_plugins/ (DEPRECATED) — utiliser le binaire secagent-inventory à la place (voir §1b)
          │
          │ HTTPS bloquant (requests/httpx)
          ▼
      Relay Server :7770
          │
          │ WebSocket
          ▼
      secagent-minion (hôte cible)
```

### 1a. Contrainte Ansible : Python uniquement

**Les plugins Ansible ne peuvent pas être en GO.**

- `ConnectionBase` : API Python uniquement (définit `exec_command()`, `put_file()`, `fetch_file()`)
- `InventoryModule` : API Python uniquement (définit `parse()`, `verify_file()`)
- Ansible charge dynamiquement les `.py` depuis `connection_plugins/` et `inventory_plugins/`
- Impossible d'écrire un plugin natif GO — ce n'est pas une limitation de l'architecture, c'est une contrainte d'Ansible

→ **Conséquence** : `connection_plugins/relay.py` reste **obligatoirement Python**

### 1b. Inventaire : Binaire GO uniquement (v3.0.2+)

**À partir de la v3.0.2, l'inventaire Ansible est fourni par le binaire GO `secagent-inventory` uniquement.**

Le plugin Python d'inventaire (`inventory_plugins/secagent_inventory.py`) est **DEPRECATED** et **n'est pas implémenté**. Les raisons :
- Le binaire GO offre les mêmes fonctionnalités avec moins de dépendances
- Performance identique ou meilleure (pas de runtime Python)
- Meilleure portabilité (déploiements Docker, CI/CD)
- Compatible avec le protocole Ansible externe `--list` / `--host`

**Usage** : Ansible interroge directement le binaire `secagent-inventory` via `ansible.cfg` :
```ini
[defaults]
inventory = /usr/local/bin/secagent-inventory
```

Voir `DOC/inventory/INVENTORY_SPEC.md` pour les détails complets.

**Contrainte fondamentale :** `exec_command()` d'Ansible est synchrone.
Les plugins utilisent `requests` ou `httpx` (HTTP bloquant), jamais `asyncio`.

---

## 2. Authentification

Les plugins s'authentifient avec un **jeton plugin** statique (jeton opaque `secagent_plg_…`, pas un JWT) :

```
Authorization: Bearer <jeton plugin>
X-Relay-Client-Host: <hostname du control node>  ← lu par le serveur pour le binding (voir ci-dessous)
```

Chaque composant lit le jeton à sa façon (il n'existe **aucune** variable `RELAY_PLUGIN_TOKEN`) :

| Composant | Source du jeton |
|---|---|
| Plugin de connexion `relay.py` | **fichier** : `RELAY_TOKEN_FILE` / `[secagent_connection] token_file` / `ansible_secagent_token_file` (voir §3) |
| Binaire `secagent-inventory` | variable d'environnement **`RELAY_TOKEN`** (`cmd/secagent-inventory/main.go:530`) |

> Le plugin `relay.py` n'envoie pas l'en-tête `X-Relay-Client-Host` : un jeton créé avec
> `--allowed-hostname-pattern` est donc inopérant avec ce plugin : le serveur compare le motif à cet en-tête
> (`handlers/plugin_auth.go:104-120`), reçu vide, et répond 403 `hostname_not_allowed` sauf si le motif accepte la chaîne vide.
> Le binding par IP (`--allowed-ips`) fonctionne.

Ce token est créé par l'admin via :
```bash
secagent-server tokens create --role plugin --description "ansible-control-prod" \
  --allowed-ips "192.168.1.10/32" --expires 24h
# Optionnel : --allowed-hostname-pattern '<regexp>' (voir ci-dessus pour la restriction)
```

> Voir `DOC/security/SECURITY.md` §6 pour le modèle complet (IP binding, hostname binding).

---

## 3. Connection Plugin (`relay.py`)

### Classe et méthodes

```python
class ConnectionPlugin(ConnectionBase):   # alias : Connection = ConnectionPlugin
    transport = 'relay'

    def _connect(self) -> None
    def exec_command(self, cmd: str, in_data=None, sudoable=True) -> tuple[int, bytes, bytes]
    def put_file(self, in_path: str, out_path: str) -> None
    def fetch_file(self, in_path: str, out_path: str) -> None
    def close(self) -> None
```

### `exec_command()`

Ce que le plugin envoie réellement (`relay.py`, `exec_command`) :

```python
POST /api/exec/{hostname}
Authorization: Bearer <jeton lu dans le fichier de jeton>

{
  "cmd": "<commande>",
  "stdin": "<in_data décodé en UTF-8>"   # chaîne vide si pas de stdin
}
```

Le serveur accepte en plus `task_id`, `timeout`, `become`, `become_method` (`handlers/exec.go`
`ExecRequest`), mais le plugin ne les envoie pas : le serveur applique ses défauts (timeout 30 s, sudo).

```python
# Mapping retour → Ansible (_post_relay)
200 { rc, stdout, stderr } → (rc, stdout_bytes, stderr_bytes)
404                        → AnsibleConnectionFailure("Host '<h>' not registered or not connected …")
>= 500                     → AnsibleConnectionFailure("Relay server error <code> …; request not retried")
autre code non-200         → AnsibleError("Relay server error <code>[: <error|detail|message>]")
timeout de lecture         → AnsibleConnectionFailure("Relay timeout …; request not retried")
```

### Plusieurs adresses (relay actif/passif, v3.0.3)

`secagent_server` (alias env `RELAY_SERVER_URL`) accepte une **liste d'URL séparées par des virgules** :

```ini
[secagent_connection]
server = https://relay-a.example.com:7770,https://relay-b.example.com:7770
```

Règles (`relay.py` : `_parse_urls`, `_validate_url`, `_order_urls`, `_post_relay`) :

- Chaque entrée doit être en `http://` ou `https://`, avec un hôte et un port valide ; **`user:pass@hôte` est refusé**
  (erreur nommant seulement la position de l'entrée, jamais l'URL). `http://` hors bouclage envoie le jeton en clair et
  déclenche un avertissement.
- Ordre d'essai : la **dernière adresse qui a répondu en tête**, puis les autres dans l'ordre configuré.
- Bascule vers l'adresse suivante **uniquement avant l'envoi de la requête** : erreur de connexion, `connect_timeout`
  ou échec TLS (`httpx.ConnectError` / `ConnectTimeout`).
- **Jamais de rejeu après envoi** : timeout de lecture/écriture, erreur de protocole ou réponse HTTP 5xx lèvent une erreur
  sans réessayer sur une autre adresse (une commande ne doit pas s'exécuter deux fois).
- Une réponse non-5xx marque l'adresse comme « bonne » ; un 5xx n'est pas mémorisé.
- La mémoire « dernière bonne adresse » est **par processus** (variable de module, pas de cache fichier). Ansible
  forkant ses workers, chaque fork repart de l'ordre configuré : une adresse morte coûte un `connect_timeout` par fork.
  Placer l'adresse la plus probable en premier.
- Toutes les adresses injoignables : `AnsibleConnectionFailure("Cannot reach any relay server address: <hôte:port (erreur)>, …")`.
- `connect_timeout` (défaut 5 s) s'applique à **chaque** adresse ; `timeout` (défaut 30 s) à l'attente du résultat.

### `put_file()`

```python
POST /api/upload/{hostname}
{
  "dest": out_path,
  "data": base64.b64encode(open(in_path, 'rb').read()).decode(),
  "mode": "0644"
}
```

**Limite : 500KB**. Si `os.path.getsize(in_path) > 500*1024` → lever `AnsibleError`.

### `fetch_file()`

```python
POST /api/fetch/{hostname}
{ "src": in_path }

# Réponse :
{ "rc": 0, "data": "<base64>" }
# Écrire base64.b64decode(data) → out_path
```

### Pipelining

Le plugin déclare `has_pipelining = True`. Si le pipelining Ansible est activé, Ansible injecte le module Python via `stdin` (pas de `put_file`).
Le plugin supporte cela via le champ `stdin` de `exec_command`.

```ini
# ansible.cfg
[defaults]
pipelining = true
```

### Configuration plugin

Options déclarées dans `relay.py` (`DOCUMENTATION`) :

| Option | ini `[secagent_connection]` | Variable d'environnement | Variable hôte | Défaut |
|---|---|---|---|---|
| `secagent_server` | `server` | `RELAY_SERVER_URL` | `ansible_secagent_server` | `http://localhost:7770` |
| `secagent_token_file` | `token_file` | `RELAY_TOKEN_FILE` | `ansible_secagent_token_file` | voir ci-dessous |
| `secagent_ca_bundle` | `ca_bundle` | `RELAY_CA_BUNDLE` | `ansible_secagent_ca_bundle` | aucun (CA système) |
| `secagent_timeout` | `timeout` | `RELAY_TIMEOUT` | `ansible_secagent_timeout` | `30` (s) |
| `secagent_connect_timeout` | `connect_timeout` | `RELAY_CONNECT_TIMEOUT` | `ansible_secagent_connect_timeout` | `5` (s, par adresse) |

```ini
# ansible.cfg
[secagent_connection]
server          = https://relay.example.com:7770      # ou liste séparée par des virgules (voir ci-dessus)
token_file      = /etc/ansible/secagent_plugin.jwt    # fichier contenant le jeton plugin
ca_bundle       = /etc/ssl/certs/ca.pem
timeout         = 30
connect_timeout = 5
```

- **Jeton lu depuis un fichier** (`token_file`), jamais directement depuis une variable : si le fichier est absent ou vide,
  `_connect()` échoue (`JWT token file is empty or not readable`). Le contenu est le jeton plugin (`secagent_plg_…`) ;
  le nom « jwt » du fichier par défaut est historique.
- **Défaut du fichier de jeton — écart doc/code** : la déclaration `DOCUMENTATION` indique
  `/etc/ansible/secagent_plugin.jwt`, mais le repli codé dans `_secagent_token_file()` (utilisé quand Ansible n'enregistre
  pas la définition d'option du plugin, cas signalé pour Ansible 2.19 avec des chemins `ansible.cfg` personnalisés) est
  `/tmp/secagent_token.jwt`. Le comportement effectif dépend donc de la version d'Ansible ; **toujours définir
  `token_file` / `RELAY_TOKEN_FILE` explicitement** (un défaut sous `/tmp` est de surcroît déconseillé).
- La vérification TLS est toujours active (`verify=True`, ou le `ca_bundle` s'il est fourni) ; il n'existe pas d'option
  `verify_tls` dans le plugin.

Variables hôte (`host_vars/my-host.yml`) :
```yaml
ansible_connection: relay
ansible_secagent_server: https://relay.example.com:7770
ansible_secagent_timeout: 60
```

---

## 4. Inventaire Ansible : Binaire GO recommandé

### ⚠️ DÉPRÉCIÉE : Plugin Python `secagent_inventory.py`

La tâche Phase 3 #36 (plugin Python inventory) ne sera **pas implémentée**. À la place, utilisez le **binaire GO** (`secagent-inventory`, Phase 9) qui fournit une interface identique via le protocole Ansible `--list` / `--host`.

**Raison** : Le binaire GO (Phase 9, complet + testé) remplace fonctionnellement le plugin Python sans ajouter de dépendances Python.

---

### 4a. Approche recommandée : Binaire GO (`secagent-inventory`)

L'exécutable `secagent-inventory` (Phase 9) interroge `GET /api/inventory` et retourne le format JSON Ansible standard.

**Endpoint serveur** :
```http
GET /api/inventory?only_connected={bool}
Authorization: Bearer <jeton plugin>
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
        "secagent_status": "connected",
        "secagent_last_seen": "2026-03-06T10:00:00Z"
      }
    }
  }
}
```

**Usage Ansible** :
```bash
# En ligne de commande
ansible-playbook -i secagent-inventory site.yml

# Ou dans ansible.cfg
[defaults]
inventory = /usr/local/bin/secagent-inventory
```

**Configuration via variables d'environnement** :
```bash
export RELAY_SERVER_URL=https://relay.example.com   # ou liste : https://a:7770,https://b:7770 (voir INVENTORY_SPEC §3b)
export RELAY_TOKEN=secagent_plg_xxxxx               # jeton plugin (RELAY_PLUGIN_TOKEN n'existe pas)
export RELAY_CA_BUNDLE=/etc/ssl/certs/ca.pem     # optionnel
export RELAY_INSECURE_TLS=false                  # true = tests uniquement
export RELAY_ONLY_CONNECTED=false                # true = hôtes connectés uniquement
```

Voir `DOC/inventory/INVENTORY_SPEC.md` pour spécifications complètes.

---

### 4b. Alternative (non recommandée) : Plugin Python `secagent_inventory.py`

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

Traitement réel par `relay.py` (`_post_relay`) :

| Situation | Exception Ansible |
|---|---|
| Aucune adresse joignable (connexion/TLS) | `AnsibleConnectionFailure` (UNREACHABLE) |
| Timeout de lecture/écriture | `AnsibleConnectionFailure` (pas de rejeu) |
| `404` (hôte inconnu ou non connecté) | `AnsibleConnectionFailure` |
| `>= 500` (dont 500, 503, 504) | `AnsibleConnectionFailure` (pas de rejeu) |
| Autre code non-200 (`401`, `403`, `413`, `429`…) | `AnsibleError("Relay server error <code>[: détail]")` — le plugin ne distingue pas `AnsibleAuthenticationFailure` |
| Réponse non JSON | `AnsibleError` |
| Fichier local > 500 KB (`put_file`) | `AnsibleError` avant tout envoi |

---

## 6. Flow complet (référence)

Exemple avec `ansible-playbook -i secagent-inventory site.yml` :

```
1. secagent-inventory → GET /api/inventory → [host-A(connected), host-B(disconnected)]
2. Ansible prépare les workers

Pour host-A :
  gather_facts → POST /api/exec/host-A { cmd: "python3 -c <setup>" }
  task: copy   → POST /api/upload/host-A { dest: "/tmp/module.py" }
               → POST /api/exec/host-A { cmd: "python3 /tmp/module.py" }
  task: shell  → POST /api/exec/host-A { cmd: "sudo systemctl restart x",
                                          stdin: base64(pass), become: true }

Pour host-B :
  POST /api/exec/host-B → 404/5xx → AnsibleConnectionFailure → UNREACHABLE
```

---

## 7. Installation

```bash
# Dans ansible.cfg
[defaults]
connection_plugins = /usr/lib/ansible-secagent/connection_plugins   # contient relay.py (source : SECAGENT-PYTHON/ansible_plugins/connection_plugins/)
# inventory_plugins : inutile, l'inventaire est le binaire secagent-inventory

# Variables d'environnement du control node
export RELAY_SERVER_URL=https://relay.example.com
export RELAY_TOKEN_FILE=/etc/ansible/secagent_plugin.jwt   # plugin de connexion : fichier contenant le jeton
export RELAY_TOKEN=secagent_plg_xxxxx                      # secagent-inventory uniquement
export RELAY_CA_BUNDLE=/etc/ssl/certs/relay-ca.pem         # si CA custom
```
