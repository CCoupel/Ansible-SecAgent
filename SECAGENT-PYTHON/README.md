# SECAGENT-PYTHON — plugin de connexion Ansible

Ce répertoire contient la **seule partie Python** d'Ansible-SecAgent : le plugin de connexion Ansible `relay` (contrainte de l'API Ansible : `ConnectionBase` n'existe qu'en Python). Le serveur (`secagent-server`), l'agent (`secagent-minion`) et l'inventaire dynamique (`secagent-inventory`) sont écrits en **GO** (`GO/cmd/`). Les anciennes implémentations Python du serveur et de l'agent (FastAPI, NATS, SQLite) sont retirées.

```
SECAGENT-PYTHON/
├── ansible.cfg                                   # exemple de configuration
├── ansible_plugins/connection_plugins/relay.py   # plugin de connexion (ansible_connection: relay)
└── tests/unit/test_relay.py                      # tests pytest
```

Spécification : `DOC/plugins/PLUGINS_SPEC.md` · contrat REST : `DOC/contracts/REST_PLUGIN.md` · poste de contrôle Ansible de la chaîne de qualif : `DEPLOYMENT/qualif/README.md` (`chain-test.sh smoke`).

## Fonctionnement

Le plugin remplace SSH : `exec_command`, `put_file` et `fetch_file` sont des appels **REST bloquants** vers `secagent-server` (`POST /api/exec|upload|fetch/{hostname}`, port 7770, HTTPS), authentifiés par un **jeton plugin** (`secagent_plg_…`, chaîne opaque, pas un JWT) créé par `secagent-server tokens create --role plugin`. Le serveur route la tâche vers le minion par sa WebSocket.

- **stdin** : `exec_command` envoie `stdin` en **base64** des octets bruts (le champ est omis s'il n'y a pas de données).
- **Multi-adresses** : `server` accepte une liste d'URL séparées par des virgules (instances actif/passif d'un même relay). Les adresses sont essayées dans l'ordre (la dernière qui a répondu en tête) ; le plugin ne passe à la suivante **que si la connexion échoue avant l'envoi de la requête** (erreur de connexion, délai de connexion, échec TLS). Une erreur après l'envoi (délai de lecture, erreur de protocole, HTTP 5xx) est remontée **sans rejouer** la requête ailleurs. Une adresse avec identifiants (`user:pass@host`) est refusée ; `http://` hors boucle locale envoie le jeton en clair et déclenche un avertissement : utiliser `https://`. La mémoire de la dernière bonne adresse est propre à un processus Ansible (chaque fork repart de l'ordre configuré).

## Configuration

Options (ini `[secagent_connection]`, variable d'environnement, variable d'hôte Ansible) :

| Option | ini | Variable d'environnement | Variable d'hôte | Défaut |
|---|---|---|---|---|
| URL(s) du serveur | `server` | `RELAY_SERVER_URL` | `ansible_secagent_server` | `http://localhost:7770` (renseigner une URL `https://`) |
| Fichier du jeton plugin | `token_file` | `RELAY_TOKEN_FILE` | `ansible_secagent_token_file` | `/etc/ansible/secagent_plugin.jwt` |
| Bundle CA (HTTPS) | `ca_bundle` | `RELAY_CA_BUNDLE` | `ansible_secagent_ca_bundle` | aucun |
| Délai d'une tâche (s) | `timeout` | `RELAY_TIMEOUT` | `ansible_secagent_timeout` | `30` |
| Délai de connexion par adresse (s) | `connect_timeout` | `RELAY_CONNECT_TIMEOUT` | `ansible_secagent_connect_timeout` | `5` |

**Ordre de priorité** (identique pour `server`, `token_file`, `ca_bundle`, `timeout` et `connect_timeout`) :

1. variable d'hôte `ansible_secagent_*` (inventaire, `group_vars`, `host_vars`, variables de play) ;
2. variable d'environnement `RELAY_*` ;
3. `[secagent_connection]` d'`ansible.cfg` ;
4. valeur par défaut du tableau.

Cet ordre vaut pour les deux modes de chargement du plugin (`connection_plugins = …` d'`ansible.cfg` ou `ANSIBLE_CONNECTION_PLUGINS`).

> **Changement de comportement (v3.0.3)** : une variable d'hôte passe désormais **avant** l'environnement. Jusqu'ici, la classe du plugin s'appelait `ConnectionPlugin` au lieu de `Connection` : Ansible déduit le type du plugin du nom de la classe, `get_option()` échouait et le plugin retombait silencieusement sur `RELAY_*` seul, ignorant variables d'hôte et `[secagent_connection]`. La classe s'appelle maintenant `Connection` (`ConnectionPlugin` reste un alias). Une variable `ansible_secagent_server` ou `ansible_secagent_token_file` déjà présente dans un inventaire, jusque-là sans effet, **s'applique maintenant** et prend le pas sur l'environnement : la vérifier avant de mettre à jour.

```ini
# ansible.cfg
[defaults]
connection_plugins = ./ansible_plugins/connection_plugins
inventory = /usr/local/bin/secagent-inventory   # binaire GO (RELAY_TOKEN, RELAY_SERVER_URL…)
host_key_checking = False

[secagent_connection]
server = https://relay.example.com:7770
token_file = /etc/ansible/secagent_plugin.jwt
ca_bundle = /etc/ansible/secagent_ca.pem
```

### Fichier de jeton

Le jeton est lu dans un **fichier**, jamais dans une variable. Le plugin le refuse (sans envoyer de requête, et sans jamais afficher le jeton) si le fichier :
- est un lien symbolique (`O_NOFOLLOW`, qui ne protège que le dernier composant du chemin : protéger aussi le répertoire parent) ;
- n'est pas un fichier régulier (FIFO, socket, périphérique) ;
- n'appartient pas à l'utilisateur qui lance Ansible ;
- est lisible par le groupe ou les autres (mode ≠ `0600`/`0400` : `chmod 600`).

Un fichier absent ou vide donne une erreur de connexion explicite. Il n'y a plus de repli sur `/tmp` : ne jamais placer le jeton dans un répertoire partagé.

```bash
install -m 600 /dev/null /etc/ansible/secagent_plugin.jwt
printf '%s' "$PLUGIN_TOKEN" > /etc/ansible/secagent_plugin.jwt
```

L'inventaire dynamique est le binaire `secagent-inventory`, qui lit son jeton dans `RELAY_TOKEN` (voir `DOC/inventory/INVENTORY_SPEC.md`).

## Utilisation

```bash
export RELAY_SERVER_URL=https://relay.example.com:7770
export RELAY_CA_BUNDLE=/etc/ansible/secagent_ca.pem
export RELAY_TOKEN="$PLUGIN_TOKEN"        # pour secagent-inventory seulement
ansible-playbook -i /usr/local/bin/secagent-inventory playbooks/site.yml
```

Les hôtes de l'inventaire portent `ansible_connection: relay`.

## Tests

```bash
pip install pytest httpx ansible-core
pytest SECAGENT-PYTHON/tests/unit/ -v
```
