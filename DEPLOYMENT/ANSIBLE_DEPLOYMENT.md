# Poste de contrôle Ansible — guide de déploiement

> **Conteneur Ansible obsolète (v3.0.3)** : `DEPLOYMENT/qualif/docker-compose.ansible.yml` porte un bandeau OBSOLETE et `GO/Dockerfile.ansible` n'est plus constructible tel quel (il copie `GO/cmd/inventory` et `PYTHON/…/secagent.py`, qui n'existent plus : les sources sont `GO/cmd/secagent-inventory` et `SECAGENT-PYTHON/ansible_plugins/connection_plugins/relay.py`). Ce guide décrit l'installation **sur un poste de contrôle Ansible** (machine ou conteneur que vous construisez vous-même) avec les composants actuels.

## Vue d'ensemble

```
Poste de contrôle Ansible
    ├── secagent-inventory (binaire GO)          — inventaire dynamique
    └── relay.py (plugin de connexion, Python)   — exécution des tâches (ansible_connection: relay)
    ↓ HTTPS bloquant (REST)
secagent-server (maître, port 7770, TLS natif)
    ↓ WebSocket
secagent-minion (hôtes cibles)
```

L'inventaire est le **binaire** `secagent-inventory` (pas de plugin d'inventaire Python). Le plugin de connexion reste en Python (contrainte de l'API Ansible). Les deux s'authentifient avec un **jeton plugin** (`secagent_plg_…`, opaque, pas un JWT), créé côté serveur :

```bash
docker exec secagent-server secagent-server tokens create --role plugin --description "ansible-control" --expires 365d
# affiché une seule fois
```

## Installation

1. Installer `ansible-core` et les dépendances Python du plugin (voir `SECAGENT-PYTHON/`).
2. Copier le binaire `secagent-inventory` (par ex. dans `/usr/local/bin/`) et le dossier `SECAGENT-PYTHON/ansible_plugins/connection_plugins/` (`relay.py`, `__init__.py`).
3. Écrire le jeton plugin dans un **fichier** lu par le plugin de connexion — propriétaire = utilisateur qui lance Ansible, mode `0600`, ni lien symbolique ni fichier spécial, jamais sous `/tmp` (le plugin refuse sinon) :

```bash
install -m 600 /dev/null /etc/ansible/secagent_plugin.jwt     # défaut du plugin
printf '%s' "$PLUGIN_TOKEN" > /etc/ansible/secagent_plugin.jwt
```

## Configuration

### Variables d'environnement

| Composant | Variable | Défaut | Description |
|---|---|---|---|
| inventaire | `RELAY_SERVER_URL` | `https://localhost:7770` | URL du serveur (liste d'adresses séparées par des virgules : instances du même relay) |
| inventaire | `RELAY_TOKEN` | (obligatoire) | Jeton plugin, lu **directement** dans la variable |
| inventaire | `RELAY_CA_BUNDLE` | vide | Bundle CA PEM pour vérifier le serveur |
| inventaire | `RELAY_ONLY_CONNECTED` | `false` | Limiter aux agents connectés |
| inventaire | `RELAY_SCOPE` | vide | Limiter à la descendance d'un relay |
| inventaire | `RELAY_INSECURE_TLS` | `false` | Désactiver la vérification TLS (**tests uniquement** ; vers un serveur non-bouclage exige aussi `RELAY_INSECURE_TLS_ACK=i-understand-the-risk`) |
| connexion | `RELAY_SERVER_URL` | `http://localhost:7770` (le défaut du plugin est en clair : renseigner l'URL `https://`) | URL du serveur |
| connexion | `RELAY_TOKEN_FILE` | `/etc/ansible/secagent_plugin.jwt` | **Fichier** du jeton plugin |
| connexion | `RELAY_CA_BUNDLE` | vide | Bundle CA PEM |
| connexion | `RELAY_TIMEOUT` / `RELAY_CONNECT_TIMEOUT` | `30` / `5` | Délais en secondes |

Il n'existe pas de variable `RELAY_ADMIN_TOKEN` ni `RELAY_PLUGIN_TOKEN` : un `ADMIN_TOKEN` est refusé par l'API plugin (403).

### ansible.cfg

```ini
[defaults]
# Inventaire dynamique : binaire GO
inventory = /usr/local/bin/secagent-inventory
# Plugin de connexion (relay.py)
connection_plugins = ./ansible_plugins/connection_plugins
host_key_checking = False
timeout = 30

[secagent_connection]
server = https://relay.example.com:7770
token_file = /etc/ansible/secagent_plugin.jwt
ca_bundle = /etc/ansible/secagent_ca.pem
# timeout = 30
# connect_timeout = 5
```

Clés réelles de la section `[secagent_connection]` : `server`, `token_file`, `ca_bundle`, `timeout`, `connect_timeout` (variables d'hôte équivalentes : `ansible_secagent_server`, `ansible_secagent_token_file`…). Le détail est dans `DOC/plugins/PLUGINS_SPEC.md` ; l'inventaire : `DOC/inventory/INVENTORY_SPEC.md`. Les hôtes de l'inventaire portent `ansible_connection: relay`.

## Utilisation

```bash
export RELAY_SERVER_URL=https://relay.example.com:7770
export RELAY_TOKEN="$PLUGIN_TOKEN"
export RELAY_CA_BUNDLE=/etc/ansible/secagent_ca.pem

secagent-inventory --list                                   # inventaire JSON
ansible-inventory -i /usr/local/bin/secagent-inventory --list -y
ansible all -i /usr/local/bin/secagent-inventory -m ping
ansible-playbook -i /usr/local/bin/secagent-inventory playbooks/my-playbook.yml
ansible-playbook -i /usr/local/bin/secagent-inventory -f 5 -l qualif-host-01 playbooks/my-playbook.yml
```

### Exemple de playbook

```yaml
---
- hosts: all
  gather_facts: yes
  tasks:
    - name: Ping all agents
      ansible.builtin.ping:

    - name: Run a command
      ansible.builtin.command: uptime
      register: uptime

    - name: Display result
      ansible.builtin.debug:
        msg: "{{ inventory_hostname }} : {{ uptime.stdout }}"
```

### Tâches longues (async)

```yaml
tasks:
  - name: Long running task
    ansible.builtin.command: /usr/bin/long-running-command
    async: 300
    poll: 0
    register: long_task

  - name: Wait for long task
    ansible.builtin.async_status:
      jid: "{{ long_task.ansible_job_id }}"
    register: job_result
    until: job_result.finished
    retries: 30
    delay: 10
```

## Dépannage

| Symptôme | Cause / vérification |
|---|---|
| Inventaire en `403` | Jeton non plugin (un `ADMIN_TOKEN` donne 403), jeton révoqué (`token_revoked`) ou expiré, IP source hors `allowed_ips` : `tokens list --role plugin` |
| Inventaire en `401 missing_authorization` | `RELAY_TOKEN` absent ou vide |
| Plugin : « token file … » refusé | Fichier de jeton non régulier, d'un autre propriétaire ou en mode ≠ `0600`/`0400` : `chmod 600`, propriétaire = utilisateur d'Ansible, pas de lien symbolique |
| `Failed to connect` | URL/CA : `curl --cacert ca.pem https://relay.example.com:7770/health` |
| `No hosts matched` | Agents non connectés : `secagent-server minions list` ; `RELAY_ONLY_CONNECTED=true` filtre les déconnectés |
| Agent `UNREACHABLE` / `agent_suspended` | Agent hors ligne ou suspendu par l'admin (503) |

## CI/CD (exemple)

```yaml
ansible_deploy:
  stage: deploy
  script:
    - ansible-playbook -i /usr/local/bin/secagent-inventory playbooks/my-playbook.yml
  environment:
    name: qualif
```

Fournir `RELAY_SERVER_URL` (https), `RELAY_TOKEN` et le fichier de jeton comme secrets du pipeline.

## Références

- [Plugins Ansible (spec)](../DOC/plugins/PLUGINS_SPEC.md) · [Contrat REST plugin](../DOC/contracts/REST_PLUGIN.md)
- [secagent-inventory (spec)](../DOC/inventory/INVENTORY_SPEC.md)
- Connexion : `SECAGENT-PYTHON/ansible_plugins/connection_plugins/relay.py` · `SECAGENT-PYTHON/ansible.cfg`
