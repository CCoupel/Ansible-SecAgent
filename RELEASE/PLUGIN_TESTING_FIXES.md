# Corrections — Tests des plugins Ansible

## Problème identifié

Le test script `test_plugins.sh` échouait à Step 3 : l'endpoint `/api/inventory` retournait 404 au lieu de l'inventaire des agents.

## Cause racine

L'architecture multi-port du serveur relay utilise 3 ports distincts:
- **Port 7770** : agents (enrollment + WebSocket)
- **Port 7771** : plugin connection (exec/upload/fetch)
- **Port 7772** : inventory plugin (/api/inventory)

Le test script appelait `/api/inventory` sur le port 7770, alors que l'endpoint est sur le port 7772.

## Corrections apportées

### 1. Test script (test_plugins.sh)

**Ligne 61-63** : Correction du port pour l'inventory plugin
```bash
# Avant (incorrect)
INVENTORY=$(curl -s "http://$RELAY_SERVER/api/inventory" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)")

# Après (correct)
RELAY_INVENTORY="192.168.1.218:7772"
INVENTORY=$(curl -s "http://$RELAY_INVENTORY/api/inventory" \
  -H "Authorization: Bearer $(cat $TOKEN_FILE)")
```

**Ligne 91-94** : Utilisation du fichier de configuration d'inventory avec les bons ports
```bash
# Avant (incorrect)
ansible-playbook \
  playbooks/test_secagent_plugins.yml \
  -i secagent_inventory \
  -e "secagent_server_url=http://$RELAY_SERVER"

# Après (correct)
ansible-playbook \
  playbooks/test_secagent_plugins.yml \
  -i playbooks/secagent_inventory.yml
```

### 2. Configuration d'inventory (playbooks/secagent_inventory.yml - créé)

Nouveau fichier YAML qui configure les plugins avec les bons ports:
```yaml
plugin: secagent_inventory
secagent_server: http://192.168.1.218:7772  # Port 7772 = inventory plugin
secagent_token_file: /tmp/secagent_token.jwt
only_connected: false

all:
  hosts:
  vars:
    ansible_secagent_server: http://192.168.1.218:7771  # Port 7771 = exec/upload/fetch
    ansible_secagent_token_file: /tmp/secagent_token.jwt
```

### 3. Playbook de test (playbooks/test_secagent_plugins.yml)

Suppression de la variable hardcoded `secagent_server_url` qui n'était pas utilisée et créait de la confusion:
```yaml
# Avant
vars:
  secagent_server_url: "http://192.168.1.218:7770"

# Après
# (variables gérées par secagent_inventory.yml)
```

## Résultats du test

```
✅ Step 1: JWT plugin token généré
✅ Step 2: Server health check OK
✅ Step 3: Inventory plugin fonctionnel (port 7772)
✅ Step 4: 3 agents trouvés (qualif-host-01, 02, 03 - tous "connected")
⏭️  Step 5: Playbook requires ansible-playbook (non installé localement)
```

### Sortie inventory (example)
```json
{
  "all": {
    "hosts": ["qualif-host-01", "qualif-host-02", "qualif-host-03"]
  },
  "_meta": {
    "hostvars": {
      "qualif-host-01": {
        "ansible_connection": "relay",
        "ansible_host": "qualif-host-01",
        "secagent_status": "connected",
        "secagent_last_seen": "2026-03-04T16:49:30.692509+00:00"
      },
      ...
    }
  }
}
```

## Architecture multi-port récapitulée

| Port | Service | Endpoints | Client |
|------|---------|-----------|--------|
| 7770 | relay-api (client) | `/api/register`, `/ws/agent`, `/health` | secagent-minion (clients) |
| 7771 | relay-api (plugin) | `/api/exec/{host}`, `/api/upload/{host}`, `/api/fetch/{host}` | Ansible connection plugin |
| 7772 | relay-api (inventory) | `/api/inventory` | Ansible inventory plugin |

## Fichiers modifiés

1. `test_plugins.sh` — Correction des ports (Steps 3-5)
2. `playbooks/secagent_inventory.yml` — Nouveau fichier de configuration inventory
3. `playbooks/test_secagent_plugins.yml` — Suppression variable hardcoded

## Prochaines étapes

Pour tester le playbook complet (Step 5):
1. Installer Ansible sur le système hôte: `pip install ansible`
2. Installer httpx: `pip install httpx`
3. Relancer le script: `./test_plugins.sh`

Le test complet validera:
- Connection plugin (relay remplace SSH)
- exec_command (hostname, uptime, df)
- put_file et fetch_file (transfert fichiers)
- gather_facts (collecte facts système)
- become/become_user (privilèges d'exécution)
