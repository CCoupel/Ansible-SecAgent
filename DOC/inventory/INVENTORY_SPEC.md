# secagent-inventory — Spécifications techniques

> Référence pour le binaire secagent-inventory GO (Phase 9).
> Source canonique : `DOC/common/ARCHITECTURE.md` §14
> Plugin Python : `DOC/plugins/PLUGINS_SPEC.md` §4
> **Contrat d'interface** : `DOC/contracts/REST_PLUGIN.md` §2 (GET /api/inventory)

---

## 1. Rôle

`secagent-inventory` est un binaire GO standalone compatible avec le protocole
d'inventaire externe Ansible (`--list` / `--host`).

Il interroge `GET /api/inventory` sur le secagent-server et formate la réponse
en JSON Ansible standard.

**Construction de l'inventaire** : Le serveur construit l'inventaire complet à partir de :
- **Synchronisation initiale** : Chaque relay enfant envoie `topology_snapshot` avec son sous-arbre complet (relays descendants + hôtes)
- **Mises à jour** : Événements `event_forward` (host.up/down/new, relay.updated) propagés depuis les relays
- **Résultat** : Groupes Ansible = noms exacts des relays (ex: `dmz1`), hôtes = toute la descendance avec `secagent_relay_chain` pour le routage

---

## 2. Usage

```bash
# Inventaire complet (utilisé par Ansible)
secagent-inventory --list

# Vars d'un hôte spécifique
secagent-inventory --host my-host
```

---

## 3. Configuration

```bash
RELAY_SERVER_URL=https://relay.example.com    # défaut: https://localhost:7770
RELAY_TOKEN=secagent_plugin_xxxxx              # Bearer token (PLUGIN_TOKEN)
RELAY_CA_BUNDLE=/path/to/ca.pem               # CA custom (optionnel)
RELAY_INSECURE_TLS=false                      # true = désactiver vérif TLS (TESTS UNIQUEMENT, voir ci-dessous)
RELAY_INSECURE_TLS_ACK=                       # i-understand-the-risk = confirmation pour un serveur non-bouclage
RELAY_ONLY_CONNECTED=false                    # true = hôtes connectés uniquement
RELAY_SCOPE=                                  # ID du relay à interroger (optionnel, voir §3a ci-dessous)
```

### 3a. Scoping — RELAY_SCOPE (v3.0.2+)

Par défaut, `secagent-inventory --list` retourne **toute la descendance** du relay interogé. Avec `RELAY_SCOPE`, limitez l'inventaire à un sous-arbre :

```bash
RELAY_SCOPE="zone2-relay1"
secagent-inventory --list
# Retourne uniquement les hôtes et sous-relays de zone2-relay1
```

**Détail du scoping** :
- Requête interne : `GET /api/inventory?relay=zone2-relay1`
- Le serveur filtre les groupes et hôtes à la descendance de `zone2-relay1`
- Les chaînes `secagent_relay_chain` sont recalculées relativement au relay racine du scope (ex: si le relay demandé a des enfants, la chaîne devient `[enfant_direct, zone2-relay1]`)
- Erreur **400** si le relay ID est mal formé ou introuvable
- Authentification : même Bearer token que pour l'inventaire complet

**Garde `RELAY_INSECURE_TLS`** (vérifiée avant toute requête, pour `--list` comme `--host`) :

- À chaque exécution avec `RELAY_INSECURE_TLS=true`, le binaire écrit sur **stderr**
  `[SECURITY WARNING] TLS verification disabled …` ; stdout reste du JSON pur.
- Si `RELAY_SERVER_URL` n'est pas une adresse de bouclage (`localhost`, `127.0.0.0/8`, `::1`), le binaire
  **refuse** (message explicite sur stderr, code de sortie 1) sauf si
  `RELAY_INSECURE_TLS_ACK=i-understand-the-risk`. Un seul oubli de variable ne désactive donc jamais la
  vérification vers un serveur distant.
- Le token n'apparaît jamais dans ces messages.

---

## 4. Format de sortie

### `--list`

```json
{
  "all": {
    "children": ["dmz1", "zone2"],
    "hosts": ["host-C"]
  },
  "dmz1": {
    "hosts": ["host-A", "host-B"],
    "children": ["zone2-relay1"],
    "vars": {"region": "dmz"}
  },
  "zone2-relay1": {
    "hosts": ["host-D"],
    "children": [],
    "vars": {"region": "zone2"}
  },
  "zone2": {
    "hosts": [],
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
        "secagent_relay_chain": ["zone2-relay1", "dmz1"],
        "secagent_next_hop": "zone2-relay1"
      }
    }
  }
}
```

### `--host <hostname>`

```json
{
  "ansible_connection": "relay",
  "ansible_host": "host-A",
  "secagent_status": "connected",
  "secagent_last_seen": "2026-03-06T10:00:00Z"
}
```

---

## 5. Intégration Ansible

```ini
# ansible.cfg
[defaults]
inventory = /usr/local/bin/secagent-inventory
```

Ou en ligne de commande :
```bash
ansible-playbook -i secagent-inventory site.yml
```

---

## 5a. Group Vars — Comportements et Limitations (v3.0.2+)

### Visibilité des group vars

**Un relay sans agent n'apparaît pas dans l'inventaire**, donc ses `group_vars` ne s'affichent pas non plus (cohérent : aucun hôte auquel les appliquer). Seuls les groupes Ansible qui ont des hôtes directs ou indirects apparaissent dans la sortie `--list`.

### Noms de variables réservées

**Noms réservés par Ansible** (ex: `tags`, `retries`, `play_context`, `role_names`) passent la validation RELAY_GROUP_VARS au serveur, mais Ansible lui-même affiche un avertissement : `Found variable using reserved name`. 

**Comportement** : c'est un avertissement seulement, pas une erreur. La variable reste lisible et utilisable, mais Ansible met en garde l'opérateur.

**Recommandation** : éviter les noms réservés. Consulter la documentation Ansible pour la liste complète.

### Héritage et Précédence

Dans une topologie hiérarchique, les sous-relays **héritent** des `group_vars` du relay parent. 

**Précédence** : si le relay parent et le sous-relay définissent la même clé, la **valeur du groupe enfant l'emporte** (comportement Ansible observé sur ansible-core 2.17 et 2.21).

Exemple :
```yaml
# Relay parent (dmz1): group_vars = {"env": "prod", "region": "dmz"}
# Relay enfant (zone-a): group_vars = {"env": "staging", "team": "ops"}
# Résultat chez Ansible :
# - zone-a hérite env=staging (enfant l'emporte sur prod du parent)
# - zone-a hérite region=dmz (du parent)
# - zone-a a team=ops (propre)
```

### Test avec Ansible Ad Hoc

Pour tester les variables avec une commande ad hoc, la variable `ansible_connection` doit être explicitement définie en `extra_var` : 

```bash
# ❌ Ne suffira PAS (l'inventaire a priorité) :
ansible -i secagent-inventory <host> -m debug -a var=region -c local

# ✅ Correct (extra vars ont priorité maximale) :
ansible -i secagent-inventory <host> -m debug -a var=region -e ansible_connection=local
```

La raison : la variable `ansible_connection=relay` définie dans l'inventaire a priorité sur l'option `-c` CLI, sauf si l'extra var (priorité maximale) la surcharge.

---

## 6. Endpoint serveur

```
GET /api/inventory?only_connected=false
Authorization: Bearer <PLUGIN_TOKEN>

→ voir DOC/server/SERVER_SPEC.md §3 pour le format de réponse complet
```

Les agents `secagent_status: disconnected` sont inclus par défaut.
Ansible les marquera UNREACHABLE lors de l'exécution (HTTP 503 → `AnsibleConnectionError`).

---

## 7. Code source

```
GO/cmd/inventory/
├── main.go              — parsing args, config, appel HTTP, formatage JSON
└── inventory_test.go    — 19 tests (mock HTTP, formats, filtres)
```
