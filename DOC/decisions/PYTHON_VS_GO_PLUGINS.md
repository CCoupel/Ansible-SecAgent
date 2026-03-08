# Décision architecturale : Plugins Ansible en Python vs GO

**Date** : 2026-03-08
**Statut** : DÉCIDÉ
**Impact** : Phase 3 (tâche #36 OBSOLÈTE), Phase 9 (VALIDE)

---

## Question

Pourquoi les plugins Ansible (`connection_plugins/`, `inventory_plugins/`) restent-ils en Python alors que tout le reste (server, agent, inventory binary) est en GO ?

## Réponse courte

**Contraint Ansible** : Les API de plugin Ansible (`ConnectionBase`, `InventoryModule`, `LookupModule`, etc.) ne sont disponibles qu'en Python. Il n'y a pas d'API GO natif pour écrire des plugins Ansible.

## Réponse longue

### Contrainte technique

Ansible charge dynamiquement les plugins depuis les répertoires de plugins :
- `connection_plugins/*.py` → Import Python, instanciation de `ConnectionBase`
- `inventory_plugins/*.py` → Import Python, instanciation de `InventoryModule`
- `lookup_plugins/*.py` → Import Python, instanciation de `LookupBase`

Ansible **NE SUPPORTE PAS** les plugins GO nativement. Les alternatives sont :

| Approche | Faisabilité | Complexité | Notes |
|----------|-------------|-----------|-------|
| Plugin Python (direct) | ✅ | Basse | Fonctionnalité complète via API Ansible |
| Binaire externe + wrapping Python | ❌ | Extrême | Ajoute une couche indirection inutile |
| Binaire GO standalone (external inventory protocol) | ✅ | Basse | Compatible Ansible `--list`/`--host` |
| GO plugin via cgo | ❌ | Impossible | Ansible ne supporte pas |

### Décision : Hybrid approach

**Deux cas de figure** :

#### 1. Connection Plugin (`connection_plugins/relay.py`)

- **Status** : OBLIGATOIRE en Python (Phase 3, #35)
- **Raison** : Pas d'alternative. L'API `exec_command()`, `put_file()`, `fetch_file()` n'existe que en Python
- **Implémentation** : COMPLÈTÉE (Phase 3 MVP)

#### 2. Inventory Plugin (`inventory_plugins/relay_inventory.py`)

- **Status** : OBSOLÈTE (Phase 3, #36) — remplacé par binaire GO
- **Raison** : Le binaire `relay-inventory` (Phase 9, GO) fournit la même fonctionnalité via le protocole Ansible `--list`/`--host`
- **Avantages du binaire** :
  - Zéro dépendance Python additionnelle
  - Déjà implémenté, testé, déployé (Phase 9, 19 tests PASS)
  - Performance identique
  - Compatible avec Ansible external inventory script protocol
- **Implémentation** : VIA BINAIRE GO (Phase 9)

## Tableau comparatif

| Composant | Langage | Phase | Status | Raison |
|-----------|---------|-------|--------|--------|
| `relay-server` | GO | 7 | ✅ Complète | Décision de réécriture v2 |
| `relay-agent` | GO | 8 | ✅ Complète | Décision de réécriture v2 |
| `relay-inventory` | GO | 9 | ✅ Complète | Binaire standalone (alternative à plugin) |
| `connection_plugins/relay.py` | Python | 3 | ✅ Complète | **Contrainte Ansible** : ConnectionBase Python uniquement |
| `inventory_plugins/relay_inventory.py` | Python | 3 #36 | ⏸ OBSOLÈTE | Remplacé par `relay-inventory` (GO) |

## Implications

### Pour le déploiement

- Le **container Ansible** inclut :
  - ✅ `relay.py` (connection plugin, Python)
  - ✅ `relay-inventory` (binaire GO)
  - ✅ `ansible.cfg` pointe sur binaire GO pour l'inventaire

- Le **Dockerfile.ansible** installe :
  - Python 3.11 + ansible-core (pour connection plugin API)
  - GO relay-inventory binaire (copié depuis build GO)

### Pour la maintenance

- **Plugins Python** : Maintenez ensemble si changements API Ansible
  - Vérifiez compatibility avec Ansible versions
  - Tests via `pytest` dans PYTHON/

- **Binaire GO** : Maintenez dans GO/cmd/inventory/
  - Mêmes tests que serveur/agent
  - Binaire inclus dans images Docker

### Pour les futures extensions

- **Lookup plugins** : DOIVENT rester Python (pas d'alternative GO)
- **Filter plugins** : DOIVENT rester Python (pas d'alternative GO)
- **Module custom** : CAN be GO (modules sont exécutés sur l'agent, pas côté Ansible)

## Références

- `DOC/common/ARCHITECTURE.md` §2 : tableau composants
- `DOC/plugins/PLUGINS_SPEC.md` §1 : constraint Ansible expliquée
- `DOC/inventory/INVENTORY_SPEC.md` : specs relay-inventory binary
- `GO/cmd/inventory/main.go` : implémentation binaire
- `PYTHON/ansible_plugins/connection_plugins/relay.py` : plugin connection

---

## Conclusion

L'approche hybride Python/GO n'est **pas un compromis**, c'est une **nécessité architecturale** imposée par Ansible. Les plugins restent Python car c'est la seule option. Pour l'inventaire, nous avons choisi le binaire GO pour réduire les dépendances Python et améliorer la maintenabilité.

**Pas d'action requise** : Phase 3 #36 est OBSOLÈTE mais non-nécessaire. La fonctionnalité existe via Phase 9.
