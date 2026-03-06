# Architecture des ports — Séparation sécurité

**Date** : 2026-03-04
**Objectif** : Isoler les canaux par rôle (client/plugin/admin) pour prévenir les risques d'authentification croisée.

---

## Vue d'ensemble

```
┌─────────────────────────────────────────────────────────────┐
│ Serveur AnsibleRelay (192.168.1.218)                        │
│                                                              │
│  Port 7770 ─ Client (enrollment + WSS)                      │
│  Port 7771 ─ Plugin connection (exec/upload/fetch)         │
│  Port 7772 ─ Inventory plugin                               │
└─────────────────────────────────────────────────────────────┘
```

---

## Port 7770 — Client (enrollment + WebSocket)

**Rôle** : Agents clients (relay-agent daemon)

**Endpoints** :
```
POST   /api/register              → Enrollment agent
GET    /ws/agent                  → WebSocket persistante
GET    /health                    → Health check
```

**Authentification** :
- `/api/register` : **Pré-authorized** (clef publique en DB via API admin)
- `/ws/agent` : **JWT** avec rôle `agent`

**Flux nominal** :
```
1. Agent : POST /api/register (hostname, os, ip, python_version)
2. Serveur : Vérifier clef publique en DB, générer JWT(rôle=agent)
3. Serveur : 201 + JWT
4. Agent : Ouvre WebSocket /ws/agent avec JWT en header Authorization
5. Serveur : Accepte WS, stocke ws_connections[hostname]
6. Agent : Maintient WS ouverte, prête pour tâches exec
```

**Cas de sécurité** :
- ✓ Seuls les agents avec clef pré-autorisée peuvent s'enregistrer
- ✓ JWT signé côté serveur, valide la signature à chaque message WS
- ✓ Plugin ne peut PAS accéder ce port (rôle plugin ≠ rôle agent)

---

## Port 7771 — Plugin connection (exec/upload/fetch)

**Rôle** : Plugins Ansible (connection_plugins/relay.py)

**Endpoints** :
```
POST   /api/exec/{host}           → Execute command
POST   /api/upload/{host}         → Put file
POST   /api/fetch/{host}          → Get file
GET    /health                    → Health check
```

**Authentification** :
- Tous les endpoints : **JWT** avec rôle `plugin`

**Flux nominal** :
```
1. Plugin Ansible : POST /api/exec/{host} avec JWT(rôle=plugin)
2. Serveur : Vérifier JWT rôle=plugin, vérifier host existe en DB
3. Serveur : Publish NATS task sur sujet tasks.{host}
4. Agent WS (sur Port 7770) : Reçoit tâche exec
5. Agent : Exécute, envoie résultat via WS
6. Serveur : Reçoit résultat, résout future
7. Serveur : HTTP 200 + résultat vers plugin
```

**Cas de sécurité** :
- ✓ Plugin DOIT avoir JWT(rôle=plugin) — refus si rôle=agent
- ✓ Plugin ne peut PAS ouvrir WebSocket (endpoint /ws/agent inexistant sur ce port)
- ✓ Client (agent) ne peut PAS appeler /api/exec (pas JWT rôle=plugin)

---

## Port 7772 — Inventory plugin

**Rôle** : Inventaire dynamique Ansible

**Endpoints** :
```
GET    /api/inventory             → Inventaire JSON Ansible
GET    /health                    → Health check
```

**Authentification** :
- `/api/inventory` : **ADMIN_TOKEN** (Bearer token simple ou JWT rôle=admin)

**Flux nominal** :
```
1. Ansible Control Node : GET /api/inventory?token=ADMIN_TOKEN
2. Serveur : Vérifier token = ADMIN_TOKEN
3. Serveur : SELECT agents WHERE status='registered'
4. Serveur : Format JSON Ansible standard
5. Serveur : HTTP 200 + inventaire
6. Ansible : Parse inventaire, popule hosts
```

**Réponse attendue** :
```json
{
  "_meta": {
    "hostvars": {
      "qualif-host-01": {
        "ansible_host": "192.168.1.100",
        "ansible_connection": "relay",
        "relay_port": "7771",
        "os": "Linux"
      }
    }
  },
  "all": {
    "hosts": ["qualif-host-01"]
  }
}
```

**Cas de sécurité** :
- ✓ Inventaire exposé UNIQUEMENT sur port dédié
- ✓ Authentification simple (ADMIN_TOKEN) ou JWT(rôle=admin)
- ✓ Pas d'accès aux secrets agents (JWT, become_pass, etc.)

---

## Matrice de sécurité

| Port | Endpoint | Rôle requis | Client (agent) | Plugin (connection) | Admin (inventory) |
|------|----------|-------------|---|---|---|
| **7770** | POST /api/register | - (pré-authorized) | ✓ | ✗ | ✗ |
| **7770** | GET /ws/agent | agent | ✓ | ✗ | ✗ |
| **7771** | POST /api/exec | plugin | ✗ | ✓ | ✗ |
| **7771** | POST /api/upload | plugin | ✗ | ✓ | ✗ |
| **7771** | POST /api/fetch | plugin | ✗ | ✓ | ✗ |
| **7772** | GET /api/inventory | admin | ✗ | ✗ | ✓ |

---

## Règles firewall recommandées

```
# Port 7770 — Agents uniquement
ufw allow from 192.168.1.0/24 to any port 7770

# Port 7771 — Control Nodes / Plugins uniquement
ufw allow from 10.0.0.0/8 to any port 7771      # Réseau control nodes

# Port 7772 — Control Nodes / Admin uniquement
ufw allow from 10.0.0.0/8 to any port 7772      # Réseau control nodes

# Refuser tout le reste
ufw default deny incoming
```

---

## Variables de configuration

### Côté relay-api (server/main.py)

```python
# Port par rôle
PORT_AGENT = os.getenv("PORT_AGENT", "7770")        # Client
PORT_PLUGIN = os.getenv("PORT_PLUGIN", "7771")      # Plugin connection
PORT_INVENTORY = os.getenv("PORT_INVENTORY", "7772") # Admin
```

### Côté relay-agent (agent/relay_agent.py)

```python
# Configuration d'enrollment
RELAY_SERVER_URL = "http://192.168.1.218:7770"   # Uniquement port client
ENROLLMENT_ENDPOINT = f"{RELAY_SERVER_URL}/api/register"
WS_ENDPOINT = f"{RELAY_SERVER_URL}/ws/agent"
```

### Côté plugin Ansible (ansible_plugins/connection_plugins/relay.py)

```python
# Configuration du plugin
RELAY_API_URL = os.getenv("ANSIBLE_RELAY_API_URL",
                          "http://192.168.1.218:7771")
ADMIN_TOKEN = os.getenv("ANSIBLE_RELAY_ADMIN_TOKEN")
```

### Côté inventaire (ansible_plugins/inventory_plugins/relay_inventory.py)

```python
# Configuration de l'inventaire
RELAY_INVENTORY_URL = os.getenv("ANSIBLE_RELAY_INVENTORY_URL",
                                "http://192.168.1.218:7772")
ADMIN_TOKEN = os.getenv("ANSIBLE_RELAY_ADMIN_TOKEN")
```

---

## Docker Compose — Configuration

Voir `docker-compose.yml` :

```yaml
relay-api:
  ports:
    - "7770:7770"  # Client
    - "7771:7771"  # Plugin
    - "7772:7772"  # Inventory
  environment:
    PORT_AGENT: "7770"
    PORT_PLUGIN: "7771"
    PORT_INVENTORY: "7772"
```

---

## Déploiement en production

### Option 1 : Reverse proxy unique (Caddy/Nginx)

Caddy écoute **3 sockets différents**, route vers relay-api selon le port :

```caddyfile
:7770 { reverse_proxy relay-api:7770 }
:7771 { reverse_proxy relay-api:7771 }
:7772 { reverse_proxy relay-api:7772 }
```

### Option 2 : Kubernetes Ingress (recommandé)

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: ansible-relay
spec:
  rules:
  - host: agents.example.com
    http:
      paths:
      - path: /
        backend:
          service:
            name: relay-api-client
            port:
              number: 7770
  - host: plugins.example.com
    http:
      paths:
      - path: /
        backend:
          service:
            name: relay-api-plugin
            port:
              number: 7771
  - host: inventory.example.com
    http:
      paths:
      - path: /
        backend:
          service:
            name: relay-api-inventory
            port:
              number: 7772
```

Avantages :
- Isolation DNS (agents.example.com vs plugins.example.com vs inventory.example.com)
- Certificats TLS séparés possibles
- Règles WAF/rate-limiting par rôle

---

## Test de validation

```bash
# Port 7770 — Client enrollment
curl -X POST http://192.168.1.218:7770/api/register \
  -H "Content-Type: application/json" \
  -d '{"hostname":"test","os":"Linux","ip":"192.168.1.100","python_version":"3.11"}'

# Port 7771 — Plugin health check
curl http://192.168.1.218:7771/health

# Port 7772 — Inventory
curl http://192.168.1.218:7772/api/inventory
```

---

## Points clés

1. **Pas de confusion d'authentification** : chaque port = chaque rôle
2. **Traçabilité** : logs de chaque port séparés (audit facile)
3. **Scalabilité** : ports peuvent être sur des machines différentes (K8s)
4. **Règles firewall simples** : par port, par source IP
5. **Configuration claire** : PORT_* en variables d'environnement

