# Migration vers architecture multi-port

**Date** : 2026-03-04
**Status** : Implémentation complète
**Objectif** : Séparer les rôles (client/plugin/admin) sur 3 ports distincts pour améliorer la sécurité.

---

## Changements d'architecture

### Avant (port unique)
```
Port 8443 → relay-api (FastAPI)
  ├─ POST /api/register          (client)
  ├─ GET  /ws/agent              (client)
  ├─ POST /api/exec/{host}       (plugin)
  ├─ POST /api/upload/{host}     (plugin)
  ├─ POST /api/fetch/{host}      (plugin)
  ├─ GET  /api/inventory         (admin)
  └─ GET  /health                (tous)
```

### Après (3 ports distincts)
```
Port 7770 → app_client (enrollment + WSS)
  ├─ POST /api/register          (client)
  ├─ GET  /ws/agent              (client)
  └─ GET  /health

Port 7771 → app_plugin (exec/upload/fetch)
  ├─ POST /api/exec/{host}       (plugin)
  ├─ POST /api/upload/{host}     (plugin)
  ├─ POST /api/fetch/{host}      (plugin)
  └─ GET  /health

Port 7772 → app_inventory (admin)
  ├─ GET  /api/inventory         (admin)
  └─ GET  /health
```

---

## Fichiers modifiés

### 1. **server/api/main_multi_port.py** (NOUVEAU)
Launcher multi-port avec :
- **Lifespan partagée** : DB et NATS initialisés une seule fois (par le premier app)
- **3 instances FastAPI** : `app_client`, `app_plugin`, `app_inventory`
- **Routeurs différents** : chaque app inclut UNIQUEMENT ses routes
  - app_client : routes_register + ws_handler
  - app_plugin : routes_exec
  - app_inventory : routes_inventory

**Utilisation** (local dev) :
```bash
# Lancer avec hypercorn (3 processus)
hypercorn server.api.main_multi_port:app_client --bind 0.0.0.0:7770 &
hypercorn server.api.main_multi_port:app_plugin --bind 0.0.0.0:7771 &
hypercorn server.api.main_multi_port:app_inventory --bind 0.0.0.0:7772
```

### 2. **server/Dockerfile**
Modifié pour :
- Installer `hypercorn` (multi-worker async server)
- EXPOSE 7770 7771 7772
- CMD : lance les 3 apps en parallèle via shell script
- Healthcheck sur port 7770 (client)

### 3. **docker-compose.yml**
Changements :
- **relay-api** : ports 7770/7771/7772 (au lieu de 8443)
- **relay-agent** : RELAY_SERVER_URL=`http://relay-api:7770` (au lieu de 8443)
- **smoke-test** : RELAY_API_URL=`http://relay-api:7770`
- **caddy** : PORT_* env vars pour router correctement

### 4. **Caddyfile** (Nouveau)
Router TLS pour les 3 ports si besoin (optionnel en qualif).

### 5. **PORTS_SECURITY.md** (Nouveau)
Documentation complète de la séparation sécurité.

### 6. **start_multi_port.sh** (Nouveau)
Script bash pour lancer les 3 hypercorn workers (optionnel).

---

## Implémentation détaillée

### main_multi_port.py — Structure

```python
# Singleton global (initialization flag)
_db_initialized = False
_nats_initialized = False
_shutdown_called = False

# Shared lifespan
@asynccontextmanager
async def shared_lifespan(app: FastAPI):
    """
    Runs ONCE pour le premier app (les autres apps réutilisent le state existant).
    """
    if not _db_initialized:
        # Initialize DB (AgentStore)
        # Initialize NATS (NatsClient)
        _db_initialized = True
        _nats_initialized = True

    yield  # app runs

    if not _shutdown_called:
        # Shutdown DB et NATS
        _shutdown_called = True

# 3 app factories
def create_app_client(settings=None) -> FastAPI:
    app = FastAPI(title="... Client (Port 7770)")
    app.state.settings = settings
    app.include_router(routes_register.router)   # POST /api/register
    app.include_router(ws_handler.router)        # GET /ws/agent
    return app

def create_app_plugin(settings=None) -> FastAPI:
    app = FastAPI(title="... Plugin (Port 7771)")
    app.state.settings = settings
    app.include_router(routes_exec.router)       # POST /api/exec/*
    return app

def create_app_inventory(settings=None) -> FastAPI:
    app = FastAPI(title="... Inventory (Port 7772)")
    app.state.settings = settings
    app.include_router(routes_inventory.router)  # GET /api/inventory
    return app

# Module-level instances
app_client = create_app_client()
app_plugin = create_app_plugin()
app_inventory = create_app_inventory()
```

### Avantages

✓ **Isolation complète** : chaque port = chaque rôle, pas de confusion possible
✓ **Authentification claire** : JWT(rôle=agent) ≠ JWT(rôle=plugin) ≠ ADMIN_TOKEN
✓ **Firewall facile** :
  - Port 7770 → agents only (192.168.1.0/24)
  - Port 7771 → control nodes only (10.0.0.0/8)
  - Port 7772 → control nodes + admin
✓ **Scalabilité K8s** : 3 déploiements différents possibles
✓ **Logs séparés** : audit par port

---

## Test de déploiement

### En local (développement)

```bash
# Lancer docker-compose
cd /path/to/Ansible_Agent
docker compose up --build -d

# Vérifier les ports
curl http://localhost:7770/health
curl http://localhost:7771/health
curl http://localhost:7772/health

# Tester enrollment (port 7770)
curl -X POST http://localhost:7770/api/register \
  -H "Content-Type: application/json" \
  -d '{"hostname":"test","os":"Linux","ip":"192.168.1.100","python_version":"3.11"}'

# Tester inventaire (port 7772)
curl http://localhost:7772/api/inventory
```

### Sur 192.168.1.218 (qualification)

```bash
# Déployer
DOCKER_HOST=tcp://192.168.1.218:2375 docker compose up --build -d

# Vérifier
curl http://192.168.1.218:7770/health
curl http://192.168.1.218:7771/health
curl http://192.168.1.218:7772/health
```

---

## Migration des configurations

### relay-agent

**Avant** :
```python
RELAY_SERVER_URL = "http://relay-api:8443"
```

**Après** :
```python
RELAY_SERVER_URL = "http://relay-api:7770"  # Client port
```

### Plugins Ansible

**Avant** (si utilisé) :
```python
RELAY_API_URL = "http://relay-api:8443"
```

**Après** :
```python
# Connection plugin (exec/upload/fetch)
RELAY_API_URL = "http://relay-api:7771"

# Inventory plugin
RELAY_INVENTORY_URL = "http://relay-api:7772"
ADMIN_TOKEN = "..."
```

---

## État de déploiement

| Composant | Avant | Après | Status |
|-----------|-------|-------|--------|
| relay-api | port 8443 (1 port) | 3 ports (7770/7771/7772) | ✓ Implémenté |
| main.py | single app | multi-port app_client/app_plugin/app_inventory | ✓ Implémenté |
| Dockerfile | EXPOSE 8443 | EXPOSE 7770 7771 7772 | ✓ Mis à jour |
| docker-compose.yml | 8080:8443 | 7770/7771/7772 | ✓ Mis à jour |
| relay-agent config | port 8443 | port 7770 | ✓ Mis à jour |
| Caddyfile | facultatif | documenté | ✓ Nouveau |

---

## Limitations actuelles

### Lifespan partagée
- Les 3 apps partagent la MÊME lifespan (DB et NATS)
- Si l'un des ports s'arrête, les autres restent actifs
- Shutdown complet seulement quand tous les processus sont terminés

**Mitigation** : en Docker Compose, les 3 apps tournent dans le même container, donc l'une d'elles s'arrête = le container s'arrête = tout s'arrête.

### State partagé
- `ws_handler.ws_connections` : global, partagé par app_client et app_plugin
- `routes_exec.pending_futures` : global, partagé
- `routes_exec.result_cache` : global, partagé

**Mitigation** : c'est intentionnel. Les futures et resultats doivent être partagés (un exec peut être lancé par plugin et réceptionné par agent).

---

## Prochaines étapes

1. **Rebuild docker image** :
   ```bash
   docker compose build relay-api
   ```

2. **Test complet** :
   ```bash
   docker compose up -d
   curl http://localhost:7770/health
   curl http://localhost:7771/health
   curl http://localhost:7772/health
   ```

3. **Test enrollment** :
   ```bash
   # Enrollment sur port 7770
   curl -X POST http://localhost:7770/api/register ...

   # Inventaire sur port 7772
   curl http://localhost:7772/api/inventory
   ```

4. **Deploy sur 192.168.1.218** :
   ```bash
   DOCKER_HOST=tcp://192.168.1.218:2375 docker compose up --build -d
   ```

---

## Rollback (si nécessaire)

Pour revenir à l'architecture mono-port :
1. Restaurer `server/api/main.py` original (port 8443)
2. Mettre à jour docker-compose.yml (ports 8080:8443)
3. Mettre à jour relay-agent (RELAY_SERVER_URL port 8443)

---

## Architecture Kubernetes future (optionnel)

Pour une vraie scalabilité, on peut avoir 3 **services Kubernetes différents** :

```yaml
apiVersion: v1
kind: Service
metadata:
  name: relay-api-client
spec:
  ports:
  - port: 7770
  selector:
    app: relay-api-client

---
apiVersion: v1
kind: Service
metadata:
  name: relay-api-plugin
spec:
  ports:
  - port: 7771
  selector:
    app: relay-api-plugin

---
apiVersion: v1
kind: Service
metadata:
  name: relay-api-inventory
spec:
  ports:
  - port: 7772
  selector:
    app: relay-api-inventory
```

Chaque service peut avoir son propre Deployment, load balancer, et règles réseau différentes.

