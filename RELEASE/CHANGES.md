# Journal des changements — Architecture multi-port

**Date** : 2026-03-04
**Changement** : Séparation des ports pour isolation par rôle
**Impact** : Sécurité accrue, pas de ports 80/443 utilisés

---

## Résumé des changements

| Type | Fichier | Statut | Description |
|------|---------|--------|-------------|
| Nouveau | server/api/main_multi_port.py | ✓ Créé | Launcher 3 apps FastAPI (7770/7771/7772) |
| Nouveau | Caddyfile | ✓ Créé | Router TLS optionnel |
| Nouveau | PORTS_SECURITY.md | ✓ Créé | Documentation sécurité |
| Nouveau | MULTI_PORT_MIGRATION.md | ✓ Créé | Guide migration |
| Nouveau | DEPLOYMENT_CHECKLIST.md | ✓ Créé | Checklist déploiement (7 phases) |
| Nouveau | start_multi_port.sh | ✓ Créé | Script lancement optionnel |
| Modifié | server/Dockerfile | ✓ Maj | EXPOSE 7770/7771/7772, hypercorn |
| Modifié | docker-compose.yml | ✓ Maj | Ports et URLs actualisées |
| À vérifier | agent/secagent_agent.py | ⚠ Révision | RELAY_SERVER_URL → port 7770 |
| À vérifier | qualif/Dockerfile.smoke | ⚠ Révision | RELAY_API_URL → port 7770 |

---

## Architecture avant → après

### Avant (port unique 8443)
```
Port 8443
├─ POST /api/register (client)
├─ GET  /ws/agent (client)
├─ POST /api/exec/* (plugin)
├─ POST /api/upload/* (plugin)
├─ POST /api/fetch/* (plugin)
├─ GET  /api/inventory (admin)
└─ GET  /health

Risque : JWT(agent) vs JWT(plugin) sur même port
```

### Après (3 ports distincts)
```
Port 7770 (Client)
├─ POST /api/register
├─ GET  /ws/agent
└─ GET  /health

Port 7771 (Plugin)
├─ POST /api/exec/*
├─ POST /api/upload/*
├─ POST /api/fetch/*
└─ GET  /health

Port 7772 (Inventory)
├─ GET  /api/inventory
└─ GET  /health

Bénéfice : Isolation complète par rôle
```

---

## Fichiers détaillés

### Créés

#### 1. server/api/main_multi_port.py (381 lignes)
- Classe `Settings` : configuration env vars
- Fonction `shared_lifespan()` : initialisation DB et NATS une seule fois
- Fonctions `create_app_client()`, `create_app_plugin()`, `create_app_inventory()`
- Module-level instances : `app_client`, `app_plugin`, `app_inventory`
- Avantage : chaque app n'inclut que ses routeurs

#### 2. Caddyfile (56 lignes)
- Port 7770 : reverse proxy vers relay-api:7770
- Port 7771 : reverse proxy vers relay-api:7771
- Port 7772 : reverse proxy vers relay-api:7772
- Optionnel (pas utilisé en Docker Compose simple)

#### 3. PORTS_SECURITY.md (280+ lignes)
- Vue d'ensemble architecture
- Détail de chaque port (endpoints, auth, flux)
- Matrice de sécurité
- Variables de configuration
- Règles firewall recommandées
- Déploiement K8s futur

#### 4. MULTI_PORT_MIGRATION.md (320+ lignes)
- Changements d'architecture
- Fichiers modifiés/créés
- Structure main_multi_port.py
- Avantages sécurité
- Test de déploiement
- Limitations et mitigations

#### 5. DEPLOYMENT_CHECKLIST.md (260+ lignes)
- 7 phases de déploiement
- Vérifications pour chaque port
- Tests d'isolation
- Logs et diagnostics
- Rollback
- Format de rapport

#### 6. start_multi_port.sh (25 lignes)
- Script optionnel pour lancer 3 hypercorn workers
- Alternative à docker-compose (dev local)

### Modifiés

#### 1. server/Dockerfile
```diff
- FROM python:3.11-slim
+ FROM python:3.11-slim
  RUN groupadd --system relay && useradd --system --gid relay --no-create-home relay
  WORKDIR /app
  COPY server/requirements.txt /app/requirements.txt
- RUN pip install --no-cache-dir -r requirements.txt
+ RUN pip install --no-cache-dir -r requirements.txt && \
+     pip install --no-cache-dir hypercorn
  COPY server/ /app/server/
  RUN mkdir -p /data && chown relay:relay /data
  USER relay
- EXPOSE 8443
+ EXPOSE 7770 7771 7772
  HEALTHCHECK --interval=10s --timeout=5s --retries=5 --start-period=10s \
-     CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8443/health')"
+     CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:7770/health')"
- CMD ["uvicorn", "server.api.main:app", "--host", "0.0.0.0", "--port", "8443", "--log-level", "info"]
+ CMD ["/bin/bash", "-c", \
+      "hypercorn server.api.main_multi_port:app_client --bind 0.0.0.0:7770 & \
+       hypercorn server.api.main_multi_port:app_plugin --bind 0.0.0.0:7771 & \
+       hypercorn server.api.main_multi_port:app_inventory --bind 0.0.0.0:7772 && \
+       wait"]
```

#### 2. docker-compose.yml
```diff
relay-api:
  build:
    context: .
    dockerfile: server/Dockerfile
  # ...
  environment:
    # (PORT_AGENT, PORT_PLUGIN, PORT_INVENTORY supprimés)
  ports:
-   - "8080:8443"
+   - "7770:7770"  # Client
+   - "7771:7771"  # Plugin
+   - "7772:7772"  # Inventory
  healthcheck:
    test: ["CMD", "python3", "-c",
-          "import urllib.request; urllib.request.urlopen('http://localhost:8443/health')"]
+          "import urllib.request; urllib.request.urlopen('http://localhost:7770/health')"]

secagent-minion:
  # ...
  environment:
-   RELAY_SERVER_URL: "http://relay-api:8443"
+   RELAY_SERVER_URL: "http://relay-api:7770"

smoke-test:
  # ...
  environment:
-   RELAY_API_URL: "http://relay-api:8443"
+   RELAY_API_URL: "http://relay-api:7770"

caddy:
  # ...
  ports:
-   - "443:443"
-   - "80:80"
+   - "7443:7443"   # TLS optionnel
```

### À vérifier

#### 1. agent/secagent_agent.py
Vérifier que `RELAY_SERVER_URL` utilise port 7770 :
```python
RELAY_SERVER_URL = "http://192.168.1.218:7770"  # Client port
```

#### 2. qualif/Dockerfile.smoke (si exists)
Vérifier que `RELAY_API_URL` utilise port 7770 :
```
RELAY_API_URL=http://relay-api:7770
```

---

## Configuration requise

### Variables d'environnement
Inchangées (voir ARCHITECTURE.md) :
- `JWT_SECRET_KEY` : clef HMAC-SHA256
- `ADMIN_TOKEN` : token Bearer
- `NATS_URL` : URL NATS
- `DATABASE_URL` : URL SQLite

### Dépendances nouvelles
- `hypercorn` : ASGI server multi-process (ajouté à requirements.txt via Dockerfile)

---

## Impact sur les tests

### Tests unitaires (server/tests/)
Pas de changement requis (tests mocker les apps).

### Tests d'intégration
À actualiser si nécessaire :
- `RELAY_API_URL` → port 7770 (client)
- `RELAY_EXEC_URL` → port 7771 (plugin)
- `RELAY_INVENTORY_URL` → port 7772 (admin)

### Tests E2E
À actualiser :
- Enrollment sur port 7770
- Exec sur port 7771
- Inventaire sur port 7772

---

## Impact sécurité

### Améliorations
✓ Isolation des rôles (client/plugin/admin)
✓ Authentification par rôle != par endpoint
✓ Règles firewall par port possibles
✓ Pas de ports 80/443 utilisés (prod-safe)

### Limitations
⚠ DB et NATS partagés (intentionnel, nécessaire)
⚠ WebSocket connections partagées (intentionnel)
⚠ Futures et resultats partagés (intentionnel)

---

## Rollback

Pour revenir à l'architecture mono-port (8443) :

```bash
# Restaurer fichiers
git checkout server/Dockerfile docker-compose.yml agent/secagent_agent.py

# Rebuild
docker compose build relay-api

# Redéployer
docker compose up --build -d
```

---

## Validation

Avant de déployer en production :

- [ ] Tous les 3 ports sont accessibles
- [ ] Health checks passent sur les 3 ports
- [ ] Isolation des endpoints validée (pas de croisement)
- [ ] Tests d'authentification passent (JWT par rôle)
- [ ] Firewall rules appliquées (par port/IP)
- [ ] Logs propres (pas d'erreurs)
- [ ] Rapport final produit (DEPLOYMENT_CHECKLIST.md)

---

## Références

- `PORTS_SECURITY.md` : Architecture et sécurité détaillée
- `MULTI_PORT_MIGRATION.md` : Guide d'implémentation
- `DEPLOYMENT_CHECKLIST.md` : Checklist de déploiement
- `server/api/main_multi_port.py` : Implémentation

