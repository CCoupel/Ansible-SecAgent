# Checklist déploiement multi-port (7770/7771/7772)

**Date** : 2026-03-04
**Responsable** : deploy-qualif
**Cible** : 192.168.1.218

---

## Phase 1 : Préparation

- [ ] Vérifier que les ports 7770, 7771, 7772 ne sont PAS utilisés sur 192.168.1.218
  ```bash
  ssh root@192.168.1.218 "netstat -tlnp | grep -E ':(7770|7771|7772)'"
  # Doit être vide
  ```

- [ ] Vérifier les variables d'environnement
  ```bash
  echo "JWT_SECRET_KEY=$JWT_SECRET_KEY" (ne pas afficher la valeur)
  echo "ADMIN_TOKEN=$ADMIN_TOKEN" (ne pas afficher la valeur)
  # Doivent être non-vides
  ```

- [ ] Backup de la DB existante (si présente)
  ```bash
  docker cp relay-api:/data/relay.db relay.db.backup
  ```

---

## Phase 2 : Build et déploiement

- [ ] Build l'image relay-api avec le nouveau Dockerfile
  ```bash
  DOCKER_HOST=tcp://192.168.1.218:2375 docker compose build relay-api
  ```

- [ ] Vérifier que l'image contient `hypercorn`
  ```bash
  DOCKER_HOST=tcp://192.168.1.218:2375 docker run relay-api pip list | grep hypercorn
  ```

- [ ] Déployer avec docker-compose
  ```bash
  DOCKER_HOST=tcp://192.168.1.218:2375 docker compose up -d
  ```

- [ ] Attendre que tous les services soient healthy (30-60s)
  ```bash
  DOCKER_HOST=tcp://192.168.1.218:2375 docker compose ps
  # STATUS doit être "Up" pour tous les services
  ```

---

## Phase 3 : Vérification des ports

### Port 7770 (Client — enrollment + WSS)

- [ ] Health check
  ```bash
  curl http://192.168.1.218:7770/health
  # Réponse attendue : {"status":"ok","db":"ok","nats":"unavailable"}
  ```

- [ ] Enrollment nominal
  ```bash
  curl -X POST http://192.168.1.218:7770/api/register \
    -H "Content-Type: application/json" \
    -d '{
      "hostname": "test-agent-01",
      "os": "Linux",
      "ip": "192.168.1.100",
      "python_version": "3.11"
    }'
  # Réponse attendue : 201 + JWT
  ```

- [ ] Vérifier dans la DB
  ```bash
  docker exec relay-api sqlite3 /data/relay.db \
    "SELECT hostname, status FROM agents;" | head -5
  # Doit voir test-agent-01 avec status 'registered'
  ```

### Port 7771 (Plugin — exec/upload/fetch)

- [ ] Health check
  ```bash
  curl http://192.168.1.218:7771/health
  # {"status":"ok","db":"ok","nats":"unavailable"}
  ```

- [ ] Logs du container
  ```bash
  docker logs relay-api 2>&1 | grep -E "(7770|7771|7772|uvicorn|hypercorn)" | tail -20
  # Doit montrer que les 3 ports sont en écoute
  ```

### Port 7772 (Inventory — admin)

- [ ] Health check
  ```bash
  curl http://192.168.1.218:7772/health
  # {"status":"ok","db":"ok","nats":"unavailable"}
  ```

- [ ] Inventaire
  ```bash
  curl http://192.168.1.218:7772/api/inventory
  # Réponse attendue : JSON Ansible format
  # Doit contenir test-agent-01 dans hostvars
  ```

---

## Phase 4 : Vérification sécurité

- [ ] Isolation des ports
  ```bash
  # Port 7770 → accepte POST /api/register
  curl -X POST http://192.168.1.218:7770/api/exec/test 2>&1
  # Doit retourner 404 ou 405 (NOT FOUND / METHOD NOT ALLOWED)

  # Port 7771 → accepte POST /api/exec
  curl -X POST http://192.168.1.218:7771/api/register 2>&1
  # Doit retourner 404 ou 405
  ```

- [ ] WebSocket port 7770
  ```bash
  # Tester WS avec curl ou Python websocket
  # GET /ws/agent doit être accessible UNIQUEMENT sur port 7770
  ```

- [ ] Inventaire port 7772
  ```bash
  # GET /api/inventory doit être UNIQUEMENT sur port 7772
  curl http://192.168.1.218:7770/api/inventory
  # Doit retourner 404
  ```

---

## Phase 5 : Logs et diagnostics

- [ ] Logs du container
  ```bash
  docker logs relay-api 2>&1 | tail -50
  # Doit montrer :
  # - "Database ready"
  # - "NATS unavailable" (expected, NATS not running)
  # - "AnsibleRelay multi-port server started"
  # - Pas d'erreur
  ```

- [ ] Logs de chaque port (si possible)
  ```bash
  docker logs relay-api 2>&1 | grep -E "(7770|7771|7772)"
  ```

- [ ] Status des services
  ```bash
  DOCKER_HOST=tcp://192.168.1.218:2375 docker compose ps
  ```

---

## Phase 6 : Test de charge basique (optionnel)

- [ ] Test enrollment multiple
  ```bash
  for i in {1..5}; do
    curl -X POST http://192.168.1.218:7770/api/register \
      -H "Content-Type: application/json" \
      -d "{\"hostname\":\"agent-$i\",\"os\":\"Linux\",\"ip\":\"192.168.1.$((100+i))\",\"python_version\":\"3.11\"}"
    sleep 1
  done
  ```

- [ ] Vérifier la DB
  ```bash
  docker exec relay-api sqlite3 /data/relay.db \
    "SELECT COUNT(*) FROM agents;"
  # Doit voir 6 agents (test-agent-01 + agent-1 à agent-5)
  ```

---

## Phase 7 : Rollback (si besoin)

- [ ] Arrêter le déploiement actuel
  ```bash
  DOCKER_HOST=tcp://192.168.1.218:2375 docker compose down
  ```

- [ ] Restaurer la DB (si backup fait en Phase 1)
  ```bash
  docker cp relay.db.backup relay-api:/data/relay.db
  ```

- [ ] Redéployer l'ancienne image (si nécessaire)
  ```bash
  git checkout server/Dockerfile docker-compose.yml
  DOCKER_HOST=tcp://192.168.1.218:2375 docker compose up -d
  ```

---

## Rapport final

### Format de rapport à envoyer au CDP

```
DÉPLOIEMENT MULTI-PORT — Date : YYYY-MM-DD

Déploiement : ✓ SUCCÈS

Ports vérifiés :
✓ Port 7770 (Client)      : Health OK, enrollment nominal
✓ Port 7771 (Plugin)      : Health OK, health accessible
✓ Port 7772 (Inventory)   : Health OK, inventaire accessible

Agents enregistrés : N
NATS : unavailable (expected)
DB : ok

Logs d'erreur : [aucun/liste si applicables]

Points notables :
- [liste des observations importantes]

RÉSULTAT : OK
```

---

## Points clés

1. **Les 3 ports DOIVENT être accessibles** depuis l'extérieur
2. **Pas d'erreurs** dans les logs du container
3. **Isolation des endpoints** : aucun croisement possible
4. **DB et NATS partagés** : c'est intentionnel
5. **Healthcheck sur port 7770** : c'est le point d'entrée principal

---

## Contacts et escalade

- En cas d'erreur réseau (port non accessible) : vérifier firewall/iptables
- En cas d'erreur de déploiement : consulter les logs du container
- En cas de perte de DB : rollback avec le backup
- En cas de défaut sécurité (croisement endpoints) : rollback et audit

