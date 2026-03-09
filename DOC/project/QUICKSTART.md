# Ansible-SecAgent — Quick Start Guide

## Déploiement Rapide

### Depuis Windows (ou n'importe où)

```batch
# Déployer serveur + minions
.\deploy.bat all

# Voir le statut
.\deploy.bat status

# Arrêter tout
.\deploy.bat stop
```

### Depuis Linux/macOS

```bash
# Rendre exécutable
chmod +x deploy.sh

# Déployer serveur + minions
./deploy.sh all

# Voir le statut
./deploy.sh status

# Arrêter tout
./deploy.sh stop
```

### Sur srv8 (192.168.1.218) via Docker Remote API

Les scripts gèrent automatiquement la connexion à `tcp://192.168.1.218:2375`.

```batch
# Depuis Windows
.\deploy.bat status

# Depuis Linux
./deploy.sh status
```

---

## Déploiement Manuel (pas recommandé)

Si tu veux déployer manuellement sans les scripts :

### Server uniquement

```bash
cd ansible_server
docker compose up --build -d

# Vérifier santé
curl http://192.168.1.218:7770/health
```

### Minions uniquement (après server)

```bash
cd ansible_minion
docker compose up --build -d

# Vérifier logs
docker logs secagent-minion-01
docker logs secagent-minion-02
docker logs secagent-minion-03
```

---

## Commandes Utiles

```bash
# Statut des services
./deploy.sh status

# Logs du serveur
./deploy.sh logs-server

# Logs d'un agent (01, 02, ou 03)
./deploy.sh logs-agent 01

# Arrêter proprement
./deploy.sh stop

# Tout arrêter y compris les volumes
cd ansible_server && docker compose down -v
cd ../ansible_minion && docker compose down -v
```

---

## Vérifications Après Déploiement

```bash
# 1. Server sain ?
curl http://192.168.1.218:7770/health
# {"status":"ok","db":"ok","nats":"ok"}

# 2. Agents connectés ?
docker logs secagent-minion-01 | grep "WebSocket connecté"
docker logs secagent-minion-02 | grep "WebSocket connecté"
docker logs secagent-minion-03 | grep "WebSocket connecté"

# 3. Agents enregistrés en base ?
# Les agents doivent d'abord être pré-autorisés (voir DEPLOYMENT.md)
```

---

## Structure

```
ansible-secagent/
├── deploy.sh                 ← Linux/macOS
├── deploy.bat               ← Windows
├── ansible_server/
│   ├── docker-compose.yml
│   └── .env
├── ansible_minion/
│   └── docker-compose.yml
└── ...
```

## Variables d'Environnement (optionnel)

```bash
# Utiliser un autre Docker host
export DOCKER_HOST=unix:///var/run/docker.sock
./deploy.sh status

# Ou sur une seule commande
DOCKER_HOST=unix:///var/run/docker.sock ./deploy.sh status
```

---

## Troubleshooting

### "Cannot connect to Docker daemon at tcp://192.168.1.218:2375"

→ Vérifier que Docker Remote API est accessible sur 192.168.1.218:2375
→ Vérifier `DOCKER_HOST` environment variable

### "Agents ne s'enregistrent pas"

→ Vérifier que les clefs publiques sont pré-autorisées
→ Voir DEPLOYMENT.md section "Pré-autoriser les agents"

### "WebSocket connecté" mais pas de tâches

→ Les agents sont bien connectés !
→ Utiliser Ansible avec le plugin `relay` pour envoyer les tâches

---

## Prochaines Étapes

1. **Vérifier l'enrollment** → Voir DEPLOYMENT.md
2. **Tester avec Ansible** → Voir README.md "E2E Testing"
3. **Production Kubernetes** → Voir ARCHITECTURE.md
