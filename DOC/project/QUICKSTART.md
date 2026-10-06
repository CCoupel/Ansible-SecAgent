# Ansible-SecAgent — Quick Start v3.0.3

**Durée estimée** : 10 minutes  
**Prérequis** : Docker 20.10+, Docker Compose 2.0+, openssl

---

## 1️⃣ Préparer l'environnement (2 min)

```bash
cd DEPLOYMENT/qualif

# Générer certificats TLS auto-signés
openssl req -x509 -newkey rsa:2048 -keyout tls.key -out tls.crt \
  -days 365 -nodes -subj "/CN=localhost"

# Créer répertoire d'état
mkdir -p state logs

# Créer .env si absent (docker-compose.yml le référence)
cat > .env <<'EOF'
STATE_DIR=./state
TLS_CERT=./tls.crt
TLS_KEY=./tls.key
ADMIN_ADDR=127.0.0.1:7771
EOF
```

---

## 2️⃣ Initialiser le relay (2 min)

```bash
# Créer le fichier d'état vierge
docker compose run --rm secagent-server state init

# Vérifier l'initialisation
docker compose run --rm secagent-server state verify
# Sortie : exit code 0 (OK)
```

---

## 3️⃣ Lancer le relay (2 min)

```bash
# Démarrer le relay server
docker compose up -d relay

# Vérifier que les ports écoutent
sleep 2
curl -k https://localhost:7770/health
# Réponse attendue : {"status":"ok","agents":0,"uptime_seconds":...}
```

---

## 4️⃣ Enrôler et lancer les agents (2 min)

```bash
# Générer un token d'enrôlement (valide 1 heure)
TOKEN=$(docker compose exec relay \
  secagent-server admin token create --role agent --duration 1h | grep -oE '[a-zA-Z0-9._-]{80,}' | tail -1)

echo "Token: $TOKEN"

# Passer le token aux agents via docker compose
export RELAY_ENROLLMENT_TOKEN=$TOKEN

# Démarrer les agents
docker compose up -d minion-01 minion-02 minion-03

# Vérifier la connexion
sleep 3
docker compose logs minion-01 | grep -i "enrolled\|connected"
# Chercher : "Enrolled successfully" + "WebSocket open"
```

---

## 5️⃣ Vérifier l'inventaire (1 min)

```bash
# Générer un token admin
ADMIN_JWT=$(docker compose exec relay \
  secagent-server admin token create --role admin --duration 1h | grep -oE '[a-zA-Z0-9._-]{80,}' | tail -1)

# Récupérer l'inventaire
curl -s -k -H "Authorization: Bearer $ADMIN_JWT" \
  https://localhost:7770/api/inventory | jq .

# Résultat attendu :
# {
#   "_meta": {
#     "hostvars": {
#       "qualif-host-01": {"ansible_host": "...", "os": "Linux", ...},
#       ...
#     }
#   },
#   "all": {"hosts": ["qualif-host-01", "qualif-host-02", "qualif-host-03"]}
# }
```

---

## 6️⃣ Tester une exécution simple (1 min)

```bash
# Générer token plugin
PLUGIN_JWT=$(docker compose exec relay \
  secagent-server admin token create --role plugin --duration 1h | grep -oE '[a-zA-Z0-9._-]{80,}' | tail -1)

# Exécuter une commande sur un agent (REST bloquant)
curl -s -k -X POST \
  -H "Authorization: Bearer $PLUGIN_JWT" \
  -H "Content-Type: application/json" \
  -d '{"cmd":"echo Hello from minion-01","timeout":10}' \
  https://localhost:7770/api/exec/qualif-host-01 | jq .

# Résultat : {"rc":0,"stdout":"Hello from minion-01\n","stderr":"","truncated":false}
```

---

## 📋 Commandes Utiles

```bash
# Voir logs du relay
docker compose logs relay -f

# Voir logs d'un agent
docker compose logs minion-01 -f

# Redémarrer un agent
docker compose restart minion-01

# Arrêter tout
docker compose down

# Nettoyer l'état (pour recommencer)
rm -rf state/* && docker compose run --rm secagent-server state init
```

---

## 🐛 Troubleshooting

| Problème | Cause | Solution |
|----------|-------|----------|
| Relay ne démarre pas | Certificats manquants | Exécuter `openssl req -x509 ...` |
| Agents ne se connectent pas | Token expiré | Générer nouveau token |
| Status 401 on /api/inventory | JWT invalide | Vérifier l'expiration du JWT |
| Inventaire vide | Agents pas connectés | Vérifier `docker compose logs minion-01` |

---

## 📚 Prochaines Étapes

1. **Deployer en production** : Voir [DEPLOYMENT/README.md](../../DEPLOYMENT/README.md)
2. **Écrire des playbooks** : Utiliser plugin connection `relay`
3. **Configurer les hooks** : Voir [DOC/server/HOOKS_SPEC.md](../server/HOOKS_SPEC.md)

---

**Questions ?** Consulter [DOC/](../) ou créer une issue sur GitHub.
