# Ansible-SecAgent — Quick Start v3.0.4

**Durée estimée** : 15 minutes
**Prérequis** : Docker 20.10+, Docker Compose 2.0+, openssl, le binaire `secagent-minion` (archive de release), `jq`

> **Portée** : démarrage **QUALIF / essai local** avec un certificat auto-signé. Pour la production
> (stockage partagé, actif/passif) voir [DEPLOYMENT/prod/README.md](../../DEPLOYMENT/prod/README.md).
> Le Compose utilisé est `DEPLOYMENT/qualif/docker-compose.server.yml` (deux instances `a`/`b` sur un
> même volume d'état ; seule l'instance maître ouvre ses ports, l'autre n'en ouvre aucun).
> Les autres fichiers de `DEPLOYMENT/qualif/` (`docker-compose.minion.yml`, `.proxy.yml`, `.ansible.yml`)
> sont marqués OBSOLETES en v3.0.3 : ne pas les utiliser.

---

## 1️⃣ Préparer l'environnement (3 min)

```bash
cd DEPLOYMENT/qualif

# Certificat TLS auto-signé. Le SAN est obligatoire : sans lui, la vérification TLS échoue.
mkdir -p tls
openssl req -x509 -newkey rsa:2048 -keyout tls/tls.key -out tls/tls.crt \
  -days 365 -nodes -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
# Le conteneur tourne en UID 10001 : la clef doit lui être lisible (essai local UNIQUEMENT).
chmod 0644 tls/tls.key

# Secrets du serveur (hors dépôt)
cp qualif.env.example qualif.env
# Renseigner dans qualif.env : JWT_SECRET_KEY, ADMIN_TOKEN, RSA_MASTER_KEY
#   (chaînes aléatoires, ex. `openssl rand -hex 32` ; RSA_MASTER_KEY est un secret
#    dont dérivent l'HMAC de l'état et le chiffrement AES-GCM de ses secrets, pas une clef RSA)

# Image candidate (voir l'en-tête de docker-compose.server.yml) et répertoire TLS
export SECAGENT_IMAGE=ghcr.io/ccoupel/secagent-server:sha-<commit>@sha256:<digest>
export QUALIF_TLS_DIR="$PWD/tls"
```

---

## 2️⃣ Initialiser l'état (2 min)

Le serveur **ne crée jamais son état implicitement** : sans `relay.state` il refuse de démarrer.
`state init` exige `RSA_MASTER_KEY` (présent dans `qualif.env`, chargé par le Compose).

```bash
# Crée relay.state (clef RSA-4096 du serveur + secret JWT) dans le volume partagé
docker compose -p secagent-qualif -f docker-compose.server.yml run --rm secagent-server-a state init

# Vérifier : `state verify` prend le chemin du fichier en argument
docker compose -p secagent-qualif -f docker-compose.server.yml run --rm secagent-server-a \
  state verify /data/relay.state
# Sortie : code retour 0 (OK). Codes 2-7 = défaut détecté (voir `state verify --help`).
```

---

## 3️⃣ Lancer le relay (2 min)

```bash
docker compose -p secagent-qualif -f docker-compose.server.yml up -d

sleep 5
# 7770 (API) est ouvert par l'instance maître ; l'autre instance n'ouvre aucun port.
curl -s --cacert tls/tls.crt https://localhost:7770/health
# Réponse : {"instance_id":"...","role":"master","status":"ok","timestamp":"..."}
```

> Le port d'hôte `7770` est publié par l'instance `a` ; l'instance `b` est publiée sur `8770`.
> Si `b` a pris le verrou en premier, interrogez `https://localhost:8770/health`.

---

## 4️⃣ Créer les jetons et enrôler un agent (4 min)

La CLI parle à l'API d'administration (7771, TLS). Dans le conteneur : `RELAY_API_URL` pointe sur
`https://localhost:7771`, `REPEATER_CA_FILE` sur le certificat monté, `ADMIN_TOKEN` vient de `qualif.env`.

```bash
# Alias de commodité : exécute la CLI dans l'instance a
srv() {
  docker compose -p secagent-qualif -f docker-compose.server.yml exec \
    -e RELAY_API_URL=https://localhost:7771 -e REPEATER_CA_FILE=/certs/tls.crt \
    secagent-server-a secagent-server "$@"
}

# Jeton d'enrôlement (1 h). Jeton opaque `secagent_enr_` + 64 hex (77 car.), pas un JWT.
ENR=$(srv tokens create --role enrollment --hostname-pattern 'qualif-host-.*' --expires 1h \
      | grep -oE 'secagent_enr_[0-9a-f]{64}' | tail -1)
echo "$ENR"
```

> Un jeton n'est affiché qu'**une seule fois**. Rôles possibles : `enrollment`, `plugin`, `relay-child`, `relay-parent` (les deux derniers sont des jetons de lien, créés sur la racine seulement)
> (il n'existe pas de rôle `agent` ou `admin`). Le jeton d'enrôlement est à usage unique sauf `--reusable`.

Démarrer l'agent (binaire `secagent-minion`, sur l'hôte ou dans un conteneur). Il n'a **aucun fichier de
configuration** : uniquement des variables d'environnement.

```bash
mkdir -p ./minion-data
RELAY_SERVER_URL=https://localhost:7770 \
RELAY_WS_URL=wss://localhost:7772/ws/agent \
RELAY_CA_BUNDLE="$PWD/tls/tls.crt" \
RELAY_AGENT_HOSTNAME=qualif-host-01 \
RELAY_PRIVATE_KEY="$PWD/minion-data/id_rsa" \
RELAY_JWT_PATH="$PWD/minion-data/token.jwt" \
RELAY_ASYNC_DIR="$PWD/minion-data/async" \
RELAY_ENROLLMENT_TOKEN="$ENR" \
secagent-minion
```

- `RELAY_WS_URL` **doit contenir le chemin `/ws/agent`** : l'agent compose l'URL telle quelle.
- Le 7772 est le port WebSocket dédié (`/ws/agent`, `/ws/relay`) ; le 7770 sert aussi ces chemins.
- Si l'instance maître est `b`, utilisez les ports d'hôte `8770`/`8772`.
- Succès : l'agent journalise l'enrôlement puis l'ouverture de la WebSocket.

---

## 5️⃣ Vérifier l'inventaire (1 min)

`GET /api/inventory` sur 7770 exige un **jeton plugin** (un jeton `ADMIN_TOKEN` renvoie 403).

```bash
PLG=$(srv tokens create --role plugin --description quickstart --expires 1h \
      | grep -oE 'secagent_plg_[0-9a-f]{64}' | tail -1)

curl -s --cacert tls/tls.crt -H "Authorization: Bearer $PLG" \
  https://localhost:7770/api/inventory | jq .
# {
#   "_meta": {"hostvars": {"qualif-host-01": {"ansible_connection": "relay", ...}}},
#   "all": {"hosts": ["qualif-host-01"]}
# }
```

---

## 6️⃣ Tester une exécution simple (1 min)

```bash
# Exécuter une commande sur l'agent (REST bloquant, jeton plugin)
curl -s --cacert tls/tls.crt -X POST \
  -H "Authorization: Bearer $PLG" \
  -H "Content-Type: application/json" \
  -d '{"cmd":"echo Hello from qualif-host-01","timeout":10}' \
  https://localhost:7770/api/exec/qualif-host-01 | jq .

# Résultat : {"rc":0,"stdout":"Hello from qualif-host-01\n","stderr":"","truncated":false}
```

Pour révoquer un jeton plugin : `srv tokens list` puis `srv tokens revoke <id>`.

---

## 📋 Commandes Utiles

```bash
# Logs des instances
docker compose -p secagent-qualif -f docker-compose.server.yml logs -f

# Statut local d'une instance (maître / secondaire)
docker compose -p secagent-qualif -f docker-compose.server.yml exec secagent-server-a \
  secagent-server status --local

# Arrêter tout
docker compose -p secagent-qualif -f docker-compose.server.yml down

# Recommencer à zéro (DESTRUCTIF : supprime l'état et les clefs). Le serveur ne se ré-initialise
# pas seul : `state init` est obligatoire avant le redémarrage.
docker compose -p secagent-qualif -f docker-compose.server.yml down -v
docker compose -p secagent-qualif -f docker-compose.server.yml run --rm secagent-server-a state init
```

---

## 🐛 Troubleshooting

| Problème | Cause | Solution |
|----------|-------|----------|
| Le conteneur redémarre en boucle, « relay.state » absent | État non initialisé | Exécuter `state init` (étape 2) |
| `state init` échoue | `RSA_MASTER_KEY` absent de `qualif.env` | Renseigner `RSA_MASTER_KEY` |
| Refus de démarrer : « admin API … plain HTTP on a non-loopback address » | `ADMIN_ADDR` non loopback sans `ADMIN_TLS=true` | Le Compose qualif fixe `ADMIN_TLS=true` ; ne pas le retirer |
| `curl` : certificat inconnu / SAN absent | Certificat sans SAN | Regénérer avec `-addext subjectAltName=...` |
| Rien n'écoute sur 7770 | Cette instance est secondaire (aucun port ouvert) | Interroger l'autre instance (`8770`) ; `status --local` indique le rôle |
| Agent : requête `GET /` / pas de WebSocket | `RELAY_WS_URL` sans `/ws/agent` | Ajouter le chemin `/ws/agent` |
| Agent : arrêt (code 78) à l'enrôlement | Jeton d'enrôlement refusé (403) | Créer un nouveau jeton ; aucun retry n'est fait sur un refus |
| 401 sur `/api/inventory` (`missing_authorization`) | En-tête `Authorization: Bearer` absent ou vide | Envoyer le jeton plugin |
| 403 sur `/api/inventory` (`token_not_found`, `token_revoked`, `token_expired`, `ip_not_allowed`…) | Jeton inconnu ou non plugin (ex. `ADMIN_TOKEN`), **révoqué**, expiré, ou IP hors `allowed_ips` (`handlers/plugin_auth.go`) | `tokens list --role plugin` ; en créer un nouveau : `tokens create --role plugin` |
| Retour arrière vers une version antérieure à #193 : `state: corrupt state file: payload: json: unknown field "revoked"` | L'état contient un agent révoqué (`"revoked": true`) que l'ancien binaire ne connaît pas. **Ce n'est pas une corruption** : le fichier est valide, c'est le décodeur strict de l'ancien binaire qui le refuse | Ne pas « réparer » le fichier. Avant le retour arrière, supprimer les agents révoqués (`DELETE /api/admin/minions/<hostname>`, cela lève leur révocation) ou rester sur la version courante. Attention : l'ancien binaire peut basculer sur `relay.state.prev` (un état plus ancien, parfois sans la révocation) avec un `[SECURITY WARNING]` : ne pas s'y fier, vérifier ensuite avec `minions list` |
| Inventaire vide | Agent non connecté | Vérifier les logs de l'agent |

---

## 📚 Prochaines Étapes

1. **Installer et configurer** : guides [agent](INSTALL_AGENT.md), [serveur racine](INSTALL_SERVER.md) et [relays enfants](INSTALL_RELAY.md). **Déployer en production** : voir [DEPLOYMENT/README.md](../../DEPLOYMENT/README.md) et [DEPLOYMENT/prod/README.md](../../DEPLOYMENT/prod/README.md)
2. **Écrire des playbooks** : utiliser le plugin de connexion `relay` (voir [PLUGINS_SPEC](../plugins/PLUGINS_SPEC.md))
3. **Configurer les hooks** : voir [DOC/server/HOOKS_SPEC.md](../server/HOOKS_SPEC.md)

---

**Questions ?** Consulter [DOC/](../) ou créer une issue sur GitHub.
