# Déploiement Qualif — Multi-Zones (192.168.1.218)

Topologie qualif : `relay-proxy` ──┬── `relay-dmz1` (zone DMZ1)
                                    └── `relay-dmz2` (zone DMZ2)

## Prérequis

- Docker remote access actif sur `192.168.1.218:2375`
- Fichier `.env` renseigné depuis `.env.proxy` (voir ci-dessous)

## 1. Préparer `.env`

```bash
cp .env.proxy .env
# Éditer .env : JWT_SECRET_KEY, ADMIN_TOKEN
# NE PAS renseigner RELAY_ENROLLMENT_TOKEN_* — ils seront générés par le bootstrap (étape 3 ci-dessous)
```

`.env` est ignoré par git (`qualif/*.env`).

> **Note (premier `up`)** : les variables `RELAY_ENROLLMENT_TOKEN_*` sont **vides** au moment
> du premier `docker compose up`. C'est attendu — les agents relay-dmz1 et relay-dmz2 ne pourront
> pas s'enroller avant l'étape 3 (bootstrap). Les warnings Compose sur ces variables sont normaux.

## 2. Lancer les services

```bash
DOCKER_HOST=tcp://192.168.1.218:2375 \
  docker compose -f docker-compose.proxy.yml up --build -d
```

Vérifier que tous les services sont `healthy` :

```bash
DOCKER_HOST=tcp://192.168.1.218:2375 docker compose -f docker-compose.proxy.yml ps
```

## 3. Bootstrap (tokens et relay nodes)

Après `docker compose up -d`, exécuter le script de bootstrap (idempotent — relançable sans erreur) :

```bash
DOCKER_HOST=tcp://192.168.1.218:2375 \
  ADMIN_TOKEN=<votre-admin-token> \
  bash ../../scripts/bootstrap-qualif.sh
```

Le script :
1. Crée les tokens d'enrollment pour chaque zone (relay-dmz1, relay-dmz2)
2. Crée un token plugin Ansible sur relay-proxy
3. Enregistre les relay nodes sur relay-proxy (mode pull)
4. Écrit tous les secrets dans `DEPLOYMENT/qualif/.env.bootstrap` (permissions 600, non versionné)

> **Sécurité (qualif uniquement)** : les tokens d'enrollment sont créés avec
> `--hostname-pattern ".*"` (tout hostname accepté). En production, utiliser un pattern
> plus restrictif correspondant aux noms d'hôtes attendus.

> **JWT relay-child** : la commande `relays add` (mode pull) affiche un JWT une seule fois.
> Il est automatiquement sauvegardé dans `.env.bootstrap` sous `RELAY_JWT_DMZ1` / `RELAY_JWT_DMZ2`.
> Ce JWT sera utile pour le repeater-client une fois les issues #124/#125 implémentées.

Copier ensuite les `RELAY_ENROLLMENT_TOKEN_*` dans `.env` et **recréer** les agents
(`--force-recreate` est obligatoire : `docker compose restart` ne relit pas `.env`) :

```bash
# Exemple : copier les valeurs de .env.bootstrap dans .env
# puis recréer les containers pour qu'ils lisent les nouvelles variables :
DOCKER_HOST=tcp://192.168.1.218:2375 \
  docker compose -f docker-compose.proxy.yml \
  up -d --force-recreate agent-dmz1 agent-dmz2
```

## 4. Smoke test

```bash
ADMIN_TOKEN=<token> bash smoke-proxy.sh
```

> **Limitations actuelles** : des checks smoke sont attendus en échec jusqu'à
> l'implémentation du repeater-client (#124/#125/#140) — non vérifiés sur la qualif.

## Variables d'environnement

| Variable | Requise | Description |
|----------|---------|-------------|
| `JWT_SECRET_KEY` | ✓ | Clef HMAC-SHA256 pour JWT (min 32 chars) |
| `ADMIN_TOKEN` | ✓ | Token Bearer admin (partagé entre relays) |
| `RELAY_ENROLLMENT_TOKEN_DMZ1` | ✓ | Token enrollment agents zone DMZ1 — **vide au premier `up`, généré par le bootstrap** |
| `RELAY_ENROLLMENT_TOKEN_DMZ2` | ✓ | Token enrollment agents zone DMZ2 — **vide au premier `up`, généré par le bootstrap** |

## Ports exposés

| Port | Service | Usage |
|------|---------|-------|
| 7780 | relay-proxy API | Enrollment agents, `/api/agents` agrégés |
| 7781 | relay-proxy Admin | CLI admin (interne seulement) |
| 7782 | relay-proxy WS | WebSocket agents |
| 7783 | relay-dmz1 API | Smoke test uniquement |
| 7784 | relay-dmz2 API | Smoke test uniquement |

## Promotion QUALIF des images serveur et minion (sans rebuild)

Un push ne fait que des tests : **aucune image n'est publiée par `ci.yml`**. La publication sur GHCR est réservée
(1) à la promotion QUALIF, lancée **manuellement** : GitHub → Actions → *Candidate images (QUALIF promotion)* →
*Run workflow* (`ref` = branche ou commit, `publish` = `true`) ; (2) au tag `vX.Y.Z` (`release.yml`, PROD).
Le résumé du run donne `ghcr.io/ccoupel/<image>:sha-<commit>@sha256:<digest>` : c'est la valeur de `SECAGENT_IMAGE`
de `docker-compose.server.yml`.
