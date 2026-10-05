# Déploiement production — Docker Compose multi-hôtes (actif/passif)

Périmètre : Docker Compose uniquement. Kubernetes/Helm sont abandonnés ; Docker Swarm est **hors périmètre**.
Un Compose par relay, **déployé à l'identique sur N hôtes**, avec `STATE_DIR` (fichier d'état `relay.state`,
`relay.lock`, journal) sur un **stockage partagé**. Une seule instance est maître (ports 7770/7772 ouverts) ;
les autres sont secondaires et **n'ouvrent aucun port**. Le Compose est fourni avec la release
(`secagent-compose-<version>.tar.gz`, images en `vX.Y.Z@sha256:…`, vérifier `SHA256SUMS`).

## Fichiers

| Fichier | Rôle |
|---|---|
| `docker-compose.server.yml` | relay racine ; `docker-compose.child.yml` en surcharge pour un relay enfant |
| `.env.example` → `.env` | variables d'interpolation non secrètes (version, chemins, adresse de publication admin) |
| `prod.env.example` → `prod.env` | **secrets** (`JWT_SECRET_KEY`, `ADMIN_TOKEN`, `RSA_MASTER_KEY`, `REPEATER_UPSTREAM_TOKEN`), mode 0600, **jamais dans le dépôt** |
| `tools/test_shared_storage.py` | qualification du stockage partagé |

`JWT_SECRET_KEY`, `ADMIN_TOKEN` et `RSA_MASTER_KEY` sont **identiques sur tous les nœuds candidats** d'un relay.
Nom de projet : `docker compose -p secagent-prod-<relay_id> …`.

## Réseau et sécurité

- TLS natif : `tls.crt` (chaîne complète) et `tls.key` dans `TLS_CERT_DIR`, montés en lecture seule ; pas de reverse proxy ; `TLS_DISABLE` ne doit jamais être défini.
- 7770 et 7772 sont publiés. **7771 (admin)** : le serveur y écoute sur `0.0.0.0` *dans le conteneur* avec `ADMIN_TLS=true` ;
  l'hôte ne le publie que sur `ADMIN_PUBLISH_ADDR` (boucle locale par défaut, ou réseau d'administration), **jamais** sur `0.0.0.0`
  ni sans adresse. Contrôlé en CI sur le rendu (`scripts/ci/check_compose.py`).
- Conteneur non-root `10001:10001`, système de fichiers en lecture seule, `cap_drop: ALL`.
  **Le même UID/GID 10001 doit avoir les droits d'écriture sur le partage depuis tous les hôtes** :
  `chown 10001:10001 <partage>` ; `chmod 0700`.
- Healthcheck : `secagent-server status --local` (lit le statut local sous le tmpfs `/run/secagent`, jamais sur le partage).
  Maître et secondaire sont `healthy` ; un process figé passe `unhealthy`.
- Clients (minion, `secagent-inventory`, plugin, relays enfants) : listes d'adresses (`RELAY_SERVER_URL`, `RELAY_WS_URL`,
  `REPEATER_UPSTREAM_URL`) couvrant **tous les hôtes** : seul le maître répond. Côté minion systemd : `RestartPreventExitStatus=77 78`.

## Stockage partagé (NFS)

**Règle : stockage non testé = non supporté.** NAS d'entrée de gamme et montages CIFS/SMB sont à proscrire sans succès du test ci-dessous.

Montage recommandé sur chaque hôte (`/etc/fstab`) :

    nas:/export/secagent  /mnt/secagent-state  nfs4  rw,hard,nfsvers=4.1,noatime,actimeo=1,_netdev  0 0

`hard` (jamais `soft`), pas de `nolock`, `actimeo` bas (1 à 3 s). Puis `STATE_HOST_DIR=/mnt/secagent-state`.
Alternative : volume Docker NFS (bloc commenté en bas du Compose).

### Test avant mise en production (deux hôtes)

    # hôte 1 :  T=$(( $(date +%s) + 60 )); echo $T
    tools/test_shared_storage.py run --dir /mnt/secagent-state/.storage-test --host h1 --hosts h1,h2 --start-at $T
    tools/test_shared_storage.py run --dir /mnt/secagent-state/.storage-test --host h2 --hosts h1,h2 --start-at $T   # hôte 2
    tools/test_shared_storage.py verify --dir /mnt/secagent-state/.storage-test --hosts h1,h2

Il vérifie, avec 500 fichiers : `O_CREAT|O_EXCL` (un seul gagnant par fichier), `rename` atomique (aucun fichier partiel
lu), `fsync` fichier et répertoire. À répéter (au moins 3 fois), horloges synchronisées (NTP). Complément manuel : `kill -9`
d'un maître pendant l'écriture, puis `secagent-server state verify`. Supprimer ensuite `.storage-test`.

## Premier déploiement

1. Sur chaque hôte : `.env`, `prod.env`, certificats, partage monté, `docker login ghcr.io` si l'image est privée.
2. **Initialiser l'état une seule fois**, depuis un seul hôte, avant de démarrer les autres :
   `docker compose run --rm --no-deps secagent-server state init` (nécessite `RSA_MASTER_KEY`).
3. `docker compose -p secagent-prod-<relay_id> up -d` sur chaque hôte.
4. Contrôle : exactement **un** hôte écoute sur 7770/7772 ; `docker ps` : tous `healthy`.

## Bascule manuelle

Arrêt propre du maître : `docker compose stop secagent-server` (relâche `relay.lock`) ; un secondaire devient maître en quelques
secondes. `docker kill` / perte de l'hôte : promotion après la péremption du verrou. Le maître qui perd le verrou sort et
redémarre secondaire (`restart: unless-stopped`).

## Sauvegarde et restauration

### État (`relay.state`)
Fichier unique, cohérent par construction : copier `relay.state` (ou `relay.state.prev`) **hors hôte et hors du partage**,
à intervalle régulier et avant chaque montée de version. Restauration : relay arrêté sur tous les hôtes,
`secagent-server state verify` puis `state restore`, redémarrage. Le fichier d'état n'est pas rétrocompatible au-delà d'un
changement de `schema_version`.

### `RSA_MASTER_KEY` — procédure **distincte**
Sans cette clé, tous les champs `enc:` de l'état sont définitivement illisibles : le relay doit régénérer son identité et
**tous les agents doivent se ré-enrôler**. Stocker la clé dans un coffre **hors hôte et hors du partage**, accès restreint,
au moins deux copies. **Tester la restauration** sur un hôte vierge : clé restaurée + état restauré → le relay redémarre avec
la même identité et les agents se reconnectent sans ré-enrôlement. Refaire ce test à chaque rotation de la clé.
