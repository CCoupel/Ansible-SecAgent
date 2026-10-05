# Fichier d'état du relay (v3.0.3, #159)

Remplace SQLite pour les relays : un fichier unique chargé en mémoire, écrit atomiquement par un écrivain unique. Implémenté dans `GO/cmd/secagent-server/internal/state` (indépendant de `storage` et des handlers, sans CGO).

## Fichiers (`STATE_DIR`, défaut `/data`, mode 0600)

| Fichier | Rôle |
|---|---|
| `relay.state` | état courant |
| `relay.state.prev` | génération précédente (lien dur de l'ancien `relay.state`) |
| `relay.state.tmp` | écriture en cours |
| `relay.lock` | verrou d'exclusivité du maître (#162) |

## Format

JSON : `{"schema_version":1,"written_at","writer_instance","write_seq","hmac","sha256","payload":{...}}`. `sha256` couvre exactement les octets du `payload` : c'est une simple somme de contrôle, que quiconque peut écrire dans `STATE_DIR` peut recalculer. `hmac` (HMAC-SHA-256, hex) l'authentifie : il couvre, dans un format sans ambiguïté (champs de longueur variable préfixés par leur longueur, préfixe de domaine `secagent-state-v2`), `schema_version`, `write_seq`, `written_at`, `writer_instance`, le champ `sha256` **tel que stocké** et les octets du `payload`. Couvrir `sha256` est volontaire : sinon, corrompre ce seul champ laisserait le HMAC valide, serait pris pour une corruption accidentelle et provoquerait un repli silencieux sur un `.prev` authentique plus ancien (par exemple d'avant une révocation) ; un `sha256` modifié est désormais un refus de sécurité final, comme tout HMAC invalide. Le format a changé par rapport au premier jet de #159 : aucune migration, la v3 repart d'un état vierge (`state init`), avec une clé dérivée de `RSA_MASTER_KEY` par HKDF-SHA-256 (libellé `state-hmac-v1`, domaine distinct de la clé AES). Sans clé maître (mode test) le HMAC est omis. `write_seq` est un compteur d'écritures monotone (sans lien avec le verrou). `schema_version` inconnu ou supérieur : refus de démarrer, pas de bascule sur `.prev`.

`payload` : `agents`, `authorized_keys`, `enrollment_tokens`, `plugin_tokens`, `relay_parent_tokens`, `blacklist`, `relay_nodes` (configuration seulement), `server_config`. Jamais écrits : `relay_routing`, `status`/`last_seen`/`relay_chain` des relays, `action_log` (journal à part, #161). `last_seen` et `last_used_*` ne sont persistés qu'au passage d'une écriture naturelle (`Options.Piggyback`).

Aucun secret en clair : jetons hashés (SHA-256), `server_config` (clé RSA privée, secrets JWT) et `token_secret` des relays push chiffrés `enc:` (AES-256-GCM, `RSA_MASTER_KEY`). Chaque chiffré est lié à son champ par les données additionnelles authentifiées (AAD) : le nom de la clé pour `server_config` (`jwt_secret_current`…), `relay_nodes/<relay_id>/token_secret` pour un relay push. Un chiffré déplacé dans un autre champ ne se déchiffre plus.

## Écriture

1. Garde `BeforeWrite` (sans garde : **aucune écriture**, pas même `relay.state.tmp`).
2. Les mutations d'un lot s'appliquent sur une copie du modèle, chacune tout-ou-rien (journal d'annulation), puis le lot est écrit en une fois (group commit).
3. `relay.state.tmp` (0600) + `fsync`, `relay.state.prev` ← lien dur de `relay.state`, `rename(tmp → relay.state)`, `fsync` du répertoire.
4. Le modèle n'est publié qu'après le rename : la mémoire n'est jamais en avance sur le disque.
5. Plafond dur `STATE_MAX_BYTES` (défaut 64 Mio) : écriture refusée au-delà.

## Chargement

Ordre des contrôles : format → `schema_version` → **HMAC** (avant la somme de contrôle) → `sha256` → structure et invariants → secrets (préfixe `enc:` et ouverture avec la liaison AAD du champ). Taille vérifiée (`stat`) avant la lecture (plafond `STATE_MAX_BYTES`) ; `relay.state` et `.prev` sont ouverts sans suivre un lien symbolique (`O_NOFOLLOW`).

Deux familles d'échecs :

- **Corruption** (JSON illisible ou tronqué, somme de contrôle fausse, fichier plus gros que le plafond, invariant de structure) : bascule sur `.prev` avec `[SECURITY WARNING]`. Les deux invalides : refus de démarrer (jamais de réinitialisation automatique).
- **Violation de sécurité** (`ErrSecurityInvariant`, **refus sans bascule**, même si un `.prev` valide existe) : HMAC absent ou invalide alors qu'une clé maître est configurée, secret de `server_config` en clair, chiffré qui ne s'ouvre pas avec sa liaison AAD, `token_secret` de relay push en clair. Une falsification ne se distingue pas d'une dégradation du disque, et un `.prev` valide ne doit jamais la masquer. `relay.state.prev` suit exactement les mêmes règles.

`relay.state` **absent** alors que `.prev` existe = reprise automatique sur `.prev` (écriture interrompue : le repli par renommage de la rotation laisse un instant sans `relay.state`), avec `[SECURITY WARNING]`, après les mêmes contrôles (HMAC compris). C'est l'écart assumé avec « absent = refus », qui ne vaut que sans `.prev`. Fichier absent et sans `.prev` : `FATAL: relay.state not found in STATE_DIR=<dir> — run 'secagent-server state init' to initialize`.

Mode test : un secret de `server_config` en clair n'est accepté que par l'option explicite `InsecureTestMode` (état créé par `state init --insecure-test-mode`) et **jamais** avec une clé maître : le serveur refuse de démarrer si `RSA_MASTER_KEY` est configurée et que `InsecureTestMode` est demandé ou que l'état contient un secret en clair.

Limites connues : le HMAC interdit de forger ou d'éditer un état sans la clé maître, pas de rejouer une copie authentique plus ancienne de `relay.state` (ni de tronquer `relay.state` pour forcer le repli sur `.prev`). Une garde de `write_seq` minimal persistée dans le verrou (#163) la couvrira. **Rotation de la clé maître (#172/#163)** : elle change la clé HMAC et la clé AES ; elle doit ré-écrire d'un bloc tout l'état (secrets rechiffrés, HMAC recalculé) sous le verrou maître, sinon l'ancien fichier est refusé.

## `secagent-server state init`

Crée l'état initial (clé RSA-4096 et secret JWT, chiffrés par `RSA_MASTER_KEY`, obligatoire sauf `--insecure-test-mode`). Refuse d'agir si `relay.state`, `relay.state.prev` ou `relay.lock` existe. Création **atomique sans remplacement** : contenu écrit et synchronisé sous un nom temporaire privé puis `link` vers `relay.state` (qui échoue si le fichier existe) : de plusieurs `init` concurrents, un seul réussit. `--insecure-test-mode` est refusé si `RSA_MASTER_KEY` est définie. Commande locale : n'exige ni `ADMIN_TOKEN` ni `JWT_SECRET_KEY`. Ne démarre aucun port.

## Invariants

Unicité de hostname, jti, token_hash, relay_id ; relay `pull` sans `token_secret` ; relay `push` : `token_secret` seul, préfixé `enc:` ; relay révoqué ⇒ son jti est dans la blacklist (même mutation) ; secrets de `server_config` toujours préfixés `enc:` (écriture et chargement ; seule exception : `InsecureTestMode` sans clé maître).

La garde d'écriture `BeforeWrite` est appelée avant le lot, puis de nouveau juste avant la rotation et le `rename` (le verrou peut être perdu pendant le `fsync`) : un refus tardif annule l'écriture, supprime le temporaire et ne laisse rien en mémoire.

## Dimensionnement mesuré (10 000 agents, clé publique ~800 octets)

Fichier ≈ 10 Mio ; chargement ≈ 150 ms ; écriture complète ≈ 150 ms ; 100 enrôlements concurrents ≈ 220 ms en 2 écritures.

## Store (#160)

`internal/storage.Store` est réimplémenté sur ce moteur (même API publique ; `storage.Open(state.Options)`). Lectures : index en mémoire. Écritures : mutations du moteur. **Atomicité** : l'enrôlement (`EnrollAgent` : jeton consommé + clé autorisée + agent) et la révocation d'un relay (drapeau + blacklist, `RevokeRelayNode` / `RevokeRelayParentToken`) sont **une seule mutation** (un rename). **Volatile, jamais écrit** : statut et `last_seen` des agents et des relays, `relay_routing`, `relay_chain`. **Piggyback** : `agents.last_seen` et `last_used_at`/`last_used_ip` des tokens plugin sont fusionnés dans le fichier à la prochaine écriture naturelle (une requête plugin n'écrit jamais sur le disque). **Purge** : une tâche du serveur retire chaque heure les entrées expirées de la blacklist (elle n'écrit que s'il y en a, et passe par la garde).

Tokens de relay : `token_hash` (pull, SHA-256 du JWT) et `token_secret` (push : jeton scellé `enc:` lié au relay par AAD, `relay_nodes/<id>/token_secret`) sont deux champs distincts. Un relay révoqué sans JTI (déclaré automatiquement à sa connexion) reçoit un JTI synthétique `no-token:<relay_id>`, blacklisté dans la même mutation (le drapeau `revoked` seul refuse ses connexions).

**Sans garde d'écriture** (`Config.WriteGuard` nul) le moteur est en **lecture seule** : toute écriture échoue (`storage.ErrReadOnly`), aucun fichier n'est créé. En production la garde est toujours `CheckOwnership` du verrou (#163) : le processus n'écrit qu'une fois **maître confirmé**, et chaque écriture revérifie le verrou (avant la création du fichier temporaire et juste avant le rename). `RELAY_SINGLE_INSTANCE` n'existe plus (ignorée avec un avertissement) : le verrou est toujours actif, même pour une instance unique, et protège contre un double démarrage. Le serveur ne crée jamais l'état : `relay.state` absent = `FATAL: relay.state not found in STATE_DIR=<dir> — run 'secagent-server state init' to initialize`. `DATABASE_URL` définie = erreur de démarrage.

## Reprise : `state verify` et `state restore --from` (#187)

Le serveur refuse de démarrer, sans bascule sur `.prev`, devant un HMAC ou un `sha256` faux, un schéma inconnu ou un invariant violé. Deux commandes locales (sans API, sans port, sans verrou pris) servent à diagnostiquer et à reprendre.

### `secagent-server state verify <fichier> [--min-write-seq N]`
Applique toutes les vérifications du serveur (schéma, HMAC avec la clé dérivée de `RSA_MASTER_KEY` lue dans l'environnement, `sha256`, invariants, secrets `enc:` et liaison AAD) **sans rien écrire**. Sortie : `schema_version`, `write_seq`, `written_at`, `writer_instance`, nombre d'entités par type, verdict et motif — jamais de valeur `enc:`, de hash de token ni de clé.

| Code | Signification |
|---|---|
| 0 | authentique et valide |
| 2 | HMAC invalide (« clé maître incorrecte ou fichier falsifié ») ou `sha256` falsifié |
| 3 | `schema_version` inconnu |
| 4 | invariant violé (structure, secret sans `enc:`, liaison AAD) |
| 5 | fichier illisible, absent ou qui n'est pas un état |
| 6 | `RSA_MASTER_KEY` absente |
| 7 | `write_seq` inférieur à `--min-write-seq` (copie trop ancienne) |

### `secagent-server state restore --from <fichier> [--state-dir D] [--min-write-seq N] [--i-know-no-instance-is-running]`
1. `verify` d'abord : un fichier inauthentique ou invalide est refusé, rien n'est modifié (mêmes codes 2 à 7).
2. **Aucune instance active** : `relay.lock` est observé sans jamais être écrit, avec la règle de fraîcheur du verrou (contenu inchangé pendant la limite de son rôle, sur l'horloge monotone locale : 10 s pour un candidat, 5 min pour un maître ; tout changement du compteur de battement = instance vivante ; observation interrompue = refus). Verrou frais → code **8**, rien n'est modifié. `--i-know-no-instance-is-running` passe outre un verrou orphelin (stockage figé) : `[SECURITY WARNING]` et trace dans le journal.
3. **Sauvegarde** de `relay.state` et `relay.state.prev` en `relay.state.bak-<UTC>` / `relay.state.prev.bak-<UTC>` (0600, jamais relus par le serveur).
4. **Remplacement atomique par le code du moteur** (`atomicWrite` : fichier temporaire, `fsync`, `link`/`rename`, `fsync` du répertoire), avec les octets du fichier vérifié (HMAC intact, rien n'est ré-encodé) ; `relay.state.prev` est conservé tel quel ; 0600.
5. **Journal** `state-restore.log` dans `STATE_DIR` (une ligne JSON par intervention, sans secret, jamais lu par le serveur) : date, opérateur (utilisateur système), fichier source, `write_seq` avant/après, noms des sauvegardes, `lock_override` le cas échéant.

Redémarrer ensuite les instances. La garde `write_seq` en mémoire des secondaires (#163) peut refuser un état restauré plus ancien que ce qu'elles ont observé : c'est voulu, d'où **l'arrêt de toutes les instances avant la restauration**. Il n'y a pas de `state init --force` : la réinitialisation complète déplace `STATE_DIR` puis relance `state init` (nouvelle identité, ré-enrôlement de tous les agents).



## Anti-rejeu : garde de `write_seq` (#163)

Le HMAC interdit de **forger** un état, pas de **rejouer une copie authentique plus ancienne** de `relay.state` (ou de supprimer `relay.state` pour forcer la reprise sur un `.prev` plus ancien). Garde :

- le maître écrit le `write_seq` courant de l'état dans `relay.lock` (champ `write_seq`) : après chaque écriture d'état, publié au plus tard au contrôle d'identité suivant (~5 s), jamais décroissant, et à chaque battement ;
- chaque secondaire mémorise le plus grand `write_seq` lu dans le verrou, **y compris dans un verrou périmé juste avant de le supprimer**, et le reporte dans le verrou qu'il crée en devenant maître ;
- à la promotion, le chargement refuse un `relay.state` (ou un `.prev` de repli) dont le `write_seq` est inférieur : `[SECURITY WARNING]`, démarrage refusé (code de sortie 1, aucun port ouvert, verrou supprimé, état local `failed`).

**Limite résiduelle** : la garde vit dans la mémoire des instances. Après un **arrêt à froid de toutes les instances**, elle est perdue et le rejeu d'une copie authentique reste possible ; la protection repose alors sur le contrôle d'accès à `STATE_DIR` et sur les sauvegardes (`state verify` / `state restore --from --min-write-seq`, #187).

À l'**arrêt propre** le verrou est supprimé, et avec lui son champ `write_seq` : la garde ne subsiste alors que dans la mémoire des secondaires qui l'ont lu (au plus une période de contrôle de retard, ~5 s). Un rejeu d'une copie authentique plus ancienne juste après un arrêt propre n'est donc détecté que pour ce qui a été observé ; même limite que l'arrêt à froid de toutes les instances ci-dessus.
