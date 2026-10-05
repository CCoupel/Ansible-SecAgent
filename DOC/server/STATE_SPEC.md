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

JSON : `{"schema_version":1,"written_at","writer_instance","write_seq","hmac","sha256","payload":{...}}`. `sha256` couvre exactement les octets du `payload` : c'est une simple somme de contrôle, que quiconque peut écrire dans `STATE_DIR` peut recalculer. `hmac` (HMAC-SHA-256, hex) l'authentifie : il couvre `schema_version`, `write_seq`, `written_at`, `writer_instance` et les octets du `payload`, avec une clé dérivée de `RSA_MASTER_KEY` par HKDF-SHA-256 (libellé `state-hmac-v1`, domaine distinct de la clé AES). Sans clé maître (mode test) le HMAC est omis. `write_seq` est un compteur d'écritures monotone (sans lien avec le verrou). `schema_version` inconnu ou supérieur : refus de démarrer, pas de bascule sur `.prev`.

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
