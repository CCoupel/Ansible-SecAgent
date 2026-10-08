# Fichier d'état du relay (v3.0.3, #159)

Remplace SQLite pour les relays : un fichier unique chargé en mémoire, écrit atomiquement par un écrivain unique. Implémenté dans `GO/cmd/secagent-server/internal/state` (indépendant de `storage` et des handlers, sans CGO).

## Fichiers (`STATE_DIR`, défaut `/data`, mode 0600)

| Fichier | Rôle |
|---|---|
| `relay.state` | état courant |
| `relay.state.prev` | génération précédente (lien dur de l'ancien `relay.state`) |
| `relay.state.tmp` | écriture en cours |
| `relay.lock` | verrou d'exclusivité du maître (#162) |
| `relay.state.v1.bak` (v3.0.4) | copie octet pour octet de l'état v1 (ou de `relay.state.prev` si c'est lui qui a été chargé), écrite par le **maître** à la première écriture qui migre v1 → v2, avant toute écriture v2 ; 0600, fichier temporaire + `fsync` + `rename` ; jamais relue par le serveur ; remplacée par un contenu identique si la migration est rejouée, plus aucune sauvegarde une fois le v2 écrit ; **jamais purgée automatiquement** (suppression par l'opérateur, après validation de la v3.0.4) — voir « Migration v1 → v2 » |
| `relay.state.bak-<UTC>`, `relay.state.prev.bak-<UTC>` | copies de l'état d'avant un `state restore` ; 0600 ; horodatage `AAAAMMJJThhmmssZ` ; jamais relues par le serveur ni purgées automatiquement |
| `relay.state.linktrust-reset.<UTC>.bak` (v3.0.4) | copie complète de `relay.state` d'avant un `state link-trust reset` ; 0600 ; même horodatage ; jamais relue ni purgée automatiquement ; contient les mêmes secrets chiffrés que l'état — voir `state link-trust reset` |
| `relay.state.rekey.<UTC>.bak` (v3.0.4) | copie octet pour octet de `relay.state` d'avant un `state rekey` ; 0600, `fsync`, exclusive, jamais relue par le serveur ; **chiffrée avec l'ANCIENNE clé maître** : à protéger puis détruire une fois la nouvelle clé en service |
| `state-restore.log` | journal des interventions `state restore`, `state link-trust reset` et `state rekey` (une ligne JSON par intervention, sans secret ni clé : date, opérateur, source, `write_seq` avant/après, sauvegardes, `lock_override`) ; ouvert en ajout, 0600, sans suivre les liens symboliques ; jamais lu par le serveur ni tourné automatiquement |

## Format

JSON : `{"schema_version":2,"written_at","writer_instance","write_seq","hmac","sha256","payload":{...}}`. `sha256` couvre exactement les octets du `payload` : c'est une simple somme de contrôle, que quiconque peut écrire dans `STATE_DIR` peut recalculer. `hmac` (HMAC-SHA-256, hex) l'authentifie : il couvre, dans un format sans ambiguïté (champs de longueur variable préfixés par leur longueur, préfixe de domaine `secagent-state-v2`), `schema_version`, `write_seq`, `written_at`, `writer_instance`, le champ `sha256` **tel que stocké** et les octets du `payload`. Couvrir `sha256` est volontaire : sinon, corrompre ce seul champ laisserait le HMAC valide, serait pris pour une corruption accidentelle et provoquerait un repli silencieux sur un `.prev` authentique plus ancien (par exemple d'avant une révocation) ; un `sha256` modifié est désormais un refus de sécurité final, comme tout HMAC invalide. Le format a changé par rapport au premier jet de #159 : aucune migration, la v3 repart d'un état vierge (`state init`), avec une clé dérivée de `RSA_MASTER_KEY` par HKDF-SHA-256 (libellé `state-hmac-v1`, domaine distinct de la clé AES). Sans clé maître (mode test) le HMAC est omis. `write_seq` est un compteur d'écritures monotone (sans lien avec le verrou). `schema_version` inconnu (hors de 1 à 2) ou supérieur : refus de démarrer (`ErrSchemaVersion`), pas de bascule sur `.prev`. Ce binaire **écrit toujours la version 2** et **lit** les versions 1 et 2 (voir « Schéma 2 » ci-dessous).

`payload` : `agents`, `authorized_keys`, `enrollment_tokens`, `plugin_tokens`, `relay_parent_tokens`, `blacklist`, `relay_nodes` (configuration seulement), `server_config`, et depuis le schéma 2 `link_tokens` et `link_trust`. Jamais écrits : `relay_routing`, `status`/`last_seen`/`relay_chain` des relays, `action_log` (journal à part, #161). `last_seen` et `last_used_*` ne sont persistés qu'au passage d'une écriture naturelle (`Options.Piggyback`).

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

## Schéma 2 (v3.0.4, #141/#146) : jetons de lien signés par la racine

`SchemaVersion` passe à **2**. Décision figée : **pas de rétrocompatibilité**. Un binaire v3.0.3 (égalité stricte `schema_version == 1`) **refuse** un état v2 avec `ErrSchemaVersion`, sans bascule sur `.prev` : une paire actif/passif monte en v3.0.4 **ensemble** (arrêter le passif, monter l'actif, monter le passif). Le retour arrière est la restauration de `relay.state.v1.bak` avec les binaires v3.0.3 (les écritures faites sous v3.0.4 sont perdues).

### Ajouts au `payload`

| Section | Contenu | Propriétaire |
|---|---|---|
| `link_tokens` | registre des jetons de lien **émis** : `id`, `jti`, `role` (`relay-child` \| `relay-parent`), `sub` (présentateur), `aud` (vérificateur), `kid`, `created_at`, `expires_at`, `revoked_at`, `created_by`, `description`. Jamais le jeton ni son hash (la signature l'authentifie). | racine seulement (vide ailleurs : l'état ne le sait pas, c'est le serveur, L1d, qui refuse `mint` hors racine, 409 `not_root`) |
| `link_trust` | ancre de confiance : `root_id` (relay_id de la racine, l'`iss` attendu des jetons de lien), `current_pub`, `current_kid`, `previous_pub`, `previous_kid` (clés publiques Ed25519, **base64url sans remplissage** des 32 octets bruts, l'encodage du message `link_keys`, **non secrètes**), `seq` (**dernier numéro du compteur unique** accepté, qu'il vienne d'un `link_keys` ou d'un `link_revocations` : anti-rejeu, `repeater/linktrust.go`). Valeur nulle = pas d'ancre (le relay non racine refuse alors tout lien entrant). | relay non racine |
| `server_config.link_seq` / `server_config.link_rotation_seq` | compteurs en **clair** (chaînes décimales, non secrets) de la racine (`storage/store_link.go`) : `link_seq` = le compteur unique incrémenté à chaque révocation de jeton de lien, rotation et fermeture de fenêtre (S20) ; `link_rotation_seq` = le `seq` de la rotation qui a ouvert la fenêtre de double acceptation (sert à re-signer le `link_keys` pour un enfant qui se connecte), supprimé par `retire-link-previous`. | racine |
| `server_config.link_signing_key_current` / `_previous` | clé **privée** de signature de la racine. **Secrets** : ajoutés à `secretConfigKeys`, chiffrés `enc:` (AES-256-GCM, `RSA_MASTER_KEY`), AAD = nom du champ (un chiffré déplacé de `current` vers `previous` est un refus de sécurité final au chargement). Écriture en clair refusée (hors `InsecureTestMode`). | racine |

### Invariants ajoutés

- `link_tokens` : clé = `id` ; `jti`, `sub`, `aud`, `kid`, `expires_at` obligatoires ; `role` ∈ {`relay-child`, `relay-parent`} (l'ancien rôle `relay` n'existe plus) ; `jti` unique (index).
- **Jeton de lien révoqué (`revoked_at` posé) et non expiré ⇒ son `jti` est dans la `blacklist`**, dans **la même mutation** (une mutation qui révoque sans blacklister est annulée, `ErrInvalid`). Un jeton expiré n'exige pas d'entrée (elle peut avoir été purgée).
- Un registre `link_tokens` non vide exige `link_signing_key_current` ; `link_signing_key_previous` exige `link_signing_key_current`.
- `link_trust` cohérent : une clé publique et son `kid` vont ensemble ; une clé publique est du base64url (sans remplissage) de 32 octets ; **`root_id` est obligatoire dès qu'une clé publique est présente** (`link_trust has a public key but no root_id`) ; `previous_*`, `seq` et `root_id` exigent un `current_*` ; les deux `kid` diffèrent. Le contrôle ne recalcule pas le `kid` (défini par `auth/linkjwt.go`).
- Relay révoqué sans `jti` (R6) : valide seulement si un `link_tokens` le nomme (`sub` ou `aud`) ; la JTI d'un lien vit dans `link_tokens`, la blacklist est liée par l'invariant ci-dessus.
- Un fichier `schema_version` 1 ne peut porter aucune donnée de lien (corruption sinon).

### Migration v1 → v2

Au **premier chargement d'un état v1** le serveur le lit tel quel (HMAC vérifié avec `schema_version` 1 ; les sections de lien valent vide). Il **n'écrit rien** : un secondaire ne migre pas. La migration a lieu à la **première écriture du maître** (garde `BeforeWrite` comprise) :

1. copie du fichier v1 chargé (octet pour octet) dans **`relay.state.v1.bak`** (0600, fichier temporaire + `fsync` + `rename` + `fsync` du répertoire), **avant** toute écriture v2 ; le serveur ne relit jamais ce fichier ;
2. écriture normale du lot en `schema_version` 2 (`relay.state.prev` reste le lien dur de l'ancien v1 ; sections de lien vides, aucune autre section modifiée) ;
3. **Échec de la sauvegarde** : tout le lot est annulé, le v1 est intact (mémoire non publiée). **Échec de l'écriture v2** : le v1 est intact, la sauvegarde existe déjà ; l'essai suivant refait la sauvegarde (même contenu) puis écrit : **idempotent**. Une fois le v2 écrit, plus aucune sauvegarde n'est faite.

Si l'état v1 a été repris depuis `relay.state.prev` (écriture interrompue), c'est ce fichier qui est sauvegardé.

### `state verify`

Lit les schémas 1 et 2. Sortie : `schema_version`, nombre d'entités (dont `link_tokens`), `link_signing_key_current/previous` : **`[SEALED]` ou `[ABSENT]`** (jamais la valeur, ni le chiffré), `link_trust_current_kid` / `_previous_kid` / `_seq` (publics), et pour un v1 la ligne `migration: schema_version 1 -> 2 at the first write of the master (backup relay.state.v1.bak)`. `state restore --from` accepte un v1 vérifié (c'est le chemin du retour arrière).

## Invariants

Unicité de hostname, jti, token_hash, relay_id ; relay `pull` sans `token_secret` ; relay `push` : `token_secret` seul, préfixé `enc:` ; relay révoqué ⇒ son jti est dans la blacklist (même mutation) ; secrets de `server_config` toujours préfixés `enc:` (écriture et chargement ; seule exception : `InsecureTestMode` sans clé maître).

La garde d'écriture `BeforeWrite` est appelée avant le lot, puis de nouveau juste avant la rotation et le `rename` (le verrou peut être perdu pendant le `fsync`) : un refus tardif annule l'écriture, supprime le temporaire et ne laisse rien en mémoire.

## Dimensionnement mesuré (10 000 agents, clé publique ~800 octets)

Fichier ≈ 10 Mio ; chargement ≈ 150 ms ; écriture complète ≈ 150 ms ; 100 enrôlements concurrents ≈ 220 ms en 2 écritures.

## Store (#160)

`internal/storage.Store` est réimplémenté sur ce moteur (même API publique ; `storage.Open(state.Options)`). Lectures : index en mémoire. Écritures : mutations du moteur. **Atomicité** : l'enrôlement (`EnrollAgent` : jeton consommé + clé autorisée + agent) et la révocation d'un relay (drapeau + blacklist, `RevokeRelayNode` / `RevokeRelayParentToken`) sont **une seule mutation** (un rename). **Volatile, jamais écrit** : statut et `last_seen` des agents et des relays, `relay_routing`, `relay_chain`. **Piggyback** : `agents.last_seen` et `last_used_at`/`last_used_ip` des tokens plugin sont fusionnés dans le fichier à la prochaine écriture naturelle (une requête plugin n'écrit jamais sur le disque). **Purge** : une tâche du serveur retire chaque heure les entrées expirées de la blacklist (elle n'écrit que s'il y en a, et passe par la garde).

**Agent : champ `revoked` (#193)** (`state.Agent.Revoked`, `json:"revoked,omitempty"`, `state/model.go:41-45`). Posé par la révocation d'un agent **dans la même mutation** que la mise en blacklist de son JTI courant (`Store.RevokeAgent`, une seule écriture) ; il survit à l'expiration de l'entrée de blacklist (25 h). Tant qu'il est vrai, l'enrôlement (`EnrollAgent`/`RegisterAgent`, refus dans la transaction : annulation, jeton non consommé), le `rekey` et le handshake WS refusent l'hôte ; seule la suppression de l'agent (`DELETE /api/admin/minions/{hostname}`) le lève (pas de `unrevoke`). **Compatibilité** : (état v1 de v3.0.3 ; le schéma est passé à 2 en v3.0.4) champ optionnel à la lecture (état antérieur = `false`) et omis quand `false` (un état sans agent révoqué reste lisible par un binaire plus ancien). **⚠ Retour arrière** : le décodeur d'état est strict (`DisallowUnknownFields`) : un binaire antérieur à #193 **refuse de démarrer** sur un état contenant au moins un `"revoked": true` ; avant un rollback, lever les révocations (`DELETE` des agents concernés) ou restaurer un état antérieur. **Le refus n'est pas toujours final** : l'erreur (`state: corrupt state file: payload: json: unknown field "revoked"`) est classée corruption, donc l'ancien binaire **bascule sur `relay.state.prev`** avec un `[SECURITY WARNING]` s'il est valide (`state/file.go:258-275`) ; or `.prev` est la génération précédente, qui peut ne pas contenir la révocation : elle est alors **perdue silencieusement** et l'hôte révoqué peut se ré-enrôler. Avant tout retour arrière : **noter** la liste des agents révoqués (`DELETE` ne la conserve pas), les supprimer, puis **ré-appliquer** les révocations avec l'ancien binaire (blacklist du JTI seule : plus de drapeau persistant dans cette version). **Réparation au démarrage** : le maître appelle `Store.RepairRevokedFlags` (une écriture, aucune s'il n'y a rien à réparer, non fatale) qui pose le drapeau aux agents révoqués avant #193 dont le JTI courant est encore en blacklist ; une révocation plus ancienne que la rétention de 25 h est oubliée et doit être refaite.

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

**Pour `state restore --from`** :
| Code | Signification |
|---|---|
| 0 | restauration réussie |
| 2-7 | idem `state verify` (fichier refusé) |
| 8 | `relay.lock` frais détecté, restauration refusée (instance active) — passer `--i-know-no-instance-is-running` ou arrêter toutes les instances |

### `secagent-server state restore --from <fichier> [--state-dir D] [--min-write-seq N] [--i-know-no-instance-is-running]`
1. `verify` d'abord : un fichier inauthentique ou invalide est refusé, rien n'est modifié (mêmes codes 2 à 7).
2. **Aucune instance active** : `relay.lock` est observé sans jamais être écrit, avec la règle de fraîcheur du verrou (contenu inchangé pendant la limite de son rôle, sur l'horloge monotone locale : 10 s pour un candidat, 5 min pour un maître ; tout changement du compteur de battement = instance vivante ; observation interrompue = refus). Verrou frais → code **8**, rien n'est modifié. `--i-know-no-instance-is-running` passe outre un verrou orphelin (stockage figé) : `[SECURITY WARNING]` et trace dans le journal.
3. **Sauvegarde** de `relay.state` et `relay.state.prev` en `relay.state.bak-<UTC>` / `relay.state.prev.bak-<UTC>` (0600, jamais relus par le serveur).
4. **Remplacement atomique par le code du moteur** (`atomicWrite` : fichier temporaire, `fsync`, `link`/`rename`, `fsync` du répertoire), avec les octets du fichier vérifié (HMAC intact, rien n'est ré-encodé) ; `relay.state.prev` est conservé tel quel ; 0600.
5. **Journal** `state-restore.log` dans `STATE_DIR` (une ligne JSON par intervention, sans secret, jamais lu par le serveur) : date, opérateur (utilisateur système), fichier source, `write_seq` avant/après, noms des sauvegardes, `lock_override` le cas échéant.

Redémarrer ensuite les instances. La garde `write_seq` en mémoire des secondaires (#163) peut refuser un état restauré plus ancien que ce qu'elles ont observé : c'est voulu, d'où **l'arrêt de toutes les instances avant la restauration**. Il n'y a pas de `state init --force` : la réinitialisation complète déplace `STATE_DIR` puis relance `state init` (nouvelle identité, ré-enrôlement de tous les agents).



### `secagent-server state link-trust reset [--state-dir D] [--yes] [--i-know-no-instance-is-running]` (v3.0.4)

Efface **uniquement** l'ancre de confiance persistée (`link_trust` : `root_id`, clés publiques courante/précédente, `seq`) d'un relay **non racine**, **nœud arrêté**. Raison d'être : l'ancre persistée l'emporte sur `REPEATER_ROOT_LINK_KEY_FILE` et rien d'autre ne peut la remplacer ; sans cette commande, un relay qui a raté une rotation de la clé racine (puis un `retire-link-previous`), ou après une re-racine, ne pourrait jamais être ré-épinglé.

1. `RSA_MASTER_KEY` (ou `_FILE`) requis ; le HMAC et les invariants de `relay.state` sont vérifiés **avant** (mêmes codes 2 à 7 que `state verify`).
2. **Refus** (code **9**, rien n'est modifié) sur une **racine** (clé de signature de lien présente : elle n'a pas d'ancre à réinitialiser ; la re-racine passe par `keys rotate-link` / un nouvel état) et sur un état qui viendrait de `relay.state.prev` (réparer d'abord, par exemple `state restore`).
3. **Aucune instance active** : même règle de verrou que `state restore` (code **8** si `relay.lock` est frais ; `--i-know-no-instance-is-running` seulement pour un verrou orphelin sur stockage figé, `[SECURITY WARNING]`).
4. **Confirmation** : invite « Type "reset" » en mode interactif (rappel de la conséquence : sans ancre le relay refuse tout lien entrant) ; en mode non interactif `--yes` est **obligatoire** (sinon code 9).
5. **Sauvegarde avant toute écriture** : le `relay.state` vérifié est copié tel quel dans `relay.state.linktrust-reset.<UTC>.bak` (0600, `fsync`, exclusif, jamais relu par le serveur) ; échec de la sauvegarde ⇒ rien n'est modifié.
6. **Réécriture atomique** (moteur : fichier temporaire, `fsync`, lien/`rename`, `fsync` du répertoire), `link_trust` vidé, **HMAC recalculé**, `write_seq` + 1 (la garde anti-rejeu §#163 n'est pas contournée) ; `relay.state.prev` devient l'état d'avant. Rien d'autre n'est touché : ni agents, ni `link_tokens`, ni blacklist, ni `server_config`.
7. Journal : `[SECURITY WARNING] link trust anchor reset` (répertoire, nom de la sauvegarde, horodatage, opérateur ; **aucune clé**) et une ligne dans `state-restore.log` (`"source":"link-trust-reset"`).

Idempotent : sans `link_trust`, « nothing to reset », code 0, **rien n'est écrit** (ni sauvegarde ni nouvelle génération). C'est aussi le cas normal d'une **racine** qui n'a jamais minté (ni exporté sa clé publique) : elle n'a ni ancre ni clé de signature, la commande ne fait rien et ne la considère pas comme un défaut ; dès que la clé de signature existe, la commande **refuse** (code 9). Un relay épinglé qu'on veut transformer en racine (retrait de `REPEATER_ROOT_*`) passe aussi par ce reset : un nœud n'est racine que s'il n'a ni parent, ni ancre, ni `link_trust` persisté.

**Garde contre une instance qui démarre entre la sonde et l'écriture** : après la sonde du verrou, l'état de `relay.lock` (absent, ou contenu figé d'un verrou périmé) est mémorisé ; **juste avant le `rename`** de `relay.state` (après la sauvegarde et l'écriture du fichier temporaire) le verrou est relu : s'il est apparu ou si son contenu a changé, l'opération est **abandonnée** (code **8**, `relay.state` et `relay.state.prev` intacts, fichier temporaire supprimé, **sauvegarde conservée**). `state restore` a la même garde. Sans effet avec `--i-know-no-instance-is-running` (l'opérateur a pris la responsabilité d'un verrou orphelin). Reste une fenêtre de quelques microsecondes entre cette relecture et le `rename`, comme pour tout protocole de verrou sans verrou de fichier.

**Sauvegarde `relay.state.linktrust-reset.<UTC>.bak`** : copie **complète** de l'état d'avant (agents, clés publiques d'agents, secrets chiffrés `enc:` de `server_config`, blacklist…), mode `0600`, dans `STATE_DIR`, jamais relue par le serveur. Elle contient les mêmes secrets chiffrés que `relay.state` et se protège de la même façon (accès à `STATE_DIR`, sauvegardes hors volume) ; elle n'est **jamais purgée automatiquement** : la supprimer (ou la déplacer hors du volume) une fois le relay re-validé, selon la politique de rétention de l'exploitation. Elle permet de revenir à l'ancre précédente avec `state restore --from`. Au démarrage suivant, le relay épingle l'ancre donnée par `REPEATER_ROOT_ID` + `REPEATER_ROOT_LINK_KEY_FILE` ; sans ancre il refuse tout lien entrant (fail closed, inchangé).

| Code | Signification |
|---|---|
| 0 | ancre effacée, ou rien à effacer |
| 2-7 | idem `state verify` (clé incorrecte, état falsifié, invariant, clé maître absente…) |
| 8 | `relay.lock` frais : une instance est active |
| 9 | refusé : racine, état issu de `.prev`, confirmation absente ou refusée |

### `secagent-server state rekey [--state-dir D] [--yes] [--i-know-no-instance-is-running]` (v3.0.4)

Rotation **hors ligne** de `RSA_MASTER_KEY` : réécrit tout l'état avec une nouvelle clé maître. Implémentation : `state/rekey.go` (`Rekey`), commande `cli/state_tools.go`.

- **Clés** : jamais en argument. Actuelle : `RSA_MASTER_KEY` / `RSA_MASTER_KEY_FILE` ; nouvelle : `NEW_RSA_MASTER_KEY` / `NEW_RSA_MASTER_KEY_FILE` (règles de `secretenv` : la variable et son `_FILE` ensemble sont refusés, fichier régulier 0600 non-lien). Préférer les `_FILE` aux variables saisies au shell (historique). Nouvelle clé absente, vide ou égale à l'ancienne : refus (code 9, rien n'est modifié) ; nouvelle clé de **moins de 32 octets** : refus (`ErrRekeyKeyTooShort`, code **11**, message sans écho de la clé), car la clé AES dérive d'un SHA-256 brut de la clé maître (`crypto/aes.go:75`). Ce minimum ne s'applique qu'à la **nouvelle** clé : l'ancienne n'est pas contrôlée (une clé historique plus courte doit rester ouvrable) et `state init` est inchangé.
- **Champs rechiffrés** (AAD = nom du champ conservé, nonce neuf à chaque champ) : tous les `server_config` listés dans `secretConfigKeys` (`rsa_key_current/previous`, `jwt_secret_current/previous`, `link_signing_key_current/previous`) et `relay_nodes[].token_secret` (relays push, AAD `relay_nodes/<relay_id>/token_secret`). Une valeur `enc:` trouvée ailleurs fait **refuser** la commande (`ErrRekeyUncovered`). Le HMAC (clé HKDF de la nouvelle clé maître) est recalculé, `write_seq` + 1. Aucune valeur en clair n'est modifiée ; `JWT_SECRET_KEY` et les clés de signature gardent leur valeur (rotation de la clé maître, pas des secrets).
- **Ordre** : vérification de l'état avec l'ancienne clé (mêmes codes 2 à 6 que `state verify` ; état issu de `relay.state.prev` refusé, code 9) → sonde du verrou (code **8** si `relay.lock` est frais) → confirmation (invite « rekey », ou `--yes` obligatoire hors terminal ; code 9 sinon) → **sauvegarde** `relay.state.rekey.<UTC>.bak` (échec : rien n'est modifié) → remplacement atomique, avec relecture de `relay.lock` juste avant le `rename` (une instance apparue entre-temps : abandon, état intact, sauvegarde conservée, code 8) → **vérification de bout en bout** : relecture avec la nouvelle clé (HMAC, invariants, tous les secrets), refus de l'ancienne clé, comparaison des clairs avec l'original ; si elle échoue, l'original est remis en place atomiquement (code **10** ; si même cela échoue, le message indique comment restaurer la sauvegarde).
- **État de schéma 1** (v3.0.3 jamais écrit par un maître v3.0.4 : la migration v1 → v2 a lieu à la première écriture du maître) : accepté. Il est migré en schéma 2 par la **même** écriture atomique : `relay.state.v1.bak` (copie octet pour octet de l'original v1, fsync, écrite avant le remplacement) s'ajoute à `relay.state.rekey.<UTC>.bak` ; un « v1 » qui porterait des données de lien (jetons, ancre, clé de signature) est refusé (structure invalide). La vérification de bout en bout exige `schema_version` 2 ; un échec remet le v1 d'origine. Un binaire v3.0.3 refuse ensuite l'état (retour arrière = `relay.state.v1.bak` + binaires v3.0.3 + ancienne clé).
- `relay.state.prev` n'est pas touché (il reste chiffré avec l'ancienne clé : à détruire après la rotation).
- **Actif/passif** : arrêter les deux nœuds, exécuter la commande une fois sur le `STATE_DIR` partagé, redéployer la nouvelle clé sur tous les candidats, redémarrer. Un nœud démarré avec l'ancienne clé refuse l'état (fail closed).
- Journal : `[SECURITY WARNING] master key rekeyed` + ligne `"source":"rekey"` dans `state-restore.log` (sans clé ni valeur).

## Anti-rejeu : garde de `write_seq` (#163)

Le HMAC interdit de **forger** un état, pas de **rejouer une copie authentique plus ancienne** de `relay.state` (ou de supprimer `relay.state` pour forcer la reprise sur un `.prev` plus ancien). Garde :

- le maître écrit le `write_seq` courant de l'état dans `relay.lock` (champ `write_seq`) : après chaque écriture d'état, publié au plus tard au contrôle d'identité suivant (~5 s), jamais décroissant, et à chaque battement ;
- chaque secondaire mémorise le plus grand `write_seq` lu dans le verrou, **y compris dans un verrou périmé juste avant de le supprimer**, et le reporte dans le verrou qu'il crée en devenant maître ;
- à la promotion, le chargement refuse un `relay.state` (ou un `.prev` de repli) dont le `write_seq` est inférieur : `[SECURITY WARNING]`, démarrage refusé (code de sortie 1, aucun port ouvert, verrou supprimé, état local `failed`).

**Limite résiduelle** : la garde vit dans la mémoire des instances. Après un **arrêt à froid de toutes les instances**, elle est perdue et le rejeu d'une copie authentique reste possible ; la protection repose alors sur le contrôle d'accès à `STATE_DIR` et sur les sauvegardes (`state verify` / `state restore --from --min-write-seq`, #187).

À l'**arrêt propre** le verrou est supprimé, et avec lui son champ `write_seq` : la garde ne subsiste alors que dans la mémoire des secondaires qui l'ont lu (au plus une période de contrôle de retard, ~5 s). Un rejeu d'une copie authentique plus ancienne juste après un arrêt propre n'est donc détecté que pour ce qui a été observé ; même limite que l'arrêt à froid de toutes les instances ci-dessus.
