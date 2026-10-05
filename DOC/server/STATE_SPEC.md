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

JSON : `{"schema_version":1,"written_at","writer_instance","write_seq","sha256","payload":{...}}`. `sha256` couvre exactement les octets du `payload`. `write_seq` est un compteur d'écritures monotone (sans lien avec le verrou). `schema_version` inconnu ou supérieur : refus de démarrer, pas de bascule sur `.prev`.

`payload` : `agents`, `authorized_keys`, `enrollment_tokens`, `plugin_tokens`, `relay_parent_tokens`, `blacklist`, `relay_nodes` (configuration seulement), `server_config`. Jamais écrits : `relay_routing`, `status`/`last_seen`/`relay_chain` des relays, `action_log` (journal à part, #161). `last_seen` et `last_used_*` ne sont persistés qu'au passage d'une écriture naturelle (`Options.Piggyback`).

Aucun secret en clair : jetons hashés (SHA-256), `server_config` (clé RSA privée, secrets JWT) et `token_secret` des relays push chiffrés `enc:` (AES-256-GCM, `RSA_MASTER_KEY`).

## Écriture

1. Garde `BeforeWrite` (sans garde : **aucune écriture**, pas même `relay.state.tmp`).
2. Les mutations d'un lot s'appliquent sur une copie du modèle, chacune tout-ou-rien (journal d'annulation), puis le lot est écrit en une fois (group commit).
3. `relay.state.tmp` (0600) + `fsync`, `relay.state.prev` ← lien dur de `relay.state`, `rename(tmp → relay.state)`, `fsync` du répertoire.
4. Le modèle n'est publié qu'après le rename : la mémoire n'est jamais en avance sur le disque.
5. Plafond dur `STATE_MAX_BYTES` (défaut 64 Mio) : écriture refusée au-delà.

## Chargement

`relay.state` invalide (tronqué, empreinte fausse) ou absent alors que `.prev` existe : bascule sur `.prev` avec `[SECURITY WARNING]`. Les deux invalides : refus de démarrer (jamais de réinitialisation automatique). Un `token_secret` en clair est une violation de sécurité : refus de démarrer sans bascule. Fichier absent : `FATAL: relay.state not found in STATE_DIR=<dir> — run 'secagent-server state init' to initialize`.

## `secagent-server state init`

Crée l'état initial (clé RSA-4096 et secret JWT, chiffrés par `RSA_MASTER_KEY`, obligatoire sauf `--insecure-test-mode`). Refuse d'agir si `relay.state`, `relay.state.prev` ou `relay.lock` existe. Ne démarre aucun port.

## Invariants

Unicité de hostname, jti, token_hash, relay_id ; relay `pull` sans `token_secret` ; relay `push` : `token_secret` seul, préfixé `enc:` ; relay révoqué ⇒ son jti est dans la blacklist (même mutation) ; secrets de `server_config` préfixés `enc:` dès que la clé maître est configurée.

## Dimensionnement mesuré (10 000 agents, clé publique ~800 octets)

Fichier ≈ 10 Mio ; chargement ≈ 150 ms ; écriture complète ≈ 150 ms ; 100 enrôlements concurrents ≈ 220 ms en 2 écritures.
