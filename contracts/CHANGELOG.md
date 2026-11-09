# Changelog des contrats

> Changements de contrats (API, schemas) : `BREAKING` | `CHANGED` | `ADDED`. Lu par le CDP au GATE 2.

## [v3.0.6] — Événements de relais et de routage (hooks) (LOT-3.1 : #225, #245, #265 ; plan : `.claude/workflow/plan-v3.0.6.md`)

- **[ADDED]** `WSS /ws/relay` `event_forward` (#225, #245) — kinds `relay.failover`, `relay.up`, `relay.reconnect`, `relay.down` (sans `hostname`, clé `relay_id`, `relay_chain` origine en premier) ; formes réservées pour `relay.discover`, `relay.rerouted`, `relay.removed`, `relay.converged`, `host.reconnect`, `host.discover`, `host.rerouted`, `host.removed` ; champs additifs `instance_id`, `previous_instance_id`, `cause`, `mode`, `hosts_routed`, `relays_below`, `relays_below_ids`, `reason`, `conn_seq`, `old_chain`, `new_chain`, `relays_connected`, `relays_missing`, `hosts_direct`, `upstream_dropped_events_total`. Détail : `SERVER_SPEC.md` §9.2.
- **[ADDED]** `relay_hello.conn_seq` (pull) et `relay_ack.conn_seq` (push) (#265) — nombre de connexions du process enfant (entier `1..2³¹`, absent/invalide ⇒ 1). Ignoré par un parent v3.0.5.
- **[ADDED]** `WSS /ws/agent` — en-tête `X-SecAgent-Conn-Seq` (#265, entier décimal `1..2³¹`, absent/invalide ⇒ 1), ignoré par un serveur antérieur.
- **[CHANGED]** événement `host.up` (#265) — n'est plus émis aux reconnexions d'un **même process** minion ≥ 3.0.6 : elles donnent `host.reconnect` ; qui veut « toute connexion » s'abonne à `host.up` **et** `host.reconnect`. Minion v3.0.5 (sans en-tête) : inchangé (`host.up`).
- **[CHANGED]** documentation (SERVER_SPEC §9.7) — `relay.updated` ne déclenche aucun hook (propagé seulement) ; la doc affirmait le contraire.
- Compatibilité : un parent v3.0.5 jette les kinds inconnus (`unsupported event kind`) sans fermer le lien ; monter les parents d'abord (T9).
- Aucun changement BREAKING.

## [v3.0.5] — Durcissement et dettes issues de v3.0.4 (plan validé au GATE 2 ; détail : `_work/reports/planner-plan-v305.md`)

- **[CHANGED]** `WSS /ws/agent` trame `rekey` (#217, LOT-1) — émise aussi périodiquement par le relay pour renouveler le JWT d'agent avant expiration ; format inchangé, rétrocompatible. Nouvelles variables serveur `AGENT_JWT_TTL` (défaut 24h, était 1h codé en dur ; entre 5 min et 7 jours) et `AGENT_JWT_RENEW_INTERVAL` (défaut TTL/3, entre 1 min et TTL/2). Aucune nouvelle route.
- **[ADDED]** `GET /api/admin/link/status` (#234, LOT-3) — champ `state` par relay (`confirmed` | `unconfirmed` | `never_seen`) ; `409 rotation_unconfirmed` : champ additif `never_seen`. **[CHANGED]** `confirmed` vaut `false` pour un relay sans aucun `link_state` (était `true` hors rotation).
- **[ADDED]** `GET /api/admin/link/status` + `POST …/retire-previous` (#215, option C) — `direct` par relay et `not_direct` (relais non connectés en direct depuis la rotation), informatif.
- **[CHANGED]** `WSS /ws/relay` rate limit `event_forward` (#216, LOT-3) — compté par `relay_id` et non plus par lien ; seuil 200/s inchangé.
- **[CHANGED]** `/ws/agent` (#217, M1/M2) — un JWT dont le JTI a été remplacé n'est plus accepté pendant la grâce d'une rotation (même signé avec l'ancien secret) ; seul le JTI immédiatement précédent reste valable jusqu'au premier handshake avec le courant. `POST /api/admin/keys/rotate` : `grace` > `AGENT_JWT_TTL` refusé (`400 grace_exceeds_agent_jwt_ttl`), défaut min(24h, TTL). État : champ optionnel `prev_token_jti` par agent (retour arrière vers v3.0.4 : voir `STATE_SPEC.md`).
- **[CHANGED]** `/ws/agent` (#217, N1) — ping WebSocket du relais toutes les `AGENT_WS_PING_INTERVAL` (30s) et fermeture après 2× sans signe de vie (le minion répond au ping sans changement) ; sonde de la connexion vivante (`AGENT_WS_PROBE_TIMEOUT`, 5s) quand le JWT précédent est présenté : sans réponse il est accepté, avec réponse 401.
- **[CHANGED]** `GET /api/admin/minions/{hostname}` (#233) — `status` superpose la connexion WebSocket vivante (`connected`), comme la liste ; champs inchangés.
- **[CHANGED]** `GET /api/admin/minions/{hostname}` (#233) — champ additif `revoked`. `DELETE /api/admin/minions/{hostname}` : liste noire des JTI (courant et précédent) et drapeau révoqué **avant** la suppression de la ligne, fermeture de la WS **après** (et une seconde fois si une connexion est apparue) ; réponse inchangée.
- Hors contrat d'interface (#214, D2) : `RSA_MASTER_KEY` de moins de 32 octets refusée à `state init` et au démarrage (message avec remède) ; dérivation et fichier d'état **inchangés** (pas de HKDF, pas de `schema_version` 3) : un déploiement à clé courte exécute `state rekey` avant la montée.
- Aucun changement BREAKING.
