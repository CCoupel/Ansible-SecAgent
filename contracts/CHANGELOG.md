# Changelog des contrats

> Changements de contrats (API, schemas) : `BREAKING` | `CHANGED` | `ADDED`. Lu par le CDP au GATE 2.

## [v3.0.5] — Durcissement et dettes issues de v3.0.4 (plan validé au GATE 2 ; détail : `_work/reports/planner-plan-v305.md`)

- **[CHANGED]** `WSS /ws/agent` trame `rekey` (#217, LOT-1) — émise aussi périodiquement par le relay pour renouveler le JWT d'agent avant expiration ; format inchangé, rétrocompatible. Nouvelles variables serveur `AGENT_JWT_TTL` (défaut 24h, était 1h codé en dur ; entre 5 min et 7 jours) et `AGENT_JWT_RENEW_INTERVAL` (défaut TTL/3, entre 1 min et TTL/2). Aucune nouvelle route.
- **[ADDED]** `GET /api/admin/link/status` (#234, LOT-3) — champ `state` par relay (`confirmed` | `unconfirmed` | `never_seen`) ; `409 rotation_unconfirmed` : champ additif `never_seen`. **[CHANGED]** `confirmed` vaut `false` pour un relay sans aucun `link_state` (était `true` hors rotation).
- **[CHANGED]** `WSS /ws/relay` rate limit `event_forward` (#216, LOT-3) — compté par `relay_id` et non plus par lien ; seuil 200/s inchangé.
- Hors contrat d'interface (#214, D2) : `RSA_MASTER_KEY` de moins de 32 octets refusée à `state init` et au démarrage (message avec remède) ; dérivation et fichier d'état **inchangés** (pas de HKDF, pas de `schema_version` 3) : un déploiement à clé courte exécute `state rekey` avant la montée.
- Aucun changement BREAKING.
