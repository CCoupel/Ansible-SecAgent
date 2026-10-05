# Changelog des contrats d'interface

## [Unreleased] (v3.0.3)

- **[BREAKING]** `GET /api/admin/status` : le champ `nats` est supprimé (NATS retiré, #178). `db`, `ws_connections`, `uptime` et `links` sont inchangés. `secagent-server server status` n'affiche plus la ligne `nats`.
- `GET /api/async_status/{task_id}` supprimé (#176) : jamais alimenté en production ; le statut d'un job async passe par un `exec` de `async_status.py` vers l'agent.
- `POST /api/exec|upload|fetch/{hostname}` : nouveaux refus `503 {"error":"agent_suspended"}` et `503 {"error":"agent_state_unavailable"}` (#173). Inventaire : champ optionnel `secagent_suspended` (#173).
- `/ws/agent` : refus `401` avant l'upgrade d'un token révoqué ou remplacé (#169).
- Contrat NATS (`NATS.md`) obsolète : à retirer par #172.
