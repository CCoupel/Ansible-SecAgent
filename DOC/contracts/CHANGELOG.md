# Changelog des contrats d'interface

## [Unreleased] (v3.0.3)

- **[BREAKING]** `GET /api/admin/status` : le champ `nats` est supprimé (NATS retiré, #178). `db`, `ws_connections`, `uptime` et `links` sont inchangés. `secagent-server server status` n'affiche plus la ligne `nats`.
- `GET /api/async_status/{task_id}` supprimé (#176) : jamais alimenté en production ; le statut d'un job async passe par un `exec` de `async_status.py` vers l'agent.
- `POST /api/exec|upload|fetch/{hostname}` : nouveaux refus `503 {"error":"agent_suspended"}` et `503 {"error":"agent_state_unavailable"}` (#173). Inventaire : champ optionnel `secagent_suspended` (#173).
- `/ws/agent` : refus `401` avant l'upgrade d'un token révoqué ou remplacé (#169).
- `GET /api/admin/hooks/log` : lu dans le journal append-only `actions.log` (`RELAY_ACTION_LOG`, défaut `STATE_DIR/actions.log`, rotation 10 Mio × 5) et non plus dans la table `action_log` (#161). `config_snapshot` est désormais **masqué** (secret HMAC, valeurs des en-têtes, corps, arguments shell, query string et userinfo des URL) ; `error` masque les URL. Erreur `500 action_log_not_initialized` si le journal n'est pas configuré.
- `GET /api/admin/hooks/log` (#161b) : les URL de `config_snapshot` et de `error` ne conservent plus que schéma + hôte + port (chemin → `/***`, query → `?***` : le secret des webhooks Slack/Discord/Teams est dans le chemin) ; tout champ d'action inconnu est masqué. Journal existant mais illisible : **`503 {"error":"journal_unavailable"}`** (remplace `500 action_log_error`) ; `[]` seulement si le journal n'existe pas encore ou est vide. Section ajoutée à `REST_ADMIN.md` §5b.
- `GET /api/admin/status` (#183) : nouveaux champs `hooks_queue_depth`, `hooks_queue_capacity`, `hooks_inflight`, `hooks_dropped_events`, `hooks_dropped_actions` (additifs). Journal des actions : entrées agrégées `action_type:"dropped"` (`event:"*"`) quand la file des hooks rejette des événements. Variable `RELAY_HOOKS_QUEUE_SIZE` (défaut 10000).
- Contrat NATS (`NATS.md`) obsolète : à retirer par #172.
