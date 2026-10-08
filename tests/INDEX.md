# Index des tests

> Tests de specification ecrits par le test-writer, ranges en lots `<famille>/<theme>/<lot>/` ; statuts tenus par le CDP.
> Le chemin porte l'identite ; cet index ne porte que l'etat : une ligne par lot (chemin termine par `/`),
> plus des lignes fichier pour les exceptions (quarantaine). Lot sans ligne = `feature`.
> Convention : `context/COMMON.md` section 15. Statuts : `feature` | `regression` | `quarantaine`.
> Tags : `smoke`, `critical`, `slow`.

| Chemin | Niveau | Composant | Feature | Statut | Tags |
|--------|--------|-----------|---------|--------|------|
| GO/cmd/secagent-server/internal/integration/ | integration | secagent-server | #129 chaîne repeater e2e (pull/push, routage hiérarchique, refus, révocation) | feature | critical |
| GO/cmd/secagent-server/internal/auth/linkjwt_spec_*_test.go | unit-spec | secagent-server | #141/#146 L1c jetons de lien EdDSA (confusion d'algo, aud, rôle, rotation, seq, mutants) ; vérificateur réel en attente de câblage | feature | critical |
| GO/cmd/secagent-server/internal/state/migration_v2_spec_test.go | unit-spec | secagent-server | #141/#146 L1b migration état v1→v2 (sauvegarde, idempotence, crash à chaque étape) | feature | critical |
| GO/cmd/secagent-server/internal/integration/link_isolation_spec_test.go | integration | secagent-server | #146 un jeton de lien n'ouvre aucun endpoint (matrice complète 7770/7771//ws/agent) | feature | critical |
| GO/cmd/secagent-server/internal/integration/link_mint_spec_test.go | integration | secagent-server | #141 mint racine, 409 not_root, clé chiffrée, bascule même kid (révocation 2 niveaux / fail closed : en attente L1e) | feature | critical |
| GO/cmd/secagent-server/internal/repeater/dialpolicy_spec_*_test.go | unit-spec | secagent-server | #151 politique de dial deny/allow/loopback (matrice, CIDR invalides, rebinding+ALLOW, mutants) + non-suivi des 3xx (dialer push, client pull) | feature | critical |
| GO/cmd/secagent-server/internal/server/dialpolicy_spec_test.go | unit-spec | secagent-server | #151 ligne push stockée interdite par la politique jamais dialée au démarrage | feature | critical |
| GO/cmd/secagent-server/internal/ws/snapshot_quota_spec_test.go | unit-spec | secagent-server | #156 quota des topology_snapshot par relay_id (6 critères) — armé par specSnapshotQuotaByIdentity | feature | critical |
| GO/cmd/secagent-server/internal/ws/task_purge_spec_test.go | unit-spec | secagent-server | #179 un chemin de purge = un test (résultat, timeout, déconnexion, révocation, perte de verrou), purge une seule fois | feature | critical |
| GO/cmd/secagent-server/internal/integration/task_limits_spec_test.go | integration | secagent-server | #179 limites par agent/globale/budget stdout (429 agent_busy, 429 too_many_tasks, 503 memory_budget_exhausted), tout fin de tâche libère son slot, charge 3 000 agents (perf, RSS<2 Gio) — armé par specTaskLimits179 | feature | slow |
| GO/cmd/secagent-server/internal/hooks/burst_slow_test.go | unit | secagent-server | #183 rafale de 3 000 événements (tag de build `slow`, job CI slow-tests) | feature | slow |
| GO/cmd/secagent-server/internal/integration/hooks_burst_slow_test.go | integration | secagent-server | #183 3 000 agents se reconnectent (tag de build `slow`, job CI slow-tests) | feature | slow |
| GO/cmd/secagent-server/internal/integration/task_limits_load_slow_test.go | integration | secagent-server | #179 charge 3 000 agents (tag de build `slow`, job CI slow-tests) | feature | slow |
| GO/cmd/secagent-server/internal/integration/exec_long_answer_slow_test.go | integration | secagent-server | #179 régression : la réponse d'un exec > 15 s (WriteTimeout API) arrive intacte (« bad record MAC » sinon) | regression | slow |
| GO/cmd/secagent-server/internal/ws/qa_gaps_test.go | unit | secagent-server | QA v3.0.4 R2 : refund stdout après coupe UTF-8, plafond global du budget abaissé, fenêtre/éviction/refus au hello du quota #156, garde « hôte local ET routé » #180 | regression | |
| GO/cmd/secagent-server/internal/integration/suspension_three_levels_test.go | integration | secagent-server | QA v3.0.4 R2 : #180 drapeau de suspension sur 3 niveaux restauré après redémarrage de la racine | regression | |
