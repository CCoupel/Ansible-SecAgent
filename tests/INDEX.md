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
