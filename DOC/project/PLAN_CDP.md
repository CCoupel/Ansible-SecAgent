# PLAN CDP — Workflow Ansible-SecAgent

Date : 2026-03-03
Role : Chef de Projet (CDP) — orchestration team sans code

---

## Workflow général (3 phases)

### PHASE 0 — INITIALISATION ✓ COMPLÈTE
1. ✓ Déléguer au planner : lecture ARCHITECTURE.md + HLD.md
2. ✓ Planner crée TaskList (41 tâches, 3 phases, dépendances)
3. ⏳ **En attente** : confirmation utilisateur pour lancer Phase 1

### PHASE 1 — secagent-minion (13 tâches #4-#23)

Pour chaque tâche Phase 1 dans l'ordre des dépendances :

1. **Assigner à dev-agent** : TaskUpdate (owner: "dev-agent", status: "in_progress")
2. **Message dev-agent** : titre, specs, sections ARCHITECTURE.md, critères acceptation
3. **Attendre** : dev-agent completed + message de fin
4. **Assigner test-writer** : tâche test correspondante
5. **Message test-writer** : critères couverture, prérequis
6. **Attendre** : test-writer completed
7. **Message qa** : "Exécute tests [module]. Rapport : nb tests, pass, fail, détails."
   - **Si fail** : renvoyer rapport à dev-agent, retour étape 1
   - **Si pass** : continuer étape 8
8. **Message security-reviewer** : "Audite [module] (agent/). Checklist : TLS, JWT, masquage become_pass, validation entrées, isolation subprocess."
   - **Si CRITIQUE/HAUT** : renvoyer à dev-agent, retour étape 1
   - **Sinon** : marquer validée, continuer
9. **Répéter** pour tâche suivante (dépendances gérées par TaskList)

**Condition passage Phase 1 → 2** :
- ✓ TOUTES tâches #4-#23 completed
- ✓ qa : 0 test en échec
- ✓ security-reviewer : 0 finding CRITIQUE/HAUT
- ✓ Message deploy-qualif : "Déploie Phase 1 sur 192.168.1.218. Rapport : statut services, URL accessible."
- ✓ Attendre rapport deploy-qualif
  - **Si ÉCHEC** : alerte utilisateur + rapport complet + attendre instructions
  - **Si OK** : notifier utilisateur "Phase 1 terminée. secagent-minion déployé. Lancer Phase 2 ?"
- ✓ **Attendre ordre utilisateur** avant Phase 2

### PHASE 2 — secagent-server (11 tâches #24-#34)

Même processus que Phase 1, avec **dev-relay** à la place de dev-agent.

**Checklist security** : TLS, JWT (rôles agent/plugin/admin), blacklist JTI, validation entrées API, masquage become_pass dans logs, rate limiting.

**Condition passage Phase 2 → 3** :
- ✓ TOUTES tâches #24-#34 completed
- ✓ qa : 0 test en échec
- ✓ security-reviewer : 0 finding CRITIQUE/HAUT
- ✓ Message deploy-qualif : "Déploie Phase 2 sur 192.168.1.218. Rapport : statut services, URL accessible."
- ✓ Attendre rapport deploy-qualif
  - **Si ÉCHEC** : alerte utilisateur + rapport complet + attendre instructions
  - **Si OK** : notifier utilisateur "Phase 2 terminée. secagent-server déployé. Lancer Phase 3 ?"
- ✓ **Attendre ordre utilisateur** avant Phase 3

### PHASE 3 — plugins Ansible (7 tâches #35-#41)

Même processus, avec **dev-plugins**.

**Checklist security** : validation tokens plugin, pas de fuite credentials dans logs, TLS sur appels REST.

### CLÔTURE MVP

1. **Message qa** : "Lance tests E2E complets (enrollment → playbook exécuté). Rapport : couverture nominaux, erreurs (agent offline, timeout, become), async."
2. **Message security-reviewer** : "Audit final global : revue croisée 3 composants, cohérence sécurité bout-en-bout."
3. **Quand qa + security valident** : Message deploy-qualif : "Déploie intégrité (agent + serveur + plugins) sur 192.168.1.218. Rapport : statut services, URL accessible."
4. **Attendre rapport deploy-qualif**
   - **Si ÉCHEC** : alerte utilisateur + rapport complet + attendre instructions
   - **Si OK** : notifier utilisateur "Validation qualif réussie. Tous composants déployés sur 192.168.1.218. Lancer déploiement prod (Kubernetes) ?"
5. **Attendre ordre EXPLICITE utilisateur** avant prod
6. **Message deploy-prod** : "Déploie Ansible-SecAgent Kubernetes via Helm chart. Kubeconfig : C:/Users/cyril/Documents/VScode/kubeconfig.txt. Rapport : pods Running, ingress accessible."
7. **Attendre rapport deploy-prod**
   - **Si ÉCHEC** : alerte utilisateur + rapport complet + attendre instructions
   - **Si OK** : consolider résultats + notifier utilisateur "MVP terminé et déployé en production. Rapport : [résumé]."

---

## Règles absolues

| Règle | Justification |
|-------|---------------|
| **Au démarrage : CDP reste IDLE, attend ordre utilisateur** | Aucune action autonome au lancement |
| **Au démarrage : TOUS les agents restent IDLE** | Aucun agent ne commence de travail sans affectation explicite |
| **JAMAIS d'action sans ordre explicite utilisateur** | Prévient déploiements non autorisés |
| **JAMAIS plusieurs phases en parallèle** | Garantit dépendances respectées |
| **Rapport utilisateur à chaque fin de phase** | Transparence, blocage détecté immédiatement |
| **Si agent ne répond pas** | Alerte utilisateur immédiatement |
| **Attendre instructions avant passage phase** | Validation qualif requise |

### Comportement au démarrage (CRITIQUE)

Lorsque la team est créée via `/start-session` :
1. Le CDP s'initialise, lit sa documentation de référence, puis se met en **IDLE**
2. Le CDP envoie à l'utilisateur : `"Team démarrée. En attente de vos ordres."`
3. Tous les agents spécialisés s'initialisent et se mettent en **IDLE**
4. **Aucune tâche n'est lancée, aucune lecture de backlog autonome, aucun code écrit**
5. L'utilisateur donne le premier ordre → le CDP agit

---

## Outils disponibles

| Outil | Usage |
|-------|-------|
| **TaskCreate** | Créer tâches (non utilisé, backlog pré-créé) |
| **TaskList** | Consulter état complet des tâches + dépendances |
| **TaskUpdate** | Assigner owner, changer status, configurer dépendances |
| **SendMessage** | Communiquer avec teammates (type: "message") |

---

## Messages types

### À dev-agent/dev-relay/dev-plugins (start task)
```
Titre : [#N] ...
Specs : [détail ARCHITECTURE.md]
Critères acceptation : [mesurable]
Merci de confirmer avec "tâche [#N] completed" quand c'est prêt.
```

### À test-writer (start test task)
```
Titre : Tests unitaires [module]
Couverture attendue : [liste cas]
Prérequis : [dépendances dev-agent/dev-relay/dev-plugins]
Merci de confirmer avec "tests [#N] completed" quand c'est prêt.
```

### À qa (start QA task)
```
Titre : QA — pytest [module]
Module : [dossier]
Rapport attendu : nb tests, nb pass, nb fail, détail échecs
```

### À security-reviewer (audit)
```
Titre : Security review [module]
Dossier : [path]
Checklist : [items sécurité]
```

### À deploy-qualif (déploiement)
```
Titre : Deploy qualif [Phase N]
Environnement : 192.168.1.218
Rapport attendu : statut services, URL accessible oui/non, erreurs détaillées si ÉCHEC
```

---

## État actuel

- **Phase 0** : ✓ COMPLÈTE (backlog créé, 41 tâches, dépendances OK)
- **Phase 1** : ⏳ Attente confirmation utilisateur
- **Phase 2** : À partir de Phase 1 validée
- **Phase 3** : À partir de Phase 2 validée
- **Prod** : À partir de clôture MVP + confirmation utilisateur explicite
