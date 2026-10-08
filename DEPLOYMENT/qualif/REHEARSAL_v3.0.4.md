# Plan de répétition : montée v3.0.3 → v3.0.4 sur la chaîne de qualif (NON JOUÉ)

> Source : `_work/reports/planner-20261007-v304-plan-rev2.md` §4 (procédure) et §2 (état v2). Préparé par `deployer`, 2026-10-07.
> **Rien n'est exécuté** par ce document. **Mis à jour le 2026-10-08** avec les commandes réelles de L1d/L1e (`tokens create --role relay-child --sub --aud`, `keys link-pubkey|rotate-link|retire-link-previous|link-status`, `REPEATER_ROOT_ID`, `REPEATER_ROOT_LINK_KEY_FILE`, `REPEATER_UPSTREAM_TOKEN_FILE`). **Retour arrière vers v3.0.3 : NON SUPPORTÉ** (décision de l'utilisateur) : le §4 ci-dessous ne décrit plus qu'une reprise sur incident en v3.0.4, pas un retour à v3.0.3. **Rotation de `RSA_MASTER_KEY` recommandée avant la mise en production.** Il ne se joue qu'au batch 4, sur l'image candidate v3.0.4, après validation QA et
> security-reviewer de L0 à L7, et sur ordre explicite du teamleader. Hôte : 192.168.1.218, projet `secagent-qualif`
> uniquement (`guard_project`). MooseFS (`chunks`, `/opt/MFS`) : jamais touché.
> Les anciens points TODO(L1d/L1e) sont résolus ci-dessous ; seules les mesures marquées « à relever » dépendent de l'exécution.

## 0. Pré-requis

- Images **v3.0.3** (référence, déjà qualifiées) et **v3.0.4** (candidate) disponibles sur l'hôte (`chain-test.sh load-images` pour chacune, deux répertoires d'artefact distincts ; `image-ids` est écrasé à chaque chargement : relancer `load-images` de la version visée avant chaque démarrage).
- `qualif.env` (secrets de qualif) et PKI de test inchangés sur toute la répétition ; `RSA_MASTER_KEY` sauvegardée à part.
- `hooks.json` en place (le journal des hooks sert de témoin à chaque étape).
- Binaire `secagent-inventory` du poste de contrôle, jeton plugin frais (`plugin_token`, automatique).

## 1. Départ : chaîne v3.0.3 saine (état de référence)

1. `chain-test.sh bootstrap` puis `smoke` avec les images v3.0.3 ; `hooks` OK. Noter : `relays list`, `minions list`, inventaire, `ping` x2.
2. Sauvegardes : `state verify` puis copie de `relay.state` de la racine ET de l'enfant (volumes nommés `${PROJECT}_backup`, modèle de `backup_restore`) ; conserver les **jetons HS256 actuels** (`chain/child.env`).

## 2. Montée (rev2 §4, commandes réelles)

1. **Annonce** : coupure des liens inter-relays ; les minions restent connectés à leur relay.
2. **Racine, passif d'abord arrêté** : `docker compose stop secagent-server-b`, monter l'actif (`secagent-server-a`) en v3.0.4 (migration `SchemaVersion` 2, `relay.state.v1.bak` créé), puis le passif. Contrôles : un seul maître, secondaire sans port, `state verify` OK, `relay.state.v1.bak` présent.
3. **Ancre et jetons, avant la fenêtre** (sur le maître) : `keys link-pubkey > root-link.pub` (relever `root_id=` sur stderr) ; `tokens create --role relay-child --sub dmz1 --aud <root_id> --expires 720h` (affiché une seule fois). Automatisé par `chain-test.sh bootstrap` pour une chaîne neuve ; pour une montée, appeler `link_anchor_prepare` / `link_mint_child` (même fichier).
4. **Enfant** : pousser la clé dans le volume (`chain-test.sh push-link-key`), écrire le jeton dans `chain/upstream-token`, `chain/child.env` = `REPEATER_ROOT_ID=<root_id>` **sans** `REPEATER_UPSTREAM_TOKEN` (les deux définis = refus de démarrer), puis `docker compose up -d --force-recreate secagent-child` en v3.0.4.
5. **Contrôles** : `relays list` (dmz1 `connected`), inventaire racine complet (minion-root + minion-child), `smoke`, `hooks`, `negative-ca` ; ancien jeton HS256 refusé (permanent).
6. Garder les anciens jetons HS256 n'a plus d'intérêt : il n'y a pas de retour arrière.

## 3. Cas à jouer pendant et après la montée

| Cas | Attendu |
|---|---|
| Minions pendant la fenêtre | restent connectés à leur relay ; tâches vers dmz1 en échec pendant la coupure |
| Enfant sans ancre (pas de `REPEATER_ROOT_LINK_KEY_FILE`) | refus de tout lien entrant, close 4010 `link_trust_missing`, `[SECURITY WARNING]` |
| Lien avec ancien jeton HS256 | refus permanent, log explicite |
| `chain-test.sh link-rotation` | kid change, `previous` ouvert puis retiré, dmz1 confirme avant le retrait, lien reconnecté, smoke OK |
| `chain-test.sh link-revoke` | lien fermé en 4010, pas de reconnexion avec le jeton révoqué, rétabli avec un nouveau jeton |
| Bascule de la racine (`failover`, puis `failover-test.sh run kill`) | nouveau maître avec la même clé (même `kid`), liens rétablis, hooks `host.up` journalisés |
| `backup-restore` sous v3.0.4 | état v2 restauré, minion déjà enrôlé reconnecté sans ré-enrôlement |
| `docker inspect` des conteneurs | aucun secret de lien en clair (jeton en `/run/secrets`, mode 0400, UID 10001 : `docker exec secagent-qualif-child stat -c '%a %u' /run/secrets/repeater_upstream_token`) |

## 4. Reprise sur incident (PAS un retour à v3.0.3)

Aucun retour à v3.0.3 n'est supporté. En cas d'échec de la montée en qualif : arrêter la chaîne (`docker compose stop`, **jamais** `down -v`), corriger, relancer. Une restauration d'état se fait avec `relay.state.v1.bak` / `state restore` **sous le binaire v3.0.4** uniquement pour récupérer l'état v1 (migration rejouée au redémarrage) : à ne pas confondre avec un retour de version. Les enrôlements et révocations d'agents faits depuis la sauvegarde sont à rejouer.

## 5. Remontée

Rejouer §2 à partir d'un état v1 restauré (qualif seulement) : la migration doit réussir à l'identique (idempotente, nouvelle `relay.state.v1.bak`). Verdict : `qa`.

## 6. Mesures à relever

Durée de la fenêtre de coupure des liens, durée de reprise après `failover` et `kill`, taille et durée de la migration v1→v2, aucune écriture d'état en régime nominal (date de modification de `relay.state`), durée de la confirmation de rotation par dmz1, `docker inspect` sans secret en clair.

## 7. Garde-fous

Aucune commande hors du projet `secagent-qualif` ; aucun `down -v` ni suppression de volume sans ordre explicite ; kills par nom de conteneur du projet seulement ; pas de push, pas de tag ; MooseFS (`chunks`, `/opt/MFS`) jamais touché.
