# Plan de répétition : montée v3.0.3 → v3.0.4 sur la chaîne de qualif (NON JOUÉ)

> Source : `_work/reports/planner-20261007-v304-plan-rev2.md` §4 (procédure) et §2 (état v2). Préparé par `deployer`, 2026-10-07.
> **Rien n'est exécuté** par ce document. Il ne se joue qu'au batch 4, sur l'image candidate v3.0.4, après validation QA et
> security-reviewer de L0 à L7, et sur ordre explicite du teamleader. Hôte : 192.168.1.218, projet `secagent-qualif`
> uniquement (`guard_project`). MooseFS (`chunks`, `/opt/MFS`) : jamais touché.
> Points marqués **TODO(L1d/L1f)** : commandes finales inconnues à ce jour, à compléter une fois L1d/L1f livrés.

## 0. Pré-requis

- Images **v3.0.3** (référence, déjà qualifiées) et **v3.0.4** (candidate) disponibles sur l'hôte (`chain-test.sh load-images` pour chacune, deux répertoires d'artefact distincts ; `image-ids` est écrasé à chaque chargement : relancer `load-images` de la version visée avant chaque démarrage).
- `qualif.env` (secrets de qualif) et PKI de test inchangés sur toute la répétition ; `RSA_MASTER_KEY` sauvegardée à part.
- `hooks.json` en place (le journal des hooks sert de témoin à chaque étape).
- Binaire `secagent-inventory` du poste de contrôle, jeton plugin frais (`plugin_token`, automatique).

## 1. Départ : chaîne v3.0.3 saine (état de référence)

1. `chain-test.sh bootstrap` puis `smoke` avec les images v3.0.3 ; `hooks` OK. Noter : `relays list`, `minions list`, inventaire, `ping` x2.
2. Sauvegardes : `state verify` puis copie de `relay.state` de la racine ET de l'enfant (volumes nommés `${PROJECT}_backup`, modèle de `backup_restore`) ; conserver les **jetons HS256 actuels** (`chain/child.env`).

## 2. Montée (rev2 §4)

1. **Annonce** : coupure des liens inter-relays attendue ; les minions restent connectés à leur relay.
2. **Racine, passif d'abord arrêté** : arrêter le passif, monter l'actif en v3.0.4 (migration `SchemaVersion` 2, création de `relay.state.v1.bak`), puis monter le passif. Contrôles : un seul maître, secondaire sans port, `state verify` v2 OK, `relay.state.v1.bak` présent. **TODO(L1b)** : commande/emplacement exacts de la sauvegarde v1.
3. **Mint** sur la racine, **avant** la fenêtre : un jeton par lien (pull dmz1 → racine : `relay-child`). Export de la clé publique racine. **TODO(L1d)** : `tokens create --role relay-child --sub dmz1 --aud <racine>`, `keys link-pubkey` (squelette : `chain-test.sh`, `link_tokens_prepare`, `LINK_TOKENS=1`).
4. **Enfant** : déployer v3.0.4 avec `REPEATER_ROOT_LINK_KEY_FILE` (clé publique racine) et le nouveau `REPEATER_UPSTREAM_TOKEN`. **TODO(L1e)** : montage de la clé (volume `${PROJECT}_link` alimenté par une commande `push-link-key` à écrire sur le modèle de `push_tls`).
5. **Contrôles** : `relays list` (dmz1 `connected`), inventaire racine complet (minion-root + minion-child), `smoke`, `hooks` (host.up journalisés), ancien jeton HS256 **refusé** (code permanent attendu), `negative-ca`.
6. **Ne pas révoquer** les anciens jetons HS256 : ils permettent le retour arrière.

## 3. Cas à jouer pendant la montée

| Cas | Attendu |
|---|---|
| Minions pendant la fenêtre | restent connectés à leur relay (aucun nouvel enrôlement) ; tâches vers dmz1 en échec pendant la coupure |
| Enfant sans ancre (pas de `REPEATER_ROOT_LINK_KEY_FILE`) | refus de tout lien entrant, `[SECURITY WARNING]` (fail closed) |
| Lien avec ancien jeton `relay` HS256 | refus permanent, log explicite |
| Bascule de la racine après montée (`chain-test.sh failover`, puis `failover-test.sh run kill`) | nouveau maître avec la même clé de signature (`kid` identique), liens rétablis, hooks `host.up` journalisés |
| Révocation d'un jeton de lien sur la racine | lien dmz1 fermé (4001) ; **TODO(L1d)** commande `tokens revoke` |
| `backup-restore` sous v3.0.4 | état v2 restauré, minion déjà enrôlé reconnecté sans ré-enrôlement |

## 4. Retour arrière (restauration v1, rev2 §4.8)

1. Arrêter chaîne (`docker compose stop`, **jamais** `down -v` : l'état v1 sauvegardé est dans un volume nommé hors projet).
2. Sur la racine et l'enfant : restaurer `relay.state.v1.bak` (`state verify` puis `state restore --from`, mécanique de `backup_restore`) avec les binaires/images **v3.0.3** et `chain/child.env` d'origine (jetons HS256).
3. `chain-test.sh` avec images v3.0.3 : `smoke`, `hooks`. Attendu : lien dmz1 rétabli, inventaire complet.
4. Noter ce qui est perdu : enrôlements et révocations d'agents faits sous v3.0.4 (liste à rejouer, rev2 §2/§4.8).

## 5. Remontée

Rejouer §2 à partir d'un état v1 restauré : doit réussir à l'identique (migration idempotente, nouvelle `relay.state.v1.bak`). Verdict : `qa`.

## 6. Mesures à relever

Durée de la fenêtre de coupure des liens, durée de reprise après `failover` et `kill`, taille et durée de la migration v1→v2, aucune écriture d'état en régime nominal (comparer la date de modification de `relay.state`), `docker inspect` sans secret en clair (item L8-6 après L3).

## 7. Garde-fous

Aucune commande hors du projet `secagent-qualif` ; aucun `down -v` ni suppression de volume sans ordre explicite ; kills par PID/nom de conteneur du projet seulement ; pas de push, pas de tag.
