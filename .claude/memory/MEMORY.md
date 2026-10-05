# MEMORY — Ansible-SecAgent

> Source de vérité au démarrage de session (lue par `/start-session`). Mise à jour par `/end-session`.

## Version et environnements
- **Version produit : v3.0** (milestones v3.0.0 à v3.0.4). **Aucun tag `v3.0.x` posé** : un tag déclenche `release.yml` (images GHCR + release GitHub) ; à décider avec l'utilisateur (probablement à la fin de v3.0.3).
- **Dernière release taguée** : `v2.0.0` (2026-10-02).
- **`main` au 2026-10-05** : HEAD `61cdebb` = `origin/main`, CI verte (run 37303866704 : « Build + tests Go » `-race` timeout 300 s, « Lint Go » golangci-lint v2.14.0, « Inventaire Ansible » avec ansible-core 2.21.4). v3.0.0, v3.0.1 et v3.0.2 livrés (≈126 commits depuis `c884dde`).
- **Qualif** : 192.168.1.218 (Docker Compose). La topologie multi-zone v2 n'y est plus fonctionnelle depuis #123 ; la chaîne de relais v3 n'a **pas été déployée en qualif** (validée par la CI et les tests d'intégration uniquement).
- **Prod** : Docker Compose, même hôte ; bloquée par `DEPLOYMENT/prod/docker-compose.server.yml` absent (à créer par `infra`). Helm/K8s = #136 (v3.0.4).
- **Template Claude** : v3.9.3 (`fb77bee`).

## Milestones GitHub (renommés le 2026-10-05 : v3.0→v3.0.0, v3.1→v3.0.1, v3.2→v3.0.2, v3.3→v3.0.3, v3.4→v3.0.4)
- **v3.0.0 Fondations** : fermé (10). **v3.0.1 Chaîne de relais** : fermé (13). **v3.0.2 Events et inventaire** : fermé (6).
- **v3.0.3 Confiance et signature des liens** (6 ouvertes) : #141 signature des tokens par la racine, #146 rôles JWT relay-child/relay-parent (code : rôle unique `relay`), #147 CA personnalisée du client repeater, #151 SSRF du dialer push (déni loopback/link-local/métadonnées, RFC1918 autorisé, `REPEATER_DIAL_ALLOW_LOOPBACK`), #152 colonne `relay_nodes.token_hash` (hash en pull, token chiffré en push + tokens push en clair hérités), #156 rate limit des snapshots par `relay_id` et non par lien.
- **v3.0.4 Packaging K8s** (1) : #136 Helm chart.
- Anciens noms « v3.1…v3.4 » présents dans les messages de commit historiques : normal, ne pas réécrire.

## Livré en v3.0.x (modèle v3 : arbre de relais)
- Arbre : un relay = un seul parent ; lien ouvert par l'enfant (pull, `REPEATER_UPSTREAM_*`, `REPEATER_ID`) ou par le parent (push, `relay_nodes.mode=push`, token chiffré AES-GCM avec `RSA_MASTER_KEY`, 503 sans clé). Handshake `relay_hello` → `relay_ack` (+ `ancestors`) → `topology_snapshot`. Refus de boucle.
- Codes de fermeture : **4010 refus permanent** (client/dialer s'arrête, `refused_permanent`), 4011 expiré (non utilisé), **4012 corrigible** (backoff). État des liens : `/api/admin/status` et `server status` ; `/health` public = seulement `degraded`.
- Routage hiérarchique (`relay_routing.hop_type/relay_chain`, next hop = `chain[0]`, **agent direct prioritaire**, `host.conflict` un par changement de propriétaire), propagation d'événements (`event_forward` : host.up/down/new/conflict + `relay.updated`), filtre hooks `relay_chain_contains`, **re-snapshot complet** à chaque changement du sous-arbre (remplacement atomique, rate limit 40/60 s), chaînes réelles (`relay_nodes.relay_chain`).
- Révocation des tokens relay (#153) : JTI persisté, blacklist, `ws.CloseRelay` 4010 ; `DELETE` d'un relay legacy non révoqué = 409 `relay_not_revoked`. Token `relay-parent` : `tokens create --role relay-parent`.
- Inventaire Ansible **= binaire Go `secagent-inventory`** (décision utilisateur : on reste en Go, pas de plugin Python d'inventaire ; l'ancien `relay_inventory.py` avait été supprimé en 7752eb9). Un groupe par relay au **nom exact du relay** (l'avertissement Ansible « Invalid characters in group names » pour les tirets est accepté et documenté), `?relay=` / `RELAY_SCOPE`, group vars `RELAY_GROUP_VARS` (liste de refus : préfixe `ansible_` interdit sauf `ansible_python_interpreter` sans `..`, `secagent_`, marqueurs Jinja ; bornes 16 KiB / 64 clés).
- Câblage de `main.go` extrait dans `internal/server` (`API_ADDR`, `ADMIN_ADDR`, `WS_ADDR` ; `Config.Tune` = seam de test, jamais lu depuis l'environnement) ; `relay_id` validé partout (`^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$`) ; garde-fou de logs `logsafe` (une ligne par appel) ; garde `RELAY_INSECURE_TLS` du binaire d'inventaire (+ `_ACK`).
- CI : `-race` partout, job « Inventaire Ansible » (`.github/ci/requirements-ansible.txt`, garde anti-faux-vert `--- PASS: .*Ansible`, `ANSIBLE_E2E=1`).

## CI GitHub et outils
- `go` dans `/usr/local/go/bin` (pas dans le PATH). golangci-lint absent : télécharger le binaire v2.14.0 de la release GitHub (scratchpad). Tests : `JWT_SECRET_KEY=test ADMIN_TOKEN=test go test -race ./... -timeout 300s` depuis `GO/`.
- Suite d'intégration (`internal/integration`) = un nœud par processus OS, vrai point d'entrée, TLS réel, ~13 s → ~80 s ; Ansible installable en venv (`pip install ansible-core==2.21.4`, Python 3.12).

## À trancher / suivis
- Tag `v3.0.x` et déploiement qualif de la chaîne de relais (jamais fait). Prod : `docker-compose.server.yml` à créer.
- **README** : contient encore l'arborescence d'un ancien serveur Python (`broker/nats_client.py`, etc.) qui n'existe plus : à nettoyer.
- Non testé : sauts d'horloge ; `slog` direct / panic fatal hors `logsafe`. Warning Ansible « Found variable using reserved name » (`tags`, `retries`) toléré.
- Suivis mineurs : la même regex `relayIDShape` est déclarée dans 5 paquets (`storage.ValidRelayID` possible) ; `test_inventory` Python (`SECAGENT-PYTHON/tests/`) toujours vide.
- Labels hérités inutilisés : `phase:1` à `phase:12`, `owner:dev-plugins` (l'agent s'appelle `dev-connexion`).
- Qualif : nettoyer `/tmp/qualif-v200`, décider du sort de `DEPLOYMENT/qualif/docker-compose.override.yml`.

## Règles / pièges (leçons de la session du 2026-10-05)
- **Questions à l'utilisateur** : toujours via AskUserQuestion. **Pas de push sans feu vert explicite** (un feu vert vaut pour un lot) ; le CDP délègue le push à `deployer` (`git push origin <SHA>:main`, jamais `HEAD`, jamais de force push) ; je ferme les issues après CI verte (`status:completed`, retrait de `status:todo`).
- **Labels** : le CDP pose `EN COURS` → `EN QA` → `DONE` ; pas de label `status:in-progress`.
- **Trailer de commit EXACT** : `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>`. Les agents écrivent parfois leur propre modèle (« Haiku 4.5 », « Sonnet 4.6 ») ou un texte parasite : contrôler les trailers de TOUS les commits non poussés avant un push (`git show -s --format=%B <sha> | grep -c '^Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>$'`). Amend d'un commit local seulement si c'est HEAD, index propre.
- **Vérifier, ne pas croire** : les agents annoncent « tout est vérifié » avec des erreurs (numéros d'issues, bornes chiffrées, événements inexistants). La documentation de sécurité et les chiffres doivent être relus contre le code par un agent qui le connaît (security-reviewer). Contrôler `git`, `gh`, grep du code.
- **Valider avec l'outil réel** : le vrai `ansible-inventory` a trouvé `hosts: null` (tout l'inventaire rejeté) que le contrôle structurel ne voyait pas ; des **arbres de 4-5 niveaux** ont trouvé l'aplatissement des chaînes (`buildSnapshot`) que les tests à 2-3 niveaux ne voyaient pas. Toujours des tests de bout en bout sur nœuds réels avec mutations.
- **Lint local avant chaque DONE** : le job Lint bloquant a été rouge deux fois après un push (`unused`, test instable `-race`). Tests intermittents : exiger 3 passes complètes `-race` sous charge, pas seulement `-count=N` par paquet ; un test relâché (borne ≤4) est un défaut.
- **Agents** : noms canoniques sans suffixe (`doc-updater`, pas `doc-updater-130`) ; un agent déjà spawné se réutilise par SendMessage. `TeamCreate` n'existe pas dans cet environnement ; l'adresse du teamleader pour les agents est `team-lead` (pas `main`) ; `TEAMMATES_PROTOCOL.md` n'existe que en `.template.md`. `doc-updater`, `infra` ne sont pas permanents (spawn manuel).
- **Sécurité** : `become_pass` jamais dans les logs ; fail closed (hooks de sécurité câblés avant tout listener) ; pas de `panic` en production ; identifiants du pair et de la base toujours en `%q` (log forging).
- Le CRLF/LF fait apparaître des fichiers « modifiés » sans diff réelle : `git diff --ignore-space-at-eol`. Le plugin Python de connexion est dans `SECAGENT-PYTHON/ansible_plugins/connection_plugins/relay.py`.
