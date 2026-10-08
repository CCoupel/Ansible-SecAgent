# Installer et configurer un relay enfant — v3.0.4

Guide opérateur. Prérequis : une **racine** installée et fonctionnelle ([`INSTALL_SERVER.md`](INSTALL_SERVER.md)). Références :
[`DECISION_141.md`](../security/DECISION_141.md) (conception des jetons de lien), [`SECURITY.md`](../security/SECURITY.md) §7,
[`SERVER_SPEC.md`](../server/SERVER_SPEC.md) §9, [`DEPLOYMENT/prod/README.md`](../../DEPLOYMENT/prod/README.md),
[`DEPLOYMENT.md`](DEPLOYMENT.md) (montée de version, rotation).

## 1. Topologie et modèle de confiance

Les relays forment un **arbre strict** : un relay enfant a *un seul* parent. Chaque relay expose à ses clients (agents,
plugin) **toute sa descendance** ; il achemine les tâches vers l'agent concerné à travers les liens.

Un lien relay ↔ relay est une WebSocket TLS sur `/ws/relay` (port 7772 du parent) :

- **pull** (le cas courant) : l'**enfant** ouvre la connexion vers son parent (`REPEATER_UPSTREAM_URL`) et présente un jeton de rôle **`relay-child`** ;
- **push** : le **parent** ouvre la connexion vers l'enfant (déclaré par `relays add --mode push`) et présente un jeton de rôle **`relay-parent`**.

Depuis la v3.0.4, **tous** les jetons de lien sont des JWT **Ed25519 signés par la racine** (champs `iss` = racine, `sub` =
porteur, `aud` = vérificateur, `kid`, `jti`, `exp`). Le rôle `relay` (HS256) de la v3.0.3 n'existe plus (`link_role_legacy`).
Chaque relay non racine vérifie les jetons avec la **clé publique de la racine épinglée à l'installation** (l'**ancre**), jamais
apprise à la première connexion, et ne détient aucun secret de signature. Sans ancre, un relay **refuse tout lien entrant**
(fermeture `4010`, `[SECURITY WARNING] … link_trust_missing`).

Identifiants : `REPEATER_ID` (et donc `relay_id`) doit respecter `^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$`.

## 2. Prérequis

- Les mêmes que pour la racine ([`INSTALL_SERVER.md`](INSTALL_SERVER.md) §2) : hôtes Docker, stockage pour `STATE_DIR` (partagé
  si l'enfant est lui-même actif/passif), certificat TLS **propre à l'enfant** (ses clients l'utilisent), secrets propres.
- Depuis le relay enfant : accès réseau sortant vers **tous** les hôtes du parent, port **7772** (le parent est lui-même
  potentiellement actif/passif : seul son maître répond).
- Si le certificat du parent est signé par une CA privée : son bundle PEM (`REPEATER_CA_FILE`, §4).
- Sur la racine : la clé publique de lien (`keys link-pubkey`) et le droit de créer des jetons de lien (`ADMIN_TOKEN`).

## 3. Préparer l'ancre et le jeton (sur la racine)

```bash
# Alias srv : voir INSTALL_SERVER.md §7 (exécute la CLI dans le conteneur racine)

# 1. Déclarer l'enfant attendu (mode pull, par défaut). Cela ne minte AUCUN jeton depuis la v3.0.4.
srv relays add --id dmz1 --description "Zone DMZ1"

# 2. Exporter l'ancre : clé publique PEM sur stdout, « root_id=<id> kid=<kid> » sur stderr
srv keys link-pubkey > root-link.pub

# 3. Minter le jeton de lien de l'enfant (affiché UNE seule fois)
srv tokens create --role relay-child --sub dmz1 --aud <relay_id du parent direct> --expires 720h
```

- `--sub` = `REPEATER_ID` de l'**enfant** ; `--aud` = `relay_id` de son **parent direct** (la racine pour un enfant direct,
  l'enfant intermédiaire pour un petit-enfant). `--sub` et `--aud` doivent être différents.
- Durée : **720 h par défaut**, **365 jours au plus**. Prévoyez le renouvellement avant l'échéance (§7). Le comportement
  d'un lien *déjà établi* à l'échéance de son jeton n'est pas documenté ici (non vérifié) : ne comptez pas dessus.
- `tokens create` de rôle `relay-*` n'existe que sur la **racine** : `409 not_root` ailleurs, `503 master_key_required` sans
  `RSA_MASTER_KEY`.

Remettez à l'hôte de l'enfant : le **jeton**, `root-link.pub` (non secret) et le **`root_id`** affiché par `keys link-pubkey`
(= le `REPEATER_ID` de la racine).

## 4. Installer le relay enfant

Même archive Compose que la racine ([`INSTALL_SERVER.md`](INSTALL_SERVER.md) §3). Un enfant utilise
`docker-compose.server.yml` **plus** la surcharge `docker-compose.child.yml`.

```bash
# Sur l'hôte de l'enfant, dans le dossier de l'archive

# Secrets propres à l'enfant (jwt_secret_key, admin_token, rsa_master_key : voir INSTALL_SERVER.md §5)
# + le jeton de lien reçu de la racine
printf '%s' "$JETON_DE_LIEN" | sudo ./preflight-secrets.sh --write repeater_upstream_token     # 0400, UID 10001

# Ancre : clé publique racine, non secrète, lisible par l'UID 10001, jamais inscriptible par le groupe ou les autres
install -m 0644 root-link.pub /etc/secagent/root-link.pub
```

`.env` de l'enfant (en plus des variables de la racine) :

```bash
REPEATER_ID=dmz1
# Adresses WSS du parent, séparées par des virgules, une par hôte du parent (16 au plus), wss:// UNIQUEMENT
REPEATER_UPSTREAM_URL=wss://relay-a.example:7772,wss://relay-b.example:7772
REPEATER_ROOT_ID=<root_id affiché par keys link-pubkey>
ROOT_LINK_KEY_FILE=/etc/secagent/root-link.pub       # chemin HÔTE de la clé publique racine
```

> `REPEATER_UPSTREAM_URL` exige le schéma **`wss://`** et le port **7772** du parent (le chemin `/ws/relay` est ajouté par
> le serveur). Un schéma `https://` est refusé au démarrage. (Le fichier `.env.example` de l'archive v3.0.4 montre à tort des
> adresses `https://…:7770` en commentaire : suivez ce guide.)

Si le parent présente un certificat signé par une CA privée, ajoutez à l'environnement du service enfant
`REPEATER_CA_FILE=/certs/ca.pem` (bundle PEM placé dans `TLS_CERT_DIR` ; il *remplace* les CA système pour tous les liens
sortants ; l'option est commentée dans `docker-compose.child.yml`).

Puis :

```bash
./preflight-secrets.sh --child        # code 0 exigé (secrets + clé publique racine)
export COMPOSE_PROJECT_NAME=secagent-prod-dmz1
docker compose -f docker-compose.server.yml -f docker-compose.child.yml run --rm --no-deps secagent-server state init
docker compose -f docker-compose.server.yml -f docker-compose.child.yml up -d
```

Le Compose enfant monte le jeton en secret (`REPEATER_UPSTREAM_TOKEN_FILE=/run/secrets/repeater_upstream_token`) et la
clé publique racine en lecture seule (`REPEATER_ROOT_LINK_KEY_FILE=/run/secagent-link/root-link.pub`). Le fichier de clé
est lu par un lecteur strict : fichier régulier, ni lien symbolique ni inscriptible par le groupe ou les autres ; un fichier
de secret doit appartenir à l'UID 10001 en mode 0400 (Compose hors Swarm **ignore** `uid`/`gid`/`mode` ; c'est le rôle de
`preflight-secrets.sh`).

### Vérifications

```bash
srv relays status               # sur la racine : l'enfant apparaît « connected »
srv keys link-status            # sur la racine : l'enfant apparaît avec son kid, CONFIRMED
```

Côté enfant, le journal contient `linked to parent relay_id="<racine>" as dmz1`. Démarrez ensuite les agents de la zone en
pointant `RELAY_SERVER_URL`/`RELAY_WS_URL` sur les hôtes **de l'enfant** ([`INSTALL_AGENT.md`](INSTALL_AGENT.md)) ; vérifiez
que l'inventaire de la racine contient les hôtes de la zone et qu'un `exec` traverse le lien.

**Lien push** (le parent ouvre vers l'enfant) : sur la racine, minter un jeton `relay-parent`
(`tokens create --role relay-parent --sub <parent> --aud <enfant>`) puis, sur le **parent** :
`srv relays add --id <enfant> --mode push --url wss://<hôte-enfant>:7772 --token "<jeton relay-parent>"` ; le jeton est
stocké chiffré sous `RSA_MASTER_KEY` (le parent refuse sans elle : 503) et n'est plus jamais affiché. L'enfant doit être
ancré comme ci-dessus. **Limite honnête** : la variante push n'a pas été couverte par la qualification de la v3.0.4 (ni le
scénario de rotation, ni de révocation).

## 5. Politique de dial des liens sortants (#151)

Pour limiter les adresses que le serveur accepte de contacter (liens sortants pull et push), trois variables optionnelles,
lues au démarrage (tout changement = redémarrage) :

| Variable | Rôle |
|---|---|
| `REPEATER_DIAL_ALLOW_LOOPBACK` | booléen strict (`true`/`false`, défaut `false`) ; `true` = développement et CI uniquement |
| `REPEATER_DIAL_DENY_CIDRS` | CIDR supplémentaires refusés (liste séparée par des virgules) |
| `REPEATER_DIAL_ALLOW_CIDRS` | si non vide : liste blanche ; `deny` l'emporte ; ne lève jamais un interdit intégré |

Interdits intégrés, jamais levables : lien-local, métadonnées cloud, adresse non spécifiée, multicast, broadcast. La règle
s'applique à chaque IP résolue et à l'IP effectivement contactée (donc aussi contre le DNS rebinding) ; les redirections
HTTP 3xx ne sont jamais suivies ; les réseaux RFC 1918 restent acceptés par défaut. Détail et ordre d'évaluation :
`SERVER_SPEC.md` §9.3. Ces variables se déclarent dans le service Compose (exemples commentés dans
`docker-compose.server.yml`).

## 6. Dimensionnement et limites

- **Quota de `topology_snapshot` (#156)** : 40 par 60 secondes **par `relay_id`** (et non par lien) ; une reconnexion ne
  remet pas le compteur à zéro, un `relay_id` au quota épuisé est refusé dès son `relay_hello` (fermeture 4012). Les
  `event_forward` restent limités à 200 par seconde et par lien.
- Plafonds de listes : `MAX_SNAPSHOT_RELAYS` (1000), `MAX_SNAPSHOT_HOSTS` (10 000), `MAX_AGENT_LIST_HOSTS` (10 000 par appel).
- **Parc > 3 000 hôtes** : mémoire 2 GiB minimum par relay, `GOMEMLIMIT` à ≈ 80 % ; taille du fichier d'état et mesures :
  `DEPLOYMENT/prod/README.md`, « Dimensionnement », et `STATE_SPEC.md`, « Dimensionnement mesuré ».
- Limites d'admission des tâches (par relay) : [`INSTALL_SERVER.md`](INSTALL_SERVER.md) §9 (204 tâches simultanées par défaut).
- **Suspension** : l'état « suspendu » d'un agent est propagé dans l'inventaire des ancêtres (informatif, à cohérence à
  terme ; le refus reste appliqué par le relay qui détient l'agent). Un parent resté en v3.0.3 journalise `unsupported
  event kind` pour ces événements : montez les parents d'abord.

## 7. Exploitation

### Rotation de la clé de lien (séquence exacte)

Un jeton de lien porte le `kid` de la clé qui l'a signé, et le relay qui le vérifie n'accepte que les clés `current` et
`previous` (`auth/linkjwt.go`). **Après `retire-link-previous`, un jeton émis avant la rotation est refusé
(`jwt_unknown_kid`) et l'ancien fichier d'ancre n'est plus accepté au redémarrage.** Dans cet ordre :

1. `srv keys rotate-link` (la clé courante devient `previous`, nouvelle courante ; `link_keys` est poussé aux enfants).
2. `srv keys link-status` jusqu'à ce que **tous** les relays soient `confirmed` (sinon `retire-link-previous` répond
   `409 rotation_unconfirmed`).
3. **Un nouveau jeton par lien**, signé par la nouvelle clé : `srv tokens create --role relay-child --sub <enfant> --aud <parent>`.
4. `srv keys link-pubkey > root-link.pub` puis, sur **chaque relay non racine** : remplacer `REPEATER_ROOT_LINK_KEY_FILE`
   par ce fichier **et** `REPEATER_UPSTREAM_TOKEN[_FILE]` par le nouveau jeton, **redémarrer** le relay (ces valeurs sont
   lues au démarrage), vérifier que le lien est `connected`.
5. Seulement alors : `srv keys retire-link-previous` (n'utilisez `--force` que pour un relay définitivement perdu).

Le défaut est **différé** : si l'on oublie le nouveau jeton, le lien établi tient encore juste après le retrait ; l'enfant
ne se reconnecte plus qu'à son redémarrage suivant et la racine journalise `jwt_unknown_kid`. **L'absence de coupure
immédiate ne prouve pas que la rotation est correcte.** Ordre des relays : lancer la rotation et obtenir la confirmation
des relays *existants* avant de déployer de nouveaux relays ancrés sur la nouvelle clé. Cette séquence est celle du
scénario `link-rotation` de `DEPLOYMENT/qualif/chain-test.sh` ; le lien **push** n'est pas couvert par ce scénario
(re-minter un `relay-parent` de la même façon, non testé).

### Révocation d'un lien

```bash
srv tokens list --role relay-child        # trouver l'id du jeton
srv tokens revoke <id-du-jeton>           # sur la racine
```

Le jeton est révoqué (blacklist de son `jti` jusqu'à son expiration), la révocation est poussée de proche en proche et
chaque relay **ferme le lien (4010, refus permanent)** ; l'enfant ne se reconnecte pas avec ce jeton (un nouveau jeton
rétablit le lien). Si la racine est injoignable, les liens établis continuent et la révocation descend au retour du lien.
Pour retirer un relay (révoquer puis supprimer, par son **UUID**, pas par son `relay_id`) : `DEPLOYMENT.md`,
« Identifiant d'un relay » et « Révoquer un relay enfant ».

### Ré-épingler un relay : `state link-trust reset`

L'ancre persistée l'emporte sur le fichier épinglé tant que celui-ci est égal à sa clé courante ou précédente. Un relay
resté hors ligne pendant une rotation *et* un `retire-link-previous`, ou après une **re-racine**, ne peut plus vérifier la
chaîne : sur ce relay **arrêté**,

```bash
docker compose run --rm --no-deps secagent-server state link-trust reset --yes
# puis remplacer REPEATER_ROOT_LINK_KEY_FILE / REPEATER_ROOT_ID par ceux de la racine, redémarrer
```

La commande n'efface que l'ancre persistée (ni agents, ni jetons, ni blacklist, ni clés), écrit une sauvegarde
`relay.state.linktrust-reset.<UTC>.bak` (0600, copie complète de l'état : à protéger puis détruire), exige `--yes` hors
terminal, refuse une racine et un verrou actif (code 8 : arrêtez *toutes* les instances), 9 pour les autres refus. Un
relais en cours de re-racine : procédure complète dans `DEPLOYMENT.md`, « Re-racine ».

## 8. Dépannage

| Symptôme (journal du parent ou de l'enfant) | Cause probable | Action |
|---|---|---|
| fermeture `4010`, `link_trust_missing` | relay non racine sans ancre | renseigner `REPEATER_ROOT_ID` + `REPEATER_ROOT_LINK_KEY_FILE` (§4) |
| `link_role_legacy` / `link_alg_not_allowed` | jeton HS256 (v3.0.3) | minter un jeton EdDSA sur la racine |
| `jwt_unknown_kid` | jeton signé par une clé retirée, ou clé racine inconnue du relay | jeton neuf (§7) ; ré-épingler si besoin |
| `jwt_wrong_aud` / `jwt_missing_aud` | `--aud` ≠ `relay_id` du parent qui vérifie | re-minter avec le bon `--aud` |
| `jwt_wrong_issuer` | `REPEATER_ROOT_ID` ≠ racine | corriger l'identité de la racine |
| `link_role_mismatch` | jeton `relay-parent` présenté en pull (ou l'inverse) | utiliser le bon rôle |
| `link_token_expired` | jeton échu | nouveau jeton (§3) |
| `link_token_revoked` | jeton révoqué | nouveau jeton |
| `link_signature_invalid`, `link_token_malformed` | jeton altéré / mal copié | re-saisir le jeton (fichier, sans guillemets) |
| l'enfant refuse de démarrer : `pinned root link key disagrees with the persisted link_trust` | fichier épinglé périmé après un `retire-link-previous` | remplacer par la clé courante (`keys link-pubkey`) et redémarrer ; sinon `state link-trust reset` |
| `REPEATER_UPSTREAM_URL must use the wss:// scheme` | schéma `https://` | `wss://hôte:7772` |
| enfant « refused_permanent » dans `server status` | refus permanent (4010) : jeton révoqué, identité ou boucle | corriger puis redémarrer ou redéclarer ; le nœud continue de servir ses agents |
| 429 `too_many_tasks` / `agent_busy`, 503 `memory_budget_exhausted` | limites d'admission | [`INSTALL_SERVER.md`](INSTALL_SERVER.md) §9 |
| quota de snapshots : fermeture `4012` | plus de 40 snapshots / 60 s pour ce `relay_id` | attendre ; chercher une boucle de reconnexion |

Les codes d'erreur de vérification des jetons sont listés dans `SERVER_SPEC.md` §9.2. Les refus corrigibles (4012, conflit)
déclenchent une reconnexion avec backoff ; les refus permanents (4010) arrêtent le client.
