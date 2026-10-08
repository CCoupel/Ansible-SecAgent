# Installer et configurer l'agent (`secagent-minion`) — v3.0.4

Guide opérateur. Référence technique : [`DOC/agent/AGENT_SPEC.md`](../agent/AGENT_SPEC.md) ; enrôlement :
[`DOC/security/SECURITY.md`](../security/SECURITY.md) §3-§4 ; serveur : [`INSTALL_SERVER.md`](INSTALL_SERVER.md).

L'agent (le « minion ») est un binaire Go unique. Il **ouvre lui-même** une connexion WebSocket TLS vers un relay :
aucun port n'est ouvert sur l'hôte géré, aucun SSH entrant n'est nécessaire.

## 1. Prérequis

- **Linux uniquement** (périmètre v1). Binaire fourni pour `linux/amd64` ; aucune autre plateforme n'est publiée.
- systemd (recommandé : l'unité ci-dessous s'appuie sur `RestartPreventExitStatus`). Sans systemd, tout superviseur
  capable de **ne pas redémarrer** sur les codes de sortie 77 et 78 convient (§9).
- Un accès réseau sortant vers un relay (API HTTPS `7770` pour l'enrôlement, WebSocket `7772`, voir
  [`INSTALL_SERVER.md`](INSTALL_SERVER.md)) et la **CA** qui a signé le certificat du relay si elle n'est pas publique.
- Un **jeton d'enrôlement** créé sur le relay par un administrateur (§4). L'agent ne reçoit jamais de mot de passe ni de
  clé SSH.
- Pour `become: true` côté Ansible, `sudo` doit être utilisable par l'utilisateur sous lequel tourne le minion (les
  tâches s'exécutent avec les droits de cet utilisateur). Point de détail non vérifié ici : voir
  [`AGENT_SPEC.md`](../agent/AGENT_SPEC.md) §9.

## 2. Installer le binaire

Les binaires sont des pièces jointes de la release GitHub `v3.0.4` (`secagent-minion-3.0.4-linux-amd64`) avec une somme
de contrôle `SHA256SUMS-3.0.4.txt`. **Vérifiez toujours la somme avant d'installer.**

```bash
V=3.0.4
mkdir -p /tmp/secagent-dl && cd /tmp/secagent-dl     # dossier vide, dédié au téléchargement
curl -fLO "https://github.com/CCoupel/Ansible-SecAgent/releases/download/v${V}/secagent-minion-${V}-linux-amd64"
curl -fLO "https://github.com/CCoupel/Ansible-SecAgent/releases/download/v${V}/SHA256SUMS-${V}.txt"
sha256sum --ignore-missing -c "SHA256SUMS-${V}.txt"   # attendu : « ./secagent-minion-3.0.4-linux-amd64: OK »
install -m 0755 "secagent-minion-${V}-linux-amd64" /usr/local/bin/secagent-minion
secagent-minion --version                              # « secagent-minion version 3.0.4 »
```

Le fichier de sommes liste aussi les autres pièces de la release : `--ignore-missing` évite une erreur pour celles que
vous n'avez pas téléchargées. (Le contrôle des sommes et la commande `--version` ont été rejoués sur les pièces de la release publiée.)

### Ligne de commande

Le minion se configure **uniquement par l'environnement** (§5). Il n'accepte presque aucun argument :

| Invocation | Effet | Code |
|---|---|---|
| `secagent-minion` (sans argument) | démarre l'agent | selon §9 |
| `secagent-minion --version` ou `-v` | affiche `secagent-minion version <version>`, rien n'est démarré | 0 |
| `secagent-minion --help` ou `-h` | affiche l'aide et les variables d'environnement | 0 |
| tout autre argument (`-d`, `--config x`, un mot, plusieurs arguments) | erreur + aide sur stderr, **avant** toute initialisation (ni clé générée, ni fichier lu) | 1 |

> **Avant la v3.0.4**, le minion démarrait sur n'importe quel argument. Ne lancez jamais un binaire plus ancien avec un
> argument inconnu sur un hôte en service.

## 3. Utilisateur et répertoires

```bash
useradd -r -s /sbin/nologin secagent-minion
install -d -m 0700 -o secagent-minion -g secagent-minion /etc/secagent-minion
install -d -m 0750 -o secagent-minion -g secagent-minion /var/lib/secagent-minion /var/lib/secagent-minion/async
```

| Chemin (défaut) | Variable | Contenu | Droits |
|---|---|---|---|
| `/etc/secagent-minion/id_rsa` | `RELAY_PRIVATE_KEY` | clé privée RSA-4096, **générée au premier démarrage** si absente | 0600 (créée par le minion) |
| `/etc/secagent-minion/token.jwt` | `RELAY_JWT_PATH` | JWT courant de l'agent | 0600 (créé par le minion) |
| `/var/lib/secagent-minion/async/` | `RELAY_ASYNC_DIR` | registre des tâches Ansible `async` (`jobs.json`) | créé par le minion s'il manque (0755) ; le créer à l'avance avec le bon propriétaire reste recommandé |

Le minion crée lui-même les répertoires parents de la clé et du JWT en 0700 (`enrollment/keys.go`,
`enrollment/enrollment.go`). Les journaux vont sur la sortie standard (journald) : il n'y a pas de fichier `agent.log`.

## 4. Créer un jeton d'enrôlement (sur le serveur)

Sur le serveur racine, avec la CLI d'administration (voir [`INSTALL_SERVER.md`](INSTALL_SERVER.md) §7 pour l'alias `srv`) :

```bash
srv tokens create --role enrollment --hostname-pattern 'web-[0-9]+' --reusable --expires 30d
```

- Le jeton est de la forme `secagent_enr_` + 64 caractères hexadécimaux. **Il n'est affiché qu'une fois.**
- `--hostname-pattern` est une expression régulière **ancrée** (`^(?:…)$`) appliquée au nom de l'hôte déclaré par
  l'agent : c'est la limitation principale d'un jeton réutilisable. Sans motif, le jeton accepte n'importe quel nom.
- Sans `--reusable`, le jeton est **à usage unique** ; sans `--expires`, il n'expire jamais (`never`).
- **Choisissez un jeton réutilisable, restreint par `--hostname-pattern`, à durée suffisante** pour tout le parc : voir
  « JWT d'une heure » en §7. Un jeton à usage unique ou court fait sortir le minion en **code 78** à la première
  reconnexion après expiration de son JWT.
- Les options complètes : `secagent-server tokens create --help`. `tokens list` (sans jamais montrer le jeton),
  `tokens delete <id>` (supprime un jeton d'enrôlement ou plugin), `tokens purge` ; `tokens revoke <id>` ne vaut que pour les jetons `plugin` et de lien (`relay-child`/`relay-parent`), pas pour un jeton d'enrôlement.

## 5. Configuration (variables d'environnement)

| Variable | Défaut | Rôle |
|---|---|---|
| `RELAY_SERVER_URL` | `https://localhost:7770` | URL(s) HTTPS de l'API du relay (enrôlement). **Liste séparée par des virgules** pour un relay actif/passif. |
| `RELAY_WS_URL` | `wss://localhost:7772/ws/agent` | URL(s) WSS de la WebSocket. Le chemin **`/ws/agent` est obligatoire**. **Même longueur** que `RELAY_SERVER_URL`, appariées par position (longueurs différentes : refus de démarrer). |
| `RELAY_ENROLLMENT_TOKEN` ou `RELAY_ENROLLMENT_TOKEN_FILE` | — | jeton `secagent_enr_…` ; **ou** chemin d'un fichier qui le contient (§6). Les deux ensemble : refus de démarrer. |
| `RELAY_AGENT_HOSTNAME` | `os.Hostname()` | nom déclaré à l'enrôlement (doit correspondre au motif du jeton) |
| `RELAY_PRIVATE_KEY` | `/etc/secagent-minion/id_rsa` | chemin de la clé privée |
| `RELAY_JWT_PATH` | `/etc/secagent-minion/token.jwt` | chemin du JWT persisté |
| `RELAY_CA_BUNDLE` | magasin système | bundle CA PEM pour vérifier le serveur (CA privée) |
| `RELAY_ASYNC_DIR` | `/var/lib/secagent-minion/async` | registre des tâches `async` |
| `MAX_CONCURRENT_TASKS` | `10` | tâches simultanées (entier > 0) |
| `RELAY_INSECURE_TLS` | `false` | `true` désactive la vérification TLS : **tests uniquement**, un `[WARN]` est journalisé |

Exemple pour un relay actif/passif sur deux hôtes (seul l'hôte maître répond, le minion essaie les adresses dans
l'ordre) :

```bash
RELAY_SERVER_URL=https://relay1.example:7770,https://relay2.example:7770
RELAY_WS_URL=wss://relay1.example:7772/ws/agent,wss://relay2.example:7772/ws/agent
```

Il n'existe **ni fichier de configuration, ni variable pour la taille de stdout** (tampon fixe de 5 MiB par tâche).
L'environnement des tâches Ansible est filtré : les variables `RELAY_*` et les noms en `*_TOKEN`, `*_KEY`, `*_SECRET`,
`*_PASSWORD`, `*_PASS` ne leur sont jamais transmis (`AGENT_SPEC.md` §11b).

Source de vérité des variables : `secagent-minion --help`.

> **Ce qui a été exécuté, et ce qui ne l'a pas été.** Rejoués (binaires de la release v3.0.4, sans Docker) : `--version`/`--help`,
> refus des arguments inconnus (code 1), arrêt en code 78 sans jeton, refus de `*_FILE` trop ouvert ou combiné à la
> variable, refus de longueurs d'adresses différentes, `systemd-analyze verify` de l'unité du §7. **Non exécutés** : le
> démarrage réel de l'unité sous systemd et les arrêts 77/78 sous systemd ; la sortie en code 0 sur SIGTERM ; le scénario
> complet 401 → ré-enrôlement → 403 → code 78 contre un vrai serveur (décrit d'après le code et `AGENT_SPEC.md` §12).

## 6. Secrets par fichier (`*_FILE`)

`RELAY_ENROLLMENT_TOKEN_FILE` évite de placer le jeton dans l'environnement du processus. Le fichier doit être :
un fichier **régulier** (ni lien symbolique, ni périphérique, ni tube), de **mode 0600 ou plus strict** (aucun droit pour
le groupe ni les autres), **non vide**, de **64 Kio au plus**, **lisible par l'utilisateur du minion** ; les espaces et fins
de ligne finaux sont ignorés. Le minion refuse de démarrer sinon.

```bash
install -m 0600 -o secagent-minion -g secagent-minion /dev/null /etc/secagent-minion/enrollment.token
printf '%s' "$JETON" > /etc/secagent-minion/enrollment.token        # $JETON : le jeton secagent_enr_… reçu
```

## 7. Unité systemd

```ini
# /etc/systemd/system/secagent-minion.service
[Unit]
Description=Ansible-SecAgent agent
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=600
StartLimitBurst=5

[Service]
Type=simple
User=secagent-minion
Group=secagent-minion
ExecStart=/usr/local/bin/secagent-minion
EnvironmentFile=/etc/secagent-minion/env
Restart=on-failure
RestartSec=30s
# 77 = agent révoqué, 78 = enrôlement refusé : arrêts définitifs, ne pas relancer en boucle
RestartPreventExitStatus=77 78

[Install]
WantedBy=multi-user.target
```

```bash
# /etc/secagent-minion/env  (mode 0600, propriétaire root ; valeurs d'exemple)
RELAY_SERVER_URL=https://relay.example:7770
RELAY_WS_URL=wss://relay.example:7772/ws/agent
RELAY_CA_BUNDLE=/etc/secagent-minion/ca.pem
RELAY_ENROLLMENT_TOKEN_FILE=/etc/secagent-minion/enrollment.token
```

```bash
systemctl daemon-reload
systemctl enable --now secagent-minion
journalctl -u secagent-minion -f        # attendu : [INIT] …, enrôlement, puis ouverture de la WebSocket
```

Au premier démarrage le minion génère sa clé RSA-4096 puis **s'enrôle** (§8). Son JWT est ensuite réutilisé depuis
`RELAY_JWT_PATH` tant qu'il est accepté.

### JWT d'une heure et ré-enrôlement (limite connue, #217)

Le JWT d'un agent dure **1 heure** et il **n'existe aucun renouvellement**. Une connexion ouverte n'est pas coupée à
l'expiration, mais **toute reconnexion après expiration** (redémarrage de l'agent, du relay, montée de version,
coupure réseau) reçoit un `401` ; le minion **se ré-enrôle alors automatiquement** avec `RELAY_ENROLLMENT_TOKEN[_FILE]`.
Si ce jeton est à usage unique (déjà consommé) ou expiré, le serveur répond `403` et le minion **sort en code 78** sans
réessayer. Conséquence : le jeton d'enrôlement doit **rester disponible et valide** pour toute la vie de l'agent
(§4 : réutilisable, restreint par motif, durée longue). Le correctif est suivi dans le milestone « v3.0.5 »
(issue #217).

## 8. Enrôlement : ce qui se passe

1. Génération de la clé RSA-4096 si elle n'existe pas (`RELAY_PRIVATE_KEY`, mode 0600).
2. `POST /api/register` avec le nom d'hôte, la clé publique et le jeton `secagent_enr_…` ; le serveur répond par un
   **challenge** chiffré (RSA-OAEP) avec la clé publique de l'agent.
3. L'agent le déchiffre et répond (`challenge_response`) ; le serveur valide le jeton, mémorise la clé et renvoie le
   **JWT chiffré** pour la clé de l'agent ; l'agent le déchiffre et l'écrit dans `RELAY_JWT_PATH` (0600).
4. L'agent ouvre la WebSocket `RELAY_WS_URL` avec ce JWT.

`POST /api/register` **sans jeton d'enrôlement est refusé** (`403 enrollment_token_required`). Une clé pré-autorisée
(`minions authorize`, `authorized_keys`) **ne donne aucun droit d'enrôlement** : le jeton est toujours exigé. Il n'y a
**pas de confiance à la première utilisation** : seule la présentation d'un jeton valide permet l'enrôlement.
Détail du protocole : [`SECURITY.md`](../security/SECURITY.md) §3.

## 9. Codes de sortie et dépannage

| Code | Cause | Que faire |
|---|---|---|
| 0 | arrêt propre (SIGTERM/SIGINT) | rien |
| 1 | erreur (clé illisible, enrôlement en échec non permanent, argument inconnu, secret `*_FILE` invalide…) | lire le journal ; systemd relance (`Restart=on-failure`) |
| **77** | agent **révoqué** (fermeture WebSocket 4001) | **ne pas relancer** ; décision de l'administrateur : la révocation est persistante, elle se lève en supprimant l'agent côté serveur (API `DELETE /api/admin/minions/{hostname}`, pas de sous-commande CLI) puis en le ré-enrôlant avec un nouveau jeton |
| **78** | enrôlement refusé définitivement : `403` (jeton invalide, **expiré**, **déjà consommé**, nom d'hôte hors motif) ou **aucun jeton** configuré | créer un nouveau jeton (§4), le mettre en place (§6), `systemctl reset-failed` puis démarrer |

Diagnostics fréquents :

| Symptôme | Cause probable | Action |
|---|---|---|
| `Enrollment cannot succeed (permanent …)` puis sortie 78 | jeton à usage unique consommé/expiré, ou `RELAY_ENROLLMENT_TOKEN` absent | §4 et §7 |
| refus de démarrer : « RELAY_SERVER_URL has N address(es) but RELAY_WS_URL has M: … must have the same length » (message en anglais, code 1) | `RELAY_SERVER_URL` et `RELAY_WS_URL` n'ont pas le même nombre d'adresses | les aligner |
| `x509 …` / certificat inconnu | CA du relay absente du magasin système | `RELAY_CA_BUNDLE=<ca.pem>` ; vérifier que le nom (SAN) du certificat correspond à l'adresse utilisée |
| connexion refusée sur 7770/7772 | l'instance interrogée est **secondaire** (aucun port ouvert) | lister toutes les adresses du relay actif/passif (§5) |
| agent sans WebSocket, requête `GET /` | `RELAY_WS_URL` sans `/ws/agent` | ajouter le chemin |
| `secret file permissions are too open` | `*_FILE` en 0640/0644 | `chmod 0600` (§6) |
| `403 hostname_not_allowed` | `RELAY_AGENT_HOSTNAME` hors du motif du jeton | corriger le nom ou le motif |
| agent `disconnected` côté serveur après redémarrage d'un relay, journal minion `token_expired` | JWT expiré + jeton à usage unique | voir « JWT d'une heure » (§7) |

Côté serveur : `secagent-server minions list` / `get <hostname>`.

## 10. Mise à jour et désinstallation

**Mise à jour** : télécharger et vérifier la nouvelle version (§2), puis
`install -m 0755 … /usr/local/bin/secagent-minion && systemctl restart secagent-minion`. La clé et le JWT sont conservés ;
si le JWT a plus d'une heure, le redémarrage provoque un ré-enrôlement (§7) : le jeton d'enrôlement doit être valide.
Les anciens agents (jusqu'à v3.0.3) doivent rester compatibles avec un serveur v3.0.4 : la montée v3.0.3 → v3.0.4 **ne coupe
pas les agents** (elle coupe les liens relay ↔ relay). *Non exécuté ici* : un agent v3.0.3 réellement connecté à un serveur v3.0.4 (affirmation tirée de `DEPLOYMENT.md`).

**Désinstallation** :

```bash
systemctl disable --now secagent-minion
rm /etc/systemd/system/secagent-minion.service /usr/local/bin/secagent-minion
# Révoquer côté serveur AVANT de supprimer la clé : voir « minions revoke » (blacklist du JWT, fermeture 4001)
rm -r /etc/secagent-minion /var/lib/secagent-minion      # supprime clé privée, JWT, registre async
userdel secagent-minion
```

## 11. Variante conteneur

Une image `ghcr.io/ccoupel/secagent-minion` (tags `3.0.4`, `v3.0.4`) est publiée. Son entrypoint transmet **tout argument**
au binaire avant d'agir (`docker run <image> --version` ne génère ni clé ni répertoire ; un argument inconnu est refusé).
Sans argument, il prépare les répertoires de données et une clé RSA-4096 sous `/var/lib/secagent-minion` puis démarre
l'agent sous l'utilisateur non privilégié `relay`. **Non vérifié ici** (pas de démon Docker dans l'environnement de
rédaction) : le montage d'un volume persistant pour `/var/lib/secagent-minion` et la gestion du jeton d'enrôlement en
conteneur ; la voie recommandée et documentée reste le binaire sous systemd.
