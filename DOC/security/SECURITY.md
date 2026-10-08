# Ansible-SecAgent — Security Design

> Document de référence pour le modèle de sécurité d'Ansible-SecAgent.
> Remplace et étend ARCHITECTURE.md §7.
> Dernière mise à jour : 2026-10-08 (v3.0.4 : jetons de lien signés par la racine, décision `DECISION_141.md`)

---

## 1. Modèle de confiance

```
Zero-Trust sur le transport  : TLS obligatoire sur toutes les connexions (WSS + HTTPS)
Zero-Trust sur les identités : chaque composant prouve son identité à chaque connexion
Pas de TOFU                  : aucun composant n'est accepté sans autorisation explicite de l'admin (jeton d'enrôlement émis par l'admin + preuve de possession de la clef)
Défense en profondeur        : IP binding + hostname claim + token secret + TLS
```

### Niveaux de confiance

| Composant | Confiance | Justification |
|---|---|---|
| Relay Server | Racine de confiance | PKI interne, secrets en DB chiffrés |
| Ansible Control Node | Machine de confiance | Administrée par l'équipe Ops |
| secagent-minion | Hôte non fiable | Déployé derrière NAT/DMZ/firewall |

---

## 2. Rôles et périmètres

| Rôle | Porteur | Endpoints autorisés | Mécanisme d'auth |
|---|---|---|---|
| `agent` | secagent-minion (hôte cible) | `POST /api/register`, `WSS /ws/agent` | JWT HMAC-HS256 chiffré RSA-OAEP |
| `plugin` | Ansible Control Node | `GET /api/inventory`, `POST /api/exec`, `/api/upload`, `/api/fetch` | Token statique hashé (SHA-256) |
| `relay-child` | repeater-enfant, lien pull (présenté au handshake) | `WSS /ws/relay` (relay_hello, agent_list, event_forward, task_forward) | **Jeton de lien** JWT Ed25519 (`alg=EdDSA`), signé par la **racine** ; `iss` = relay_id de la racine, `sub` = l'enfant, `aud` = le parent qui le vérifie, `kid`, `jti`, `exp` |
| `relay-parent` | repeater-parent en mode push (présenté au handshake) | `WSS /ws/relay` (ouvrir connexion vers enfant) | **Jeton de lien** JWT Ed25519, signé par la **racine** ; `sub` = le parent, `aud` = l'enfant qui le vérifie |
| `admin` | CLI dans le container serveur | Port 7771 — tous les endpoints d'administration | `ADMIN_TOKEN` env var (container-interne) |

### Règles d'isolation des rôles

- Un token `role: agent` ne peut **pas** appeler `/api/exec` ni `/api/inventory` ni ouvrir `/ws/relay`
- Un token `role: plugin` ne peut **pas** ouvrir `/ws/agent` ni `/ws/relay`
- Un token `role: relay-child` ne peut **pas** accéder `/api/inventory`, `/api/exec`, `/api/upload`, `/api/fetch`, ni `/ws/agent` (repeater-to-repeater uniquement)
- Le rôle HS256 `relay` de la v3.0.3 **n'existe plus** : un tel jeton est refusé (`link_role_legacy`) ; un jeton `agent` ou `plugin` ne peut pas ouvrir `/ws/relay`
- Un token `role: relay-parent` ne peut **pas** accéder `/api/inventory`, `/api/exec`, `/api/upload`, `/api/fetch`, ni `/ws/agent` (repeater-to-repeater uniquement)
- Le port 7771 (admin) n'est **jamais** exposé hors du container (`expose:` uniquement, pas `ports:`)
- L'admin CLI s'authentifie via `localhost:7771` en lisant `ADMIN_TOKEN` depuis l'environnement du container
- **Jetons de lien (v3.0.4)** : un seul vérificateur (`auth.VerifyLinkToken`) sur `/ws/relay`, jamais le chemin HS256 : `alg` EdDSA seul, `kid` ∈ {clé racine courante, précédente}, `iss` = racine, `aud` = ce relay (un jeton ne vaut qu'auprès d'**un** vérificateur), `role` conforme, `exp`, `jti` non blacklisté, `sub ≠ aud`. Les jetons `agent`, `plugin`, `enrollment` et admin ne changent pas. Décision, alternatives écartées et exigences S1-S23 : `DOC/security/DECISION_141.md`.


---

## 3. Enrollment de l'agent

### Problème de l'enrollment

L'agent démarre sur un hôte **non fiable**. Il génère sa propre paire de clefs RSA-4096.
Le serveur doit vérifier deux choses indépendantes :
1. **Autorisation** : cet hôte a-t-il le droit de s'enrôler ?
2. **Preuve de possession** : cet agent détient-il réellement la clef privée correspondant à la pubkey envoyée ?

### Modèle retenu : enrollment token + challenge-response

```
Admin                    Server                        Agent (hôte cible)
  │                        │                              │
  │ CLI: tokens create     │                              │
  │ --role enrollment      │                              │
  │ --hostname my-host     │                              │
  │ --expires 24h          │                              │
  │──────────────────────>│                              │
  │ token: "secagent_enr_..." │                              │  ← montré une seule fois
  │<──────────────────────│                              │
  │                        │                              │
  │  (transmet le token à l'opérateur qui déploie l'agent)
  │                        │                              │
  │                        │           [1er démarrage]    │
  │                        │           génère RSA-4096    │
  │                        │           stocke id_rsa      │
  │                        │                              │
  │                        │  POST /api/register          │
  │                        │  {hostname, pubkey, token}   │
  │                        │<─────────────────────────────│
  │                        │                              │
  │                        │ [valide token :              │
  │                        │  existe, non expiré,         │
  │                        │  non utilisé,                │
  │                        │  regexp.Match(hostname_pattern, hostname)]
  │                        │                              │
  │                        │  {challenge: OAEP(nonce, agent_pubkey)}
  │                        │─────────────────────────────>│
  │                        │                              │ [déchiffre nonce]
  │                        │  {response: OAEP(nonce+token, server_pubkey)}
  │                        │<─────────────────────────────│
  │                        │                              │
  │                        │ [vérifie nonce == nonce émis]│
  │                        │ [vérifie token == token stocké]
  │                        │ [marque token used=true]     │
  │                        │ [stocke {hostname, pubkey}]  │
  │                        │                              │
  │                        │  {jwt: OAEP(jwt, agent_pubkey)}
  │                        │─────────────────────────────>│
  │                        │                              │ [déchiffre JWT]
  │                        │                              │ [stocke token.jwt]
```

### Propriétés de sécurité

| Propriété | Mécanisme |
|---|---|
| Autorisation | Enrollment token — one-shot ou permanent, TTL optionnel, hostname_pattern regexp |
| Flexibilité périmètre | `hostname_pattern` couvre un hôte précis ou une flotte entière (`vp.*`) |
| Flexibilité usage | `reusable=0` : consommé après 1 usage ; `reusable=1` : pipeline CI/CD sans rotation manuelle |
| Preuve de possession | Challenge RSA-OAEP — seul l'agent avec la clef privée peut répondre |
| Confidentialité du JWT | JWT chiffré OAEP — illisible sans la clef privée de l'agent |
| Non-rejouabilité | Nonce aléatoire par enrollment + token one-shot marqué consommé |
| Traçabilité | `use_count` + `last_used_at` sur tous les tokens (one-shot et permanent) |

### Ce que ça bloque

- **Token volé sans keypair** : le challenge OAEP échoue (pas de clef privée pour déchiffrer)
- **Keypair inconnue sans token** : validation du token échoue (pas d'autorisation)
- **Replay du challenge** : nonce à usage unique, token marqué `used` après enrollment

### Modes d'usage : one-shot vs permanent

| Mode | `reusable` | Comportement |
|---|---|---|
| **One-shot** (défaut) | `0` | Consommé après le 1er enrollment (`use_count` passe à 1, tout usage suivant est rejeté) |
| **Permanent** | `1` | Réutilisable indéfiniment — chaque enrollment incrémente `use_count` (audit), le token reste valide |

**Cas d'usage typiques :**
- `one-shot + hostname_pattern = "vp-db-01"` → déploiement d'un hôte précis, token à usage unique
- `one-shot + hostname_pattern = "vp.*"` → le 1er hôte `vp-*` qui se présente consomme le token
- `permanent + hostname_pattern = "vp.*"` → pipeline CI/CD : N hôtes `vp-*` peuvent s'enrôler à volonté
- `permanent + hostname_pattern = ".*" + expires_at = now+30d` → token de bootstrap temporaire pour une vague de déploiement

### Modèle de données

> Depuis la v3.0.3 il n'y a plus de base SQL : ces enregistrements vivent dans le fichier d'état (`relay.state`). Le schéma ci-dessous est un **modèle logique** des champs conservés, pas une table existante. Le jeton en clair (`secagent_enr_` + 64 hex, opaque, non-JWT) n'est jamais stocké.

```sql
-- modèle logique (champs de l'enregistrement dans l'état)
CREATE TABLE enrollment_tokens (
    id               TEXT PRIMARY KEY,        -- UUID
    token_hash       TEXT NOT NULL UNIQUE,    -- SHA-256(token) — jamais en clair
    hostname_pattern TEXT NOT NULL,           -- regexp Go ancrée ^...$, ex: "vp.*", "web[0-9]+-prod"
    reusable         INTEGER DEFAULT 0,       -- 0 = one-shot (consommé après 1 usage)
                                              -- 1 = permanent (multi-usage)
    use_count        INTEGER DEFAULT 0,       -- nb d'enrollements effectués via ce token (audit)
    last_used_at     INTEGER,                 -- horodatage du dernier usage (audit)
    created_at       INTEGER NOT NULL,
    expires_at       INTEGER,                 -- NULL = jamais expiré (tokens permanents sans TTL)
                                              -- sinon : timestamp UNIX d'expiration
    created_by       TEXT                     -- "admin-cli", "terraform", etc.
);
```

**Logique de validation** :
```
1. token_hash présent en DB ?                          → sinon 403 token_not_found
2. expires_at IS NOT NULL AND expires_at < now() ?     → sinon 403 token_expired
3. reusable = 0 AND use_count > 0 ?                    → sinon 403 token_already_used
4. regexp.MatchString("^(?:" + hostname_pattern + ")$", hostname) ?  → sinon 403 hostname_not_allowed
   [enrollment autorisé → challenge-response → JWT]
5. use_count++ ; last_used_at = now()                  → toujours, quel que soit reusable
```

### Matching hostname

La validation du hostname utilise une **regexp Go** (`regexp.MatchString`) :

```
hostname_pattern = "vp.*"        → accepte vp-server-01, vp-db-02 — refuse vl-server-01
hostname_pattern = "web[0-9]+"   → accepte web1, web42            — refuse web-api
hostname_pattern = ".*-prod-.*"  → accepte app-prod-01, db-prod-02 — refuse app-staging-01
hostname_pattern = ".*"          → accepte tout (token générique — à utiliser avec précaution)
```

Le pattern est ancré implicitement (`^...$`) pour éviter les correspondances partielles.
Un token avec `hostname_pattern = "vp.*"` ne correspondra pas à `"notavp"` même si `vp.*` y apparaît.

---

## 4. Connexion WebSocket de l'agent

```
Agent                         Server
  │                             │
  │  WSS /ws/agent              │
  │  Authorization: Bearer <JWT>│
  │────────────────────────────>│
  │                             │ [1] vérifie signature HMAC-HS256
  │                             │ [2] vérifie expiry (exp claim)
  │                             │ [3] vérifie JTI ∉ blacklist
  │                             │ [4] vérifie role == "agent"
  │                             │ [5] stocke ws_connections[hostname]
  │  101 Switching Protocols    │
  │<────────────────────────────│
  │                             │
  │<══ ping/pong (30s) ════════>│  keepalive
```

### Codes de fermeture WebSocket

| Code | Signification | Comportement agent |
|---|---|---|
| `4001` | Révocation admin (JTI blacklisté) | **Arrêt définitif** — ne jamais reconnecter (code de sortie 77) |
| `4000` | Agent supprimé (`DELETE /api/admin/minions/{hostname}`) | Reconnexion avec backoff exponentiel |
| `1001` | Arrêt propre du serveur, perte du verrou maître, coupure réseau | Reconnexion avec backoff exponentiel (1s→2s→4s→…→60s max) |

Le serveur n'émet vers les agents que `4000`, `4001` et `1001`. `4002` existe comme constante (`ws/handler.go:24`) mais n'est jamais émis ; `4003` et `4004` n'existent pas. Un JWT expiré ou invalide n'est pas signalé par un code de fermeture : l'upgrade WebSocket est refusé en **HTTP 401** et l'agent se ré-enrôle (voir « Gestion du 401 »). Tout code autre que `4001` provoque une reconnexion.

#### Codes de fermeture WebSocket `/ws/relay` (#148)

| Code | Nature | Signification | Comportement du pair qui reçoit le close |
|---|---|---|---|
| `4010` | **Refus permanent** | Identité non autorisée pour ce lien : **jeton de lien révoqué** (révocation propagée par `link_revocations`), **relay non racine sans ancre de confiance** (`link_trust_missing`, S21), `relay_id` ≠ `jwt.sub`, identité du pair différente de celle attendue, boucle détectée (C ∈ {P} ∪ ancêtres(P)) | **Ne pas reconnecter** : le client/dialer s'arrête (état terminal, log ERROR) ; une action opérateur est nécessaire |
| `4011` | **Non émis** | Constante réservée (`ws/relay_handler.go`), jamais envoyée ni traitée : un token expiré est refusé par un 401 avant l'upgrade | — |
| `4012` | **Refus corrigible** | Erreur protocolaire ou de validation pouvant se résoudre : `topology_snapshot` invalide / reçu avant `relay_hello` / **au-delà de 40 par 60 s pour une même identité `relay_id`** (#156, y compris dès le `relay_hello` d'une identité au quota épuisé), conflit de routage ou de relay déclaré, **trame de lien trop grande** (`link frame too large` : `link_keys`/`link_revocations` > 1 Mio, `link_state` > 512 o), slot « parent unique » occupé | Reconnexion avec backoff exponentiel (5 s → 60 s max) |
| `4000` | Constante définie, non émise sur les liens relay | — | — |

> Un refus HTTP 401 avant l'upgrade (token invalide, révoqué à la reconnexion, secret non configuré) n'a pas de code de fermeture : le client le traite comme une erreur de connexion (backoff 5 s → 60 s).

---

## 5. Rotation des clefs serveur

### Problème

Les JWT agents sont signés avec `JWT_SECRET_KEY`. Si ce secret est compromis ou doit être
tourné, tous les agents connectés doivent migrer vers un nouveau JWT sans interruption de service.

### Mécanisme dual-key

```
Admin                    Server                        Agents connectés
  │                        │                              │
  │ CLI: security          │                              │
  │ keys rotate            │                              │
  │ --grace 24h            │                              │
  │──────────────────────>│                              │
  │                        │ jwt_secret_previous ← current│
  │                        │ jwt_secret_current  ← nouveau│
  │                        │ key_rotation_deadline = now+24h
  │                        │ [persiste en DB server_config]
  │                        │                              │
  │                        │  WS broadcast: {type:"rekey"}│
  │                        │─────────────────────────────>│
  │                        │                              │ [ré-enrollment auto]
  │                        │                              │ → POST /api/register
  │                        │                              │ ← nouveau JWT (signé current)
  │                        │                              │ [stocke nouveau token.jwt]
  │                        │                              │
  │                        │ [pendant grace period]       │
  │                        │ jwt_secret_previous valide   │
  │                        │ jwt_secret_current  valide   │
  │                        │                              │
  │                        │ [après deadline]             │
  │                        │ jwt_secret_previous = nil    │
  │                        │ [blacklist JTIs pré-rotation]│
```

### Gestion du 401 par les agents hors-ligne

Un agent qui se reconnecte après la deadline avec un ancien JWT reçoit HTTP 401.
Il déclenche automatiquement un ré-enrollment complet (`POST /api/register` avec `RELAY_ENROLLMENT_TOKEN`) puis se reconnecte. Un code de fermeture ne déclenche jamais de ré-enrôlement. Sans jeton d'enrôlement configuré, ou si le serveur répond `403`, le minion s'arrête avec le code 78.

### Stockage des secrets

Tous les secrets du serveur sont stockés en DB chiffrés (AES-256-GCM) :

| Secret | Table | Protection |
|---|---|---|
| `jwt_secret_current` | `server_config` | AES-256-GCM, clef dérivée de `RSA_MASTER_KEY` |
| `jwt_secret_previous` | `server_config` | idem |
| RSA keypair serveur | `server_config` | idem |
| `key_rotation_deadline` | `server_config` | idem |
| `link_signing_key_current` / `link_signing_key_previous` (v3.0.4, **racine seulement**) | `server_config` | AES-256-GCM, clef dérivée de `RSA_MASTER_KEY`, **AAD = nom du champ** (un chiffré déplacé de `current` vers `previous` est un refus de sécurité final au chargement) ; absent des logs, de l'API et de `state verify` (`[SEALED]`/`[ABSENT]`) |

### Modèle per-relay et signature centralisée des liens (v3.0.4)

- **Jetons d'agent** (HS256) : chaque relay garde sa propre `JWT_SECRET_KEY` ; la rotation (§ ci-dessus) s'applique indépendamment par relay. Une paire actif/passif partage `STATE_DIR`, donc le même secret.
- **Jetons de lien** (`relay-child` / `relay-parent`) : **plus de clé par relay**. Ils sont signés Ed25519 par la **racine** (nœud sans parent) ; la clé privée vit dans `server_config.link_signing_key_*` de la racine (chiffrée, partagée par la paire actif/passif : un nouveau maître signe avec le même `kid`). Les autres relays n'ont que la **clé publique** de la racine, épinglée au déploiement (`REPEATER_ROOT_LINK_KEY_FILE`, `REPEATER_ROOT_ID`) et persistée dans `link_trust`.
- **Rotation de la clé racine** : `keys rotate-link` (message `link_keys` signé par l'**ancienne** clé, chaîne vérifiée depuis l'ancre de chaque relay), double acceptation jusqu'à `keys retire-link-previous` (voir §7).

> **⚠️ Surface de risque de `RSA_MASTER_KEY` (v3.0.4, réserve R3 de `DECISION_141.md`)** : en v3.0.3, compromettre `RSA_MASTER_KEY` donnait accès aux secrets JWT des agents et à la clé RSA du serveur. Depuis la v3.0.4 elle donne **aussi** accès à `link_signing_key_current/previous` : **un attaquant qui la détient (avec une copie de `relay.state`) peut forger des jetons de lien valides pour toute la hiérarchie des relays**. Traiter `RSA_MASTER_KEY` comme le secret de plus haute valeur ; **faire une rotation de `RSA_MASTER_KEY` avant la mise en production de v3.0.4** (commande hors ligne `secagent-server state rekey` ; procédure : « Rotation de `RSA_MASTER_KEY` » en §11 et `DEPLOYMENT.md`), puis `keys rotate-link` si elle est soupçonnée compromise.

---

## 6. Authentification du plugin Ansible

### Modèle de confiance

Le plugin (inventory + connection) tourne sur l'**Ansible Control Node**, une machine
administrée et de confiance. Il n'a pas de keypair RSA — il utilise un token statique
émis par l'admin et hashé en DB.

### Modèle de données

> Depuis la v3.0.3 il n'y a plus de table `plugin_tokens` : les jetons plugin sont des enregistrements du fichier d'état, et le jeton lui-même (`secagent_plg_` + 64 hex) est une chaîne opaque, **pas un JWT**. Le schéma ci-dessous est un modèle logique des champs conservés.

```sql
-- modèle logique (champs de l'enregistrement dans l'état)
CREATE TABLE plugin_tokens (
    id                       TEXT PRIMARY KEY,    -- UUID (identifiant public, affiché en CLI)
    token_hash               TEXT NOT NULL UNIQUE,-- SHA-256(token) — jamais le token en clair
    description              TEXT,               -- "ansible-control-prod"
    role                     TEXT NOT NULL,       -- "plugin" uniquement
    allowed_ips              TEXT,               -- CIDRs séparés par virgule : "192.168.1.0/24,10.0.0.0/8"
                                                  -- NULL = pas de restriction IP
    allowed_hostname_pattern TEXT,               -- regexp Go : "ansible-control-.*", ".*\.prod\.example\.com"
                                                  -- NULL = pas de restriction hostname
    created_at               INTEGER NOT NULL,
    expires_at               INTEGER,            -- NULL = pas d'expiry
    last_used_at             INTEGER,            -- horodatage dernière utilisation (audit)
    last_used_ip             TEXT,               -- IP de dernière utilisation (audit)
    revoked                  INTEGER DEFAULT 0
);
```

### Vérification à chaque requête

```
POST /api/exec/{hostname}
Authorization: Bearer <token>
X-Relay-Client-Host: ansible-control-prod   ← optionnel, déclaré par le client

Server :
  1. SHA-256(token) → recherche de l'empreinte dans l'état (enregistrements plugin)
  2. revoked == 0 ?
  3. expires_at IS NULL OR expires_at > now() ?
  4. allowed_ips IS NOT NULL → r.RemoteAddr ∈ au moins un des CIDRs ?
  5. allowed_hostname_pattern IS NOT NULL → regexp.Match(pattern, X-Relay-Client-Host) ?
  6. UPDATE last_used_at, last_used_ip
  7. OK → traiter la requête
```

### Niveaux de contrainte

| Configuration | Usage recommandé |
|---|---|
| `allowed_ips=192.168.1.10/32, allowed_hostname_pattern=NULL` | Control node avec IP fixe |
| `allowed_ips=NULL, allowed_hostname_pattern=ansible-control-.*` | Control node derrière NAT, pattern hostname |
| `allowed_ips=10.0.0.0/8, allowed_hostname_pattern=ansible-[0-9]+` | Flotte control nodes, subnet connu |
| `allowed_ips=NULL, allowed_hostname_pattern=NULL` | Environnement de dev/test uniquement |

### Matching CIDR et hostname

- **IPs** : comparaison via `net.ParseCIDR` + `cidr.Contains(remoteIP)` — plusieurs CIDRs séparés par virgule, au moins un doit correspondre
- **Hostname** : regexp Go ancrée (`^...$`), même sémantique que les enrollment tokens

### Limite du hostname binding

Le hostname est une **auto-déclaration** du client (header HTTP) — il n'est pas
cryptographiquement prouvé. Il constitue une défense en profondeur contre un attaquant
interne au même réseau, pas une garantie cryptographique.

Pour une preuve cryptographique du hostname : utiliser mTLS (PKI interne, hors scope MVP).

### Authentification plugin par relay (HAUT-6, v3.0.0)

**Modèle** : chaque relay conserve ses propres jetons plugin dans son état et ne reconnaît que ceux-là.
- Un jeton plugin est une chaîne opaque `secagent_plg_…` créée par `tokens create --role plugin` ; le relay n'en garde que l'empreinte SHA-256 (il n'est **pas** signé : ce n'est pas un JWT et `JWT_SECRET_KEY` n'intervient pas)
- Le binaire `secagent-inventory` lit le jeton dans `RELAY_TOKEN` ; le plugin de connexion le lit dans un **fichier** (`RELAY_TOKEN_FILE`). Il n'existe pas de variable `RELAY_PLUGIN_TOKEN`
- Le plugin s'adresse à **un seul relay** ; il peut recevoir plusieurs adresses (les instances du même relay en actif/passif), pas plusieurs relays distincts
- **Jamais de partage** de JWT_SECRET_KEY ou des jetons plugin (`secagent_plg_…`) entre relays

**Isolation** : un jeton plugin créé sur relay-central n'est pas connu de relay-dmz1
- Chaque relay valide les jetons indépendamment, par recherche de l'empreinte dans son état
- Il n'y a pas de champ `allowed_relay_ids` — l'isolation vient du fait que l'empreinte n'existe que dans l'état du relay qui l'a créé

**Évolution envisagée (v3.0.1+)** : Centraliser la signature des tokens à la racine
- Permettre au plugin de parler à plusieurs relays avec un seul token
- Nécessite une PKI hiérarchique (racine → intermédiaires → feuilles)
- Hors scope MVP (v3.0.0)

---

## 7. Gestion des tokens (CLI)

### Création (token montré une seule fois)

```bash
# One-shot : un seul hôte précis (défaut)
secagent-server tokens create \
  --role enrollment \
  --hostname-pattern "vp-db-01" \
  --expires 4h

# One-shot : le 1er hôte vp-* qui se présente dans les 24h
secagent-server tokens create \
  --role enrollment \
  --hostname-pattern "vp.*" \
  --expires 24h

# Permanent : pipeline CI/CD — N hôtes vp-* peuvent s'enrôler à volonté
secagent-server tokens create \
  --role enrollment \
  --hostname-pattern "vp.*" \
  --reusable

# Permanent avec expiry : vague de déploiement 30 jours
secagent-server tokens create \
  --role enrollment \
  --hostname-pattern ".*-prod-.*" \
  --reusable \
  --expires 30d

# Token plugin avec restrictions IP (CIDR) + hostname (regexp)
secagent-server tokens create \
  --role plugin \
  --description "ansible-control-prod" \
  --allowed-ips "192.168.1.0/24,10.0.0.0/8" \
  --allowed-hostname-pattern "ansible-control-[0-9]+" \
  --expires 365d

# Token plugin sans restriction (dev/test)
secagent-server tokens create --role plugin --description "dev"
```

Sortie :
```
Token créé : secagent_enr_aB3xK9...      ← affiché UNE SEULE FOIS, stocker immédiatement
ID         : 550e8400-e29b-41d4-a716-446655440000
Rôle       : enrollment
Hostname   : vp.*  (regexp)
Mode       : permanent (reusable)
Expires    : 2026-04-05T00:00:00Z
Usages     : 0
```

### Listage

```bash
secagent-server tokens list [--role plugin|enrollment|all]

ID          RÔLE        HOSTNAME PATTERN         MODE        EXPIRES     USAGES  LAST USED
550e84...   plugin      ansible-control-[0-9]+   -           2027-03-06  -       2026-03-05 14:32
a1b2c3...   enrollment  vp-db-01                 one-shot    2026-03-07  0       jamais
b3c4d5...   enrollment  vp.*                     permanent   2026-04-05  3       2026-03-06 09:12
c4d5e6...   enrollment  .*-prod-.*               one-shot    2026-03-07  1       2026-03-06 08:00  [consommé]
```

### Révocation et suppression

```bash
# Révocation immédiate (permanent ou non)
secagent-server tokens revoke <id>

# Suppression définitive
secagent-server tokens delete <id>

# Purge sélective
secagent-server tokens purge --expired          # tokens dont expires_at est dépassé
secagent-server tokens purge --used             # one-shot déjà consommés (use_count > 0)
secagent-server tokens purge --expired --used   # les deux
```

### Jetons de lien relay (v3.0.4 — HAUT-4, HAUT-5, #141, #146)

Référence de conception : `DECISION_141.md`. Contrat : `SERVER_SPEC.md` §9.2 / §9.2.1, `REST_ADMIN.md` §3 et §6b.

**Création (racine seulement)** : `secagent-server tokens create --role relay-child --sub <enfant> --aud <parent>` (pull) ou `--role relay-parent --sub <parent> --aud <enfant>` (push) ; `409 not_root` sur un nœud qui a un parent ou une ancre épinglée, `503 master_key_required` sans `RSA_MASTER_KEY`. TTL 720 h par défaut, 365 jours au plus. Le jeton n'est montré qu'une fois ; le registre `link_tokens` n'en garde que les métadonnées (jamais le jeton ni son hash). `POST /api/admin/relays` **ne minte plus** de jeton en mode pull : il déclare seulement l'enfant attendu.

**Ancre de confiance** : un relay non racine épingle la clé publique de la racine (`keys link-pubkey` → `REPEATER_ROOT_LINK_KEY_FILE`, lu par un lecteur strict : fichier régulier, ni lien symbolique ni inscriptible par le groupe ou les autres, vérifié sur le descripteur) et son identité (`REPEATER_ROOT_ID`). **Sans ancre, il refuse tout lien entrant** (close `4010`, `[SECURITY WARNING]`). Une clé épinglée qui contredit le `link_trust` persisté, hors chaîne de rotation, **empêche le démarrage**.

**Révocation** : `secagent-server tokens revoke <id>` sur la racine pose `revoked_at`, blackliste le `jti` jusqu'à l'expiration du jeton et incrémente le compteur `seq`, **dans la même mutation d'état** ; la racine pousse `link_revocations` (signé, `seq` strictement croissant : un rejeu d'une liste plus ancienne est refusé) aux enfants, de proche en proche ; chaque relay ajoute les `jti` à sa blacklist et ferme (`4010`) le lien que le jeton authentifie. Liste complète renvoyée à chaque établissement de lien. **Racine injoignable** : les liens établis continuent (vérification locale) ; la révocation n'atteint les enfants qu'au retour du lien. Remède local d'urgence : `POST /api/admin/relays/{id}/revoke` (ou `tokens revoke <id-du-relay>`) sur le parent concerné : drapeau `revoked` + blacklist du `jti` relevé au premier `relay_hello` + close `4010`.

**Rotation de la clé racine** : `keys rotate-link` → nouvelle clé courante, ancienne `previous` (une seule rotation en vol : `409 previous_key_not_retired`) ; `link_keys` signé par l'ancienne clé, chaîne vérifiée par chaque relay depuis son ancre (un parent intermédiaire compromis ne peut pas injecter sa propre clé). Les relays confirment par `link_state` : « confirmé » = le relay rapporte le `kid` de la clé **courante** (le `seq` rapporté est informatif, non signé). **Ordre** : un relay ancré sur la **nouvelle** clé ne peut pas vérifier la rotation signée par l'ancienne (il n'a aucune clé de confiance capable de la vérifier) : il ignore le `link_keys` rejoué et ne le retransmet plus à ses enfants ; un enfant resté sur l'ancienne ancre sous un tel relay ne reçoit jamais la rotation et doit être ré-épinglé (`state link-trust reset`). Lancer la rotation et obtenir la confirmation de **tous les relays existants** avant de déployer de nouveaux relays épinglés sur la nouvelle clé. **Limite de la confirmation** : `link_state` n'est pas signé ; un relay intermédiaire (ou un enfant qui déclare des descendants dans son snapshot) peut rapporter le `kid` courant à la place d'un descendant qui ne l'a pas reçu (la racine n'accepte un `link_state` que du lien lui-même ou d'un descendant déclaré par lui). Le garde de `retire-link-previous` est une protection contre l'oubli, pas contre un relais malveillant ; l'impact d'un faux « confirmé » est limité à une coupure de disponibilité du descendant concerné (ré-épinglage). **`keys retire-link-previous` n'est à lancer qu'après confirmation de tous les relays** (`keys link-status`) : tant que des relays connus n'ont pas confirmé la racine répond `409 rotation_unconfirmed` ; `--force` passe outre avec un `[SECURITY WARNING]` listant les relays, qui seront refusés (`jwt_unknown_kid`) jusqu'à ré-épinglage (R2 de `DECISION_141.md`).

**Ré-épinglage** : l'ancre persistée dans `link_trust` **prime** sur le fichier épinglé tant que celui-ci est égal à sa clé courante ou précédente ; une clé épinglée qui n'est ni l'une ni l'autre (ou une autre `REPEATER_ROOT_ID`) fait **refuser le démarrage** (`ErrAnchorMismatch`). Pour ré-épingler un relay (rotation ratée suivie d'un `retire-link-previous`, ou re-racine) : **arrêter le relay**, lancer `secagent-server state link-trust reset --yes` (commande hors ligne : vérifie le HMAC, refuse une racine et un verrou actif, sauvegarde `relay.state.linktrust-reset.<horodatage>.bak` avant toute écriture, n'efface que `link_trust` ; voir `STATE_SPEC.md`), remplacer `REPEATER_ROOT_LINK_KEY_FILE` / `REPEATER_ROOT_ID` par la nouvelle ancre (`keys link-pubkey` sur la racine) et redémarrer : le relay épingle la nouvelle clé. Ses agents, ses jetons et sa blacklist sont conservés. Il faut ensuite un **nouveau jeton de lien** signé par la racine courante si l'ancien l'était par une clé qui n'est plus acceptée.

**Re-racine** (perte de `RSA_MASTER_KEY` ou de la clé privée de la racine) : arrêter la hiérarchie ; la racine regénère sa clé à la demande (`keys link-pubkey`, après `state init` si les secrets sont perdus) ; exporter la nouvelle clé publique ; sur **chaque** relay non racine : `state link-trust reset --yes`, nouvelle ancre, nouveau jeton ; **re-minter tous les jetons de lien** (les anciens sont invalides) ; redémarrer les parents d'abord. Coût équivalent à une montée de version complète : à répéter en qualification. Pas à pas : `DOC/project/DEPLOYMENT.md`.

> **Point sensible** : `state link-trust reset` déverrouille une ancre de confiance : quiconque l'exécute avec accès à `STATE_DIR` et à `RSA_MASTER_KEY` peut ensuite épingler une autre racine. Il demande donc l'arrêt du nœud, une confirmation explicite, produit une sauvegarde et une trace (`[SECURITY WARNING]`, `state-restore.log`) ; l'accès à `STATE_DIR` et à la clé maître reste le périmètre de confiance (mêmes hypothèses que `state restore`).

**Variables** : `REPEATER_ROOT_ID`, `REPEATER_ROOT_LINK_KEY_FILE` (non secrète), `REPEATER_UPSTREAM_TOKEN[_FILE]` (le jeton `relay-child` présenté au parent), `REPEATER_DIAL_ALLOW_LOOPBACK`, `REPEATER_DIAL_DENY_CIDRS`, `REPEATER_DIAL_ALLOW_CIDRS` (politique de dial des liens sortants, #151 : adresses réellement contactées, anti-rebinding, redirections 3xx jamais suivies).

**Stockage sécurisé (HAUT-5)** : Le token relay utilisé en mode push (parent ouvre vers enfant) est stocké **chiffré AES-256-GCM** :
- Colonne `relay_nodes.token_encrypted TEXT` (chiffré avec RSA_MASTER_KEY)
- Jamais stocké en clair
- Jamais loggé
- Déchiffré uniquement au moment de l'établissement de la connexion WSS vers l'enfant

---

## 8. Isolation des ports

| Port | Exposition | Accès | Contenu |
|---|---|---|---|
| `7770` | Publique (HTTPS) | Agents + Plugins | `/api/register`, `/api/exec`, `/api/inventory` |
| `7771` | **Container-interne uniquement** (`expose:`, pas `ports:`) | CLI admin | Tous les endpoints `/api/admin/*` |
| `7772` | Publique (WSS) | Agents + Relays | `/ws/agent` (agents), `/ws/relay` (inter-relay) |

**TLS** : Ports 7770 et 7772 utilisent TLS applicatif direct (via variables `TLS_CERT` et `TLS_KEY`).  
Le port 7771 ne doit **jamais** figurer dans la section `ports:` du docker-compose.
L'accès admin se fait exclusivement via `docker exec relay-api secagent-server <cmd>`.

---

## 9. Sécurité des logs

| Donnée | Règle |
|---|---|
| `become_pass` | Masqué dans tous les logs (agent + serveur) — remplacé par `[REDACTED]` |
| Token en clair | Jamais loggé — seul le hash SHA-256 ou l'UUID apparaît |
| JWT en clair | Jamais loggé — seul le JTI apparaît |
| Clef privée agent | Jamais transmise, jamais loggée |
| `stdin` avec become | Masqué dans les logs (agent + relays intermédiaires) — remplacé par `[REDACTED]` |

### Détection de détournement de route (HAUT-3)

L'événement `host.conflict` est généré quand un relay déclare un hôte déjà routé vers un autre relay.
**Recommandation pour la production** : Configurer un hook d'alerte sur `host.conflict` pour détecter les mouvements de route suspects (potentiel hijack d'un relay compromis).
Sans monitoring, le vol de route reste silencieux jusqu'à détection manuelle.

### Authentification asymétrique relay en mode push (NEW-3)

En mode push, le parent (WS client) ouvre vers l'enfant (WS serveur). L'authentification est asymétrique :
- **Parent authentifie l'enfant** : certificat TLS du serveur (truststore) + vérification `relay_ack.relay_id` contre `relay_nodes.relay_id` enregistré
  - Le JWT relay-parent ne prouve que l'identité du PARENT auprès de l'enfant (pas l'inverse)
  - TLS/X.509 fournit la garantie d'authenticité du serveur enfant
- **Enfant authentifie le parent** : JWT relay-parent (signé par l'enfant, jwt.sub=parent)
  - L'enfant doit vérifier le JWT et que jwt.sub correspond à l'identité attendue du client

**Risque résiduel** : Si l'enfant accepte les connexions sans TLS ou sans vérifier le certificat, un attaquant peut usurper l'identité du parent. Configuration sécurisée recommandée : TLS_CERT/TLS_KEY obligatoires, validation certificat client optionnelle mais recommandée.

---

## 10. Événements, hooks et group vars (v3.0.2)

### Propagation d'événements — Validation de la chaîne côté parent

Lors de la remontée d'un événement par un relay enfant, la chaîne d'événement est construite par accumulation :
1. L'enfant envoie `event_forward` avec une chaîne de son sous-arbre (ex: `[relay-A, relay-B]`)
2. Le parent ajoute son ID et relaie vers son propre parent (ex: `[relay-A, relay-B, relay-parent]`)

**Validation côté parent de la chaîne reçue (server/relay_handler.go, handleEventForward)** :
- Vérifier que le dernier élément de la chaîne (`chain[-1]`) correspond au `relay_id` du client (même en mode push)
- Vérifier que les intermédiaires de la chaîne (`chain[0..n-2]`) sont tous dans `conn.descendants` (relays déclarés en `topology_snapshot`)
- Rejet de l'événement si validation échoue (pas d'ascension vers le parent, log WARNING)
- Anti-boucle : refuse de relayer si l'ID du parent est déjà dans la chaîne (`relay_id ∈ chain`)

**Fail-closed** : les événements invalides sont silencieusement ignorés (ne bloquent pas le lien).

### Filtrage des hooks — relay_chain_contains (v3.0.2)

Les hooks configurés via `RELAY_HOOKS_CONFIG` JSON peuvent filtrer sur la chaîne d'événement :

```json
{
  "hooks": [
    {
      "event": "host.conflict",
      "filter": "relay_chain_contains:dmz1",
      "cmd": "alert-mgmt.sh {{hostname}}"
    }
  ]
}
```

**Validation du filtre au chargement** :
- **Fail-closed** : si le JSON est invalide ou un filtre malformé → tout le fichier est rejeté, configuration précédente conservée
- Format : `relay_chain_contains:<relay_id>`
- `relay_id` validé avec `relayIDShape` (format `^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$`)
- Rejet du fichier en bloc au SIGHUP (HUP) → config précédente reste active

**Sémaphore d'actions** (RELAY_HOOKS_MAX_CONCURRENT_ACTIONS) :
- Limite : défaut 64 goroutines simultanées pour l'exécution des actions (webhook, shell, etc.)
- Au-delà : actions excédentaires rejetées silencieusement (ne bloquent pas le dispatcher)
- Compteur `DroppedActions()` incrémenté
- Log [SECURITY WARNING] 1 sur 100 (pour ne pas saturer les logs) : hostname en format sûr (%q), ID relay, pas d'exposition d'identifiants tiers

### Group vars — Validation et refus de liste

`RELAY_GROUP_VARS` est un JSON optionnel contenant les variables Ansible pour un relay :

```
RELAY_GROUP_VARS='{"env":"prod", "region":"dmz"}'
```

**Validation au chargement du `relay_hello` et `topology_snapshot`** :
- **JSON invalide** → rejet du hello/snapshot en bloc (close 4012 si relais enfant ; log ERROR)
- **Interdits** :
  - Préfixe `ansible_*` (réservé à Ansible) — **sauf** `ansible_python_interpreter` si sa valeur ne contient pas `..` (prévention path traversal)
  - Préfixe `secagent_*` (réservé à secagent)
  - Marqueurs Jinja (`{{`, `{%`, `{#`) — refus du snapshot entier si présent (seuls les marqueurs ouvrants sont vérifiés, ce qui suffit à bloquer toute injection de template)
- **Bornes** (longueur totale, nombre de clefs) :
  - JSON total ≤ 16 KiB (`maxGroupVarsBytes = 16 * 1024`)
  - Nombre de clefs ≤ 64 (`maxGroupVarKeys = 64`)
  - Profondeur d'imbrication ≤ 4 (`maxGroupVarDepth = 4`)
  - Toute clef > 64 caractères → rejet (regex `^[A-Za-z_][A-Za-z0-9_]{0,63}$`)
  - Toute valeur > 1 024 octets → rejet (`maxGroupVarString = 1024`)
  - Toute liste > 64 éléments → rejet (`maxGroupVarListLen = 64`)

**Stockage** : persisté dans `relay_nodes.group_vars` TEXT (JSON sérialisé), une fois validé.

**Publication dans l'inventaire** :
- Chaque groupe Ansible (relay) expose ses `vars` depuis le `relay_nodes.group_vars` correspondant
- Omis si vide ou NULL

### Validité de relay_id partout (v3.0.2)

Le format de `relay_id` est **uniformément validé** partout dans le code :

| Contexte | Validation | Erreur |
|---|---|---|
| `POST /api/admin/relays` (enregistrement) | relayIDShape `^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$` | **400 `invalid_relay_id`** |
| `/ws/relay` upgrade (handshake) | JWT sub format check + `relay_hello.relay_id` == jwt.sub | **401** (avant upgrade WebSocket) ou **4010** (après) |
| `topology_snapshot` validation (relay enfant) | chainOK valide tous les IDs | **4012** (rejet corrigible) |
| Événements `event_forward` | relay_id de chaque maillon de la chaîne | **silencieusement rejeté** si invalide |

**Fail-closed** : un relay_id invalide génère un rejet sans accepter la connexion ou l'événement.

### Assainissement des textes du pair — Fermetures WebSocket (v3.0.2)

Quand un lien relay se termine avec un code de fermeture 4010 ou 4012, le texte de fermeture peut contenir des données envoyées par le pair distant (motif d'erreur, détail technique).

**Assainissement** (repeater/status.go, `sanitizeText`) :
- Remplace les caractères de contrôle (dont `\r`, `\n`, `\t`, `\x00`, séparateurs de ligne Unicode U+2028/U+2029/U+0085) par des espaces — le pair ne peut pas forger de ligne de log (ex. un faux `[SECURITY WARNING]`)
- Borne la longueur : **200 octets max** (tronqué sur une frontière UTF-8, `…` ajouté)
- Jamais de révélation d'identifiants tiers (relay_id du pair ne figure jamais dans le texte assaini logué)

Note : les trames de fermeture que le serveur **envoie** aux relays enfants (close 4010 / 4012) sont quant à elles bornées à **100 octets** par `closeReason()` dans `ws/relay_handler.go` (contrainte de la trame WebSocket : payload ≤ 123 octets code inclus).

**Exposition** (server status CLI/API) :
- `/api/admin/status` (port 7771) et `secagent-server server status` : affichent le texte assaini
- `/health` (port 7770, public) : **aucun détail** — seulement le flag `degraded` booléen ; pas d'exposition de topologie ni d'état du lien

### RELAY_INSECURE_TLS — Accepter certificats auto-signés (v3.0.2, client repeater)

Le binaire `secagent-inventory` utilise `RELAY_INSECURE_TLS` pour désactiver la vérification TLS vers le relay server (utile en dev/qualif avec certificats auto-signés).

**Garde** :
- À chaque appel (`--list` ou `--host`), si `RELAY_INSECURE_TLS=true` → log stderr `[SECURITY WARNING] TLS verification disabled …` ; stdout reste du JSON pur
- Si `RELAY_SERVER_URL` n'est **pas** une adresse de loopback (`localhost`, `127.0.0.0/8`, `::1`) ET `RELAY_INSECURE_TLS=true` :
  - Refuse d'exécuter (exit 1) **sauf si** `RELAY_INSECURE_TLS_ACK=i-understand-the-risk`
  - Message explicite sur stderr
- Token n'apparaît jamais dans ces messages

**Recommandation** : Utiliser des certificats signés (Let's Encrypt, PKI interne) en production. `RELAY_INSECURE_TLS=true` uniquement pour les environnements isolés (tests locaux).

---

## 11. Avis de sécurité

### Avis 1 — Endpoints `/ws/agent` et `/ws/relay` sans authentification (v1.0.0, v2.0.0)

**Versions affectées** : v1.0.0, v2.0.0

**Description** : Les endpoints WebSocket `/ws/agent` (tous les nœuds) et `/ws/relay` (nœuds en mode proxy, si `PROXY_MODE=true`) acceptaient les connexions **sans token Bearer** via un repli non signé qui acceptait un paramètre de chaîne de requête `?hostname=` (pour `/ws/agent`) ou `?relay_id=` (pour `/ws/relay`).

**Scénarios d'exploitation** :
- **`/ws/agent`** : Un client sans token pouvait usurper n'importe quel hostname et recevoir les tâches destinées à cet agent, dont les commandes et les `become_pass` en stdin.
- **`/ws/relay` (mode proxy)** : Un client pouvait usurper l'identité d'un relay, annoncer des hôtes arbitraires et détourner les tâches routées vers ces hôtes.

**Versions corrigées** :
- `/ws/agent` : **v3.0.3** (#169, commit 49ea502)
- `/ws/relay` : **v3.0.3** (réécriture v3 avec fail-closed `extractRelayAuth`, JTI-based)

**Compensation (déploiements v1.0.0 / v2.0.0)** :
- Restriction réseau stricte des ports 7770 et 7772
- Mise à jour vers v3.0.3 recommandée
- Audit des logs : rechercher `JWT verification bypassed` sur `/ws/agent` ou relays suspects dans `relay_hello`/`agent_list` côté proxy
- **Rotation des `become_pass`** des hôtes pilotés via déploiement qualif si un accès non contrôlé est possible

**Recommandation** : tous les déploiements utilisant v1.0.0 ou v2.0.0 en environnement de production doivent **minimalement** restreindre les ports 7770/7772 aux adresses de confiance, et **préférentiellement** mettre à jour vers v3.0.3 ou ultérieur.

### Avis 2 — Secrets de webhooks stockés en clair dans `action_log` (v1.0.0, v2.0.0)

**Versions affectées** : v1.0.0, v2.0.0

**Description** : L'historique des exécutions de hooks (table SQLite `action_log`) enregistrait la configuration complète de chaque hook sans masquage, y compris :
- Secrets HMAC des webhooks
- En-têtes incluant tokens d'autorisation
- URL contenant des jetons en query string

**Exposition** : L'endpoint `GET /api/admin/hooks/log` (et la CLI `secagent-server hooks log`) renvoyaient ces enregistrements à tout administrateur, et le fichier `relay.db` était accessible en clair lors de sauvegardes, exports ou accès au système de fichiers.

**Versions corrigées** : **v3.0.3** (#161)
- Action log remplacé par un journal append-only séparé avec masquage
- Retrait des secrets de l'historique d'exécution
- v3 repart d'un état vierge, pas de migration de l'historique

**Recommandation (déploiements v1.0.0 / v2.0.0)** :
- **Évaluer** tous les secrets configurés dans les hooks (HMAC, jetons URL, en-têtes) et les considérer comme exposés
- **Faire tourner** tous les secrets de webhooks (secrets HMAC, jetons)
- **Purger** les copies de `relay.db` : sauvegardes, exports, fichiers supprimés non écrasés
- Revoir la liste des détenteurs de tokens admin
- Mettre à jour vers v3.0.3

### Avis 3 — `POST /api/token/refresh` non authentifiée et enrôlement sans jeton (v1.0.0, v2.0.0)

**Versions affectées** : toutes les versions antérieures à v3.0.3, dont v1.0.0 et v2.0.0 (défaut présent depuis v1.0.0).

**Description** : deux chemins émettaient un JWT agent **sans prouver l'identité de l'appelant** et **sans consulter la blacklist des JTI** :
- **`POST /api/token/refresh`** : le seul contrôle était qu'un champ `challenge_encrypted` se déchiffre avec la clef du serveur (clef publique, donc fabricable par n'importe qui). Aucun en-tête `Authorization` n'était vérifié.
- **`POST /api/register` sans `enrollment_token`** (flux historique « clef pré-autorisée ») : il suffisait de présenter un hostname et la clef publique enregistrée dans `authorized_keys`, sans preuve de possession de la clef privée.

**Scénarios d'exploitation** :
- **Contournement de la révocation** : un agent révoqué (JTI blacklisté) qui conserve sa clef privée obtenait un nouveau JTI non blacklisté et un nouveau JWT (chiffré pour sa clef, qu'il peut donc lire), puis se reconnectait à `/ws/agent`.
- **Remplacement de JTI / déni de service** : toute personne connaissant un hostname (et, pour `/api/register`, sa clef publique, qui n'est pas secrète) remplaçait le JTI courant d'un agent légitime ; l'ancien JWT de l'agent était alors refusé (`token_replaced`) jusqu'à son ré-enrôlement. L'appelant ne pouvait pas lire le nouveau JWT (chiffré pour la clef de l'agent) : pas d'usurpation, mais une interruption répétable.

**Versions corrigées** : **v3.0.3** (#192, #192c) :
- la route `POST /api/token/refresh` est **supprimée** (`404` pour tout appelant) ; elle n'avait aucun client, le renouvellement se fait par ré-enrôlement ou message `rekey` ;
- `POST /api/register` **sans jeton d'enrôlement est refusé** (`403 enrollment_token_required`, identique quels que soient hostname et clef) ; le flux avec jeton exige le challenge RSA-OAEP, dont la preuve de possession de la clef privée est comparée côté serveur.

**Seconde porte (corrigée par #193)** : même après la suppression de ces deux chemins, la révocation ne reposait que sur la blacklist du JTI courant (rétention 25 h). Un agent révoqué qui gardait sa clef privée pouvait se **ré-enrôler avec un jeton d'enrôlement réutilisable** (ou à `hostname_pattern` large) et obtenir un nouveau JTI non blacklisté ; l'oubli de la blacklist après 25 h produisait le même effet. v3.0.3 pose à la révocation un **drapeau persistant `revoked`** sur l'agent, dans la même écriture que la blacklist : l'enrôlement (`403 agent_revoked`, jeton non consommé), le `rekey` et le handshake `/ws/agent` refusent un hôte révoqué même sans entrée de blacklist. La révocation se lève **uniquement** par `DELETE /api/admin/minions/{hostname}` (pas de `unrevoke`). Les révocations antérieures à #193 sont réparées au démarrage du maître tant que le JTI est encore en blacklist ; au-delà de 25 h elles sont oubliées et doivent être refaites. Voir `DOC/contracts/REST_ADMIN.md` et `DOC/server/STATE_SPEC.md`.

**Exposition tant que v2.0.0 est en service** : l'environnement de qualification resté en v2.0.0 est exposé jusqu'à sa migration vers v3.0.3.

**Mitigation réseau (déploiements v1.0.0 / v2.0.0)** :
- bloquer l'accès à `POST /api/token/refresh` et restreindre `POST /api/register` aux réseaux d'enrôlement (pare-feu ou reverse proxy en frontal) ;
- **en v1.0.0 / v2.0.0 la révocation n'est pas fiable** face à un agent qui conserve sa clef privée (aucun drapeau persistant) : pour un hôte à exclure, couper son accès réseau aux ports 7770/7772 (pare-feu) en attendant la mise à jour vers v3.0.3 ;
- mettre à jour vers v3.0.3.

**Recommandation** : mettre à jour vers v3.0.3 ; après la mise à jour, tous les agents se ré-enrôlent avec un jeton d'enrôlement (état vierge).

### Limites connues — v3.0.4

- **Une seule rupture, pas de retour arrière vers v3.0.3** (décision de l'utilisateur) : `schema_version` 2, un binaire v3.0.3 refuse l'état v2 (`ErrSchemaVersion`, sans repli sur `.prev`) ; le retour arrière passe par `relay.state.v1.bak` + binaires v3.0.3 + anciens jetons HS256, et perd les écritures faites sous v3.0.4 (voir `DEPLOYMENT.md`).
- **Rejeu d'un `link_keys` sur un relay déjà à jour (audit R4, corrigé en `1c231ee`)** : une trame qui annonce exactement les clés déjà de confiance (reconnexion, redémarrage) n'est acceptée que si sa **signature se vérifie avec une clé déjà de confiance** (`auth.VerifyLinkKeysReplay` : la `previous` de confiance pour une rotation encore ouverte, la `current` une fois la fenêtre fermée), jamais avec une clé lue dans la trame. Authentique : no-op idempotent. Non authentifiable (y compris un `link_keys{current_pub = clé de confiance, sig invalide, seq élevé}` forgé par un parent compromis) : **ni retransmise, ni mémorisée, ni confirmée**, et le `seq` d'un `link_state` ne provient jamais d'une trame non vérifiée ; il ne peut donc plus produire de faux consensus de rotation. Chaque relay rapporte son **propre** état authentifié (`kid`, `seq`) ; la racine confirme une rotation sur le `kid` rapporté. Limite connue restante : `link_state` n'est pas signé (un relay intermédiaire compromis peut mentir sur l'état de ses descendants) ; `retire-link-previous --force` reste donc à n'utiliser qu'en connaissance de cause. Voir `SERVER_SPEC.md` §9.2.1.
- **Racine = point unique de signature** : tant qu'elle est injoignable, aucun nouveau jeton de lien ni aucune révocation ne se propage ; les liens établis continuent.
- **`event_forward` (200/s)** reste limité par lien et non par identité.

### Limites connues — v3.0.3

#### Révocation d'agent : drapeau persistant, retour arrière et révocations anciennes (#193)

- **Retour arrière** : le décodeur d'état est strict ; un binaire antérieur à #193 rejette un état contenant `"revoked": true` (`unknown field "revoked"`, classé corruption). **Il peut alors basculer sur `relay.state.prev`** (`[SECURITY WARNING]`), génération plus ancienne qui peut ne pas contenir la révocation : **la révocation est perdue silencieusement** et l'hôte révoqué peut se ré-enrôler. Avant tout retour arrière : noter les agents révoqués, les supprimer (`DELETE`), puis ré-appliquer les révocations avec l'ancien binaire. Avant un rollback : lever les révocations (`DELETE` des agents) ou restaurer un état antérieur (`schema_version` reste 1).
- **Révocations antérieures à #193** : réparées au démarrage du maître seulement si le JTI courant est encore en blacklist (25 h). Les plus anciennes sont oubliées : **révoquer à nouveau** ces hôtes.
- **Levée** : `DELETE /api/admin/minions/{hostname}` supprime aussi les variables de l'hôte et sa clef autorisée ; il n'y a pas de levée qui les conserve.

#### Anti-rejeu limité : arrêt à froid

La garde de `write_seq` (#163) interdit le rejeu d'une copie d'état authentique plus ancienne **quand les instances sont vivantes**.

**Limite** : Après un **arrêt à froid de toutes les instances**, cette garde en mémoire est perdue. Un attaquant ayant accès en écriture à `STATE_DIR` peut rejouer une copie authentique plus ancienne (avant une révocation de token ou d'agent, par exemple).

**Mitigations** :
- **Permissions strictes** sur `STATE_DIR` : propriétaire = compte de service seul, mode 0700, export NFS restreint aux hôtes candidats
- **Sauvegardes datées** stockées hors de `STATE_DIR` (support distinct, contrôle d'accès différent)
- **Supervision des écritures** dans `STATE_DIR` : auditer toute modification de `relay.state` en dehors du processus serveur
- **Vérification avant redémarrage à froid** : utiliser `secagent-server state verify --min-write-seq` (#187) pour vérifier l'intégrité et l'antériorité d'une copie d'état avant de la restaurer

#### DoS de promotion par `relay.lock` forgé

Un attaquant ayant accès en écriture à `STATE_DIR` peut déposer un `relay.lock` contenant un `write_seq` démesuré (ex. 2^64−1).

**Cas** : Les secondaires mémorisent le maximum `write_seq` observé (`l.minSeq`), et la garde anti-rejeu refuse tout état ayant un `write_seq` inférieur. Un faux `relay.lock` avec une valeur extrême bloque **définitivement toute promotion** (déni de service) tant qu'il existe.

**Modèle de menace** : Identique à la corruption directe de `relay.state` (l'attaquant a déjà accès en écriture à `STATE_DIR`).

**Mitigation** :
- Restrictions d'accès à `STATE_DIR` (permissions OS, ACL NFS)
- En cas de blocage de promotion : identifier le `relay.lock` contenant le `write_seq` incohérent (comparer avec `secagent-server state verify`), le supprimer après vérification, redémarrer les secondaires (qui perdent `l.minSeq` à la réinitialisation)

#### Rotation de `RSA_MASTER_KEY`

`RSA_MASTER_KEY` chiffre au repos tous les secrets de `relay.state` (AES-256-GCM, lié au champ) et dérive la clé HMAC du fichier ; un état ouvert avec une autre clé est **refusé** au démarrage (`authentication failed: wrong RSA_MASTER_KEY or tampered file`). Un simple redémarrage avec une nouvelle clé **ne rechiffre donc rien** : la rotation passe par la commande hors ligne **`secagent-server state rekey`** (`state/rekey.go`, `cli/state_tools.go`).

**Ce que fait la commande** : ouvre l'état avec l'ancienne clé (HMAC vérifié), déchiffre **chaque** champ `enc:` (les secrets de `server_config` : `rsa_key_*`, `jwt_secret_*`, `link_signing_key_*`, et le `token_secret` des relays en mode push), les rechiffre avec la nouvelle clé (nonce neuf, même liaison au champ), recalcule le HMAC, écrit atomiquement avec un `write_seq` + 1, puis **rouvre** le résultat avec la nouvelle clé et compare tous les clairs à l'original ; en cas d'échec l'original est remis en place (code de sortie 10). Une valeur `enc:` trouvée dans un champ que la commande ne sait pas rechiffrer la **refuse** (rien n'est écrit : elle serait devenue illisible).

**Ce qu'elle ne fait pas** : c'est une rotation de la **clé maître** (le secret qui protège l'état au repos), **pas** des secrets eux-mêmes. `JWT_SECRET_KEY`, les secrets JWT, la clé RSA du serveur et les clés de signature des liens **gardent leur valeur** : les jetons déjà émis (agents, jetons de lien) restent valides. Si l'ancienne clé maître a pu être exposée avec une copie de `relay.state`, ces secrets sont à considérer comme exposés : faire en plus `keys rotate-link` (puis `retire-link-previous` selon `DEPLOYMENT.md`) et la rotation des secrets JWT.

**Procédure** (aucune clé en argument de ligne de commande, visible dans `ps`) :
1. Sauvegarder `STATE_DIR` (copie du volume + `secagent-server state verify relay.state`).
2. **Arrêter tous les nœuds** qui partagent `STATE_DIR` (actif **et** passif) : la commande refuse (code 8) si un `relay.lock` est frais et revérifie le verrou juste avant de remplacer le fichier.
3. Fournir la clé actuelle (`RSA_MASTER_KEY` ou `RSA_MASTER_KEY_FILE`) et la nouvelle (`NEW_RSA_MASTER_KEY` ou `NEW_RSA_MASTER_KEY_FILE`, fichier régulier 0600 non-lien ; la variable et son `_FILE` ensemble sont refusés), puis lancer **une seule fois** `secagent-server state rekey --yes` (confirmation `rekey` en interactif) sur le `STATE_DIR`. Elle refuse une nouvelle clé vide ou identique à l'ancienne (une relance est donc inoffensive). Aucune règle de robustesse de la clé n'est imposée par le code : choisir une clé aléatoire d'au moins 32 octets (par exemple `openssl rand -base64 48`).
4. Redéployer la **nouvelle** clé sur **tous** les nœuds candidats, puis les redémarrer. Un nœud qui démarre encore avec l'ancienne clé refuse l'état (fail closed, il ne retombe jamais sur une ancienne copie).
5. Contrôler : `state verify relay.state` avec la nouvelle clé, puis le démarrage et `status --local`.
6. **Détruire** les copies lisibles avec l'ancienne clé : `relay.state.rekey.<UTC>.bak` (écrite avant toute modification, 0600), `relay.state.prev` et les sauvegardes de `STATE_DIR` d'avant la rotation. Tant qu'elles existent, l'ancienne clé les ouvre. Les conserver quelques jours est le seul filet de retour arrière (`state restore --from` avec l'**ancienne** clé, puis redéployer l'ancienne clé).

Journal : `[SECURITY WARNING] master key rekeyed` et une ligne `"source":"rekey"` dans `state-restore.log` (nom de la sauvegarde, `write_seq`, opérateur ; jamais une clé ni une valeur).

#### Fichier de jeton du plugin Ansible : `O_NOFOLLOW` ne protège que le dernier composant

Le plugin de connexion lit son jeton plugin dans un fichier (défaut `/etc/ansible/secagent_plugin.jwt`, `SECAGENT-PYTHON/ansible_plugins/connection_plugins/relay.py`). Il l'ouvre en `O_NOFOLLOW`, vérifie sur le descripteur (`fstat`) que c'est un fichier **régulier** (lien symbolique, FIFO, socket, périphérique refusés), appartenant à l'utilisateur effectif, sans droit pour le groupe ni les autres (`mode & 0o077` refusé, donc `0600` ou `0400`).

**Limite** : `O_NOFOLLOW` ne s'applique qu'au **dernier** composant du chemin. Un lien symbolique placé sur un répertoire parent est suivi. **Mitigation** : protéger le répertoire parent (propriétaire root ou utilisateur Ansible, non modifiable par les autres) et ne jamais placer le fichier dans un répertoire partagé comme `/tmp`.

#### REPEATER_CA_FILE n'est pas rechargé à chaud

Contrairement à `TLS_CERT` / `TLS_KEY` qui sont rechargés à chaud via `GetCertificate`, le bundle CA du relais (`REPEATER_CA_FILE`) est chargé une seule fois au démarrage.

**Rotation de la CA** : Si des certificats internes doivent être mis à jour, l'une des deux actions est nécessaire :
1. **Redémarrage** de l'instance serveur (indisponibilité brève)
2. **Basculement actif/passif** : arrêt propre du maître (le secondaire prend le relais avec la nouvelle CA)

À documenter dans le runbook DEPLOYMENT lors de la rotation de certificats internes.

---

## 12. Matrice des menaces

| Menace | Contremesure |
|---|---|
| Agent non autorisé tente l'enrollment | Enrollment token single-use requis |
| Enrollment token volé | Challenge RSA-OAEP — sans keypair, le challenge échoue |
| Token générique (`.*`) utilisé pour un hostname non prévu | Le hostname de l'agent est loggé — traçabilité complète, token marqué used après 1 seul enrôlement |
| JWT agent volé | Chiffré OAEP — illisible sans la clef privée de l'agent |
| JWT agent compromis | Révocation JTI → close(4001) → agent ne reconnecte plus |
| Plugin token volé, usage externe | IP binding → requête refusée si IP hors CIDR |
| Plugin token volé, usage interne (même NAT) | Hostname binding → friction supplémentaire |
| Accès direct au port admin | Port 7771 non exposé hors container |
| Rotation de clefs JWT | Dual-key grace period → migration sans interruption |
| `become_pass` dans les logs | Masquage systématique côté agent et serveur |
| Homme du milieu | TLS obligatoire sur toutes les connexions (WSS + HTTPS) |
| Confusion d'algorithme sur `/ws/relay` (HS256 avec la clé publique comme secret, `none`, RS256) | Vérificateur EdDSA séparé (`auth.VerifyLinkToken`) : `WithValidMethods(EdDSA)`, aucune route vers le code HMAC |
| Jeton de lien présenté à un autre relay que son destinataire | `aud` = relay local obligatoire ; `iss` = racine ; `sub ≠ aud` |
| Relay parent compromis qui injecte sa propre clé racine | `link_keys` signé par l'**ancienne** clé et chaîne vérifiée depuis l'ancre de chaque relay ; `link_trust` inchangé en cas d'échec |
| Rejeu d'une liste de révocations plus ancienne | `link_revocations.seq` strictement croissant (compteur unique), signature de la clé racine |
| Compromission de `RSA_MASTER_KEY` | **Désormais : forge de tous les jetons de lien** (encadré §5) ; rotation avant la production (`state rekey`, §11 : elle ne change pas les secrets eux-mêmes), puis `keys rotate-link` si la clé a pu fuiter |
| Relay hors ligne pendant `retire-link-previous` | Refus `rotation_unconfirmed` tant que tous les relays connus n'ont pas confirmé ; `--force` journalise un `[SECURITY WARNING]` ; ré-épinglage par `state link-trust reset` (§7), sans perte des agents |
| Relay non racine démarré sans ancre | Refus de tout lien entrant (`4010`) ; une ancre en désaccord avec `link_trust` empêche le démarrage |
| Flood de `topology_snapshot` par reconnexions | Quota **par identité** `relay_id` (40 / 60 s), premier snapshot compté |
| Trame de lien surdimensionnée | Bornes sur les octets bruts avant décodage (1 Mio / 512 o), fermeture `4012` |
| Enfant qui ment sur la suspension d'un agent (#180) | Drapeau purement informatif ; le refus appartient au relay qui détient l'agent |
| Saturation mémoire par `exec` massifs (#179) | Admission avec réservation de 5 Mio/tâche, limites par agent et globale, `503 memory_budget_exhausted` |
