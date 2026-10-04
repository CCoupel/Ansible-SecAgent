# Ansible-SecAgent — Security Design

> Document de référence pour le modèle de sécurité d'Ansible-SecAgent.
> Remplace et étend ARCHITECTURE.md §7.
> Dernière mise à jour : 2026-03-06

---

## 1. Modèle de confiance

```
Zero-Trust sur le transport  : TLS obligatoire sur toutes les connexions (WSS + HTTPS)
Zero-Trust sur les identités : chaque composant prouve son identité à chaque connexion
Pas de TOFU                  : aucun composant n'est accepté sans pré-autorisation explicite
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
| `relay-child` | repeater-enfant (présenté au handshake) | `WSS /ws/relay` (relay_hello, agent_list, event_forward, task_forward) | JWT HMAC-HS256 (créé et signé par le relay parent avec sa JWT_SECRET_KEY) |
| `relay-parent` | repeater-parent en mode push (présenté au handshake) | `WSS /ws/relay` (ouvrir connexion vers enfant) | JWT HMAC-HS256 (créé et signé par le relay enfant avec sa JWT_SECRET_KEY) |
| `admin` | CLI dans le container serveur | Port 7771 — tous les endpoints d'administration | `ADMIN_TOKEN` env var (container-interne) |

### Règles d'isolation des rôles

- Un token `role: agent` ne peut **pas** appeler `/api/exec` ni `/api/inventory` ni ouvrir `/ws/relay`
- Un token `role: plugin` ne peut **pas** ouvrir `/ws/agent` ni `/ws/relay`
- Un token `role: relay-child` ne peut **pas** accéder `/api/inventory`, `/api/exec`, `/api/upload`, `/api/fetch`, ni `/ws/agent` (repeater-to-repeater uniquement)
- Un token `role: relay-parent` ne peut **pas** accéder `/api/inventory`, `/api/exec`, `/api/upload`, `/api/fetch`, ni `/ws/agent` (repeater-to-repeater uniquement)
- Le port 7771 (admin) n'est **jamais** exposé hors du container (`expose:` uniquement, pas `ports:`)
- L'admin CLI s'authentifie via `localhost:7771` en lisant `ADMIN_TOKEN` depuis l'environnement du container


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

### Table DB

```sql
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
4. regexp.MatchString("^" + hostname_pattern + "$", hostname) ?  → sinon 403 hostname_not_allowed
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
| `4001` | JWT blacklisté / révocation admin | **Arrêt définitif** — ne jamais reconnecter |
| `4002` | JWT expiré | Ré-enrollment automatique (POST /api/register) |
| `4003` | Re-enrollment requis (rotation de clefs) | Ré-enrollment automatique |
| `1001` | Restart serveur / coupure réseau | Reconnexion avec backoff exponentiel (1s→2s→4s→…→60s max) |

#### Codes de fermeture WebSocket `/ws/relay` (#148)

| Code | Nature | Signification | Comportement du pair qui reçoit le close |
|---|---|---|---|
| `4010` | **Refus permanent** | Identité non autorisée pour ce lien : token révoqué, `relay_id` ≠ `jwt.sub`, identité du pair différente de celle attendue, boucle détectée (C ∈ {P} ∪ ancêtres(P)) | **Ne pas reconnecter** : le client/dialer s'arrête (état terminal, log ERROR) ; une action opérateur est nécessaire |
| `4011` | Token expiré | Token relay expiré (TTL dépassé) | Rafraîchir le token puis reconnecter |
| `4012` | **Refus corrigible** | Erreur protocolaire ou de validation pouvant se résoudre : `topology_snapshot` invalide / déjà reçu / reçu avant `relay_hello`, conflit de routage ou de relay déclaré, slot « parent unique » occupé | Reconnexion avec backoff exponentiel (5 s → 60 s max) |
| `4000` | Normal | Fermeture normale ou initiée par le client | — |
| `1000` | Normal | Fermeture WebSocket standard | — |

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
Il déclenche automatiquement un ré-enrollment (close(4003) ou 401 sur /api/register).

### Stockage des secrets

Tous les secrets du serveur sont stockés en DB chiffrés (AES-256-GCM) :

| Secret | Table | Protection |
|---|---|---|
| `jwt_secret_current` | `server_config` | AES-256-GCM, clef dérivée de `RSA_MASTER_KEY` |
| `jwt_secret_previous` | `server_config` | idem |
| RSA keypair serveur | `server_config` | idem |
| `key_rotation_deadline` | `server_config` | idem |

### Modèle per-relay (v3.0)

**En mode repeater (topologie arbre)**, chaque relay a sa propre `JWT_SECRET_KEY` unique :
- Rotation s'applique **indépendamment** par relay (pas de synchronisation globale)
- Tokens relay-child et relay-parent signés par la clé du relay qui les crée
- Chaque relay exécute sa propre rotation de clef sur son CLI (la grace period s'applique localement)
- Les relays enfants gèrent la rotation des tokens relay-parent qu'ils ont émis pour leurs parents (dual-key via leur propre JWT_SECRET_KEY)
- **Hors-scope v3.0** : synchronisation des rotations de clef entre relays (envisagée pour v3.1+ avec PKI hiérarchique)

---

## 6. Authentification du plugin Ansible

### Modèle de confiance

Le plugin (inventory + connection) tourne sur l'**Ansible Control Node**, une machine
administrée et de confiance. Il n'a pas de keypair RSA — il utilise un token statique
émis par l'admin et hashé en DB.

### Table DB

```sql
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
  1. SHA-256(token) → lookup dans plugin_tokens
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

### Authentification plugin par relay (HAUT-6, v3.0)

**Modèle v3.0** : Chaque relay signe ses propres plugin tokens (RELAY_PLUGIN_TOKEN)
- Plugin pointe vers **UN relay uniquement** (pas de multi-relays)
- Plugin s'authentifie avec le `RELAY_PLUGIN_TOKEN` du relay
- Relay valide le token avec son JWT_SECRET_KEY (signature HS256)
- **Jamais de partage** de JWT_SECRET_KEY ou RELAY_PLUGIN_TOKEN entre relays

**Isolation** : Un token plugin signé par relay-central ne marche pas sur relay-dmz1
- Chaque relay valide les tokens indépendamment
- Pas de colonne `allowed_relay_ids` — l'isolation se fait par la clé de signature

**Évolution envisagée (v3.1+)** : Centraliser la signature des tokens à la racine
- Permettre au plugin de parler à plusieurs relays avec un seul token
- Nécessite une PKI hiérarchique (racine → intermédiaires → feuilles)
- Hors scope MVP (v3.0)

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

### Tokens relay (HAUT-4, HAUT-5)

**Révocation (HAUT-4, #153)** : Les tokens relay entrent dans la blacklist JTI identique aux agents :
- Persistance à l'émission : `relay_nodes.jti` / `token_exp` (jamais le token) ; réémettre un token pour le même `relay_id` (nouvel `POST /api/admin/relays`) blackliste l'ancien JTI et coupe son lien.
- Révocation : `POST /api/admin/relays/{id}/revoke` ou `secagent-server tokens revoke <id-du-relay>` (admin seulement) : INSERT dans `blacklist(jti)` + drapeau `relay_nodes.revoked` + close **4010** (permanent, le pair s'arrête) de la WS `/ws/relay` active (`ws.CloseRelay`).
- `DELETE /api/admin/relays/{id}` fait de même (blacklist + fermeture du lien ; arrêt du dialer pour un relay push).
- Aucun reconnect possible : le JTI blacklisté et le drapeau `revoked` sont vérifiés à l'upgrade (401, fail closed).
- Relais créés avant #153 (sans JTI) : révocables via le drapeau `revoked` seul (réponse `legacy_token: true`) ; un `DELETE` d'un tel relais ne peut pas blacklister de JTI inconnu → révoquer **avant** de supprimer.
- Tokens `relay-parent` (#150) : `tokens revoke <id>` blackliste le JTI et ferme le lien parent actif.

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

## 10. Matrice des menaces

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
