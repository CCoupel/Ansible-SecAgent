# Ansible-SecAgent — Security Design

> Document de référence pour le modèle de sécurité d'Ansible-SecAgent.
> Remplace et étend ARCHITECTURE.md §7.
> Dernière mise à jour : 2026-10-06 (v3.0.3)

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

### Modèle per-relay (v3.0.0)

**En mode repeater (topologie arbre)**, chaque relay a sa propre `JWT_SECRET_KEY` unique :
- Rotation s'applique **indépendamment** par relay (pas de synchronisation globale)
- Tokens relay-child et relay-parent signés par la clé du relay qui les crée
- Chaque relay exécute sa propre rotation de clef sur son CLI (la grace period s'applique localement)
- Les relays enfants gèrent la rotation des tokens relay-parent qu'ils ont émis pour leurs parents (dual-key via leur propre JWT_SECRET_KEY)
- **Hors-scope v3.0.0** : synchronisation des rotations de clef entre relays (envisagée pour v3.0.1+ avec PKI hiérarchique)

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

### Authentification plugin par relay (HAUT-6, v3.0.0)

**Modèle v3.0.0** : Chaque relay signe ses propres plugin tokens (RELAY_PLUGIN_TOKEN)
- Plugin pointe vers **UN relay uniquement** (pas de multi-relays)
- Plugin s'authentifie avec le `RELAY_PLUGIN_TOKEN` du relay
- Relay valide le token avec son JWT_SECRET_KEY (signature HS256)
- **Jamais de partage** de JWT_SECRET_KEY ou RELAY_PLUGIN_TOKEN entre relays

**Isolation** : Un token plugin signé par relay-central ne marche pas sur relay-dmz1
- Chaque relay valide les tokens indépendamment
- Pas de colonne `allowed_relay_ids` — l'isolation se fait par la clé de signature

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

### Tokens relay (HAUT-4, HAUT-5)

**Révocation (HAUT-4, #153)** : Les tokens relay entrent dans la blacklist JTI identique aux agents :
- Persistance à l'émission : `relay_nodes.jti` / `token_exp` (jamais le token) ; réémettre un token pour le même `relay_id` (nouvel `POST /api/admin/relays`) blackliste l'ancien JTI et coupe son lien.
- Révocation : `POST /api/admin/relays/{id}/revoke` ou `secagent-server tokens revoke <id-du-relay>` (admin seulement) : INSERT dans `blacklist(jti)` + drapeau `relay_nodes.revoked` + close **4010** (permanent, le pair s'arrête) de la WS `/ws/relay` active (`ws.CloseRelay`).
- `DELETE /api/admin/relays/{id}` fait de même (blacklist + fermeture du lien ; arrêt du dialer pour un relay push).
- Aucun reconnect possible : le JTI blacklisté et le drapeau `revoked` sont vérifiés à l'upgrade (401, fail closed).
- Relais créés avant #153 (sans JTI) : révocables via le drapeau `revoked` seul (réponse `legacy_token: true`) ; un `DELETE` d'un tel relais (ou d'un relais push) non révoqué est **refusé (409 `relay_not_revoked`)** : révoquer d'abord, sinon l'ancien token pourrait se reconnecter jusqu'à son expiration.
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

### Limites connues — v3.0.3

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

La rotation de la clé maître exige une **réécriture complète de l'état** (tous les secrets rechiffrés, HMAC recalculé), sinon l'ancien fichier est refusé au démarrage.

**Procédure** :
1. Sauvegarder `STATE_DIR` préalablement
2. Arrêter toutes les instances (ou utiliser la bascule actif/passif)
3. Redémarrer les instances avec la nouvelle clé : elles rechiffrent l'état au 1er démarrage
4. Monitorer les erreurs de déchiffrement (clé mal propagée)

Le serveur **ne** redéploiera **jamais** une ancienne clé en cas d'erreur : il s'arrêtera avec un message d'erreur explicite.

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
