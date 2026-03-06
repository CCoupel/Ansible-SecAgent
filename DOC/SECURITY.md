# AnsibleRelay — Security Design

> Document de référence pour le modèle de sécurité d'AnsibleRelay.
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
| relay-agent | Hôte non fiable | Déployé derrière NAT/DMZ/firewall |

---

## 2. Rôles et périmètres

| Rôle | Porteur | Endpoints autorisés | Mécanisme d'auth |
|---|---|---|---|
| `agent` | relay-agent (hôte cible) | `POST /api/register`, `WSS /ws/agent` | JWT HMAC-HS256 chiffré RSA-OAEP |
| `plugin` | Ansible Control Node | `GET /api/inventory`, `POST /api/exec`, `/api/upload`, `/api/fetch` | Token statique hashé (SHA-256) |
| `admin` | CLI dans le container serveur | Port 7771 — tous les endpoints d'administration | `ADMIN_TOKEN` env var (container-interne) |

### Règles d'isolation des rôles

- Un token `role: agent` ne peut **pas** appeler `/api/exec` ni `/api/inventory`
- Un token `role: plugin` ne peut **pas** ouvrir une connexion WebSocket agent
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
  │ token: "relay_enr_..." │                              │  ← montré une seule fois
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
  │                        │  hostname correspond]        │
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
| Autorisation | Enrollment token — single-use, TTL configurable, lié à un hostname |
| Preuve de possession | Challenge RSA-OAEP — seul l'agent avec la clef privée peut répondre |
| Confidentialité du JWT | JWT chiffré OAEP — illisible sans la clef privée de l'agent |
| Non-rejouabilité | Token single-use + nonce aléatoire |

### Ce que ça bloque

- **Token volé sans keypair** : le challenge OAEP échoue (pas de clef privée pour déchiffrer)
- **Keypair inconnue sans token** : validation du token échoue (pas d'autorisation)
- **Replay du challenge** : nonce à usage unique, token marqué `used` après enrollment

### Table DB

```sql
CREATE TABLE enrollment_tokens (
    id          TEXT PRIMARY KEY,        -- UUID
    token_hash  TEXT NOT NULL UNIQUE,    -- SHA-256(token) — jamais en clair
    hostname    TEXT NOT NULL,           -- hostname autorisé
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,        -- TTL obligatoire
    used        INTEGER DEFAULT 0,       -- 0 = disponible, 1 = consommé
    used_at     INTEGER,
    created_by  TEXT                     -- "admin-cli", "terraform", etc.
);
```

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

---

## 6. Authentification du plugin Ansible

### Modèle de confiance

Le plugin (inventory + connection) tourne sur l'**Ansible Control Node**, une machine
administrée et de confiance. Il n'a pas de keypair RSA — il utilise un token statique
émis par l'admin et hashé en DB.

### Table DB

```sql
CREATE TABLE plugin_tokens (
    id            TEXT PRIMARY KEY,    -- UUID (identifiant public, affiché en CLI)
    token_hash    TEXT NOT NULL UNIQUE,-- SHA-256(token) — jamais le token en clair
    description   TEXT,               -- "ansible-control-prod"
    role          TEXT NOT NULL,       -- "plugin" uniquement
    allowed_ips   TEXT,               -- CIDRs autorisés : "192.168.1.10/32,10.0.0.0/8"
                                      -- NULL = pas de restriction IP
    allowed_hostname TEXT,            -- hostname déclaré autorisé : "ansible-control-prod"
                                      -- NULL = pas de restriction hostname
    created_at    INTEGER NOT NULL,
    expires_at    INTEGER,            -- NULL = pas d'expiry
    last_used_at  INTEGER,            -- horodatage dernière utilisation (audit)
    last_used_ip  TEXT,               -- IP de dernière utilisation (audit)
    revoked       INTEGER DEFAULT 0
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
  4. allowed_ips IS NOT NULL → r.RemoteAddr ∈ CIDRs ?
  5. allowed_hostname IS NOT NULL → header X-Relay-Client-Host == allowed_hostname ?
  6. UPDATE last_used_at, last_used_ip
  7. OK → traiter la requête
```

### Niveaux de contrainte

| Configuration | Usage recommandé |
|---|---|
| `allowed_ips=192.168.1.10/32, allowed_hostname=NULL` | Control node avec IP fixe |
| `allowed_ips=NULL, allowed_hostname=ansible-control` | Control node derrière NAT fixe |
| `allowed_ips=10.0.0.0/8, allowed_hostname=ansible-01` | Control node derrière NAT, subnet connu |
| `allowed_ips=NULL, allowed_hostname=NULL` | Environnement de dev/test uniquement |

### Limite du hostname binding

Le hostname est une **auto-déclaration** du client (header HTTP) — il n'est pas
cryptographiquement prouvé. Il constitue une défense en profondeur contre un attaquant
interne au même réseau, pas une garantie cryptographique.

Pour une preuve cryptographique du hostname : utiliser mTLS (PKI interne, hors scope MVP).

---

## 7. Gestion des tokens (CLI)

### Création (token montré une seule fois)

```bash
# Token plugin avec restrictions
relay-server tokens create \
  --role plugin \
  --description "ansible-control-prod" \
  --allowed-ips "192.168.1.10/32" \
  --allowed-hostname "ansible-control-prod" \
  --expires 365d

# Token d'enrollment pour un agent
relay-server tokens create \
  --role enrollment \
  --hostname my-host \
  --expires 24h

# Token plugin sans restriction (dev/test)
relay-server tokens create --role plugin --description "dev"
```

Sortie :
```
Token créé : relay_plugin_aB3xK9...   ← affiché UNE SEULE FOIS, stocker immédiatement
ID         : 550e8400-e29b-41d4-a716-446655440000
Rôle       : plugin
Expires    : 2027-03-06T00:00:00Z
IP         : 192.168.1.10/32
Hostname   : ansible-control-prod
```

### Listage

```bash
relay-server tokens list [--role plugin|enrollment|all]

ID          RÔLE        DESCRIPTION            IPs              HOSTNAME            EXPIRES     LAST USED
550e84...   plugin      ansible-control-prod   192.168.1.10/32  ansible-control-prod 2027-03-06  2026-03-05 14:32
a1b2c3...   enrollment  my-host                -                -                   2026-03-07  jamais
```

### Révocation et suppression

```bash
# Révocation (marque revoked=1, garde la trace)
relay-server tokens revoke <id>

# Suppression définitive (purge)
relay-server tokens delete <id>

# Purge des tokens expirés
relay-server tokens purge --expired
```

---

## 8. Isolation des ports

| Port | Exposition | Accès | Contenu |
|---|---|---|---|
| `7770` | Publique (HTTPS via Caddy) | Agents + Plugins | `/api/register`, `/api/exec`, `/api/inventory`, `/ws/agent` |
| `7771` | **Container-interne uniquement** (`expose:`, pas `ports:`) | CLI admin | Tous les endpoints `/api/admin/*` |
| `7772` | Publique (WSS via Caddy) | Agents | `/ws/agent` |

Le port 7771 ne doit **jamais** figurer dans la section `ports:` du docker-compose.
L'accès admin se fait exclusivement via `docker exec relay-api relay-server <cmd>`.

---

## 9. Sécurité des logs

| Donnée | Règle |
|---|---|
| `become_pass` | Masqué dans tous les logs (agent + serveur) — remplacé par `[REDACTED]` |
| Token en clair | Jamais loggé — seul le hash SHA-256 ou l'UUID apparaît |
| JWT en clair | Jamais loggé — seul le JTI apparaît |
| Clef privée agent | Jamais transmise, jamais loggée |
| `stdin` avec become | Masqué dans les logs de l'agent |

---

## 10. Matrice des menaces

| Menace | Contremesure |
|---|---|
| Agent non autorisé tente l'enrollment | Enrollment token single-use requis |
| Enrollment token volé | Challenge RSA-OAEP — sans keypair, le challenge échoue |
| JWT agent volé | Chiffré OAEP — illisible sans la clef privée de l'agent |
| JWT agent compromis | Révocation JTI → close(4001) → agent ne reconnecte plus |
| Plugin token volé, usage externe | IP binding → requête refusée si IP hors CIDR |
| Plugin token volé, usage interne (même NAT) | Hostname binding → friction supplémentaire |
| Accès direct au port admin | Port 7771 non exposé hors container |
| Rotation de clefs JWT | Dual-key grace period → migration sans interruption |
| `become_pass` dans les logs | Masquage systématique côté agent et serveur |
| Homme du milieu | TLS obligatoire sur toutes les connexions (WSS + HTTPS) |
