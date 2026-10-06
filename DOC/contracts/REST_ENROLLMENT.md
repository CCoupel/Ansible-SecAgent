# Contrat d'interface — REST Enrollment (secagent-minion → secagent-server)

> Protocole d'enrôlement et de refresh JWT pour le secagent-minion.
> Endpoint : HTTPS :7770 (`POST /api/register`, `POST /api/token/refresh`)
> Sources : `DOC/security/SECURITY.md` §3 · `DOC/server/SERVER_SPEC.md` §3 · `DOC/agent/AGENT_SPEC.md` §3

---

## 1. Vue d'ensemble

L'enrollment est un **protocole en 2 étapes** combinant :
- Un **token d'enrollment** (preuve d'autorisation admin ; usage unique par défaut, ou réutilisable)
- Un **challenge RSA-OAEP** (preuve de possession de la clef privée)

```
secagent-minion                          secagent-server
    │                                    │
    │── POST /api/register (étape 1) ──▶ │  vérif token + hostname
    │◀── { challenge, … } ───────────── │  nonce chiffré avec pubkey agent
    │                                    │
    │── POST /api/register (étape 2) ──▶ │  vérif déchiffrement nonce
    │◀── { jwt_encrypted } ──────────── │  JWT chiffré avec pubkey agent
    │                                    │
    │── WSS /ws/agent ────────────────▶ │  connexion opérationnelle
```

---

## 2. Prérequis côté serveur

Avant tout enrollment, l'admin doit avoir créé un token d'enrollment avec :
```bash
secagent-server tokens create --role enrollment \
  --hostname-pattern "vp-db-.*" \
  --expires 24h
```

Le jeton (`secagent_enr_` + 64 caractères hexadécimaux, **opaque, pas un JWT**) est affiché une seule fois ; l'état n'en garde que l'empreinte SHA-256 (plus de table `enrollment_tokens` : le stockage est le fichier d'état). Propriétés :
- `hostname_pattern` — regexp Go ancrée (voir §5), obligatoire (`--hostname-pattern`)
- `expires_at` — `--expires` accepte `30d`, `24h`, `90m` ou `never` ; **le défaut est `never`** (pas d'expiration), il n'y a pas de TTL de 24 h par défaut
- `reusable=0` (usage unique, défaut) ou `reusable=1` (`--reusable`, multi-usage pipeline)

Le même jeton peut aussi être créé par `POST /api/admin/tokens` (`role: "enrollment"`, voir `REST_ADMIN.md` §3). `POST /api/admin/authorize` ne crée **pas** de jeton : il pré-autorise une clef publique (flux historique, §3b).

À **chaque** requête `/api/register` (étapes 1 et 2), le serveur :
1. Cherche le jeton par son empreinte SHA-256 (`token_not_found`)
2. Vérifie l'expiration (`token_expired`) et, pour un jeton à usage unique, qu'il n'a pas déjà servi (`token_already_used`)
3. Valide le hostname reçu contre `hostname_pattern` (regexp ancrée, `hostname_not_allowed` si mismatch)

Chacun de ces refus est un `403 {"error": "<code>"}` (`handlers/register.go` `validateEnrollmentToken`, `registerAgentWithToken`).

---

## 3. Étape 1 — Initiation

### Requête

```http
POST /api/register
Content-Type: application/json
```

```json
{
  "hostname": "host-A",
  "public_key_pem": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkq...\n-----END PUBLIC KEY-----",
  "enrollment_token": "secagent_enr_<64 hex>"
}
```

| Champ | Description |
|---|---|
| `hostname` | Nom d'hôte de l'agent (doit correspondre au `hostname_pattern` du token) |
| `public_key_pem` | Clef publique RSA-4096 de l'agent en format PEM |
| `enrollment_token` | Token créé par `secagent-server tokens create --role enrollment` (ou `POST /api/admin/tokens`) |

Un client qui envoie `pubkey_pem` au lieu de `public_key_pem` est rejeté : seuls les noms ci-dessus sont lus (`handlers/register.go` `RegisterRequest`).

### Réponse 200

```json
{
  "challenge": "<base64(OAEP(nonce_16bytes, agent_pubkey))>",
  "server_public_key_pem": "-----BEGIN PUBLIC KEY-----\n..."
}
```

Le challenge est un nonce de **16 octets** chiffré avec la clef publique de l'agent (RSAES-OAEP SHA-256). Seul l'agent possédant la clef privée correspondante peut le déchiffrer. Le nonce est conservé en mémoire 60 s (`nonceTTL`) : l'étape 2 doit arriver dans ce délai (sinon `403 challenge_expired_or_not_issued`).

### Codes d'erreur

| HTTP | Signification |
|---|---|
| `403` | Jeton invalide (`token_not_found`), expiré (`token_expired`), déjà utilisé (`token_already_used`) ou hostname refusé (`hostname_not_allowed`) |
| `400` | Payload malformé (`invalid_request`), champs manquants (`missing_fields`) ou clef publique illisible (`invalid_public_key`) |
| `500` | Erreur interne (`db_error`, `server_key_not_initialized`…) |

---

## 4. Étape 2 — Vérification

### Requête

```http
POST /api/register
Content-Type: application/json
```

```json
{
  "hostname": "host-A",
  "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...",
  "enrollment_token": "secagent_enr_<64 hex>",
  "challenge_response": "<base64(OAEP(nonce + enrollment_token, server_pubkey))>"
}
```

| Champ | Description |
|---|---|
| `challenge_response` | Nonce déchiffré concaténé au jeton, re-chiffré avec la clef publique du **serveur** (`server_public_key_pem` reçue à l'étape 1) |

Les champs `hostname`, `public_key_pem` et `enrollment_token` sont renvoyés à l'identique : le serveur revalide le jeton à chaque étape. L'agent prouve ainsi qu'il possède la clef privée (il a pu déchiffrer le challenge) ET qu'il connaît le token. Le champ s'appelle `challenge_response` (pas `response`).

### Réponse 200

```json
{
  "token_encrypted": "<base64(OAEP(jwt_string, agent_pubkey))>",
  "jwt_encrypted": "<même valeur>",
  "server_public_key_pem": "-----BEGIN PUBLIC KEY-----\n..."
}
```

`jwt_encrypted` est un alias de `token_encrypted` (même valeur ; le minion lit `jwt_encrypted`). Le JWT est chiffré avec la clef publique de l'agent — illisible sans la clef privée.

### Codes d'erreur

| HTTP | Signification |
|---|---|
| `403` | Jeton invalide (mêmes codes qu'à l'étape 1), `challenge_expired_or_not_issued` (pas de challenge en cours ou délai de 60 s dépassé), `challenge_response_invalid_encoding`, `challenge_response_decryption_failed` ou `challenge_response_mismatch` (nonce ou jeton qui ne correspondent pas) |
| `400` | `invalid_public_key` |
| `500` | `jwt_generation_failed`, `db_error` |

(Un challenge incorrect donne donc un `403`, pas un `400`.)

---

## 4b. Flux historique (clef pré-autorisée)

Sans `enrollment_token` dans la requête, le serveur utilise le flux historique : `POST /api/register {hostname, public_key_pem}` réussit en une étape si la clef a été pré-autorisée par `POST /api/admin/authorize` (`authorized_keys` de l'état). Refus : `403 unauthorized_hostname` (hostname non pré-autorisé) ou `403 public_key_mismatch` (clef différente). Réponse 200 : `token_encrypted` + `server_public_key_pem`.

---

## 5. Hostname Pattern Matching

La validation du hostname utilise une **regexp Go** (pas un glob shell). Le serveur valide le pattern à la **création du token** — si la regexp ne compile pas, l'API retourne HTTP `400 {"error":"invalid_hostname_pattern"}`.

**Ancrage automatique** : Le serveur applique l'ancrage `^(?:pattern)$` lors de l'étape 1 d'enrollment :
```
regexp.MatchString("^(?:" + hostname_pattern + ")$", hostname_from_request)
```
Le groupe non-capturant `(?:...)` prévient les bypasses d'alternation (voir exemples).

**Exemples valides** :
- `vp-db-01` → accepte **exactement** `vp-db-01`
- `vp.*` → accepte `vp-server-01`, `vp-db-02`, mais PAS `notavp` (ancrage : commence par `vp`)
- `web[0-9]+` → accepte `web1`, `web42` (classe `[0-9]+`)
- `.*-prod-.*` → accepte `app-prod-01`, `db-prod-web` (dot-star `.*` = 0+ caractères)
- `web1|db` → accepte **exactement** `web1` ou `db` (pas `web1-evil` ni `xdb` — l'alternation est ancrée)
- `(?i)web1|(?i)db` → case-insensitive pour les deux alternatives

**Erreur classique** :
- `web-*` n'est **pas** un glob shell — c'est une regexp Go cherchant un tiret littéral suivi d'une étoile. Utiliser `web-[0-9]+` ou `web-.*` à la place.

**Sécurité** :
- Un pattern invalide (ex: `[`) est rejeté à la création : `400 invalid_hostname_pattern`.
- Un pattern trop large (ex: `.*`) accepte n'importe quel hostname. Toujours préférer une restriction plus fine.
- L'alternation `web1|db` (enveloppe automatique `^(?:web1|db)$`) accepte exactement "web1" ou "db", pas les prefixes/suffixes.

---

## 6. Format du JWT agent

Une fois déchiffré, le JWT est un token HMAC-HS256 :

```json
{
  "sub": "host-A",
  "role": "agent",
  "jti": "uuid-v4",
  "iat": 1234567890,
  "exp": 1234654290
}
```

| Claim | Description |
|---|---|
| `sub` | Hostname de l'agent |
| `role` | Toujours `agent` pour ce flow |
| `jti` | ID unique du token (pour la blacklist JTI) |
| `iat` | Emission |
| `exp` | Expiration : 1 heure après l'émission (durée fixée dans le code, `handlers/register.go:121`, aucune variable ne la modifie) |

---

## 7. Refresh token

> Le minion Go n'appelle pas cette route (il se ré-enrôle, §8). Elle est servie par le serveur ; son comportement ci-dessous est celui du code (`handlers/register.go` `TokenRefresh`).

### Requête

```http
POST /api/token/refresh
Content-Type: application/json
```

```json
{
  "hostname": "host-A",
  "challenge_encrypted": "<base64(OAEP(challenge, server_pubkey))>"
}
```

Le handler **n'examine pas l'en-tête `Authorization`** : l'unique preuve exigée est un `challenge_encrypted` que le serveur sait déchiffrer avec sa clef privée (il n'est comparé à aucune valeur).

### Réponse 200

```json
{
  "token_encrypted": "<base64(OAEP(nouveau_jwt, agent_pubkey))>",
  "server_public_key_pem": "-----BEGIN PUBLIC KEY-----\n..."
}
```

### Codes d'erreur

| HTTP | Signification |
|---|---|
| `400` | `invalid_request` |
| `403` | `challenge_decryption_failed` (base64 ou déchiffrement) ou `agent_not_found` |
| `500` | `server_key_not_initialized`, `db_error`, `encryption_failed`… |

---

## 8. Comportements agent

| Situation | Action |
|---|---|
| `403` à l'étape 1 ou 2 | **Refus permanent** : pas de retry, le minion s'arrête avec le code de sortie **78** (`RestartPreventExitStatus=77 78` côté systemd). Le jeton est invalide, expiré, déjà consommé (peut-être par une autre adresse de la liste) ou le hostname est refusé |
| Autre échec (réseau, 400, 5xx, coupure après envoi) | Nouveau tour d'enrôlement après un backoff exponentiel (1 s → 60 s), en passant à l'adresse suivante de `RELAY_SERVER_URL` ; le jeton à usage unique n'est jamais rejoué sur une autre adresse une fois la requête partie |
| Pas de `RELAY_ENROLLMENT_TOKEN` et pas de JWT | Erreur de configuration permanente : arrêt avec le code **78** |
| `401` sur `/ws/agent` | Ré-enrollment complet automatique (nécessite `RELAY_ENROLLMENT_TOKEN`) puis reconnexion |
| WS close `4001` | **Arrêt définitif** (code de sortie **77**) — NE PAS ré-enroller sans intervention admin |
| Message WS `rekey` | Le minion déchiffre `token_encrypted` avec sa clef privée, remplace son JWT (fichier + mémoire) et garde la connexion ouverte : pas de ré-enrôlement |

Il n'existe pas de réponse `409` : le serveur ne renvoie pas de conflit de hostname, et aucun code de fermeture WS `4003`/`4004` n'est émis (voir `WEBSOCKET.md` §5).

(`GO/cmd/secagent-minion/main.go` `enrollWithRetry`, `internal/ws/dispatcher.go` `ExitCode`, handler `rekey`.)

---

## 9. Contraintes TLS

- HTTPS obligatoire sur tous les appels enrollment
- Certificat serveur vérifié (ou CA bundle via `RELAY_CA_BUNDLE`)
- `RELAY_INSECURE_TLS=true` **uniquement** en environnement de test
