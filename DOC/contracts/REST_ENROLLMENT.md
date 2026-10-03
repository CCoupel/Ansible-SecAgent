# Contrat d'interface — REST Enrollment (secagent-minion → secagent-server)

> Protocole d'enrôlement et de refresh JWT pour le secagent-minion.
> Endpoint : HTTPS :7770
> Sources : `DOC/security/SECURITY.md` §3 · `DOC/server/SERVER_SPEC.md` §3 · `DOC/agent/AGENT_SPEC.md` §3

---

## 1. Vue d'ensemble

L'enrollment est un **protocole en 2 étapes** combinant :
- Un **token d'enrollment OTP** (preuve d'autorisation admin)
- Un **challenge RSA-OAEP** (preuve de possession de la clef privée)

```
secagent-minion                          secagent-server
    │                                    │
    │── POST /api/register (étape 1) ──▶ │  vérif token OTP + hostname
    │◀── { challenge } ─────────────── │  nonce chiffré avec pubkey agent
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
  --expires-in "24h"
```

Cela insère dans la table `enrollment_tokens` un token OTP avec :
- `hostname_pattern` — regexp Go ancrée `^...$` (ex: `vp-db-.*`, `web[0-9]+`)
- `expires_at` (TTL configurable, défaut 24h)
- `reusable=0` (one-shot) ou `reusable=1` (multi-usage pipeline)

Lors de l'enrollment (étape 1), le serveur :
1. Vérifie que le token existe en DB
2. Valide le hostname reçu contre `hostname_pattern` en utilisant `regexp.MatchString("^" + pattern + "$", hostname)`
3. Accepte ou rejette avec 403 `hostname_not_allowed` si mismatch

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
  "pubkey_pem": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkq...\n-----END PUBLIC KEY-----",
  "enrollment_token": "secagent_enr_xxxxxxxxxxxxx"
}
```

| Champ | Description |
|---|---|
| `hostname` | Nom d'hôte de l'agent (doit correspondre au token) |
| `pubkey_pem` | Clef publique RSA-4096 de l'agent en format PEM |
| `enrollment_token` | Token OTP délivré par `secagent-server minions authorize` |

### Réponse 200

```json
{
  "challenge": "<base64(OAEP(nonce_32bytes, agent_pubkey))>"
}
```

Le challenge est un nonce de 32 octets chiffré avec la clef publique de l'agent (RSAES-OAEP SHA-256). Seul l'agent possédant la clef privée correspondante peut le déchiffrer.

### Codes d'erreur

| HTTP | Signification |
|---|---|
| `403` | Token invalide, expiré ou déjà utilisé |
| `409` | Hostname déjà enregistré avec une autre clef publique |
| `400` | Payload malformé |

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
  "response": "<base64(OAEP(nonce + enrollment_token, server_pubkey))>"
}
```

| Champ | Description |
|---|---|
| `response` | Nonce déchiffré + token, re-chiffrés avec la clef publique du **serveur** |

L'agent prouve ainsi qu'il possède la clef privée (il a pu déchiffrer le challenge) ET qu'il connaît le token.

### Réponse 200

```json
{
  "jwt_encrypted": "<base64(OAEP(jwt_string, agent_pubkey))>"
}
```

Le JWT est chiffré avec la clef publique de l'agent — illisible sans la clef privée.

### Codes d'erreur

| HTTP | Signification |
|---|---|
| `400` | Challenge incorrect (nonce ne correspond pas) |
| `403` | Token invalide ou hostname non autorisé |

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
| `exp` | Expiration (configurable, défaut 24h) |

---

## 7. Refresh token

### Requête

```http
POST /api/token/refresh
Authorization: Bearer <JWT expiré ou proche expiration>
Content-Type: application/json
```

```json
{
  "hostname": "host-A"
}
```

### Réponse 200

```json
{
  "jwt_encrypted": "<base64(OAEP(nouveau_jwt, agent_pubkey))>"
}
```

### Codes d'erreur

| HTTP | Signification |
|---|---|
| `401` | JWT invalide ou JTI blacklisté → ré-enrollment complet requis |
| `403` | Agent suspendu ou révoqué |

---

## 8. Comportements agent

| Situation | Action |
|---|---|
| `403` à l'étape 1 | Log + backoff + retry (token peut avoir expiré) |
| `409` | Log CRITIQUE — hostname conflit, intervention admin requise |
| `401` sur `/ws/agent` | Ré-enrollment complet automatique |
| WS close `4001` | **Arrêt définitif** — NE PAS ré-enroller sans intervention admin |
| WS close `4003` | Ré-enrollment complet automatique |
| Message `rekey` | Ré-enrollment avec nouveau token (via admin ou refresh) |

---

## 9. Contraintes TLS

- HTTPS obligatoire sur tous les appels enrollment
- Certificat serveur vérifié (ou CA bundle via `RELAY_CA_BUNDLE`)
- `RELAY_INSECURE_TLS=true` **uniquement** en environnement de test
