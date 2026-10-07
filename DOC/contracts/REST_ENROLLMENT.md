# Contrat d'interface — REST Enrollment (secagent-minion → secagent-server)

> Protocole d'enrôlement et de renouvellement du JWT pour le secagent-minion.
> Endpoint : HTTPS :7770 (`POST /api/register`). `POST /api/token/refresh` a été **supprimée en v3.0.3** (voir §7).
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

Le même jeton peut aussi être créé par `POST /api/admin/tokens` (`role: "enrollment"`, voir `REST_ADMIN.md` §3). `POST /api/admin/authorize` ne crée **pas** de jeton et ne donne **aucun droit d'enrôlement** : il se contente de mémoriser une clef publique dans les `authorized_keys` de l'état, que `/api/register` ne consulte plus (§4b).

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
| `403` | Jeton invalide (`token_not_found`), expiré (`token_expired`), déjà utilisé (`token_already_used`), hostname refusé (`hostname_not_allowed`) ou **hostname révoqué (`agent_revoked`)** |
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
| `403` | Jeton invalide ou hostname révoqué (mêmes codes qu'à l'étape 1, dont `agent_revoked`), `challenge_expired_or_not_issued` (pas de challenge en cours ou délai de 60 s dépassé), `challenge_response_invalid_encoding`, `challenge_response_decryption_failed` ou `challenge_response_mismatch` (nonce ou jeton qui ne correspondent pas) |
| `400` | `invalid_public_key` |
| `500` | `jwt_generation_failed`, `db_error` |

(Un challenge incorrect donne donc un `403`, pas un `400`.)

---

## 4a. Hostname révoqué : `403 agent_revoked`

Un hôte révoqué (`POST /api/admin/revoke/{hostname}`) porte un **drapeau persistant** `revoked` dans l'état. Tant que cette révocation n'est pas levée, `POST /api/register` répond `403 {"error":"agent_revoked"}` **quel que soit le jeton** (y compris un jeton réutilisable ou à `hostname_pattern` large) : à l'étape 1 avant tout challenge, et à l'étape 2 (le refus est pris dans la transaction d'enrôlement). Le jeton n'est **pas consommé** et aucun JWT/JTI n'est émis. Le drapeau survit à l'expiration de l'entrée de blacklist (25 h). La révocation se lève explicitement par `DELETE /api/admin/minions/{hostname}` (`REST_ADMIN.md`) ; l'hôte peut ensuite s'enrôler avec un jeton. Les autres hostnames ne sont pas affectés (`handlers/register.go:495-505,577-580`, `storage/store.go:260-270,522-554`).

## 4b. Requête sans jeton d'enrôlement : refusée

Depuis la v3.0.3 (#192), `POST /api/register` **sans** `enrollment_token` répond **toujours** :

```http
HTTP/1.1 403 Forbidden
{"error": "enrollment_token_required"}
```

La réponse est identique quels que soient le hostname et la clef (aucun oracle) ; aucun JWT n'est émis, aucun JTI n'est posé, aucun agent n'est créé, et un `[SECURITY WARNING]` est journalisé côté serveur (`handlers/register.go:463-475`). L'ancien flux « clef pré-autorisée en une étape » (réponses `unauthorized_hostname` / `public_key_mismatch`) n'existe plus : il émettait un JWT sans preuve de possession de la clef privée et sans consulter la révocation (voir l'avis de sécurité dans `DOC/security/SECURITY.md` §11). Tout enrôlement passe par un jeton d'enrôlement **et** le challenge du §3-§4. `authorized_keys` n'est plus lue par `/api/register`.

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

## 7. Renouvellement du JWT

La route `POST /api/token/refresh` a été **supprimée en v3.0.3** (#192) : elle répond `404` à tout appelant (agent révoqué compris). Elle n'avait aucun client (le minion Go ne l'a jamais appelée) et, dans les versions antérieures, elle émettait un JWT sans authentifier l'appelant (contournement de la révocation, remplacement du JTI d'un agent : voir `DOC/security/SECURITY.md` §11).

Le JWT se renouvelle par deux chemins seulement :
- **ré-enrôlement complet** (§3-§4, avec le jeton d'enrôlement) quand le serveur répond `401` à l'upgrade WebSocket ;
- **message WebSocket `rekey`** lors d'une rotation de clefs : le serveur envoie le nouveau JWT chiffré avec la clef publique de l'agent, sur une connexion déjà authentifiée (voir `WEBSOCKET.md`).

-----BEGIN PUBLIC KEY-----\n..."
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
| `403 agent_revoked` à l'enrôlement | Même traitement que tout `403` : refus permanent, sortie code **78** ; l'opérateur doit lever la révocation (`DELETE`) puis créer un jeton |
| Message WS `rekey` | Le minion déchiffre `token_encrypted` avec sa clef privée, remplace son JWT (fichier + mémoire) et garde la connexion ouverte : pas de ré-enrôlement |

Il n'existe pas de réponse `409` : le serveur ne renvoie pas de conflit de hostname, et aucun code de fermeture WS `4003`/`4004` n'est émis (voir `WEBSOCKET.md` §5).

(`GO/cmd/secagent-minion/main.go` `enrollWithRetry`, `internal/ws/dispatcher.go` `ExitCode`, handler `rekey`.)

---

## 9. Contraintes TLS

- HTTPS obligatoire sur tous les appels enrollment
- Certificat serveur vérifié (ou CA bundle via `RELAY_CA_BUNDLE`)
- `RELAY_INSECURE_TLS=true` **uniquement** en environnement de test
