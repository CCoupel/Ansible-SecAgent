# Contrat d'interface — REST Admin (CLI → secagent-server)

> Interface d'administration entre le CLI cobra et le secagent-server.
> Endpoint : HTTP :7771 — **container-interne uniquement**, jamais exposé externalement.
> Sources : `DOC/server/SERVER_SPEC.md` §7 · `DOC/server/MANAGEMENT_CLI_SPECS.md` · `DOC/security/SECURITY.md` §8

---

## 1. Accès et authentification

```
Port    : 7771 (expose: seulement dans docker-compose, jamais ports:)
Auth    : Authorization: Bearer <ADMIN_TOKEN>
Accès   : docker exec relay-api secagent-server <commande>
```

Le CLI lit `ADMIN_TOKEN` depuis les variables d'environnement du container et appelle `http://localhost:7771/api/admin/*`.

**Ce port ne doit jamais être exposé hors du container.**

---

## 2. Minions

### `GET /api/admin/minions` — Liste des agents

```http
GET /api/admin/minions?format=json
Authorization: Bearer <ADMIN_TOKEN>
```

**Réponse 200 :**
```json
[
  {
    "hostname": "host-A",
    "status": "connected",
    "pubkey_pem": "-----BEGIN PUBLIC KEY-----\n...",
    "enrolled_at": "2026-03-01T10:00:00Z",
    "last_seen_at": "2026-03-06T10:00:00Z"
  }
]
```

---

### `GET /api/admin/minions/{hostname}` — Détail d'un agent

**Réponse 200 :** même structure qu'un élément de la liste.

**Codes d'erreur :**

| HTTP | Signification |
|---|---|
| `404` | Hostname non enregistré |

---

### `POST /api/admin/minions/{hostname}/authorize` — Créer un token d'enrollment

Génère un token OTP single-use pour permettre l'enrollment d'un agent.

```http
POST /api/admin/minions/{hostname}/authorize
Authorization: Bearer <ADMIN_TOKEN>
Content-Type: application/json
```

```json
{
  "expires_in": "24h"
}
```

**Réponse 200 :**
```json
{
  "enrollment_token": "secagent_enr_xxxxxxxxxxxxx",
  "hostname": "host-A",
  "expires_at": "2026-03-07T10:00:00Z"
}
```

---

### `POST /api/admin/minions/{hostname}/revoke` — Révoquer un agent

Blackliste le JTI du JWT actif et ferme la connexion WS avec le code `4001`.

```http
POST /api/admin/minions/{hostname}/revoke
Authorization: Bearer <ADMIN_TOKEN>
```

**Réponse 200 :**
```json
{ "status": "revoked", "hostname": "host-A" }
```

L'agent reçoit `close(4001)` et s'arrête définitivement (pas de reconnexion).

---

### `POST /api/admin/minions/{hostname}/suspend` — Suspendre

Ferme la WS avec `4001` mais conserve l'agent en DB. L'agent ne peut pas reconnecter tant qu'il est suspendu.

---

### `POST /api/admin/minions/{hostname}/resume` — Reprendre

Retire la suspension, l'agent peut se ré-enroller.

---

### `GET /api/admin/minions/{hostname}/vars` — Variables hôte

```http
GET /api/admin/minions/{hostname}/vars
Authorization: Bearer <ADMIN_TOKEN>
```

**Réponse 200 :**
```json
{
  "ansible_user": "deploy",
  "ansible_become": true
}
```

---

### `PUT /api/admin/minions/{hostname}/vars/{key}` — Définir une variable

```http
PUT /api/admin/minions/{hostname}/vars/{key}
Authorization: Bearer <ADMIN_TOKEN>
Content-Type: application/json
```

```json
{ "value": "deploy" }
```

---

### `DELETE /api/admin/minions/{hostname}/vars/{key}` — Supprimer une variable

---

## 3. Tokens plugin

### `GET /api/admin/tokens` — Liste des tokens

```http
GET /api/admin/tokens?role=plugin
Authorization: Bearer <ADMIN_TOKEN>
```

**Paramètres :**
- `role` : `plugin` | `enrollment` | `all` (défaut: `all`)

**Réponse 200 :**
```json
[
  {
    "id": "tok-uuid",
    "description": "ansible-control-prod",
    "role": "plugin",
    "allowed_ips": "192.168.1.10/32",
    "allowed_hostname": "ansible-control-prod",
    "created_at": "2026-03-01T10:00:00Z",
    "expires_at": null,
    "last_used_at": "2026-03-06T10:00:00Z",
    "last_used_ip": "192.168.1.10",
    "revoked": false
  }
]
```

---

### `POST /api/admin/tokens` — Créer un token plugin

```http
POST /api/admin/tokens
Authorization: Bearer <ADMIN_TOKEN>
Content-Type: application/json
```

```json
{
  "description": "ansible-control-prod",
  "role": "plugin",
  "allowed_ips": "192.168.1.10/32",
  "allowed_hostname": "ansible-control-prod",
  "expires_in": "365d"
}
```

**Réponse 201 :**
```json
{
  "id": "tok-uuid",
  "token": "secagent_plugin_xxxxxxxxxxxxx"
}
```

Le token en clair n'est retourné **qu'une seule fois** à la création. Ensuite, seul le hash est stocké.

---

### `POST /api/admin/tokens/{id}/revoke` — Révoquer un token

**Réponse 200 :** `{ "status": "revoked" }`

---

### `DELETE /api/admin/tokens/{id}` — Supprimer un token

---

### `POST /api/admin/tokens/purge` — Purger les tokens expirés

---

## 4. Sécurité — rotation des clefs JWT

### `GET /api/admin/security/keys/status` — État des clefs

**Réponse 200 :**
```json
{
  "current_key_id": "key-2026-03-06",
  "previous_key_id": "key-2026-02-01",
  "rotation_deadline": "2026-03-07T10:00:00Z",
  "grace_period_active": true
}
```

---

### `POST /api/admin/security/keys/rotate` — Déclencher une rotation

```http
POST /api/admin/security/keys/rotate
Authorization: Bearer <ADMIN_TOKEN>
Content-Type: application/json
```

```json
{
  "grace_period": "24h"
}
```

**Réponse 200 :**
```json
{
  "new_key_id": "key-2026-03-07",
  "rotation_deadline": "2026-03-08T10:00:00Z",
  "agents_notified": 42
}
```

Pendant `grace_period`, les deux clefs (`jwt_secret_current` + `jwt_secret_previous`) sont valides.
Après `rotation_deadline`, `jwt_secret_previous` est invalidé et les JTIs pré-rotation sont blacklistés.

Les agents connectés reçoivent un message WS `{type: "rekey"}` et ré-enrollment automatiquement.

---

### `GET /api/admin/security/blacklist` — Consulter la blacklist JTI

**Réponse 200 :**
```json
[
  {
    "jti": "uuid-v4",
    "hostname": "host-A",
    "revoked_at": "2026-03-06T10:00:00Z",
    "reason": "manual_revoke",
    "expires_at": "2026-03-07T10:00:00Z"
  }
]
```

---

### `POST /api/admin/security/blacklist/purge` — Purger les JTIs expirés

---

## 5. Inventaire

### `GET /api/admin/inventory` — Inventaire complet

```http
GET /api/admin/inventory?only_connected=false
Authorization: Bearer <ADMIN_TOKEN>
```

Format de réponse identique à `GET /api/inventory` (voir `DOC/contracts/REST_PLUGIN.md` §2).

---

## 6. Statut serveur

### `GET /api/admin/server/status`

**Réponse 200 :**
```json
{
  "status": "healthy",
  "uptime_seconds": 86400,
  "connected_agents": 3,
  "nats_connected": true,
  "db_ok": true,
  "version": "1.1.0"
}
```

---

### `GET /api/admin/server/stats`

**Réponse 200 :**
```json
{
  "tasks_processed_total": 14250,
  "tasks_in_progress": 2,
  "tasks_failed_total": 12,
  "agents_registered": 15,
  "agents_connected": 3,
  "tokens_active": 4
}
```

---

## 7. Codes d'erreur communs

| HTTP | Signification |
|---|---|
| `401` | ADMIN_TOKEN absent ou invalide |
| `404` | Ressource introuvable |
| `409` | Conflit (ex: hostname déjà existant) |
| `500` | Erreur interne |
