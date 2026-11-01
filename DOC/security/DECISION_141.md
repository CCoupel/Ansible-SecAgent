# Décision de sécurité — #141 : Signature des jetons de lien relay (hybride Ed25519)

| Champ | Valeur |
|---|---|
| **Statut** | **Validé par l'utilisateur le 2026-10-07** |
| **Milestone** | v3.0.4 |
| **Issues** | #141 (signature jetons inter-relay), #146 (renommage relay-child, absorbé dans L1) |
| **Auteur** | security-reviewer |
| **Revue code** | `main` bb39463 + commits L1b/L1c (`milestone/v3.0.4`) |

---

## 1. Périmètre

### Ce qui est signé par la racine (Ed25519 / EdDSA)

**Uniquement les jetons de lien relay** :

- `relay-child` : présenté par l'enfant X au parent P en mode pull.
- `relay-parent` : présenté par le parent P à l'enfant X en mode push.

### Ce qui n'est pas concerné

| Jeton | Mécanisme | Changement en v3.0.4 |
|---|---|---|
| `agent` | HS256, `JWT_SECRET_KEY` par relay | Aucun |
| `plugin` | Opaque SHA-256 | Aucun |
| `enrollment` | Opaque | Aucun |
| `admin` | `ADMIN_TOKEN` env | Aucun |

**Les 3 000+ agents ne sont pas affectés** : leurs jetons ne changent pas, leurs connexions ne sont pas coupées par la montée de version.

---

## 2. Format du jeton de lien

| Champ | `relay-child` (pull, X→P) | `relay-parent` (push, P→X) |
|---|---|---|
| `alg` | `EdDSA` (seul accepté) | `EdDSA` |
| `kid` | Empreinte SHA-256 tronquée (base64url) de la clé publique racine | idem |
| `iss` | `relay_id` de la racine | idem |
| `sub` | X (émetteur) | P (émetteur) |
| `aud` | P (vérificateur) | X (vérificateur) |
| `role` | `relay-child` | `relay-parent` |
| `jti`, `iat`, `exp` | Obligatoires ; TTL 720 h par défaut, configurable | idem |

**Gain vs HS256** : `aud` lie le jeton à **un seul** vérificateur. Un jeton HS256 `relay` était valide auprès de tout relay partageant le même `JWT_SECRET_KEY` ; ce n'est plus possible.

---

## 3. Architecture de confiance

### Clé privée de signature (racine)

- Stockée dans `server_config` sous les clés `link_signing_key_current` et `link_signing_key_previous`.
- Ces clés sont dans `secretConfigKeys` → chiffrement AES-256-GCM obligatoire sous `RSA_MASTER_KEY`, AAD = nom du champ.
- Partagée entre actif et passif via `STATE_DIR` (même clé, pas de synchronisation réseau).
- **Génération paresseuse** au premier mint sur un nœud **sans** `REPEATER_UPSTREAM_URL` (nœud racine).
- **Fail closed** : sans `RSA_MASTER_KEY`, mint refusé (503).

### Ancre de confiance (relays non racine)

- `REPEATER_ROOT_LINK_KEY_FILE` : chemin vers la clé publique racine en PEM, exportée par `keys link-pubkey`.
- Persistée dans la section `link_trust` de l'état (SchemaVersion 2).
- **Fail closed** : un relay sans ancre refuse tout lien entrant `/ws/relay` (4010).

### Vérificateur EdDSA séparé (`auth/linkjwt.go`)

Le chemin de vérification HS256 (`auth/jwt.go`, `validateJWTDualKey`) n'est **jamais** appelé sur `/ws/relay` en v3.0.4. Protection structurelle contre la confusion d'algorithme : un jeton HS256 avec la clé publique comme secret HMAC n'a aucun chemin de vérification.

---

## 4. Rotation de la clé racine

```
keys rotate-link  →  current → previous, nouvelle current générée
```

Le message `link_keys` (signé par l'**ancienne** clé `current`) est poussé vers les enfants :
```
{ current_pub, current_kid, previous_pub, previous_kid, seq, sig }
```

Chaque relay vérifie `sig` depuis son ancre avant de mettre à jour `link_trust`. Un parent intermédiaire compromis ne peut pas injecter sa propre clé.

**Double acceptation** : jetons signés par `current` ou `previous` valides jusqu'à `keys retire-link-previous`.

⚠️ **Appeler `retire-link-previous` seulement après** avoir vérifié via `relays status` que tous les relays ont `link_trust.seq ≥ seq_de_la_rotation`. Un relay hors ligne pendant la rotation reviendra avec une ancre périmée et sera bloqué si `previous` a déjà été retiré (R2 — voir §7).

---

## 5. Propagation de la révocation

```
tokens revoke <id>  →  link_tokens.revoked_at  +  JTI blacklisté  +  seq++
                    →  message link_revocations  (parent→enfants, de proche en proche)
```

Format du message :
```
{ seq, entries: [{jti, exp}], sig }
```

- `sig` vérifiée contre `link_trust.current` avant toute écriture locale.
- `seq` strictement supérieur au dernier accepté (anti-rejeu).
- JTIs ajoutés dans la blacklist locale, lien ciblé fermé avec code 4010.
- Racine injoignable : les liens existants continuent (vérification locale par la clé publique en cache). Remède local d'urgence : `relays revoke <id>` sur le parent concerné.

---

## 6. Compatibilité de l'état : analyse et décision

### Code vérifié (`state/file.go:134-138`)

```go
dec := json.NewDecoder(bytes.NewReader(env.Payload))
dec.DisallowUnknownFields()
if err := dec.Decode(&p); err != nil {
    return nil, env, fmt.Errorf("%w: payload: %v", ErrCorrupt, err)
}
```

`DisallowUnknownFields()` est présent dans le code de **toutes les versions**. Un binaire antérieur à v3.0.4 ne **ignore pas** les champs inconnus : il retourne `ErrCorrupt` (non final → repli possible sur `relay.state.prev`). La description du plan v1 ("ignore silencieusement") était inexacte.

### Options

| Option | Comportement v3.0.3 face à un état v2 | Risque |
|---|---|---|
| **A. `SchemaVersion` 2** (décision Q5) | `env.SchemaVersion != SchemaVersion` → `ErrSchemaVersion` (final, aucun repli) | **Aucune perte silencieuse.** Refus explicite. |
| B. Champs additifs, `SchemaVersion` 1 | `DisallowUnknownFields()` → `ErrCorrupt` (non final → repli sur `relay.state.prev`) | Possible repli sur un état plus ancien qui n'a pas les nouvelles sections → perte des `link_tokens` et `link_trust`. |
| C. Tout dans `server_config`, `SchemaVersion` 1 | Démarre, conserve les valeurs sans les valider | Dette de format ; les liens sont de toute façon coupés par le changement d'alg. |

**Option A retenue.** `ErrSchemaVersion` est final (`state/errors.go:27` + `isFinal()` dans `file.go:248`), pas de repli sur `.prev`. Refus explicite et sans ambiguïté.

### Décision Q5 (figée par l'utilisateur)

> **Pas de rétrocompatibilité** : `SchemaVersion` 2 ; retour arrière vers v3.0.3 **non supporté** (v3.0.3 refuse l'état v2 avec `ErrSchemaVersion`). La migration v1→v2, faite à la première écriture du maître v3.0.4 (pas au simple démarrage) ou pendant `state rekey`, est conservée (sinon tous les agents seraient à ré-enrôler).

---

## 7. Réserves — exigences à intégrer dans L1c/L1d/L1f

### R1 — [MOYEN] Vérification `iss` obligatoire dans `auth/linkjwt.go`

La keyfunc vérifie `kid ∈ {current, previous}` mais ne vérifie pas `iss == rootRelayID()`. Sans ce check, un jeton EdDSA dont `kid` collisionne avec la clé racine pourrait être accepté sans que l'émetteur soit identifié.

**Exigence L1c** : `iss` vérifié contre l'identité racine configurée localement. Si absent ou différent → refus `jwt_wrong_issuer`.  
**Test T3c/T3d** : `iss ≠ rootRelayID()` et `iss` absent → refus.

---

### R2 — [MOYEN] Relay hors ligne pendant `retire-link-previous`

**Scénario** : relay R hors ligne lors d'une rotation + `retire-link-previous`. Son ancre = ancienne clé K₀. Le `link_keys` reçu au retour a `previous = ∅`, signé par K₁. R ne peut plus vérifier la chaîne depuis K₀ → **bloqué**.

**Exigence L1f** : La commande `keys retire-link-previous` doit :
1. Vérifier (ou avertir) que tous les relays actifs ont `link_trust.seq ≥ seq_rotation` via `relays status`.
2. La procédure opérateur doit documenter cette vérification comme étape obligatoire.

**Test T5d** : `link_keys` dont la chaîne ne remonte pas à l'ancre → rejeté, `link_trust` inchangé.

---

### R3 — [MOYEN] Amplification du blast radius de `RSA_MASTER_KEY`

En v3.0.3 : compromis RSA_MASTER_KEY → accès aux JWT secrets agents + clés RSA serveur.  
En v3.0.4 : **+ accès à `link_signing_key_current/previous`** → forge de tous les jetons de lien EdDSA de toute la hiérarchie relay.

**Mise en œuvre (v3.0.4)** : la rotation se fait par la commande hors ligne `secagent-server state rekey` (`SECURITY.md` §11, `STATE_SPEC.md`).

**Exigence L1f** : SECURITY.md §5 doit documenter ce changement de surface de risque. La procédure de montée de version (§4) doit inclure la rotation de `RSA_MASTER_KEY` comme étape recommandée avant mise en production — **après** la montée en v3.0.4 (`state rekey` n'existe qu'en v3.0.4 et refuse un état en schéma 1) et avant d'accepter du trafic (`DEPLOYMENT.md`, étape 6 bis).

---

### R4 — [MOYEN] Validation `aud` : exigence d'implémentation explicite

Le plan spécifie `aud = P` / `aud = X` comme propriété du format, mais ne liste pas `jwt.WithAudiences(localRelayID())` comme contrainte de code dans la spec de `auth/linkjwt.go`. Sans ce check, un jeton X→P fonctionnerait auprès de Q (même `link_trust`).

**Exigence L1c/L1d** : `aud` vérifié contre `localRelayID()` via `jwt.WithAudiences` ou équivalent. `aud` absent → refus `jwt_missing_aud`.  
**Test T3a** : `aud = Q` présenté à P → refus.

---

### R5 — [BAS] Analyse incorrecte de l'option B dans le plan rev2 (correctif doc)

Le plan rev2 §2 affirme que v3.0.3 "ignore les champs inconnus silencieusement". C'est incorrect. `file.go:135` utilise `DisallowUnknownFields()` : champs inconnus → `ErrCorrupt` (non final, repli possible sur `.prev`). Option B reste à écarter mais pour cette raison, pas pour une perte silencieuse directe. **Impact nul sur les décisions d'implémentation**. Correctif incorporé dans §6 ci-dessus.

---

### R6 — [BAS] Invariant `checkRelayNode` à mettre à jour en L1b

`state/model.go` (à confirmer sur la branche) contient :
```go
if n.Revoked && n.JTI == "" {
    return fmt.Errorf("%w: revoked relay %q has no jti to blacklist", ErrInvalid, k)
}
```
En v3.0.4, la JTI du jeton de lien est dans `link_tokens`, plus dans `relay_nodes.JTI`. Cet invariant doit être mis à jour dans L1b pour éviter de rejeter les nœuds relay v3.0.4 révoqués.

**Exigence L1b** : adapter ou supprimer cette condition dans `checkRelayNode` en cohérence avec le nouveau schéma.

---

## 8. Exigences de sécurité obligatoires (S1–S23)

### `auth/linkjwt.go` (L1c — dev-agent)

| # | Exigence | Condition de refus |
|---|---|---|
| S1 | `jwt.WithValidMethods([]string{"EdDSA"})` | alg ≠ EdDSA |
| S2 | keyfunc : n'accepte QUE `ed25519.PublicKey` | Tout autre type → erreur explicite |
| S3 | `kid` absent → refus `jwt_missing_kid` | kid absent de l'en-tête |
| S4 | `kid` inconnu → refus `jwt_unknown_kid` | kid ∉ {current, previous}, jamais fallback HS256 |
| S5 | `aud` vérifié contre `localRelayID()` (R4) | aud absent ou ≠ local |
| S6 | `iss` vérifié contre `rootRelayID()` (R1) | iss absent ou ≠ racine connue |
| S7 | `role` vérifié selon le sens de connexion | relay-child en sens push → refus |
| S8 | JTI non blacklisté | JTI révoqué → refus |
| S9 | `exp` vérifié | Token expiré → refus |
| S10 | Clé privée JAMAIS dans les logs, l'API, `state verify` | grep stdout/stderr = 0 occurrence |

### `link_signing_key_current/previous` (L1b — dev-relay)

| # | Exigence |
|---|---|
| S11 | Ajoutés à `secretConfigKeys` → chiffrement `enc:` obligatoire |
| S12 | AAD = nom du champ (ex. `link_signing_key_current`) |
| S13 | `state verify` masque leur valeur (`[SEALED]` ou `[ABSENT]`) |
| S14 | `keys link-pubkey` exporte UNIQUEMENT la clé **publique** Ed25519 (PEM) |
| S15 | Test : grep sur stdout/stderr de `state verify`, `keys link-pubkey`, logs de démarrage → 0 fragment de clé privée |

### Messages `link_keys` et `link_revocations` (L1d / L1e)

| # | Exigence |
|---|---|
| S16 | `link_keys.sig` signé par l'ANCIENNE clé `current` (avant rotation) |
| S17 | Vérification chaîne : ancre → `previous_pub` → nouvelle clé. Si ancre ∉ {previous_pub} → rejet + `[SECURITY WARNING]`, `link_trust` inchangé |
| S18 | `link_revocations.sig` signé par `link_trust.current` et vérifié avant écriture |
| S19 | `link_revocations.seq` strictement supérieur au dernier accepté (init : 0) |
| S20 | `seq` incrémenté à chaque révocation ET à chaque rotation (compteur unique) |
| S21 | Relay non racine sans ancre → close 4010 + log explicite |
| S22 | Mint sans `RSA_MASTER_KEY` → 503, jamais de clé en clair |
| S23 | Mint sur nœud non racine (`REPEATER_UPSTREAM_URL` défini) → 409 `not_root` |

---

## 9. Tests de sécurité obligatoires (test-writer)

| Test | Description | Résultat attendu |
|---|---|---|
| T1 | Jeton EdDSA signé par autre clé Ed25519 | Refus |
| T2a | Jeton HS256 avec clé publique racine comme secret HMAC | Refus (`alg` mismatch) |
| T2b | `alg: none` | Refus |
| T2c | RS256 / ES256 | Refus |
| T2d | `kid` absent | Refus `jwt_missing_kid` |
| T2e | `kid` inconnu | Refus `jwt_unknown_kid` |
| T3a | `aud = Q` présenté à P (R4) | Refus |
| T3b | `aud` absent | Refus `jwt_missing_aud` |
| T3c | `iss ≠ rootRelayID()` (R1) | Refus `jwt_wrong_issuer` |
| T3d | `iss` absent (R1) | Refus |
| T4a | `relay-child` présenté en sens push | Refus |
| T4b | `relay-parent` présenté en sens pull | Refus |
| T4c | Ancien rôle `relay` (HS256 v3.0.3) | Refus + log explicite |
| T5a | Jeton signé par `previous` pendant double acceptation | Accepté |
| T5b | Jeton signé par `previous` après `retire-link-previous` | Refus |
| T5c | Enfant reconnecté après rotation → reçoit `link_keys` → accepte nouvelle clé | OK |
| T5d | `link_keys` dont chaîne ne remonte pas à l'ancre (R2) | Rejeté, `link_trust` inchangé |
| T6a | `tokens revoke` racine → lien ciblé à 2 niveaux fermé 4010 | OK |
| T6b | `link_revocations` avec `seq ≤ dernier` | Rejeté |
| T6c | `link_revocations` signature invalide | Rejeté |
| T6d | Liste complète rejouée à la reconnexion après coupure | OK |
| T7 | Liens existants actifs, racine injoignable | Continuent |
| T7b | Mint sur nœud non racine | 409 `not_root` |
| T8a | Bascule racine actif→passif → mint avec même `kid` | OK |
| T8b | Passif v3.0.3 face à état v2 | Refus `ErrSchemaVersion` |
| T9a | Migration v1→v2 : sauvegarde créée avant écriture | OK |
| T9b | Idempotence migration | OK |
| T9c | Échec écriture → v1 intact | OK |
| T9d | v2 lu par binaire v3.0.3 → refus | OK |
| T10a | Mint sans `RSA_MASTER_KEY` | 503 |
| T10b | Relay non racine sans ancre → lien entrant | Refus 4010 |
| T10c | Grep clé privée : logs + `state verify` + API | 0 occurrence |
| T11 | `relay-child`/`relay-parent` sur exec/upload/fetch/inventory/ws-agent/admin | Refus 403 |
| T12a | Mutation `aud` non vérifié | Tuée |
| T12b | Mutation `kid` previous toujours accepté après retire | Tuée |
| T12c | Mutation `seq` non vérifié | Tuée |
| T12d | Mutation `iss` non vérifié (R1) | Tuée |

---

## 10. Procédures opérateur

### Déploiement initial

1. Racine : `keys link-pubkey > /srv/relay/root_link.pub` (exporte la clé **publique** seulement).
2. Distribuer `root_link.pub` à chaque relay non racine : `REPEATER_ROOT_LINK_KEY_FILE=/srv/relay/root_link.pub`.
3. Minter les jetons de lien sur la racine (un par paire) :
   - Pull : `tokens create --role relay-child --sub X --aud P`
   - Push : `tokens create --role relay-parent --sub P --aud X`
4. Démarrer les relays enfants avec leurs nouveaux jetons.

### Rotation de la clé racine

1. `keys rotate-link` → nouvelle `current`, ancienne → `previous`.
2. Message `link_keys` poussé automatiquement vers les relays connectés.
3. Vérifier via `keys link-status` que **tous** les relays sont `confirmed` (et `relays status` : `link_trust.seq ≥ seq_rotation`).
4. **Mettre à jour `REPEATER_ROOT_LINK_KEY_FILE` de CHAQUE relay non racine avec la NOUVELLE clé publique** (`keys link-pubkey` sur la racine), **avant** `retire-link-previous`. Tant que `previous` existe, l'ancien fichier épinglé est encore accepté (il égale la clé précédente) ; **dès le retrait, il n'est plus ni la courante ni la précédente** : le prochain démarrage du relay (même fortuit : redémarrage du conteneur, mise à jour d'image) est **refusé** en boucle, fail closed voulu, avec `link trust anchor: pinned root link key disagrees with the persisted link_trust (outside a valid rotation chain)` (`ErrAnchorMismatch`). Constaté en qualification réelle (2026-10-08) : le lien déjà établi survit jusqu'au redémarrage, puis l'enfant ne repart plus.
5. **Re-minter le jeton de chaque lien AVANT le retrait** (`tokens create --role relay-child|relay-parent --sub … --aud …` sur la racine) et le remplacer sur le relay porteur (`REPEATER_UPSTREAM_TOKEN[_FILE]`, redémarrage) : le `kid` d'un jeton émis avant la rotation désigne l'ancienne clé, qui n'est plus ni `current` ni `previous` après le retrait (`auth/linkjwt.go:251-258`, `jwt_unknown_kid`).
6. **Seulement après** (fichier épinglé ET jeton remplacés, lien `connected`) : `keys retire-link-previous`.
7. Si le retrait a déjà eu lieu avec un fichier périmé : remplacer le fichier par la clé courante (`keys link-pubkey`) et redémarrer le relay ; si l'ancre persistée est elle-même obsolète, `state link-trust reset --yes` (relay arrêté) puis redémarrer.

### Montée de version v3.0.3 → v3.0.4 (rupture de liens, pas des agents)

1. Annonce : fenêtre de coupure des **liens inter-relays** (les agents restent connectés).
2. Sauvegarde de `relay.state` sur chaque relay.
3. Racine : arrêter le passif, monter l'actif v3.0.4 (migration automatique v1→v2), puis monter le passif.
4. Minter les jetons de lien depuis la racine.
5. Descendre niveau par niveau avec `REPEATER_ROOT_LINK_KEY_FILE` et les nouveaux jetons.
6. Contrôles : `relays status`, inventaire complet, smoke exec.

### Re-racine (perte de `RSA_MASTER_KEY` ou de la clé privée Ed25519)

1. Arrêter tous les relays.
2. Re-générer la clé privée (nouveau `link_signing_key_current` à la prochaine génération paresseuse).
3. Exporter la nouvelle clé publique : `keys link-pubkey`.
4. Distribuer et ré-épingler sur chaque relay (`REPEATER_ROOT_LINK_KEY_FILE`).
5. Re-minter tous les jetons de lien (tous les anciens sont invalides).
6. Redémarrer la hiérarchie (parents d'abord).

> Coût équivalent à une montée de version complète. Cette procédure doit être répétée en qualif (L8).

---

## 11. Impact sur SECURITY.md (à appliquer en L1f)

**Ne pas modifier SECURITY.md maintenant** — c'est le périmètre de L1f.

Sections à mettre à jour :

- **§2 Rôles** : remplacer `relay` HS256 / `relay-parent` HS256 → `relay-child` EdDSA / `relay-parent` EdDSA avec `iss`, `aud`, `kid`.
- **§5 Stockage des secrets** : ajouter `link_signing_key_current/previous` ; note amplification blast radius RSA_MASTER_KEY (R3).
- **§7 Tokens relay** : nouvelle sous-section sur les jetons de lien EdDSA (création, rotation, révocation, propagation).
- **§12 Matrice des menaces** : ajouter parent compromis / RSA_MASTER_KEY amplification / rejeu révocation / relay hors ligne au retire.

---

## 12. Checklist de revue — après L1d + L1e (security-reviewer)

- [ ] S1–S4 : vérificateur EdDSA strict (`alg`, type clé, `kid`)
- [ ] S5 : `aud` vérifié contre `localRelayID()` (R4)
- [ ] S6 : `iss` vérifié contre `rootRelayID()` (R1)
- [ ] S7 : rôle vérifié selon le sens de connexion
- [ ] S8 : JTI blacklist vérifiée avant acceptation
- [ ] S10, S15 : clé privée absente des logs, API, `state verify`
- [ ] S11–S14 : `link_signing_key_*` dans `secretConfigKeys`, masqués, exportés publics seulement
- [ ] S16–S20 : `link_keys` / `link_revocations` signés et vérifiés
- [ ] S21–S23 : fail closed sans ancre ou sans `RSA_MASTER_KEY`
- [ ] R2 : `retire-link-previous` bloqué ou avertissement si relays non confirmés
- [ ] R6 : invariant `checkRelayNode` mis à jour (L1b)
- [ ] Tests T1–T12d : tous définis dans le scope test-writer
- [ ] SECURITY.md §2, §5, §7, §12 mis à jour (L1f)
