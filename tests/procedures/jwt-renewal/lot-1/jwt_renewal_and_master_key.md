# Procedure de Test — Renouvellement du JWT d'agent (#217) et clé maître minimale (#214)

**Version** : 3.0.5
**Date** : 2026-11-01
**Testeur** : QA

## Prerequis

- [ ] Environnement : QUALIF (192.168.1.218), chaîne `DEPLOYMENT/qualif/docker-compose.server.yml` (racine actif/passif a/b) + au moins 2 minions
- [ ] Donnees : `AGENT_JWT_TTL=10m` et `AGENT_JWT_RENEW_INTERVAL=3m` sur les relays (durées courtes pour la qualif) ; les minions déjà enrôlés **sans** jeton d'enrôlement réutilisable actif (jetons consommés)
- [ ] Acces : `ADMIN_TOKEN`, accès `docker.exe compose` sur l'hôte de qualif
- [ ] Verifier **avant** la montée de version que les `RSA_MASTER_KEY` de la qualif font ≥ 32 octets (`printf %s "$RSA_MASTER_KEY" | wc -c`) ; sinon `state rekey` d'abord (risque du plan)

## Scenarios

### Scenario 1 — Le relay renouvelle le JWT des minions connectés

**Validation** : AUTO — **Issues** : #217

**Objectif** : Verifier que chaque minion connecte recoit au moins 2 trames `rekey` de renouvellement en 10 minutes, sans deconnexion.

| Etape | Action | Resultat Attendu | Resultat Obtenu | OK ? |
|-------|--------|-----------------|----------------|------|
| 1 | Noter l'heure ; laisser les minions connectes 7 minutes | Aucune deconnexion (`GET /api/admin/minions` : `connected: true`) | | |
| 2 | `docker logs <relay actif> \| grep "Rekey sent to agent"` | ≥ 2 lignes par minion, `jti` tronque (jamais le JWT ni le `jti` complet) | | |
| 3 | Lire le journal du minion (`journalctl -u secagent-minion` ou `docker logs`) | Compteur de renouvellements incremente, aucun jeton dans le texte | | |

**Verdict** : [ ] PASS  [ ] FAIL

---

### Scenario 2 — Redemarrage du relay apres plus d'un TTL : reconnexion sans re-enrolement

**Validation** : AUTO — **Issues** : #217

**Objectif** : Verifier qu'un minion connecte depuis plus d'un TTL se reconnecte apres un `failover` / redemarrage du relay, sans jeton d'enrolement.

| Etape | Action | Resultat Attendu | Resultat Obtenu | OK ? |
|-------|--------|-----------------|----------------|------|
| 1 | Attendre 12 minutes apres le demarrage des minions (> TTL) | Minions toujours connectes | | |
| 2 | Lancer `DEPLOYMENT/qualif/failover-test.sh` (ou arreter proprement le relay actif) | Le passif devient actif | | |
| 3 | Lire `GET /api/admin/minions` sur le nouvel actif | Tous les minions `connected: true` en moins de 60 s | | |
| 4 | Chercher `register` / `403` dans les journaux des minions | Aucune tentative d'enrolement, aucun code de sortie 78 | | |

**Verdict** : [ ] PASS  [ ] FAIL

---

### Scenario 3 — Un minion revoque ne recoit jamais de JWT

**Validation** : AUTO — **Issues** : #217

**Objectif** : Verifier qu'apres `POST /api/admin/revoke/<hostname>` aucun renouvellement n'est emis.

| Etape | Action | Resultat Attendu | Resultat Obtenu | OK ? |
|-------|--------|-----------------|----------------|------|
| 1 | Revoquer un minion de test | 200, lien coupe (code 4001), le minion s'arrete (code 77) | | |
| 2 | Attendre 2 periodes de renouvellement (6 min) | Aucune ligne `Rekey sent to agent` pour ce hostname apres la revocation | | |
| 3 | Rejouer le dernier JWT du minion sur `/ws/agent` | 401 | | |

**Verdict** : [ ] PASS  [ ] FAIL

---

### Scenario 4 — Cle maitre trop courte refusee a `state init` et au demarrage

**Validation** : AUTO — **Issues** : #214

**Objectif** : Verifier le refus d'une `RSA_MASTER_KEY` < 32 octets, avec message de remede, sans fuite de la cle.

| Etape | Action | Resultat Attendu | Resultat Obtenu | OK ? |
|-------|--------|-----------------|----------------|------|
| 1 | `RSA_MASTER_KEY=court secagent-server state init --state-dir /tmp/s1` | Code de sortie ≠ 0 ; message contient `32`, `openssl rand -base64 48` ; ne contient pas `court` ; `/tmp/s1` vide | | |
| 2 | Demarrer un relay de test avec `RSA_MASTER_KEY=<31 octets>` sur un etat existant | Refus avant tout port ouvert, message de remede (`state rekey`), `relay.state` inchange | | |
| 3 | `RSA_MASTER_KEY=$(openssl rand -base64 48)` puis `state init` et demarrage | Succes | | |
| 4 | `grep -r "<la cle>"` dans les journaux des etapes 1 a 3 | Aucune occurrence | | |

**Verdict** : [ ] PASS  [ ] FAIL

---

### Scenario 5 — Lisibilite du message de remede (#214)

**Validation** : HUMAIN — **Issues** : #214

**Objectif** : Un operateur qui lit le refus comprend quoi faire sans consulter la documentation.

| Etape | Action | Resultat Attendu | Resultat Obtenu | OK ? |
|-------|--------|-----------------|----------------|------|
| 1 | Provoquer le refus du scenario 4 etape 2 sur un deploiement existant a cle courte | Le message dit : la longueur actuelle, le minimum, la commande de generation, la commande `state rekey` a lancer **avant** la montee de version | | |
| 2 | Suivre le remede tel que decrit | Le deploiement redemarre avec la nouvelle cle | | |

**Verdict** : [ ] PASS  [ ] FAIL

---

### Scenario 6 — Documentation d'exploitation du renouvellement (#217)

**Validation** : HUMAIN — **Issues** : #217

**Objectif** : Les exemples de `DEPLOYMENT.md` (jetons de production `--reusable --hostname-pattern --expires 90d`, procedure de montee de version d'un relay, `AGENT_JWT_TTL` / `AGENT_JWT_RENEW_INTERVAL`) sont clairs et executables tels quels.

| Etape | Action | Resultat Attendu | Resultat Obtenu | OK ? |
|-------|--------|-----------------|----------------|------|
| 1 | Lire `DOC/project/DEPLOYMENT.md` et `DOC/security/SECURITY.md` (cycle de vie du JWT d'agent) | Plus d'exemple `--expires 1h` ; tolerance d'indisponibilite `TTL − intervalle` expliquee | | |
| 2 | Rejouer les commandes copiables | Elles fonctionnent sans adaptation | | |

**Verdict** : [ ] PASS  [ ] FAIL

## Criteres de Validation

- [ ] Tous les scenarios nominaux passent
- [ ] Aucun jeton, JWT ni cle maitre dans les journaux
- [ ] Aucune regression sur l'enrolement, la revocation (4001/77) et la rotation `keys rotate`

## Notes QA

(espace libre)
