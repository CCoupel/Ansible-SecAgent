# Ansible-SecAgent — High-Level Design (HLD) v3.0.3

> Vue d'ensemble architecturale du système.
> **v3.0.3** : WebSocket direct dispatch (sans NATS), état fichier persistant, Compose multi-hôtes.
> Pour les spécifications détaillées, voir [ARCHITECTURE.md](ARCHITECTURE.md).

---

## Table des matières

1. [Contexte système](#1-contexte-système)
2. [Décomposition des composants](#2-décomposition-des-composants)
3. [Flux de messages](#3-flux-de-messages)
   - 3.1 [Provisioning et enrollment](#31-provisioning-et-enrollment)
   - 3.2 [Exécution d'un playbook — chemin nominal](#32-exécution-dun-playbook--chemin-nominal)
   - 3.3 [Failover actif/passif](#33-failover-actifpassif)
   - 3.4 [Gestion des erreurs](#34-gestion-des-erreurs)
   - 3.5 [Révocation d'un agent](#35-révocation-dun-agent)
4. [Vue déploiement](#4-vue-déploiement)
   - 4.1 [Docker Compose — qualification/production](#41-docker-compose--qualificationproduction)
5. [Matrice des interfaces](#5-matrice-des-interfaces)
6. [Décisions architecturales clés](#6-décisions-architecturales-clés)

---

## 1. Contexte système

Ansible-SecAgent permet d'exécuter des playbooks Ansible sur des hôtes distants **sans ouvrir de port entrant**. Les agents initient toutes les connexions vers le serveur central.

```
╔══════════════════════════════════════════════════════════════════════════╗
║                         CONTEXTE SYSTÈME v3.0.3                          ║
╠══════════════════════════════════════════════════════════════════════════╣
║                                                                          ║
║   ┌──────────────┐     lance des       ┌────────────────────────────┐   ║
║   │   Opérateur  │────playbooks───────▶│    Ansible Control Node    │   ║
║   │   Ansible    │                     │  (inventory + conn plugin)  │   ║
║   └──────────────┘                     └──────────────┬─────────────┘   ║
║                                                        │ HTTPS           ║
║   ┌──────────────┐    autorise les     ┌──────────────▼─────────────┐   ║
║   │  Pipeline    │───nouvelles clefs──▶│                            │   ║
║   │  CI/CD       │    HTTPS admin      │   RELAY SERVER (GO, TLS)   │   ║
║   │(Terraform    │                     │   État fichier (STATE_DIR) │   ║
║   │  /Packer)    │                     │                            │   ║
║   └──────────────┘                     └──────────────▲─────────────┘   ║
║                                                        │ WSS 7770/7772   ║
║                                          ┌─────────────┴──────────────┐  ║
║                                          │      HÔTES GÉRÉS           │  ║
║                                          │   host-A  host-B  host-C   │  ║
║                                          │  (secagent-minion + systemd) ║  ║
║                                          └────────────────────────────┘  ║
║                                                                          ║
║  Flux sortants uniquement depuis les hôtes gérés (NAT/firewall friendly) ║
╚══════════════════════════════════════════════════════════════════════════╝
```

### Acteurs

| Acteur | Rôle |
|---|---|
| Opérateur Ansible | Lance des playbooks depuis le control node |
| Pipeline CI/CD | Provisionne les serveurs et pré-enregistre leurs clefs |
| Ansible Control Node | Hôte exécutant `ansible-playbook`, portant les plugins relay |
| Relay Server (actif) | Broker central v3.0.3 (GO, TLS natif, état fichier) |
| Relay Server (passif) | Failover standby (partagé NFS, verrou) |
| Hôtes gérés | Serveurs cibles portant `secagent-minion` en tant que service systemd |

---

## 2. Décomposition des composants

```
╔═════════════════════════════════════════════════════════════════════════╗
║                    ARCHITECTURE v3.0.3 SIMPLIFIÉ                         ║
╠═════════════════════════════════════════════════════════════════════════╣
║                                                                         ║
║  ┌─────────────────────────────────────────────────────────────────┐   ║
║  │                ANSIBLE CONTROL NODE                              │   ║
║  │  ┌──────────────────────────┐ ┌──────────────────────────────┐  │   ║
║  │  │  INVENTORY PLUGIN        │ │  CONNECTION PLUGIN           │  │   ║
║  │  │  secagent.py (Python)    │ │  relay.py (Python)           │  │   ║
║  │  │  • GET /api/inventory    │ │  • POST /api/exec/{host}     │  │   ║
║  │  │  • retourne JSON Ansible │ │  • POST /api/upload/{host}   │  │   ║
║  │  └──────────┬───────────────┘ └────────────┬─────────────────┘  │   ║
║  └────────────┼────────────────────────────────┼──────────────────────┘   ║
║               │ HTTPS                          │ HTTPS bloquant           ║
║  ┌────────────▼────────────────────────────────▼──────────────────────┐  ║
║  │                     RELAY SERVER (GO v3.0.3)                       │  ║
║  │                                                                    │  ║
║  │  ┌────────────────────┐  ┌─────────────────────────────────────┐ │  ║
║  │  │  REST API          │  │  WebSocket HANDLER (7770/7772)      │ │  ║
║  │  │  (7770)            │  │  • /ws/agent (agent minions)        │ │  ║
║  │  │  • /api/register   │  │  • /ws/relay (relay enfants)        │ │  ║
║  │  │  • /api/exec       │  │  • Dispatch direct aux agents       │ │  ║
║  │  │  • /api/inventory  │  │  • Multiplexage par task_id         │ │  ║
║  │  │  • /api/admin      │  └─────────────────────────────────────┘ │  ║
║  │  └────────────────────┘  ┌─────────────────────────────────────┐ │  ║
║  │  ┌────────────────────┐  │  STATE FILE (STATE_DIR, NFS)        │ │  ║
║  │  │  AUTH MANAGER      │  │  • relay.state (JSON signé+chiffré) │ │  ║
║  │  │  • Enroll          │  │  • relay.lock (actif/passif)        │ │  ║
║  │  │  • Verify JWT      │  │  • authorized_keys                  │ │  ║
║  │  │  • Blacklist JTI   │  │  • Blacklist JTI                    │ │  ║
║  │  │  • Rôles           │  │  • write_seq (anti-rejeu)           │ │  ║
║  │  └────────────────────┘  └─────────────────────────────────────┘ │  ║
║  └────────────────────────────────────────────────────────────────────┘  ║
║               ▲                                                           ║
║               │ WSS persistant (connexion longue, multiplexée)            ║
║  ┌────────────┴──────────────────────────────────────────────────────┐  ║
║  │                       HÔTES GÉRÉS                                 │  ║
║  │  ┌─────────────────────┐  ┌─────────────────────┐               │  ║
║  │  │  RELAY AGENT        │  │  RELAY AGENT        │      ...      │  ║
║  │  │  host-A             │  │  host-B             │               │  ║
║  │  │  (secagent-minion)  │  │  (secagent-minion)  │               │  ║
║  │  │  • WS LISTENER      │  │  • WS LISTENER      │               │  ║
║  │  │  • TASK RUNNER      │  │  • TASK RUNNER      │               │  ║
║  │  │    (subprocess)     │  │    (subprocess)     │               │  ║
║  │  │  • ASYNC REGISTRY   │  │  • ASYNC REGISTRY   │               │  ║
║  │  └─────────────────────┘  └─────────────────────┘               │  ║
║  └────────────────────────────────────────────────────────────────────┘  ║
╚═════════════════════════════════════════════════════════════════════════╝
```

---

## 3. Flux de messages

### 3.1 Provisioning et enrollment

```
PIPELINE CI/CD       RELAY SERVER           RELAY AGENT (host-A)
     │                    │                        │
     │ ① POST /api/admin/authorize               │
     │  { hostname, public_key, approved_by }    │
     │───────────────────▶│                        │
     │                    │ INSERT authorized_keys │
     │  HTTP 201          │                        │
     │◀───────────────────│                        │
     │                    │                        │
     │  [serveur provisionné, agent démarre]      │
     │                    │                        │
     │                    │  ② POST /api/register  │
     │                    │  { hostname, pubkey }  │
     │                    │◀───────────────────────│
     │                    │ SELECT authorized_keys │
     │                    │ → clef OK ? génère JWT │
     │                    │                        │
     │                    │  HTTP 200              │
     │                    │  { token_encrypted }   │
     │                    │──────────────────────▶│
     │                    │                        │ déchiffre token
     │                    │                        │ stocke JWT local
     │                    │                        │
     │                    │  ③ WSS /ws/agent       │
     │                    │  Bearer <JWT>          │
     │                    │◀───────────────────────│
     │                    │ verify JWT             │
     │                    │ → enregistre session   │
     │                    │                        │
     │                    │  WS OPEN ✓             │
     │                    │──────────────────────▶│
     │                    │         ◀──────────────
     │                    │     (connexion persistante)
```

---

### 3.2 Exécution d'un playbook — chemin nominal

```
PLUGIN ANSIBLE       RELAY SERVER (GO)        RELAY AGENT (host-A)
     │                       │                         │
     │  ① POST /api/exec/    │                         │
     │   host-A              │                         │
     │  { task_id, cmd,      │                         │
     │    timeout: 30 }      │                         │
     │──────────────────────▶│                         │
     │                       │  ② WS: exec task      │
     │  [bloquant]           │─────────────────────▶│
     │                       │                         │ spawn subprocess
     │                       │  ③ WS: ack            │
     │                       │◀──────────────────────│
     │                       │                         │ exécute cmd
     │                       │  ④ WS: stdout         │
     │                       │◀──────────────────────│
     │                       │  (streaming)          │
     │                       │                         │
     │                       │  ⑤ WS: result         │
     │                       │  { rc, stdout }       │
     │                       │◀──────────────────────│
     │                       │                         │
     │  HTTP 200             │                         │
     │  { rc, stdout }       │                         │
     │◀──────────────────────│                         │
     │                       │                         │
    [exec_command() retourne] [endpoint /api/exec déverrouille]
```

---

### 3.3 Failover actif/passif

```
Relay #1 (ACTIF)    │ STATE_DIR (NFS)    │    Relay #2 (PASSIF)
  A lock             │  relay.lock        │    attend verrou
  │                  │  relay.state       │    │
  │ détient verrou   │                    │    │
  ├─────────────────▶│                    │    │
  │                  │                    │    │
  [agent connecté]   │                    │    [agent attente]
  │                  │                    │    │
  X [CRASH]          │                    │    │
                     │                    │    │
                     │ verrou libéré      │    │ Relay #2 acquiert
                     │◀────────────────────────│
                     │                    │ ✓  │
                     │                    │◀──▶│ restaure state
                     │ Relay #2 ACTIF     │    │
                     │◀────────────────────────│
                         │
                         ▼ Agent se reconnecte (backoff, multi-adresses)
                    Relay #2 redevient ACTIF
```

---

### 3.4 Gestion des erreurs

| Cas | Scénario | Réponse Relay | Comportement Ansible |
|---|---|---|---|
| Agent offline | POST /api/exec, agent disconnecté | HTTP 503 `agent_offline` | UNREACHABLE |
| Timeout tâche | POST /api/exec timeout=30, tâche > 30s | HTTP 504 `timeout` (SIGTERM envoyé) | FAILED |
| Agent crash mid-tâche | WS fermée pendant exécution | HTTP 500 `agent_disconnected` | FAILED |
| Task annulée | POST /api/cancel/{task_id} | SIGTERM subprocess, WS close | FAILED |

---

### 3.5 Révocation d'un agent

```
ADMIN               RELAY SERVER          RELAY AGENT (host-E)
  │                       │                         │
  │ DELETE /api/admin/    │                  [WS active]
  │ agents/host-E         │                         │
  │──────────────────────▶│                         │
  │                       │ INSERT blacklist        │
  │                       │ (jti, revoked_at)       │
  │                       │                         │
  │                       │ WS close(4001)          │
  │                       │────────────────────────▶│
  │                       │                         │ reçoit close(4001)
  │                       │                         │ → NE PAS reconnecter
  │  HTTP 200             │                         │ → log + alerte
  │◀──────────────────────│                         │
  │                       │                         │
  │        [plus tard, host-E reconnect attempt]   │
  │                       │ WSS + Bearer <old JWT>  │
  │                       │◀───────────────────────│
  │                       │ verify JWT              │
  │                       │ check JTI → IN blacklist│
  │                       │                         │
  │                       │ WS close(4001)          │
  │                       │────────────────────────▶│
```

---

## 4. Vue déploiement

### 4.1 Docker Compose — Qualification/Production

#### Qualification (mono-hôte, tests)

```
┌────────────────────────────────────────────────────────────┐
│              HOST DOCKER (machine unique)                   │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │                docker-compose network                │   │
│  │                                                       │   │
│  │  ┌───────────────────────────┐                       │   │
│  │  │  secagent-server          │                       │   │
│  │  │  (GO, TLS natif)          │                       │   │
│  │  │                           │                       │   │
│  │  │  Ports:                   │                       │   │
│  │  │  7770 → API + /ws/agent   │                       │   │
│  │  │  7771 → Admin CLI         │                       │   │
│  │  │  7772 → /ws/relay         │                       │   │
│  │  │                           │                       │   │
│  │  │  STATE_DIR: ./data        │                       │   │
│  │  │  TLS_CERT, TLS_KEY        │                       │   │
│  │  └───────────────────────────┘                       │   │
│  │                                                       │   │
│  │  Volume: ./data (État local)                         │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                              │
│  Fichiers: ./certs/ (TLS auto-signé)                        │
└────────────────────────────────────────────────────────────┘

          ▲                                    ▲
          │ WSS 7770/7772                      │ HTTPS
          │                                    │
┌─────────┴──────────────┐         ┌───────────┴────────────┐
│   HÔTE GÉRÉ (agent)    │         │  ANSIBLE CONTROL NODE  │
│   secagent-minion      │         │  inventory + conn      │
│   systemd              │         │  plugin                │
└────────────────────────┘         └────────────────────────┘
```

#### Production (multi-hôte actif/passif, NFS)

```
┌─────────────────────────────────────────────────────────┐
│              HOST 1 (RELAY ACTIF)                        │
│  secagent-server:3.0.3  [détient lock]                  │
├─────────────────────────────────────────────────────────┤
│              HOST 2 (RELAY PASSIF)                       │
│  secagent-server:3.0.3  [attend lock]                   │
└─────────────────────────────────────────────────────────┘
         ▲  │
         │  └─────────────┐
         │                │
    ┌────▼────────────────▼──────────┐
    │    NFS (STATE_DIR partagé)     │
    │  • relay.state                 │
    │  • relay.lock  (exclusivité)   │
    │  • relay.state.backup          │
    │  • write_seq                   │
    └────────────────────────────────┘
         │         ▲
         │ mount   │ hard mount (robuste)
         │         │
    ┌────▼─────────┴──────┐
    │  NAS/NFS Server     │
    │  (recommandé)       │
    └─────────────────────┘
```

---

## 5. Matrice des interfaces

| # | De | Vers | Protocole | Endpoint | Auth |
|---|---|---|---|---|---|
| I1 | Pipeline CI/CD | Relay | HTTPS | POST /api/admin/authorize | Bearer admin token |
| I2 | secagent-minion | Relay | HTTPS | POST /api/register | Public key + TLS |
| I3 | secagent-minion | Relay | WSS | /ws/agent (7770/7772) | Bearer JWT agent |
| I4 | Inventory Plugin | Relay | HTTPS | GET /api/inventory | Bearer JWT plugin |
| I5 | Connection Plugin | Relay | HTTPS | POST /api/exec/{host} | Bearer JWT plugin |
| I6 | Connection Plugin | Relay | HTTPS | POST /api/upload/{host} | Bearer JWT plugin |
| I7 | Connection Plugin | Relay | HTTPS | POST /api/fetch/{host} | Bearer JWT plugin |
| I8 | Relay enfant | Relay parent | WSS | /ws/relay (7772) | Bearer JWT relay-child |
| I9 | Relay parent | Relay enfant | WSS | /ws/relay (7772) | Bearer JWT relay-parent |

**v3.0.3** : Plus d'interfaces NATS (I10-I13 retiré). État persistant via fichier (STATE_DIR).

---

## 6. Décisions architecturales clés

| # | Décision | Alternatives écartées | Raison v3.0.3 |
|---|---|---|---|
| DA-01 | **Connexion WSS initiée par l'agent** | SSH sortant, polling HTTP | Traverse NAT/firewall sans règle entrante |
| DA-02 | **1 WS par agent, multiplexée par `task_id`** | 1 WS par tâche | Scalabilité — évite N×M connexions TCP |
| DA-03 | **État fichier (STATE_DIR), pas NATS** | Redis, NATS JetStream (v2) | Modèle actif/passif = simpler, plus stable (verrou seul) |
| DA-04 | **REST HTTP bloquant pour le plugin Ansible** | WS côté plugin | `exec_command()` Ansible est synchrone par nature |
| DA-05 | **authorized_keys en état fichier** | Fichiers sur disque, DB | Dynamique, multi-nodes, API admin, signée |
| DA-06 | **JWT + blacklist JTI pour l'auth** | mTLS, sessions côté serveur | Stateless, révocation immédiate |
| DA-07 | **subprocess par tâche (pas de threads)** | Thread pool | Isolation mémoire, kill propre |
| DA-08 | **Infra immuable — clef pré-enregistrée avant boot** | TOFU, auto-enrollment | Sécurité renforcée, zero-touch |
| DA-09 | **Verrou fichier pour actif/passif** | Base de données distribuée | Élémentaire, robuste, NFS-friendly |
| DA-10 | **Compose multi-hôtes (prod)** | Kubernetes, Swarm | Portabilité, simplicité, TLS natif |

---

*HLD v3.0.3 — Ansible-SecAgent*
*Basé sur [ARCHITECTURE.md](ARCHITECTURE.md) · [STATE_SPEC.md](../server/STATE_SPEC.md) · [DEPLOYMENT.md](../project/DEPLOYMENT.md)*
