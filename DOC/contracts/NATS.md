# ⚠️ DEPRECATED v3.0.3 — Contrat NATS JetStream

**STATUS** : Supprimé en v3.0.3 — Voir #178 (NATS removal)

> Interface interne OBSOLÈTE (v2.0-v3.0.2) entre les nœuds secagent-server pour le routage HA.
> **Remplacé par** : WebSocket direct dispatch + état fichier (STATE_DIR).
> Voir : `DOC/common/ARCHITECTURE.md` §5 (Routage WebSocket Direct) · `DOC/server/STATE_SPEC.md` (persistance)

---

## Note historique

---

## Raison du retrait

**v3.0.3** adopte un modèle de déploiement actif/passif :
- Un seul relay actif à la fois (détient le verrou sur STATE_DIR/relay.lock)
- Pas de multi-relay stateless → pas besoin de bus de messages inter-nodes
- État centralisé en fichier → simpler, plus stable que NATS clusters
- WebSocket direct : les tâches vont directement au relay actif via WSS

**Historique** : NATS était utilisé pour :
- Acheminer les tâches depuis le nœud qui reçoit le POST vers celui qui a la WS de l'agent
- Retourner les résultats en sens inverse
- Fournir une base pour la HA stateless

Ce modèle a été remplacé par un verrou en fichier + failover actif/passif + multi-adresses agent.

---

## 2. Connexion

```
URL     : nats://nats:4222  (configurable via NATS_URL)
Auth    : credentials NATS (optionnel, recommandé en prod)
Cluster : 3 nœuds JetStream (replicas: 3)
```

---

## 3. Stream RELAY_TASKS

### Configuration

```
Nom         : RELAY_TASKS
Subjects    : tasks.{hostname}
Retention   : WorkQueue
MaxAge      : 300s (5 minutes)
MaxMsgSize  : 1 MB
Replicas    : 3
```

**WorkQueue** : chaque message est délivré à exactement un consumer. Après ACK, le message est supprimé du stream.

### Consumer par agent

```
Nom         : secagent-minion-{hostname}
Type        : Push durable
AckPolicy   : Explicit
AckWait     : 30s
MaxDeliver  : 1
```

**MaxDeliver: 1** est délibéré — pas de retry automatique. Si l'agent ne peut pas prendre en charge la tâche, le message expire et Ansible reçoit un timeout. C'est l'opérateur qui relance le playbook. Évite les états incohérents.

### Format du message

Le payload est la tâche à router vers l'agent (JSON sérialisé) :

```json
{
  "task_id": "uuid-v4",
  "type": "exec",
  "hostname": "host-A",
  "cmd": "python3 /tmp/module.py",
  "stdin": null,
  "timeout": 30,
  "become": false,
  "become_method": "sudo",
  "expires_at": 1234567890
}
```

Même structure pour `put_file` et `fetch_file` (champs spécifiques selon le type).

### Publication (nœud recevant le POST HTTP)

```
Subject : tasks.{hostname}
Exemple : tasks.host-A
```

Le nœud qui reçoit le POST du plugin publie dans ce subject. Le nœud qui a la connexion WS de `host-A` est subscriber et reçoit le message.

---

## 4. Stream RELAY_RESULTS

### Configuration

```
Nom         : RELAY_RESULTS
Subjects    : results.{task_id}
Retention   : Limits
MaxAge      : 60s
MaxMsgSize  : 5 MB  (taille max stdout)
Replicas    : 3
```

### Format du message

```json
{
  "task_id": "uuid-v4",
  "rc": 0,
  "stdout": "output...",
  "stderr": "",
  "truncated": false
}
```

Pour les erreurs serveur :
```json
{
  "task_id": "uuid-v4",
  "error": "agent_disconnected"
}
```

### Publication (nœud ayant la WS de l'agent)

```
Subject : results.{task_id}
Exemple : results.a1b2c3d4-...
```

Le nœud qui reçoit le `result` WS de l'agent publie dans ce subject. Le nœud en attente du résultat (celui qui a le POST HTTP bloquant) résout sa `future()`.

---

## 5. Séquence de routage HA

```
Plugin  ──POST /api/exec/host-A──▶  Node #2
                                        │
                                        │ publish tasks.host-A
                                        ▼
                                    NATS JetStream
                                        │
                                        │ deliver (WorkQueue)
                                        ▼
Node #1 (a la WS de host-A)  ◀─────────┘
    │
    │ WS exec message
    ▼
secagent-minion host-A
    │
    │ WS result message
    ▼
Node #1  ──publish results.{task_id}──▶ NATS JetStream
                                            │
                                            │ deliver
                                            ▼
                                        Node #2  ──HTTP 200──▶  Plugin
```

---

## 6. Sujets NATS utilisés

| Subject | Stream | Direction | Description |
|---|---|---|---|
| `tasks.{hostname}` | RELAY_TASKS | Node → Node | Acheminement tâche vers nœud WS |
| `results.{task_id}` | RELAY_RESULTS | Node → Node | Retour résultat vers nœud HTTP |

**Règle de sécurité :** aucun secret (JWT, become_pass décodé) dans les sujets NATS.

---

## 7. Gestion des erreurs NATS

| Situation | Comportement |
|---|---|
| Nœud NATS indisponible | Retry avec backoff, alerte opérateur |
| Message expiré (MaxAge) | Task perdue → plugin reçoit `504 timeout` |
| Agent déconnecté pendant exécution | Node publie `error: agent_disconnected` dans results |
| Consumer ACK timeout (30s) | Re-deliver jusqu'à MaxDeliver=1, puis abandon |
