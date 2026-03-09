# DOC/contracts — Contrats d'interface Ansible-SecAgent

Un fichier par interface inter-composants. Ces contrats sont la **référence canonique**
pour l'implémentation, les tests et la validation de cohérence.

## Interfaces

| Fichier | Interface | Initiateur → Récepteur | Port |
|---|---|---|---|
| [`REST_PLUGIN.md`](REST_PLUGIN.md) | REST HTTPS | Plugin Ansible / secagent-inventory → secagent-server | 7770 |
| [`REST_ENROLLMENT.md`](REST_ENROLLMENT.md) | REST HTTPS | secagent-minion → secagent-server (enrollment + refresh) | 7770 |
| [`REST_ADMIN.md`](REST_ADMIN.md) | HTTP (interne) | CLI cobra → secagent-server | 7771 |
| [`WEBSOCKET.md`](WEBSOCKET.md) | WSS | secagent-server ↔ secagent-minion (opérationnel) | 7772 |
| [`NATS.md`](NATS.md) | NATS JetStream | secagent-server ↔ secagent-server (HA interne) | 4222 |

## Schéma global

```
Ansible Control Node
  ├── connection plugin ──────────────────────────────────────▶┐
  ├── inventory plugin ────────────────────────────────────────▶│  REST_PLUGIN (7770)
  └── secagent-inventory binary ──────────────────────────────────▶│
                                                                 │
                                                     ┌───────────▼───────────┐
secagent-minion ──── REST_ENROLLMENT (7770) ────────────▶│                       │
secagent-minion ◀─── WEBSOCKET (7772) ──────────────────▶│   secagent-server        │◀──── REST_ADMIN (7771) ◀── CLI
                                                      │                       │
                                                      └───────────┬───────────┘
                                                                  │
                                                        NATS (4222) entre nœuds
```

## Règle de cohérence

Tout champ, code HTTP ou message WS présent dans ces contrats doit être :
1. Implémenté dans le composant émetteur
2. Validé dans le composant récepteur
3. Couvert par un test dans `GO/cmd/*/` (tests unitaires ou d'intégration)
