# DOC/contracts — Contrats d'interface Ansible-SecAgent

Un fichier par interface inter-composants. Ces contrats sont la **référence canonique**
pour l'implémentation, les tests et la validation de cohérence.

## Interfaces

| Fichier | Interface | Initiateur → Récepteur | Port |
|---|---|---|---|
| [`REST_PLUGIN.md`](REST_PLUGIN.md) | REST HTTPS | Plugin Ansible / secagent-inventory → secagent-server | 7770 |
| [`REST_ENROLLMENT.md`](REST_ENROLLMENT.md) | REST HTTPS | secagent-minion → secagent-server (enrôlement ; la route de refresh a été supprimée) | 7770 |
| [`REST_ADMIN.md`](REST_ADMIN.md) | HTTPS (`ADMIN_TLS=true`) ou HTTP sur boucle locale | CLI cobra → secagent-server | 7771 |
| [`WEBSOCKET.md`](WEBSOCKET.md) | WSS | secagent-server ↔ secagent-minion (opérationnel) | 7772 |
| [`NATS.md`](NATS.md) | **RETIRÉ en v3.0.3 (#178)** — archive historique, pas un contrat vivant | — | — |

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
                                       actif/passif : état fichier (STATE_DIR) + verrou, sans bus de messages
```

## Règle de cohérence

Tout champ, code HTTP ou message WS présent dans ces contrats doit être :
1. Implémenté dans le composant émetteur
2. Validé dans le composant récepteur
3. Couvert par un test dans `GO/cmd/*/` (tests unitaires ou d'intégration)
