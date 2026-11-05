# Contribuer à Ansible-SecAgent

Merci de votre intérêt pour Ansible-SecAgent. Ce fichier décrit le flux de contribution, l'accord de contribution (CLA) et l'en-tête de licence obligatoire.

Le projet est distribué sous **AGPL-3.0-or-later** (voir [`LICENSE`](LICENSE)). Code source : <https://github.com/CCoupel/Ansible-SecAgent>.

## Flux de contribution

1. **Ouvrir une issue** décrivant le besoin ou le défaut ([issues](https://github.com/CCoupel/Ansible-SecAgent/issues)) ; les issues sont la source de vérité de l'avancement.
2. **Lire la documentation de référence** avant d'implémenter : `DOC/common/ARCHITECTURE.md`, `DOC/security/SECURITY.md` et la spécification du composant concerné (`DOC/server/`, `DOC/agent/`, `DOC/inventory/`, `DOC/plugins/`).
3. **Créer une branche** et ouvrir une **pull request** ; le mainteneur la rattache à un milestone et la fusionne dans `main` une fois le milestone validé.
4. **Signer le CLA** (voir ci-dessous) : une pull request dont l'auteur n'a pas signé n'est pas fusionnée.

### Conventions

- **Go** : `gofmt`, erreurs retournées explicitement, pas de `panic` en production, journaux avec `log/slog` ; ne jamais journaliser `become_pass` ni un secret.
- **Python** (plugins Ansible uniquement) : PEP 8, annotations de type, docstrings sur les fonctions publiques ; un fichier `test_<module>.py` par module.
- **Tests** : `JWT_SECRET_KEY=test ADMIN_TOKEN=test go test ./... -v` pour Go, `pytest` pour Python. Toute correction ou fonctionnalité s'accompagne de ses tests.
- **Commits** : messages conventionnels (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`).
- **Sécurité** : une vulnérabilité ne se signale pas dans une issue publique ; voir `DOC/security/SECURITY.md`.

## En-tête de licence (obligatoire)

Tout fichier source `.go`, `.py` ou `.sh` commence par les deux lignes suivantes (après le shebang ou la ligne de codage s'il y en a une ; pour Go, suivies d'une ligne vide) :

```
// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later
```

En Python et en shell, le préfixe est `#` au lieu de `//`.

## Accord de contribution (CLA)

Pour que le projet puisse être distribué, y compris sous d'autres licences que l'AGPL (par exemple une licence commerciale), chaque contributeur accepte le **Harmony Contributor License Agreement 1.0** :

- **individu** : [`CLA.md`](CLA.md) ;
- **entité** (société, association) : [`CLA-entity.md`](CLA-entity.md). Si vous contribuez dans le cadre de votre emploi, l'entité qui vous emploie doit signer cette version.

Vous **conservez la propriété** de votre contribution : le CLA accorde au projet une licence large, non exclusive et irrévocable, et ne transfère pas vos droits.

Le CLA se signe une seule fois, sur votre première pull request, en suivant les instructions que le robot de signature y publie. Si le contrôle CLA reste en échec après votre signature, commentez `recheck` sur la pull request pour le relancer.

Une contribution qui n'est pas de vous, ou dont vous ne détenez pas tous les droits, ne doit pas être soumise sans l'accord de son auteur et la mention de sa licence dans la pull request.

Il n'y a pas de DCO (`Signed-off-by`) : le CLA le remplace.

## Licence des contributions

Sous réserve du CLA, vos contributions sont distribuées sous **AGPL-3.0-or-later**, comme le reste du dépôt.
