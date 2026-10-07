# Verrou d'exclusivité du maître (v3.0.3, #162, variante A)

Package `GO/cmd/secagent-server/internal/lock`. Plusieurs instances d'un même relay partagent `STATE_DIR` ; une seule est maître (ports ouverts, écriture de l'état). L'intégration au serveur (promotion, ports, garde `BeforeWrite`) est faite par #163.

## Protocole

- Un seul fichier `relay.lock`. Contenu : `{"instance_id","role":"candidate"|"master","beat","host"}`. `instance_id` : 128 bits aléatoires, régénérés à **chaque démarrage du process**.
- **Candidat** : création exclusive (`O_CREAT|O_EXCL`, 0755), descripteur gardé ouvert pour toute la vie du verrou.
- **Maître** : pause aléatoire 1-2 s, **relecture par réouverture** ; seulement si le contenu porte son propre `instance_id` : `fchmod 0700` sur le descripteur, vérification que le chemin désigne toujours son inode, écriture `role: master` + premier battement, relecture de contrôle. Jamais de `chmod` sur le chemin ; on ne touche jamais au fichier d'un autre.
- **Battement** toutes les 30 s (écriture en place + `fsync`) ; **contrôle d'identité** toutes les 5 s ; **auto-retrait** si aucun battement n'a réussi depuis 3 min.
- **Péremption** jugée par l'observateur sur son **horloge monotone locale** (jamais `mtime`) : maître 5 min sans changement du compteur, candidat 10 s. Un verrou périmé est supprimé, puis création exclusive.
- **Garde d'écriture** : `CheckOwnership()` avant toute écriture d'état (compare l'inode d'abord, relit le contenu en dernier : les numéros d'inode sont réutilisés après suppression). Un échec est définitif (`OnLost`).
- **Arrêt propre** : `Release()` supprime le verrou s'il est encore le sien (reprise immédiate).
- Les modes (0755/0700) ne sont qu'une aide visuelle ; l'`instance_id` du contenu fait référence.

## Calibrage (constantes, surchargeables par les tests seulement)

battement 30 s, contrôle 5 s, auto-retrait 3 min, péremption maître 5 min, péremption candidat 10 s, pause 1-2 s, latence d'écriture max 500 ms. Refus de démarrer si : contrôle < battement < auto-retrait < péremption maître ; latence max < pause min ; pause max < péremption candidat.

## Chevauchement résiduel accepté

Une suppression périmée retardée peut effacer un verrou frais : deux instances se croient maîtres au plus une période de contrôle (~5 s). La garde refuse les écritures de l'évincée et son contrôle suivant l'arrête.
