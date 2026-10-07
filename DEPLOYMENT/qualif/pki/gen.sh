#!/usr/bin/env bash
# PKI de TEST de la topologie en chaine (#188) : une CA privee et un certificat serveur (chaine complete) dont
# les SAN couvrent toutes les instances de la chaine. Aucune cle privee n'est versionnee : tout est ecrit dans
# $PKI_OUT (defaut : ce repertoire/out, ignore par git). NE JAMAIS reutiliser en production.
#
#   bash pki/gen.sh [repertoire_de_sortie]
# Produit : ca.crt (bundle de confiance : REPEATER_CA_FILE, RELAY_CA_BUNDLE), tls.crt + tls.key (TLS_CERT/TLS_KEY).
# SAN : localhost, 127.0.0.1, secagent-server-a/-b, secagent-child (noms DNS du reseau Compose).
# SAN supplementaires (hote distant, ex. la qualif reelle) : PKI_EXTRA_SAN="IP:192.168.1.218,DNS:qualif.lan"
# (liste separee par des virgules ; defaut vide = comportement inchange, utilise par la CI).
# Choix : UN certificat pour toutes les instances (au lieu d'un par instance) : le Compose monte un seul repertoire
# QUALIF_TLS_DIR ; une CA de test et des SAN explicites suffisent a verifier la chaine TLS sans skip-verify.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${1:-${PKI_OUT:-$HERE/out}}"
DAYS="${PKI_DAYS:-30}"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
# Garde : refuse d'ecrire des cles dans un depot git hors d'un chemin IGNORE (une cle ne doit jamais etre versionnee).
if git -C "$OUT" rev-parse --is-inside-work-tree >/dev/null 2>&1 && ! { git -C "$OUT" check-ignore -q "$OUT/tls.key" && git -C "$OUT" check-ignore -q "$OUT/ca.key"; }; then
  echo "ERREUR : $OUT est dans un depot git et n'est pas ignore : refus de generer des cles (utiliser pki/out ou un repertoire hors depot)." >&2
  exit 1
fi
cd "$OUT"
umask 077
openssl req -x509 -newkey rsa:2048 -nodes -days "$DAYS" -subj "/CN=secagent-test-ca" \
  -keyout ca.key -out ca.crt 2>/dev/null
openssl req -newkey rsa:2048 -nodes -subj "/CN=secagent-chain" -keyout tls.key -out tls.csr 2>/dev/null
SAN="DNS:localhost,IP:127.0.0.1,DNS:secagent-server-a,DNS:secagent-server-b,DNS:secagent-child"
if [ -n "${PKI_EXTRA_SAN:-}" ]; then
  IFS=',' read -r -a EXTRA <<< "$PKI_EXTRA_SAN"
  for e in "${EXTRA[@]}"; do
    [[ "$e" =~ ^(IP|DNS):[A-Za-z0-9.:_-]{1,253}$ ]] || { echo "ERREUR : SAN supplementaire invalide '$e' (attendu IP:<adresse> ou DNS:<nom>)" >&2; exit 1; }
    SAN="$SAN,$e"
  done
fi
cat > san.ext <<EXT
subjectAltName=$SAN
extendedKeyUsage=serverAuth
keyUsage=digitalSignature,keyEncipherment
basicConstraints=CA:FALSE
EXT
openssl x509 -req -in tls.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days "$DAYS" -extfile san.ext -out tls.crt 2>/dev/null
rm -f tls.csr san.ext ca.srl
# CLE DE TEST JETABLE, generee dans le runner/poste de test, jamais versionnee (garde ci-dessus), JAMAIS POUR LA
# PRODUCTION. 0644 car le conteneur tourne en UID 10001 (autre proprietaire que l'utilisateur du runner) : pas
# d'alternative simple (chown impossible sans root, group_add dependrait du GID du runner) pour une cle de 30 jours.
chmod 644 tls.key tls.crt ca.crt
chmod 600 ca.key   # la cle de la CA ne sort jamais du repertoire et n'est montee nulle part
echo "PKI de test ecrite dans $OUT (ca.crt, tls.crt, tls.key ; ca.key conservee en 0600)"
