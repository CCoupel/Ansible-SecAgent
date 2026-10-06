#!/usr/bin/env bash
# PKI de TEST de la topologie en chaine (#188) : une CA privee et un certificat serveur (chaine complete) dont
# les SAN couvrent toutes les instances de la chaine. Aucune cle privee n'est versionnee : tout est ecrit dans
# $PKI_OUT (defaut : ce repertoire/out, ignore par git). NE JAMAIS reutiliser en production.
#
#   bash pki/gen.sh [repertoire_de_sortie]
# Produit : ca.crt (bundle de confiance : REPEATER_CA_FILE, RELAY_CA_BUNDLE), tls.crt + tls.key (TLS_CERT/TLS_KEY).
# SAN : localhost, 127.0.0.1, secagent-server-a/-b, secagent-child (noms DNS du reseau Compose).
# Choix : UN certificat pour toutes les instances (au lieu d'un par instance) : le Compose monte un seul repertoire
# QUALIF_TLS_DIR ; une CA de test et des SAN explicites suffisent a verifier la chaine TLS sans skip-verify.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${1:-${PKI_OUT:-$HERE/out}}"
DAYS="${PKI_DAYS:-30}"
mkdir -p "$OUT"
cd "$OUT"
umask 077
openssl req -x509 -newkey rsa:2048 -nodes -days "$DAYS" -subj "/CN=secagent-test-ca" \
  -keyout ca.key -out ca.crt 2>/dev/null
openssl req -newkey rsa:2048 -nodes -subj "/CN=secagent-chain" -keyout tls.key -out tls.csr 2>/dev/null
cat > san.ext <<'EXT'
subjectAltName=DNS:localhost,IP:127.0.0.1,DNS:secagent-server-a,DNS:secagent-server-b,DNS:secagent-child
extendedKeyUsage=serverAuth
keyUsage=digitalSignature,keyEncipherment
basicConstraints=CA:FALSE
EXT
openssl x509 -req -in tls.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days "$DAYS" -extfile san.ext -out tls.crt 2>/dev/null
rm -f tls.csr san.ext ca.srl
# Le conteneur tourne en UID 10001 (autre proprietaire) : la cle doit etre lisible ; certificat jetable de test.
chmod 644 tls.key tls.crt ca.crt
chmod 600 ca.key   # la cle de la CA ne sort jamais du repertoire et n'est montee nulle part
echo "PKI de test ecrite dans $OUT (ca.crt, tls.crt, tls.key ; ca.key conservee en 0600)"
