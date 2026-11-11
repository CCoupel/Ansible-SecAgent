#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
# SPDX-License-Identifier: AGPL-3.0-or-later

# PKI de TEST de la topologie en chaine (#188) : une CA privee et un certificat serveur (chaine complete) dont
# les SAN couvrent toutes les instances de la chaine. Aucune cle privee n'est versionnee : tout est ecrit dans
# $PKI_OUT (defaut : $SECAGENT_PRIVATE_DIR/QUALIF/pki, racine PRIVATE/ du depot ignoree par git, #250).
# NE JAMAIS reutiliser en production.
#
#   bash pki/gen.sh [repertoire_de_sortie]
# Produit : ca.crt (bundle de confiance : REPEATER_CA_FILE, RELAY_CA_BUNDLE), tls.crt + tls.key (TLS_CERT/TLS_KEY).
# ca.key (cle de la CA, #267) est ecrite A PART dans $PKI_CA_OUT (defaut : repertoire frere `pki-ca` de la sortie,
# ex. PRIVATE/QUALIF/pki-ca) : le repertoire de sortie ne contient que ce qui est monte dans les conteneurs (/certs).
# SAN : localhost, 127.0.0.1, secagent-server-a/-b, secagent-child (noms DNS du reseau Compose).
# SAN supplementaires (hote distant, ex. la qualif reelle) : PKI_EXTRA_SAN="IP:192.168.1.218,DNS:qualif.lan"
# (liste separee par des virgules ; defaut vide = comportement inchange, utilise par la CI).
# Choix : UN certificat pour toutes les instances (au lieu d'un par instance) : le Compose monte un seul repertoire
# QUALIF_TLS_DIR ; une CA de test et des SAN explicites suffisent a verifier la chaine TLS sans skip-verify.
# Extensions X.509 EXPLICITES (RFC 5280), independantes de l'openssl.cnf du systeme : Python >= 3.13 active
# VERIFY_X509_STRICT par defaut et OpenSSL 3.5 refuse alors une CA sans keyUsage (« CA cert does not include key usage
# extension », plugin Ansible du poste, 2026-11-11). CA : basicConstraints=critical,CA:TRUE,pathlen:0,
# keyUsage=critical,keyCertSign,cRLSign, SKI/AKI. Feuille (serveur seulement : aucun mTLS) :
# basicConstraints=critical,CA:FALSE, keyUsage=critical,digitalSignature,keyEncipherment, extendedKeyUsage=serverAuth,
# SKI, AKI=keyid (selftest : scripts/ci/qualif_pki_selftest.sh, poignee de main stricte).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
PRIVATE_DIR="${SECAGENT_PRIVATE_DIR:-$REPO/PRIVATE}"
PRIVATE_DIR="${PRIVATE_DIR%/}"
OUT="${1:-${PKI_OUT:-$PRIVATE_DIR/QUALIF/pki}}"
DAYS="${PKI_DAYS:-30}"
# Garde FAIL-CLOSED (#250) : la racine PRIVATE/ n'est jamais creee ici (copie ephemere du depot = refus) ; une racine
# RELATIVE est refusee (elle dependrait du repertoire courant et contournerait la comparaison des chemins).
case "$PRIVATE_DIR" in /*) ;; *) echo "ERREUR : SECAGENT_PRIVATE_DIR=$PRIVATE_DIR n'est pas un chemin absolu : refus (exporter SECAGENT_PRIVATE_DIR=<checkout>/PRIVATE en chemin absolu)." >&2; exit 1 ;; esac
case "$OUT" in
  "$PRIVATE_DIR"|"$PRIVATE_DIR"/*)
    [ -d "$PRIVATE_DIR" ] || { echo "ERREUR : racine des donnees privees introuvable (SECAGENT_PRIVATE_DIR=$PRIVATE_DIR) : refus de generer des cles dans un emplacement ephemere. Creer la racine ou exporter SECAGENT_PRIVATE_DIR=<checkout>/PRIVATE (chemin absolu)." >&2; exit 1; } ;;
esac
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
CA_OUT="${PKI_CA_OUT:-$(dirname "$OUT")/pki-ca}"
case "$CA_OUT" in /*) ;; *) echo "ERREUR : PKI_CA_OUT=$CA_OUT n'est pas un chemin absolu : refus." >&2; exit 1 ;; esac
[ "$CA_OUT" != "$OUT" ] || { echo "ERREUR : PKI_CA_OUT ne doit pas etre le repertoire de sortie (ca.key serait montee dans /certs)." >&2; exit 1; }
( umask 077; mkdir -p "$CA_OUT" ); chmod 700 "$CA_OUT"
# Garde : refuse d'ecrire des cles dans un depot git hors d'un chemin IGNORE (une cle ne doit jamais etre versionnee).
if git -C "$OUT" rev-parse --is-inside-work-tree >/dev/null 2>&1 && ! { git -C "$OUT" check-ignore -q "$OUT/tls.key" && git -C "$OUT" check-ignore -q "$CA_OUT/ca.key"; }; then
  echo "ERREUR : $OUT est dans un depot git et n'est pas ignore : refus de generer des cles (utiliser PRIVATE/QUALIF/pki ou un repertoire hors depot)." >&2
  exit 1
fi
cd "$OUT"
umask 077
# config minimale propre (jamais l'openssl.cnf du systeme : ses x509_extensions par defaut varient selon la distribution)
cat > ca.cnf <<'CNF'
[req]
distinguished_name = dn
x509_extensions = v3_ca
prompt = no
[dn]
CN = secagent-test-ca
[v3_ca]
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
CNF
openssl req -x509 -newkey rsa:2048 -nodes -days "$DAYS" -config ca.cnf \
  -keyout "$CA_OUT/ca.key" -out ca.crt 2>/dev/null
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
keyUsage=critical,digitalSignature,keyEncipherment
basicConstraints=critical,CA:FALSE
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
EXT
openssl x509 -req -in tls.csr -CA ca.crt -CAkey "$CA_OUT/ca.key" -CAcreateserial -days "$DAYS" -extfile san.ext -out tls.crt 2>/dev/null
rm -f tls.csr san.ext ca.srl ca.cnf
# CLE DE TEST JETABLE, generee dans le runner/poste de test, jamais versionnee (garde ci-dessus), JAMAIS POUR LA
# PRODUCTION. 0644 car le conteneur tourne en UID 10001 (autre proprietaire que l'utilisateur du runner) : pas
# d'alternative simple (chown impossible sans root, group_add dependrait du GID du runner) pour une cle de 30 jours.
chmod 644 tls.key tls.crt ca.crt
chmod 600 "$CA_OUT/ca.key"   # la cle de la CA reste dans pki-ca/ et n'est montee nulle part
rm -f ca.key                   # ancienne disposition (< v3.0.6) : plus jamais a cote des fichiers montes
echo "PKI de test ecrite dans $OUT (ca.crt, tls.crt, tls.key) ; ca.key dans $CA_OUT (0600)"
