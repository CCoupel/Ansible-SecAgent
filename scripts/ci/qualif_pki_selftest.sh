#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
# SPDX-License-Identifier: AGPL-3.0-or-later

# Autotest des generateurs de certificats de TEST de la qualif : DEPLOYMENT/qualif/pki/gen.sh (CA + feuille de la
# chaine) et gen_ci_tls de DEPLOYMENT/qualif/failover-test.sh (certificat jetable de setup-ci). Verifie les extensions
# X.509 (RFC 5280) puis une poignee de main TLS STRICTE : Python `ssl.create_default_context(cafile=...)` avec
# VERIFY_X509_STRICT (defaut de Python >= 3.13, force ici pour les Python plus anciens du runner) contre un
# `openssl s_server` local sur la boucle locale, arrete par son PID. Temoin negatif : une CA sans keyUsage (ancienne
# generation) doit etre REFUSEE, sinon le controle ne prouverait rien. Tout est genere dans un repertoire temporaire ;
# rien dans PRIVATE/. Prerequis : openssl, python3.
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
Q="$HERE/../../DEPLOYMENT/qualif"
T="$(mktemp -d)"; SP=""
cleanup() { [ -z "$SP" ] || kill "$SP" 2>/dev/null; rm -rf "$T"; }
trap cleanup EXIT
bad=0
ok() { echo "ok   $*"; }
ko() { echo "KO   $*"; bad=1; }
ext() { openssl x509 -in "$1" -noout -ext "$2" 2>/dev/null | tr -s ' \n' ' ' | sed 's/ $//'; }
has() { # $1 nom, $2 certificat, $3 extension, $4 valeur attendue (sous-chaine exacte)
  local v; v="$(ext "$2" "$3")"
  case "$v" in *"$4"*) ok "$1 : $3 = $4" ;; *) ko "$1 : $3 = '$v' (attendu '$4')" ;; esac
}

cat > "$T/hs.py" <<'EOF'
import socket, ssl, sys
ca, port, host = sys.argv[1], int(sys.argv[2]), sys.argv[3]
ctx = ssl.create_default_context(cafile=ca)
ctx.verify_flags |= ssl.VERIFY_X509_STRICT   # defaut de Python >= 3.13 ; force pour les Python plus anciens
try:
    with socket.create_connection(("127.0.0.1", port), timeout=5) as s, ctx.wrap_socket(s, server_hostname=host) as t:
        print("HANDSHAKE OK", t.version())
except ssl.SSLError as e:
    print("HANDSHAKE ECHEC", e)
    sys.exit(1)
EOF
# $1 certificat serveur, $2 cle, $3 bundle de confiance, $4 nom verifie ; sortie dans $HS, code de retour = poignee de main
handshake() {
  local port rc
  port="$(python3 -I -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')"
  openssl s_server -accept "127.0.0.1:$port" -cert "$1" -key "$2" -quiet < /dev/null > "$T/s_server.log" 2>&1 &
  SP=$!
  for _ in $(seq 1 50); do
    python3 -I -c "import socket,sys; socket.create_connection(('127.0.0.1', $port), timeout=1).close()" 2>/dev/null && break
    sleep 0.1
  done
  HS="$(python3 -I "$T/hs.py" "$3" "$port" "$4" 2>&1)"; rc=$?
  kill "$SP" 2>/dev/null; wait "$SP" 2>/dev/null; SP=""
  return $rc
}

echo "python3 $(python3 -I -c 'import ssl, sys; print(sys.version.split()[0], "|", ssl.OPENSSL_VERSION)') ; $(openssl version)"

# --- gen.sh : CA + feuille -------------------------------------------------------------------------------------------
P="$T/QUALIF/pki"
if SECAGENT_PRIVATE_DIR="$T" PKI_EXTRA_SAN="IP:192.168.1.218,DNS:qualif.lan" bash "$Q/pki/gen.sh" "$P" > /dev/null 2>&1; then
  ok "gen.sh : PKI generee (repertoire temporaire)"
else
  ko "gen.sh : echec"; exit 1
fi
[ "$(ls -A "$P" | LC_ALL=C sort | tr '\n' ' ')" = "ca.crt tls.crt tls.key " ] && ok "gen.sh : pki/ ne contient que ca.crt, tls.crt, tls.key (ca.cnf retire)" \
  || ko "gen.sh : contenu de pki/ : $(ls -A "$P")"
[ -f "$T/QUALIF/pki-ca/ca.key" ] && ok "gen.sh : ca.key dans pki-ca/" || ko "gen.sh : ca.key absente de pki-ca/"
has "CA" "$P/ca.crt" basicConstraints "critical CA:TRUE, pathlen:0"
has "CA" "$P/ca.crt" keyUsage "critical Certificate Sign, CRL Sign"
has "CA" "$P/ca.crt" subjectKeyIdentifier "Subject Key Identifier"
[ -z "$(ext "$P/ca.crt" extendedKeyUsage)" ] && ok "CA : pas d'extendedKeyUsage" || ko "CA : extendedKeyUsage inattendu"
has "feuille" "$P/tls.crt" basicConstraints "critical CA:FALSE"
has "feuille" "$P/tls.crt" keyUsage "critical Digital Signature, Key Encipherment"
has "feuille" "$P/tls.crt" extendedKeyUsage "TLS Web Server Authentication"
has "feuille" "$P/tls.crt" subjectAltName "DNS:localhost, IP Address:127.0.0.1, DNS:secagent-server-a, DNS:secagent-server-b, DNS:secagent-child, IP Address:192.168.1.218, DNS:qualif.lan"
ski="$(ext "$P/ca.crt" subjectKeyIdentifier | awk '{print $NF}')"
aki="$(ext "$P/tls.crt" authorityKeyIdentifier | awk '{print $NF}')"
[ -n "$ski" ] && [ "$ski" = "$aki" ] && ok "feuille : authorityKeyIdentifier = SKI de la CA" || ko "feuille : AKI '$aki' != SKI de la CA '$ski'"
openssl verify -x509_strict -purpose sslserver -CAfile "$P/ca.crt" "$P/tls.crt" > /dev/null 2>&1 \
  && ok "openssl verify -x509_strict -purpose sslserver" || ko "openssl verify -x509_strict : $(openssl verify -x509_strict -CAfile "$P/ca.crt" "$P/tls.crt" 2>&1)"
for h in localhost secagent-server-a 127.0.0.1 192.168.1.218; do
  if handshake "$P/tls.crt" "$P/tls.key" "$P/ca.crt" "$h"; then ok "poignee de main stricte ($h) : $HS"; else ko "poignee de main stricte ($h) : $HS"; fi
done
handshake "$P/tls.crt" "$P/tls.key" "$P/ca.crt" autre-nom && ko "nom hors SAN accepte : $HS" || ok "nom hors SAN refuse (verification d'hote active)"

# --- temoin negatif : CA de l'ancienne generation (openssl.cnf systeme, sans keyUsage) --------------------------------
N="$T/neg"; mkdir -p "$N"
printf '%s\n' '[req]' 'distinguished_name = dn' 'x509_extensions = v3' 'prompt = no' '[dn]' 'CN = ancienne-ca' '[v3]' \
  'basicConstraints = critical,CA:TRUE' 'subjectKeyIdentifier = hash' > "$N/ca.cnf"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -config "$N/ca.cnf" -keyout "$N/ca.key" -out "$N/ca.crt" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -subj "/CN=x" -keyout "$N/tls.key" -out "$N/tls.csr" 2>/dev/null
printf 'subjectAltName=DNS:localhost\nbasicConstraints=CA:FALSE\n' > "$N/san.ext"
openssl x509 -req -in "$N/tls.csr" -CA "$N/ca.crt" -CAkey "$N/ca.key" -CAcreateserial -days 1 -extfile "$N/san.ext" -out "$N/tls.crt" 2>/dev/null
if handshake "$N/tls.crt" "$N/tls.key" "$N/ca.crt" localhost; then
  ko "temoin : CA sans keyUsage ACCEPTEE (le controle strict ne prouve rien) : $HS"
else
  case "$HS" in *"key usage"*) ok "temoin : CA sans keyUsage refusee ($(printf '%s' "$HS" | grep -o 'CA cert does not include key usage extension' || echo "$HS"))" ;;
    *) ko "temoin : refus pour une autre raison : $HS" ;; esac
fi

# --- failover-test.sh : certificat jetable de setup-ci (auto-signe) ---------------------------------------------------
C="$T/ci-tls"; mkdir -p "$C" "$T/priv"
if env -u TLS_MODE -u DOCKER_HOST SECAGENT_PRIVATE_DIR="$T/priv" bash -c 'source "$1"; gen_ci_tls "$2"' _ "$Q/failover-test.sh" "$C" > /dev/null 2>&1; then
  ok "gen_ci_tls : certificat genere"
else
  ko "gen_ci_tls : echec"
fi
[ "$(ls -A "$C" | LC_ALL=C sort | tr '\n' ' ')" = "tls.crt tls.key " ] && ok "gen_ci_tls : seuls tls.crt et tls.key (config retiree)" || ko "gen_ci_tls : contenu $(ls -A "$C")"
[ "$(stat -c %a "$C/tls.key")" = 644 ] && ok "gen_ci_tls : tls.key 0644 (UID 10001 du conteneur)" || ko "gen_ci_tls : mode $(stat -c %a "$C/tls.key")"
has "ci-tls" "$C/tls.crt" basicConstraints "critical CA:FALSE"
has "ci-tls" "$C/tls.crt" keyUsage "critical Digital Signature, Key Encipherment"
has "ci-tls" "$C/tls.crt" extendedKeyUsage "TLS Web Server Authentication"
has "ci-tls" "$C/tls.crt" subjectAltName "DNS:localhost, IP Address:127.0.0.1"
if handshake "$C/tls.crt" "$C/tls.key" "$C/tls.crt" localhost; then ok "ci-tls : poignee de main stricte (certificat lui-meme en confiance) : $HS"; else ko "ci-tls : poignee de main stricte : $HS"; fi

exit $bad
