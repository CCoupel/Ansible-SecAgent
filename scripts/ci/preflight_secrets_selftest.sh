#!/usr/bin/env bash
# Autotest de DEPLOYMENT/prod/preflight-secrets.sh : SECRET_OWNER_UID = uid courant (aucun droit root requis).
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
P="$HERE/../../DEPLOYMENT/prod/preflight-secrets.sh"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
export SECRET_OWNER_UID="$(id -u)"
FAIL=0
expect() { # $1 attendu (0|1), $2 description, reste : commande
  local want="$1" what="$2"; shift 2
  "$@" >/dev/null 2>&1; local rc=$?
  if [ "$rc" = "$want" ]; then echo "ok   $what"; else echo "KO   $what (rc=$rc, attendu $want)"; FAIL=1; fi
}
mk() { mkdir -p "$T/s"; for n in jwt_secret_key admin_token rsa_master_key; do printf 'x' > "$T/s/$n"; chmod 0400 "$T/s/$n"; done; }
run() { SECRETS_DIR="$T/s" "$P" "$@"; }
mk;                                     expect 0 "3 secrets 0400 du bon proprietaire" run
chmod 0600 "$T/s/admin_token";          expect 0 "0600 accepte" run
chmod 0644 "$T/s/admin_token";          expect 1 "0644 refuse" run
chmod 0440 "$T/s/admin_token";          expect 1 "0440 refuse" run
chmod 0400 "$T/s/admin_token"
rm "$T/s/rsa_master_key";               expect 1 "fichier absent refuse" run
mkdir "$T/s/rsa_master_key";            expect 1 "repertoire a la place du fichier refuse" run
rmdir "$T/s/rsa_master_key"; printf 'x' > "$T/real"; chmod 0400 "$T/real"; ln -s "$T/real" "$T/s/rsa_master_key"
                                        expect 1 "lien symbolique refuse" run
rm "$T/s/rsa_master_key"; : > "$T/s/rsa_master_key"; chmod 0400 "$T/s/rsa_master_key"
                                        expect 1 "fichier vide refuse" run
chmod 0600 "$T/s/rsa_master_key"; printf x > "$T/s/rsa_master_key"; chmod 0400 "$T/s/rsa_master_key"
SECRET_OWNER_UID=1 expect 1 "mauvais proprietaire refuse" run
                                        expect 1 "enfant sans repeater_upstream_token ni cle racine refuse" run --child
printf 'tok' > "$T/s/repeater_upstream_token"; chmod 0400 "$T/s/repeater_upstream_token"
printf 'pub' > "$T/pub"; chmod 0644 "$T/pub"
export REPEATER_UPSTREAM_URL="wss://relay-a.example:7772, wss://relay-b.example:7772"
ROOT_LINK_KEY_FILE="$T/pub" expect 0 "enfant complet" run --child
# #232 / B17 : liste d'adresses du parent obligatoire, wss://<hote>[:port] sans identifiants ; la valeur n'est jamais affichee
up() { local want="$1" what="$2" v="$3" out rc
  out="$(REPEATER_UPSTREAM_URL="$v" ROOT_LINK_KEY_FILE="$T/pub" SECRETS_DIR="$T/s" "$P" --child 2>&1)"; rc=$?
  if [ "$rc" != "$want" ]; then echo "KO   $what (rc=$rc, attendu $want)"; FAIL=1
  elif printf '%s' "$out" | grep -qE 'relay-[ab]\.example|s3cret|user:|r1[0-7]?:7772'; then echo "KO   $what (valeur affichee)"; FAIL=1
  else echo "ok   $what"; fi; }
up 0 "upstream : [::1] et port"               "wss://[::1]:7772"
up 0 "upstream : WSS:// accepte comme le serveur" "WSS://relay-a.example:7772"
up 1 "upstream : vide refusee"                ""
up 1 "upstream : espaces seuls refusee"       "   "
(unset REPEATER_UPSTREAM_URL; ROOT_LINK_KEY_FILE="$T/pub" expect 1 "upstream : absente refusee" run --child)
up 1 "upstream : https:// refuse"             "https://relay-a.example:7770"
up 1 "upstream : ws:// refuse"                "ws://relay-a.example:7772"
up 1 "upstream : sans schema refuse"          "relay-a.example:7772"
up 1 "upstream : hote vide refuse"            "wss://:7772"
up 1 "upstream : hote vide sans port refuse"  "wss://"
up 1 "upstream : identifiants refuses"        "wss://user:s3cret@relay-a.example:7772"
up 1 "upstream : adresse vide dans la liste"  "wss://relay-a.example:7772,,wss://relay-b.example:7772"
up 1 "upstream : virgule finale refusee"      "wss://relay-a.example:7772,"
up 1 "upstream : 17 adresses refusees"        "$(for n in $(seq 1 17); do printf 'wss://r%s:7772,' "$n"; done | sed 's/,$//')"
chmod 0666 "$T/pub"
ROOT_LINK_KEY_FILE="$T/pub" expect 1 "cle racine inscriptible par les autres refusee" run --child
printf 'nouveau' | SECRETS_DIR="$T/s" "$P" --write admin_token >/dev/null 2>&1
[ "$(stat -c %a "$T/s/admin_token")" = 400 ] && [ "$(cat "$T/s/admin_token")" = nouveau ] && echo "ok   --write (0400, valeur ecrite)" || { echo "KO   --write"; FAIL=1; }
SECRETS_DIR="$T/s" "$P" --write admin_token </dev/null >/dev/null 2>&1; [ $? -ne 0 ] && echo "ok   --write valeur vide refusee" || { echo "KO   --write vide"; FAIL=1; }
exit $FAIL
