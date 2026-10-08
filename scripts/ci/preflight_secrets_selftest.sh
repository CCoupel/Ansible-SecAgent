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
ROOT_LINK_KEY_FILE="$T/pub" expect 0 "enfant complet" run --child
chmod 0666 "$T/pub"
ROOT_LINK_KEY_FILE="$T/pub" expect 1 "cle racine inscriptible par les autres refusee" run --child
printf 'nouveau' | SECRETS_DIR="$T/s" "$P" --write admin_token >/dev/null 2>&1
[ "$(stat -c %a "$T/s/admin_token")" = 400 ] && [ "$(cat "$T/s/admin_token")" = nouveau ] && echo "ok   --write (0400, valeur ecrite)" || { echo "KO   --write"; FAIL=1; }
SECRETS_DIR="$T/s" "$P" --write admin_token </dev/null >/dev/null 2>&1; [ $? -ne 0 ] && echo "ok   --write valeur vide refusee" || { echo "KO   --write vide"; FAIL=1; }
exit $FAIL
