#!/usr/bin/env bash
# Autotest de l'entrypoint de l'image minion (extrait de GO/Dockerfile.agent) : avec au moins un argument il passe la main
# au binaire IMMEDIATEMENT (aucune cle RSA, aucun mkdir, aucun chown, meme pour un argument inconnu) ; sans argument il
# initialise puis demarre. Les commandes sensibles sont des FAUX qui journalisent leur appel (PATH reduit au dossier des
# faux) : un appel avant l'exec se voit dans le journal. Aucune commande reelle, aucun droit root.
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
DF="${1:-$REPO/GO/Dockerfile.agent}"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
FAIL=0
chk() { if [ "$2" = 1 ]; then echo "ok   $1"; else echo "KO   $1"; FAIL=1; fi; }
# extraction du script : entre « <<'EOF' /app/entrypoint.sh » et la ligne « EOF »
awk "/<<'EOF' \/app\/entrypoint\.sh/ {f=1; next} f && /^EOF\$/ {exit} f {print}" "$DF" > "$T/entrypoint.sh"
[ -s "$T/entrypoint.sh" ] || { echo "KO   entrypoint.sh introuvable dans $DF"; exit 1; }
BIN="$T/bin"; mkdir -p "$BIN"
for c in openssl chown mkdir chmod dirname; do
  printf '#!/bin/sh\necho "%s $*" >> "$CALLS"\n' "$c" > "$BIN/$c"; chmod +x "$BIN/$c"
done
# su-exec FAUX : journalise l'identite et la commande, n'execute rien
printf '#!/bin/sh\necho "su-exec $*" >> "$CALLS"\nexit 0\n' > "$BIN/su-exec"; chmod +x "$BIN/su-exec"
run() { # $1 nom du cas, reste : arguments de l'entrypoint ; CALLS = journal des appels
  CALLS="$T/calls.$1"; : > "$CALLS"; export CALLS; local n="$1"; shift
  PATH="$BIN" RELAY_PRIVATE_KEY="$T/data/id_rsa" RELAY_JWT_PATH="$T/data/token.jwt" RELAY_ASYNC_DIR="$T/data/async" \
    /bin/sh "$T/entrypoint.sh" "$@" >/dev/null 2>&1; echo $? > "$T/rc.$n"
}
only_exec() { [ "$(wc -l < "$T/calls.$1")" = 1 ] && grep -q "^su-exec relay /app/secagent-minion" "$T/calls.$1"; }
run version --version
chk "--version : une seule action, l'exec su-exec relay du binaire" $(only_exec version && grep -q -- '--version$' "$T/calls.version" && echo 1 || echo 0)
chk "--version : ni openssl, ni chown, ni mkdir, ni chmod" $(grep -qE '^(openssl|chown|mkdir|chmod|dirname)' "$T/calls.version" && echo 0 || echo 1)
chk "--version : aucun fichier cree" $([ ! -e "$T/data" ] && echo 1 || echo 0)
run help -h; chk "-h : exec immediat" $(only_exec help && echo 1 || echo 0)
run unknown kyes; chk "argument inconnu : exec immediat (le binaire le refuse), aucune cle generee" $(only_exec unknown && ! grep -q '^openssl' "$T/calls.unknown" && echo 1 || echo 0)
run two --version extra; chk "plusieurs arguments : exec immediat avec tous" $(only_exec two && grep -q -- '--version extra$' "$T/calls.two" && echo 1 || echo 0)
run empty ""; chk "argument vide : exec immediat aussi" $(only_exec empty && echo 1 || echo 0)
run noargs
chk "sans argument : cle RSA generee" $(grep -q '^openssl genrsa' "$T/calls.noargs" && echo 1 || echo 0)
chk "sans argument : mkdir et chown executes" $(grep -q '^mkdir' "$T/calls.noargs" && grep -q '^chown' "$T/calls.noargs" && echo 1 || echo 0)
chk "sans argument : demarre le binaire en tant que relay, sans argument" $(tail -n 1 "$T/calls.noargs" | grep -qx 'su-exec relay /app/secagent-minion' && echo 1 || echo 0)
exit $FAIL
