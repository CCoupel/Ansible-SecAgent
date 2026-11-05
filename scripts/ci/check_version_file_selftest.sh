#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
# SPDX-License-Identifier: AGPL-3.0-or-later

# Autotest de check_version_file.sh sur des fichiers synthetiques (aucun acces au depot).
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
FAIL=0
run() { bash "$HERE/check_version_file.sh" "$@" >"$T/out" 2>&1; echo $?; }
chk() { local name="$1" want="$2"; shift 2; local got; got=$(run "$@")
  if [ "$got" = "$want" ]; then echo "ok   $name"; else echo "KO   $name (rc $got, attendu $want) : $(cat "$T/out")"; FAIL=1; fi; }
w() { printf "$2" > "$T/$1"; echo "$T/$1"; }
chk "3.0.5 + LF conforme"                    0 "$(w a '3.0.5\n')"
chk "egal a --expect"                        0 --expect 3.0.5 "$(w b '3.0.5\n')"
chk "different de --expect refuse"           1 --expect 3.0.6 "$(w c '3.0.5\n')"
chk "prefixe v refuse"                       1 "$(w d 'v3.0.5\n')"
chk "suffixe -rc1 refuse"                    1 "$(w e '3.0.5-rc1\n')"
chk "compteur de build X.Y.Z.a refuse"       1 "$(w f '3.0.5.2\n')"
chk "zero non significatif refuse"           1 "$(w g '3.05.1\n')"
chk "sans LF final refuse"                   1 "$(w h '3.0.5')"
chk "CRLF refuse"                            1 "$(w i '3.0.5\r\n')"
chk "deux lignes refuse"                     1 "$(w j '3.0.5\n3.0.6\n')"
chk "espace final refuse"                    1 "$(w k '3.0.5 \n')"
chk "fichier vide refuse"                    1 "$(w l '')"
chk "fichier absent refuse"                  1 "$T/absent"
ln -s "$T/a" "$T/lien"
chk "lien symbolique refuse"                 1 "$T/lien"
chk "--expect invalide = usage"              2 --expect v3.0.5 "$T/a"
exit $FAIL
