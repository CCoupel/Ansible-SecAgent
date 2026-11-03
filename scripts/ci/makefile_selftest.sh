#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
# SPDX-License-Identifier: AGPL-3.0-or-later

# Autotest de GO/Makefile (#224) sans compiler ni lancer les tests Go : `make -n` (affiche les commandes sans les
# executer). Prouve que les cibles existent, visent des paquets REELS du depot et que `test` porte les variables
# d'environnement des tests. Le Makefile etait perime (./cmd/server, relay-server : des chemins qui n'existent plus).
# Si GO/Makefile est supprime (autre issue possible de #224), l'autotest le constate et reussit : il n'y a rien a prouver.
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GO_DIR="$HERE/../../GO"
FAIL=0
chk() { local what="$1" ok="$2"; if [ "$ok" = 1 ]; then echo "ok   $what"; else echo "KO   $what"; FAIL=1; fi; }
if [ ! -f "$GO_DIR/Makefile" ]; then
  echo "ok   GO/Makefile supprime : rien a prouver"
  exit 0
fi
if ! command -v make >/dev/null 2>&1; then
  if [ -n "${CI:-}" ]; then echo "KO   make est introuvable sur le runner"; exit 1; fi
  echo "skip make est introuvable (poste local sans make) : l'autotest est joue par la CI"
  exit 0
fi
dry() { make -n -C "$GO_DIR" "$@" 2>&1; }

# 1. aucun chemin perime
chk "aucune reference a ./cmd/server (paquet inexistant)" $(! grep -n -E '\./cmd/server([^-a-z]|$)' "$GO_DIR/Makefile" >/dev/null && echo 1 || echo 0)
chk "aucune reference a relay-server (ancien binaire)" $(! grep -n 'relay-server' "$GO_DIR/Makefile" >/dev/null && echo 1 || echo 0)

# 2. `make build` compile les trois binaires, depuis des paquets qui existent
OUT="$(dry build)"; rc=$?
chk "make -n build reussit (rc 0)" $([ $rc -eq 0 ] && echo 1 || echo 0)
for bin in secagent-server secagent-minion secagent-inventory; do
  [ -d "$GO_DIR/cmd/$bin" ] || { chk "le paquet GO/cmd/$bin existe" 0; continue; }
  chk "make build vise ./cmd/$bin" $(printf '%s' "$OUT" | grep -q "\./cmd/$bin" && echo 1 || echo 0)
done
# chaque paquet vise par une commande go build existe vraiment
MISSING=0
for pkg in $(printf '%s' "$OUT" | grep -o '\./cmd/[A-Za-z0-9_-]*' | sort -u); do
  [ -d "$GO_DIR/$pkg" ] || { echo "     paquet inexistant : $pkg"; MISSING=1; }
done
chk "tous les paquets vises par make build existent" $([ $MISSING -eq 0 ] && echo 1 || echo 0)

# 3. cibles individuelles (#224 : secagent-server | secagent-minion | secagent-inventory)
for t in secagent-server secagent-minion secagent-inventory; do
  O="$(dry "$t")"; r=$?
  chk "make -n $t reussit et compile ./cmd/$t" $([ $r -eq 0 ] && printf '%s' "$O" | grep -q "\./cmd/$t" && echo 1 || echo 0)
done

# 4. `make test` : go test du module avec les variables requises par les tests
OUT="$(dry test)"; rc=$?
chk "make -n test reussit (rc 0)" $([ $rc -eq 0 ] && echo 1 || echo 0)
chk "make test lance go test" $(printf '%s' "$OUT" | grep -q 'go test' && echo 1 || echo 0)
chk "make test fixe JWT_SECRET_KEY=test et ADMIN_TOKEN=test" $(printf '%s' "$OUT" | grep -q 'JWT_SECRET_KEY=test' && printf '%s' "$OUT" | grep -q 'ADMIN_TOKEN=test' && echo 1 || echo 0)
chk "make test couvre tout le module (./...)" $(printf '%s' "$OUT" | grep -q '\./\.\.\.' && echo 1 || echo 0)
exit $FAIL
