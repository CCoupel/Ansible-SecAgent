#!/usr/bin/env bash
# Autotest de release_notes.sh (CHANGELOG synthetiques).
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
R="$HERE/release_notes.sh"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
FAIL=0
chk() { local what="$1" ok="$2"; if [ "$ok" = 1 ]; then echo "ok   $what"; else echo "KO   $what"; FAIL=1; fi; }
cat > "$T/good.md" <<'MD'
# Changelog

## [Unreleased]

### v3.0.5 — a venir

- rien

## [v3.0.4] — 2026-10-09 — Titre

### Ajouts
- A
- B

## [v3.0.3] — 2026-10-06 — Ancien

- ancien
MD
OUT="$(bash "$R" v3.0.4 "$T/good.md" 2>/dev/null)"; rc=$?
chk "section trouvee (rc 0)" $([ $rc -eq 0 ] && echo 1 || echo 0)
chk "contenu de la section" $(printf '%s' "$OUT" | grep -q '^- A$' && printf '%s' "$OUT" | grep -q '^- B$' && echo 1 || echo 0)
chk "s'arrete a la section suivante" $(printf '%s' "$OUT" | grep -q 'ancien' && echo 0 || echo 1)
chk "n'inclut pas Unreleased" $(printf '%s' "$OUT" | grep -q 'a venir' && echo 0 || echo 1)
bash "$R" v3.0.5 "$T/good.md" >/dev/null 2>&1; chk "tag sans section refuse (### v3.0.5 n'est pas ## [v3.0.5])" $([ $? -eq 1 ] && echo 1 || echo 0)
bash "$R" v3.0.40 "$T/good.md" >/dev/null 2>&1; chk "prefixe de version refuse (v3.0.40)" $([ $? -eq 1 ] && echo 1 || echo 0)
printf '## [Unreleased]\n\n### v3.0.4 — en cours\n\n- X\n' > "$T/unreleased.md"
bash "$R" v3.0.4 "$T/unreleased.md" >/dev/null 2>&1; chk "format actuel (Unreleased + ### v3.0.4) refuse" $([ $? -eq 1 ] && echo 1 || echo 0)
printf '## [v3.0.4] — date\n\n   \n\n## [v3.0.3] — d\n- x\n' > "$T/empty.md"
bash "$R" v3.0.4 "$T/empty.md" >/dev/null 2>&1; chk "section vide refusee" $([ $? -eq 1 ] && echo 1 || echo 0)
printf '## [v3.0.4] — date\n- dernier\n' > "$T/last.md"
bash "$R" v3.0.4 "$T/last.md" >/dev/null 2>&1; chk "derniere section du fichier acceptee" $([ $? -eq 0 ] && echo 1 || echo 0)
bash "$R" 3.0.4 "$T/good.md" >/dev/null 2>&1; chk "tag sans v refuse" $([ $? -eq 2 ] && echo 1 || echo 0)
bash "$R" v3.0.4 "$T/absent.md" >/dev/null 2>&1; chk "fichier absent refuse" $([ $? -eq 2 ] && echo 1 || echo 0)
exit $FAIL
