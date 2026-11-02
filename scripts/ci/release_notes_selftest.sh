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
# #224 : cas « prefixe inverse » — le CHANGELOG ne contient que `## [v3.0.40]`, on demande v3.0.4. Une correspondance par
# prefixe (mutant) accepterait la section de v3.0.40 et publierait de mauvaises notes.
printf '## [v3.0.40] — date — Autre\n\n- notes de la 3.0.40\n\n## [v3.0.3] — d\n- x\n' > "$T/reverse.md"
bash "$R" v3.0.4 "$T/reverse.md" >/dev/null 2>&1; chk "prefixe inverse refuse (v3.0.4 demande, seul ## [v3.0.40] present)" $([ $? -eq 1 ] && echo 1 || echo 0)
printf '## [v3.0.4-rc1] — date\n\n- rc\n' > "$T/rc.md"
bash "$R" v3.0.4 "$T/rc.md" >/dev/null 2>&1; chk "suffixe refuse (## [v3.0.4-rc1] n'est pas v3.0.4)" $([ $? -eq 1 ] && echo 1 || echo 0)
printf '## [v13.0.4] — date\n\n- autre\n' > "$T/infix.md"
bash "$R" v3.0.4 "$T/infix.md" >/dev/null 2>&1; chk "sous-chaine refusee (## [v13.0.4] n'est pas v3.0.4)" $([ $? -eq 1 ] && echo 1 || echo 0)
# Le mutant « correspondance par prefixe » (le crochet fermant retire de la comparaison) doit etre TUE par ces cas, et il
# SURVIVAIT au seul cas v3.0.40-demande-a-v3.0.4 (O2 de la QA v3.0.4) : on le prouve en l'executant.
sed 's/index(\$0, "\[" tag "\]")/index($0, "[" tag)/' "$R" > "$T/release_notes_mutant.sh"
if cmp -s "$R" "$T/release_notes_mutant.sh"; then
  chk "mutant prefixe fabrique (le motif de release_notes.sh a change : adapter ce selftest)" 0
else
  bash "$T/release_notes_mutant.sh" v3.0.40 "$T/good.md" >/dev/null 2>&1
  chk "mutant prefixe SURVIT a l'ancien cas (v3.0.40 demande a un CHANGELOG v3.0.4) : le cas seul ne suffisait pas" $([ $? -eq 1 ] && echo 1 || echo 0)
  bash "$T/release_notes_mutant.sh" v3.0.4 "$T/reverse.md" >/dev/null 2>&1
  chk "mutant prefixe TUE par le cas inverse (il accepte la section v3.0.40)" $([ $? -eq 0 ] && echo 1 || echo 0)
fi
exit $FAIL
