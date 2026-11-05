#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Auto-test de check_actions_pinned.py (garde d'epinglage des actions, #227 / M6 de la revue securite) sur des
workflows SYNTHETIQUES (aucun fichier du depot, aucun reseau). Exit 0 = conforme.

Trois familles :
  - formes conformes, qui doivent etre ACCEPTEES (aucun faux positif) ;
  - injections de base : tag flottant, SHA court, SHA sans commentaire de version, ${{ }} dans un `run:` ;
  - contournements YAML (M6) : ecritures valides que l'ancienne garde, fondee sur des expressions regulieres ligne par
    ligne, ne voyait pas. Chaque cas est un mutant : il DOIT etre refuse, pour la bonne raison.
PyYAML est requis (en CI : le venv jetable de la garde, .github/ci/requirements-guard.txt)."""
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from check_actions_pinned import check_text, default_files  # noqa: E402

SHA = "11d5960a326750d5838078e36cf38b85af677262"
SHA2 = "40f1582b2485089dde7abd97c1529aa768e1baff"
DIGEST = "sha256:" + "ab" * 32
CHECKOUT = f"actions/checkout@{SHA} # v4.4.0"
# B33 : tout actions/checkout porte with.persist-credentials: false (sinon GITHUB_TOKEN reste dans la config git du job)
PERSIST = "        with:\n          persist-credentials: false\n"
CK = f"      - uses: {CHECKOUT}\n{PERSIST}"  # etape checkout conforme (indentation des steps de wf())


def wf(steps: str, head: str = "") -> str:
    """Un workflow a un job dont `steps` (deja indente de 6 espaces) forme les etapes."""
    return f"name: t\non: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n{head}    steps:\n{steps}"


ACCEPT = [
    ("etape conforme", wf(CK)),
    ("SHA + commentaire de version precise (v7.0.2)", wf(f"      - uses: actions/upload-artifact@{SHA2} # v7.0.2\n")),
    ("action avec sous-chemin", wf(f"      - uses: github/codeql-action/analyze@{SHA} # v3.1.0\n")),
    ("action locale ./.github/actions/x", wf("      - uses: ./.github/actions/setup\n")),
    ("image docker:// epinglee par digest", wf(f"      - uses: docker://alpine@{DIGEST}\n")),
    ("${{ }} dans with:", wf(f"      - uses: {CHECKOUT}\n        with:\n          persist-credentials: false\n          ref: ${{{{ github.sha }}}}\n")),
    ("${{ }} dans env: puis run: sans expression",
     wf("      - env:\n          V: ${{ needs.prepare.outputs.version }}\n        run: |\n          echo \"$V\"\n")),
    ("${{ }} dans name: et if:", wf(f"      - name: v ${{{{ matrix.v }}}}\n        if: ${{{{ github.ref == 'x' }}}}\n        uses: {CHECKOUT}\n{PERSIST}")),
    ("run: sans expression", wf("      - run: |\n          make build\n          echo $HOME\n")),
    ("github-script avec script sans expression",
     wf(f"      - uses: actions/github-script@{SHA} # v7.0.1\n        with:\n          script: |\n            core.info('ok')\n")),
    ("container epingle par digest", wf(CK, head=f"    container: node@{DIGEST}\n")),
    ("services epingles par digest",
     wf(CK, head=f"    services:\n      db:\n        image: postgres@{DIGEST}\n")),
    ("workflow reutilisable epingle", f"on: push\njobs:\n  j:\n    uses: org/repo/.github/workflows/x.yml@{SHA} # v1.2.3\n"),
    ("action composite epinglee", f"name: c\nruns:\n  using: composite\n  steps:\n    - uses: {CHECKOUT}\n      with:\n        persist-credentials: false\n    - run: echo ok\n      shell: bash\n"),
    ("B33 persist-credentials: false (booleen)", wf(CK)),
    ("B33 persist-credentials: 'false' (chaine entre apostrophes)", wf(f"      - uses: {CHECKOUT}\n        with:\n          persist-credentials: 'false'\n")),
    ("B33 persist-credentials: \"false\" (chaine entre guillemets)", wf(f"      - uses: {CHECKOUT}\n        with:\n          persist-credentials: \"false\"\n")),
    ("B33 persist-credentials: False / FALSE (booleens YAML)", wf(f"      - uses: {CHECKOUT}\n        with:\n          persist-credentials: False\n      - uses: actions/checkout@{SHA2} # v4.4.0\n        with:\n          persist-credentials: FALSE\n")),
    ("B33 avec d'autres cles de with:", wf(f"      - uses: {CHECKOUT}\n        with:\n          fetch-depth: 0\n          persist-credentials: false\n          submodules: true\n")),
    ("B33 with: en mapping de flux", wf(f"      - uses: {CHECKOUT}\n        with: {{fetch-depth: 0, persist-credentials: false}}\n")),
    ("B33 une autre action n'est pas concernee (setup-go sans with)", wf(f"      - uses: actions/setup-go@{SHA2} # v5.6.0\n")),
    ("mapping de flux conforme", wf(f"      - {{name: x, with: {{persist-credentials: false}}, uses: actions/checkout@{SHA2}}} # v4.4.0\n")),
]

# (nom, texte, fragments attendus dans les erreurs)  — chaque cas doit produire au moins une erreur contenant TOUS les fragments
REJECT = [
    # --- injections de base ---
    ("tag flottant @v4", wf("      - uses: actions/checkout@v4\n"), ["non epinglee"]),
    ("branche @main", wf("      - uses: actions/checkout@main\n"), ["non epinglee"]),
    ("SHA court @abc1234", wf("      - uses: actions/checkout@abc1234\n"), ["non epinglee"]),
    ("SHA de 39 caracteres", wf(f"      - uses: actions/checkout@{SHA[:39]} # v4.4.0\n"), ["non epinglee"]),
    ("SHA de 41 caracteres", wf(f"      - uses: actions/checkout@{SHA}a # v4.4.0\n"), ["non epinglee"]),
    ("SHA en majuscules", wf(f"      - uses: actions/checkout@{SHA.upper()} # v4.4.0\n"), ["non epinglee"]),
    ("SHA complet sans commentaire", wf(f"      - uses: actions/checkout@{SHA}\n"), ["commentaire"]),
    ("commentaire qui n'est pas une version", wf(f"      - uses: actions/checkout@{SHA} # latest\n"), ["commentaire"]),
    ("commentaire de version sans patch (v4)", wf(f"      - uses: actions/checkout@{SHA} # v4\n"), ["commentaire"]),
    ("commentaire sur la ligne AU-DESSUS", wf(f"      # v4.4.0\n      - uses: actions/checkout@{SHA}\n"), ["commentaire"]),
    ("action deja epinglee ailleurs avec commentaire : pas de commentaire emprunte",
     wf(CK + f"      - uses: actions/checkout@{SHA}\n        with:\n          persist-credentials: false\n"), ["commentaire"]),
    ("${{ }} dans un run: |", wf("      - run: |\n          echo ${{ github.sha }}\n"), ["run", "${{"]),
    ("${{ }} dans un run: sur une ligne", wf("      - run: echo ${{ github.event.head_commit.message }}\n"), ["run", "${{"]),
    # --- B33 : persist-credentials ---
    ("B33 checkout sans with:", wf(f"      - uses: {CHECKOUT}\n"), ["persist-credentials"]),
    ("B33 with: sans la cle persist-credentials", wf(f"      - uses: {CHECKOUT}\n        with:\n          fetch-depth: 0\n"), ["persist-credentials"]),
    ("B33 persist-credentials: true", wf(f"      - uses: {CHECKOUT}\n        with:\n          persist-credentials: true\n"), ["persist-credentials"]),
    ("B33 persist-credentials: 'true'", wf(f"      - uses: {CHECKOUT}\n        with:\n          persist-credentials: 'true'\n"), ["persist-credentials"]),
    ("B33 persist-credentials: True (booleen YAML)", wf(f"      - uses: {CHECKOUT}\n        with:\n          persist-credentials: True\n"), ["persist-credentials"]),
    ("B33 persist-credentials vide", wf(f"      - uses: {CHECKOUT}\n        with:\n          persist-credentials:\n"), ["persist-credentials"]),
    ("B33 persist-credentials: expression", wf(f"      - uses: {CHECKOUT}\n        with:\n          persist-credentials: ${{{{ inputs.persist }}}}\n"), ["persist-credentials"]),
    ("B33 with: {} en mapping de flux vide", wf(f"      - uses: {CHECKOUT}\n        with: {{}}\n"), ["persist-credentials"]),
    ("B33 la cle est ailleurs que sous with: (env:)", wf(f"      - uses: {CHECKOUT}\n        env:\n          persist-credentials: false\n"), ["persist-credentials"]),
    ("B33 etape checkout en mapping de flux sans with", wf(f"      - {{name: x, uses: actions/checkout@{SHA2}}} # v4.4.0\n"), ["persist-credentials"]),
    ("B33 checkout d'une action composite sans la cle", f"name: c\nruns:\n  using: composite\n  steps:\n    - uses: {CHECKOUT}\n", ["persist-credentials"]),
    ("B33 un seul des deux checkout conforme : l'autre est signale", wf(CK + f"      - uses: actions/checkout@{SHA2} # v4.4.0\n"), ["persist-credentials"]),
    # --- contournements YAML (M6) ---
    ("uses: ${{ matrix.action }} (cible non verifiable)", wf("      - uses: ${{ matrix.action }}\n"), ["uses", "${{"]),
    ("uses: avec expression partielle", wf(f"      - uses: actions/checkout@${{{{ inputs.ref }}}}\n"), ["${{"]),
    ("`uses :` (espace avant les deux-points)", wf("      - uses : actions/checkout@v4\n"), ["non epinglee"]),
    ("cle entre guillemets \"uses\":", wf("      - \"uses\": actions/checkout@v4\n"), ["non epinglee"]),
    ("cle entre apostrophes 'uses':", wf("      - 'uses': actions/checkout@v4\n"), ["non epinglee"]),
    ("valeur de uses sur la ligne suivante", wf("      - uses:\n          actions/checkout@v4\n"), ["non epinglee"]),
    ("valeur de uses avec ancre YAML", wf("      - uses: &a actions/checkout@v4\n"), ["non epinglee"]),
    ("uses entre guillemets", wf("      - uses: \"actions/checkout@v4\"\n"), ["non epinglee"]),
    ("mapping de flux {uses: ...}", wf("      - {name: x, uses: actions/checkout@v4}\n"), ["non epinglee"]),
    ("mapping de flux sur plusieurs lignes", wf("      - {name: x,\n         uses: actions/checkout@v4}\n"), ["non epinglee"]),
    ("run: multi-ligne replie >-", wf("      - run: >-\n          echo\n          ${{ github.sha }}\n"), ["run", "${{"]),
    ("run: multi-ligne litteral |-", wf("      - run: |-\n          set -e\n          echo ${{ github.actor }}\n"), ["run", "${{"]),
    ("run: entre guillemets doubles", wf("      - run: \"echo ${{ github.sha }}\"\n"), ["run", "${{"]),
    ("run: entre apostrophes", wf("      - run: 'echo ${{ github.sha }}'\n"), ["run", "${{"]),
    ("run: entre guillemets sur plusieurs lignes", wf("      - run: \"echo a\n          ${{ github.sha }}\"\n"), ["run", "${{"]),
    ("run: dans un mapping de flux", wf("      - {run: \"echo ${{ github.sha }}\"}\n"), ["run", "${{"]),
    ("cle \"run\": entre guillemets", wf("      - \"run\": echo ${{ github.sha }}\n"), ["run", "${{"]),
    ("github-script : ${{ }} dans script", wf(f"      - uses: actions/github-script@{SHA} # v7.0.1\n        with:\n          script: |\n            core.info('${{{{ github.sha }}}}')\n"), ["script", "${{"]),
    ("shell: avec ${{ }}", wf("      - run: echo ok\n        shell: bash ${{ inputs.opts }}\n"), ["shell", "${{"]),
    ("working-directory: avec ${{ }}", wf("      - run: echo ok\n        working-directory: ${{ inputs.dir }}\n"), ["working-directory", "${{"]),
    ("action locale avec .. (./../evil)", wf("      - uses: ./../evil\n"), [".."]),
    ("action locale avec .. au milieu", wf("      - uses: ./.github/actions/../../evil\n"), [".."]),
    ("docker:// sans digest", wf("      - uses: docker://alpine:3.20\n"), ["digest"]),
    ("docker:// avec tag seul", wf("      - uses: docker://ghcr.io/x/y:latest\n"), ["digest"]),
    ("container: node:20 (tag)", wf(CK, head="    container: node:20\n"), ["container", "digest"]),
    ("container: {image: ...} sans digest", wf(CK, head="    container:\n      image: node:20\n"), ["container", "digest"]),
    ("container: avec ${{ }}", wf(CK, head="    container: ${{ matrix.image }}\n"), ["container"]),
    ("services.db.image sans digest", wf(CK, head="    services:\n      db:\n        image: postgres:16\n"), ["services.db", "digest"]),
    ("workflow reutilisable @main", "on: push\njobs:\n  j:\n    uses: org/repo/.github/workflows/x.yml@main\n", ["non epinglee"]),
    ("action composite : uses flottant dans runs.steps", "name: c\nruns:\n  using: composite\n  steps:\n    - uses: actions/checkout@v4\n", ["non epinglee"]),
    ("action composite : ${{ }} dans run", "name: c\nruns:\n  using: composite\n  steps:\n    - run: echo ${{ inputs.x }}\n      shell: bash\n", ["run", "${{"]),
    ("plusieurs erreurs dans un fichier : toutes listees",
     wf("      - uses: actions/checkout@v4\n      - uses: actions/setup-go@v5\n      - run: echo ${{ github.sha }}\n"), ["checkout", "setup-go", "run"]),
    ("YAML invalide", "on: push\njobs: [unclosed\n", ["YAML"]),
    ("document qui n'est pas un mapping", "- a\n- b\n", ["mapping"]),
]

bad = 0


def report(ok: bool, name: str, detail: str = "") -> None:
    global bad
    print(("ok  " if ok else "KO  ") + name + ("" if ok else "  -> " + detail))
    bad += not ok


for name, text in ACCEPT:
    errs = check_text(text, "w.yml")
    report(not errs, "accepte : " + name, repr(errs))

for name, text, fragments in REJECT:
    errs = check_text(text, "w.yml")
    joined = "\n".join(errs)
    report(bool(errs) and all(f in joined for f in fragments), "refuse  : " + name, f"erreurs={errs!r} attendu={fragments!r}")

# les erreurs designent le fichier et la ligne (l'operateur doit retrouver l'etape sans relire le fichier)
errs = check_text(wf(CK + f"      - uses: actions/setup-go@{SHA2}\n"), "ci.yml")
report(bool(errs) and all(e.startswith("ci.yml:") for e in errs) and any(re.match(r"ci\.yml:\d+:", e) or ".steps[1]" in e for e in errs),
       "les erreurs nomment le fichier et la ligne ou l'etape", repr(errs))

# fichiers analyses par defaut : *.yml ET *.yaml, workflows ET actions composites (action.yml / action.yaml)
with tempfile.TemporaryDirectory() as root:
    for rel in (".github/workflows/a.yml", ".github/workflows/b.yaml", ".github/actions/setup/action.yml",
                ".github/actions/deep/er/action.yaml", "action.yml", "action.yaml", ".github/workflows/notes.txt"):
        p = os.path.join(root, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        open(p, "w", encoding="utf-8").write("x: 1\n")
    found = sorted(os.path.relpath(f, root).replace(os.sep, "/") for f in default_files(root))
    want = sorted([".github/workflows/a.yml", ".github/workflows/b.yaml", ".github/actions/setup/action.yml",
                   ".github/actions/deep/er/action.yaml", "action.yml", "action.yaml"])
    report(found == want, "fichiers analyses par defaut : *.yml et *.yaml, workflows et actions composites", f"{found!r} != {want!r}")

# bout en bout : le CLI sort en 1 avec ::error:: (fichier .yaml compris), en 0 pour un fichier conforme, 2 sans aucun workflow
def cli(args, cwd=None):
    r = subprocess.run([sys.executable, "-I", os.path.join(HERE, "check_actions_pinned.py"), *args], capture_output=True, text=True, cwd=cwd)
    return r.returncode, r.stdout


with tempfile.TemporaryDirectory() as tmp:
    good, evil = os.path.join(tmp, "good.yml"), os.path.join(tmp, "evil.yaml")
    open(good, "w", encoding="utf-8").write(wf(CK))
    open(evil, "w", encoding="utf-8").write(wf("      - uses: actions/checkout@v4\n      - run: echo ${{ github.sha }}\n"))
    rc, out = cli([good])
    report(rc == 0 and "OK" in out, "cli : fichier conforme -> exit 0", f"rc={rc} {out}")
    rc, out = cli([evil])
    report(rc == 1 and out.count("::error::") >= 2, "cli : fichier .yaml fautif -> exit 1, toutes les erreurs", f"rc={rc} {out}")
    rc, out = cli([good, evil])
    report(rc == 1, "cli : un seul fichier fautif parmi deux suffit a echouer", f"rc={rc}")
    rc, out = cli([], cwd=tmp)
    report(rc == 2 and "aucun workflow" in out, "cli : aucun workflow trouve -> exit 2 (jamais un faux OK)", f"rc={rc} {out}")

sys.exit(1 if bad else 0)
