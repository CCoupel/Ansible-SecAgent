#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Auto-test de check_spdx.py (garde des en-tetes SPDX, LOT-7 / #237) sur des depots git JETABLES : aucun fichier du
depot reel n'est lu ni modifie, aucun reseau. Exit 0 = conforme.

Contrat teste (plan LOT-7, Phase 2) :
  - `python3 -I check_spdx.py [--fix]`, lance depuis la racine d'un depot git ; fichiers = `git ls-files` limite a
    `*.go`, `*.py`, `*.sh` (donc : un fichier non suivi par git est ignore), moins les exclusions D17 ;
  - en-tete exact (deux lignes, prefixe `//` pour Go, `#` pour Python/shell), dans les 5 premieres lignes, AVANT
    `package`/code ; shebang, ligne coding ou `# shellcheck shell=bash` restent en tete, l'en-tete vient APRES eux ;
  - une ligne vide apres l'en-tete : Go (sinon il fusionne dans le godoc) ET Python/shell (exigence de la garde
    livree par infra ; le plan ne la prevoit explicitement que pour Go : ecart signale) ;
  - fichier genere (`Code generated ... DO NOT EDIT`) ignore ;
  - sortie `::error::` (une ligne par fichier fautif, avec son chemin), rc 1 si au moins une erreur, 0 sinon ;
  - `--fix` : insere l'en-tete, idempotent, preserve le reste a l'octet pres, LF seuls, rc 0 une fois corrige.
Non teste faute de contrat (a trancher par le plan si besoin) : en-tete place AVANT le shebang, identifiant errone
corrige par --fix, fins de ligne CRLF."""
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "check_spdx.py")

# Les etiquettes sont coupees : la garde livree compte toute occurrence du motif dans un fichier (meme dans une chaine),
# elle rejetterait ce fichier lui-meme (ecart signale dans le rapport).
TAG_COPY = "SPDX-" + "FileCopyrightText"
TAG_LIC = "SPDX-" + "License-Identifier"
COPY = TAG_COPY + ": 2025-2026 Cyril Coupel"
LIC = TAG_LIC + ": AGPL-3.0-or-later"
GO_HDR = f"// {COPY}\n// {LIC}\n"
HASH_HDR_NB = f"# {COPY}\n# {LIC}\n"   # sans ligne vide : refuse par la garde livree (ecart au plan, voir rapport)
HASH_HDR = HASH_HDR_NB + "\n"

GO_BODY = "package main\n\nfunc main() {}\n"
PY_BODY = "print('x')\n"
SH_BODY = "set -eu\necho x\n"

bad = 0


def report(ok: bool, name: str, detail: str = "") -> None:
    global bad
    print(("ok  " if ok else "KO  ") + name + ("" if ok else "  -> " + detail))
    bad += not ok


class Repo:
    """Depot git jetable : write() cree un fichier (suivi par defaut), run() lance la garde dedans."""

    def __init__(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="spdx-selftest-")
        self.root = self._tmp.name
        self.git("init", "-q")

    def git(self, *args):
        subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", *args], cwd=self.root, check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def write(self, path: str, content: str, tracked: bool = True) -> str:
        full = os.path.join(self.root, path)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w", encoding="utf-8", newline="") as f:
            f.write(content)
        if tracked:
            self.git("add", "--", path)
        return path

    def read(self, path: str) -> str:
        with open(os.path.join(self.root, path), encoding="utf-8", newline="") as f:
            return f.read()

    def run(self, *args):
        r = subprocess.run([sys.executable, "-I", SCRIPT, *args], cwd=self.root, capture_output=True, text=True)
        return r.returncode, r.stdout + r.stderr

    def close(self):
        self._tmp.cleanup()


def errors_for(out: str, path: str) -> list:
    return [ln for ln in out.splitlines() if ln.startswith("::error") and path in ln]


def case_check(name, files, want_rc, bad_paths=(), good_paths=()):
    """Une garde (sans --fix) sur `files` ({chemin: contenu}) : rc attendu, ::error:: pour chaque chemin fautif,
    aucun ::error:: pour les chemins conformes."""
    r = Repo()
    try:
        for p, c in files.items():
            r.write(p, c)
        rc, out = r.run()
        problems = []
        if rc != want_rc:
            problems.append(f"rc={rc} (attendu {want_rc})")
        for p in bad_paths:
            if not errors_for(out, p):
                problems.append(f"pas de ::error:: pour {p}")
        for p in good_paths:
            if errors_for(out, p):
                problems.append(f"::error:: inattendu pour {p}")
        if want_rc == 0 and "::error" in out:
            problems.append("::error:: alors que rc 0")
        report(not problems, name, f"{'; '.join(problems)} | sortie : {out.strip()[:300]}")
    finally:
        r.close()


# --- 0. la garde existe -----------------------------------------------------------------------------------------------
if not os.path.isfile(SCRIPT):
    print(f"KO  check_spdx.py introuvable ({SCRIPT}) : livrable d'infra, Phase 2.1 du plan LOT-7")
    sys.exit(1)

# --- 1. fichiers conformes acceptes -----------------------------------------------------------------------------------
case_check("conforme : Go, Python, shell avec en-tete", {
    "a/main.go": GO_HDR + "\n" + GO_BODY,
    "a/tool.py": HASH_HDR + PY_BODY,
    "a/run.sh": HASH_HDR + SH_BODY,
}, 0)
case_check("conforme : shebang puis en-tete (python et shell)", {
    "t.py": "#!/usr/bin/env python3\n" + HASH_HDR + PY_BODY,
    "t.sh": "#!/usr/bin/env bash\n" + HASH_HDR + SH_BODY,
}, 0)
case_check("conforme : shebang + ligne coding puis en-tete", {
    "c.py": "#!/usr/bin/env python3\n# -*- coding: utf-8 -*-\n" + HASH_HDR + PY_BODY,
}, 0)
case_check("conforme : ligne coding seule puis en-tete", {
    "c2.py": "# -*- coding: utf-8 -*-\n" + HASH_HDR + PY_BODY,
}, 0)
case_check("conforme : `# shellcheck shell=bash` puis en-tete", {
    "lib.sh": "# shellcheck shell=bash\n" + HASH_HDR + SH_BODY,
}, 0)
case_check("conforme : //go:build conserve apres l'en-tete", {
    "slow_test.go": GO_HDR + "\n//go:build slow\n\npackage main\n",
}, 0)
case_check("conforme : commentaire de package apres l'en-tete et une ligne vide", {
    "doc.go": GO_HDR + "\n// Package x fait quelque chose.\npackage x\n",
}, 0)

# --- 2. fichiers non conformes refuses --------------------------------------------------------------------------------
case_check("refus : Go sans en-tete", {"bad/main.go": GO_BODY, "ok/main.go": GO_HDR + "\n" + GO_BODY}, 1,
           bad_paths=["bad/main.go"], good_paths=["ok/main.go"])
case_check("refus : Python sans en-tete", {"bad.py": PY_BODY}, 1, bad_paths=["bad.py"])
case_check("refus : shell sans en-tete", {"bad.sh": "#!/usr/bin/env bash\n" + SH_BODY}, 1, bad_paths=["bad.sh"])
case_check("refus : en-tete Go APRES `package`", {"late.go": "package main\n\n" + GO_HDR + "\nfunc main() {}\n"}, 1,
           bad_paths=["late.go"])
case_check("refus : en-tete Python apres du code", {"late.py": PY_BODY + HASH_HDR}, 1, bad_paths=["late.py"])
case_check("refus : en-tete au-dela des 5 premieres lignes", {
    "far.py": "# a\n# b\n# c\n# d\n# e\n" + HASH_HDR + PY_BODY}, 1, bad_paths=["far.py"])
case_check("refus : mauvais identifiant (MIT)", {
    "mit.go": f"// {COPY}\n// {TAG_LIC}: MIT\n\n" + GO_BODY}, 1, bad_paths=["mit.go"])
case_check("refus : mauvais identifiant (AGPL-3.0-only, sans le « or-later »)", {
    "only.py": f"# {COPY}\n# {TAG_LIC}: AGPL-3.0-only\n" + PY_BODY}, 1, bad_paths=["only.py"])
case_check("refus : ligne de copyright absente", {
    "nocopy.go": f"// {LIC}\n\n" + GO_BODY}, 1, bad_paths=["nocopy.go"])
case_check("refus : ligne de licence absente", {
    "nolic.sh": f"# {COPY}\n" + SH_BODY}, 1, bad_paths=["nolic.sh"])
case_check("refus : fichier //go:build sans en-tete", {
    "tag_test.go": "//go:build slow\n\npackage main\n"}, 1, bad_paths=["tag_test.go"])
case_check("refus : Python/shell, en-tete sans ligne vide ensuite", {
    "nb.py": HASH_HDR_NB + PY_BODY, "nb.sh": "#!/usr/bin/env bash\n" + HASH_HDR_NB + SH_BODY, "ok.py": HASH_HDR + PY_BODY}, 1,
    bad_paths=["nb.py", "nb.sh"], good_paths=["ok.py"])
case_check("refus : Go, en-tete sans ligne vide ensuite", {"nb.go": GO_HDR + GO_BODY}, 1, bad_paths=["nb.go"])
case_check("refus : fichier vide", {"empty.py": ""}, 1, bad_paths=["empty.py"])

# --- 3. une erreur par fichier fautif, rc 1 ---------------------------------------------------------------------------
r = Repo()
try:
    for p in ("x/a.go", "x/b.py", "x/c.sh"):
        r.write(p, GO_BODY if p.endswith(".go") else PY_BODY)
    r.write("x/ok.py", HASH_HDR + PY_BODY)
    rc, out = r.run()
    n = [ln for ln in out.splitlines() if ln.startswith("::error")]
    report(rc == 1 and len(n) == 3 and all(errors_for(out, p) for p in ("x/a.go", "x/b.py", "x/c.sh"))
           and not errors_for(out, "x/ok.py"),
           "sortie : une ligne ::error:: par fichier fautif (3), aucune pour le fichier conforme", f"rc={rc} sortie : {out}")
finally:
    r.close()

# --- 4. exclusions (D17) et perimetre --------------------------------------------------------------------------------
EXCLUDED = [
    "scripts/ci/testdata/sample.py", "scripts/ci/testdata/sample.go", "pkg/__pycache__/m.py",
    ".claude/hooks/h.py", ".claude/hooks/h.sh", "TEMPLATE_claude/x.sh", "docs/gen.py", "RELEASE/tool.sh", "_work/tmp.py",
]
case_check("exclusions : testdata, __pycache__, .claude, TEMPLATE_claude, docs, RELEASE, _work ignores",
           {p: (GO_BODY if p.endswith(".go") else PY_BODY) for p in EXCLUDED}, 0)
case_check("perimetre : Markdown, YAML, Dockerfile, go.mod non controles", {
    "README.md": "# x\n", "ci.yml": "a: 1\n", "Dockerfile": "FROM scratch\n", "GO/go.mod": "module x\n", "GO/go.sum": "",
}, 0)
case_check("perimetre : un fichier non suivi par git est ignore", {}, 0)
r = Repo()
try:
    r.write("untracked.go", GO_BODY, tracked=False)
    rc, out = r.run()
    report(rc == 0 and "::error" not in out, "perimetre : fichier non suivi (git ls-files) ignore", f"rc={rc} {out}")
finally:
    r.close()
case_check("exclusion ciblee : un fichier hors liste (scripts/ci/check.py) reste controle", {
    "scripts/ci/check.py": PY_BODY, "scripts/ci/testdata/t.py": PY_BODY}, 1,
    bad_paths=["scripts/ci/check.py"], good_paths=["scripts/ci/testdata/t.py"])

# --- 5. fichiers generes ----------------------------------------------------------------------------------------------
case_check("fichier genere (`Code generated ... DO NOT EDIT.`) ignore", {
    "gen.pb.go": "// Code generated by protoc-gen-go. DO NOT EDIT.\n\npackage x\n"}, 0)
case_check("fichier genere ignore, mais pas le fichier voisin sans en-tete", {
    "gen.pb.go": "// Code generated by protoc-gen-go. DO NOT EDIT.\n\npackage x\n", "hand.go": GO_BODY}, 1,
    bad_paths=["hand.go"], good_paths=["gen.pb.go"])

# --- 6. --fix ---------------------------------------------------------------------------------------------------------
FIX_CASES = {   # chemin : (avant, apres attendu)
    "f/plain.go": (GO_BODY, GO_HDR + "\n" + GO_BODY),
    "f/tag_test.go": ("//go:build slow\n\npackage main\n", GO_HDR + "\n//go:build slow\n\npackage main\n"),
    "f/doc.go": ("// Package x fait quelque chose.\npackage x\n",
                 GO_HDR + "\n// Package x fait quelque chose.\npackage x\n"),
    "f/noblank.py": (HASH_HDR_NB + PY_BODY, HASH_HDR + PY_BODY),     # en-tete correct sans ligne vide : --fix l'ajoute
    "f/noblank.go": (GO_HDR + GO_BODY, GO_HDR + "\n" + GO_BODY),
    "f/plain.py": (PY_BODY, HASH_HDR + PY_BODY),
    "f/shebang.py": ("#!/usr/bin/env python3\n" + PY_BODY, "#!/usr/bin/env python3\n" + HASH_HDR + PY_BODY),
    "f/coding.py": ("#!/usr/bin/env python3\n# -*- coding: utf-8 -*-\n" + PY_BODY,
                    "#!/usr/bin/env python3\n# -*- coding: utf-8 -*-\n" + HASH_HDR + PY_BODY),
    "f/shebang.sh": ("#!/usr/bin/env bash\n" + SH_BODY, "#!/usr/bin/env bash\n" + HASH_HDR + SH_BODY),
    "f/lib.sh": ("# shellcheck shell=bash\n" + SH_BODY, "# shellcheck shell=bash\n" + HASH_HDR + SH_BODY),
}
UNTOUCHED = {   # fichiers que --fix ne doit PAS modifier
    "f/already.go": GO_HDR + "\n" + GO_BODY,
    "f/already.py": "#!/usr/bin/env python3\n" + HASH_HDR + PY_BODY,
    "scripts/ci/testdata/x.py": PY_BODY,
    "docs/x.py": PY_BODY,
    "gen.pb.go": "// Code generated by protoc-gen-go. DO NOT EDIT.\n\npackage x\n",
}
r = Repo()
try:
    for p, (before, _) in FIX_CASES.items():
        r.write(p, before)
    for p, c in UNTOUCHED.items():
        r.write(p, c)
    rc_pre, _ = r.run()
    report(rc_pre == 1, "fix : le depot de depart est bien refuse par la garde (rc 1)", f"rc={rc_pre}")
    rc, out = r.run("--fix")
    report(rc == 0, "fix : rc 0 apres correction", f"rc={rc} sortie : {out[:300]}")
    for p, (_, after) in FIX_CASES.items():
        got = r.read(p)
        report(got == after, f"fix : {p} = en-tete insere, reste intact, shebang/coding/go:build conserves",
               f"obtenu {got!r}")
    for p, c in UNTOUCHED.items():
        report(r.read(p) == c, f"fix : {p} non modifie (conforme, exclu ou genere)", f"obtenu {r.read(p)!r}")
    rc2, out2 = r.run()
    report(rc2 == 0 and "::error" not in out2, "fix : la garde accepte le depot corrige", f"rc={rc2} {out2[:300]}")
    snapshot = {p: r.read(p) for p in list(FIX_CASES) + list(UNTOUCHED)}
    rc3, _ = r.run("--fix")
    report(rc3 == 0 and all(r.read(p) == c for p, c in snapshot.items()),
           "fix : idempotent (second --fix : rc 0, aucun octet change, pas de double en-tete)")
    report(all(r.read(p).count(TAG_LIC) == (0 if p in ("scripts/ci/testdata/x.py", "docs/x.py", "gen.pb.go") else 1)
               for p in snapshot), "fix : exactement un en-tete par fichier corrige")
    report(all("\r" not in r.read(p) for p in FIX_CASES), "fix : fins de ligne LF seules")
    go_after = r.read("f/plain.go").split("\n")
    report(go_after[2] == "" and go_after[3] == "package main",
           "fix : Go, ligne vide entre l'en-tete et `package` (pas de fusion dans le godoc)", repr(go_after[:5]))
finally:
    r.close()

# --fix ne casse pas un fichier Go compilable : gofmt le laisse inchange quand l'outil est present
r = Repo()
try:
    r.write("g/a.go", GO_BODY)
    r.write("g/b_test.go", "//go:build slow\n\npackage main\n")
    r.run("--fix")
    try:
        res = subprocess.run(["gofmt", "-l", "g"], cwd=r.root, capture_output=True, text=True)
        report(res.returncode == 0 and res.stdout.strip() == "", "fix : `gofmt -l` vide sur les fichiers Go corriges",
               res.stdout + res.stderr)
    except FileNotFoundError:
        print("info gofmt absent : controle gofmt ignore")
finally:
    r.close()

# --- 7. --fix, depot deja conforme : rien a faire ---------------------------------------------------------------------
r = Repo()
try:
    r.write("ok.go", GO_HDR + "\n" + GO_BODY)
    rc, out = r.run("--fix")
    report(rc == 0 and r.read("ok.go") == GO_HDR + "\n" + GO_BODY, "fix : depot deja conforme, rc 0 et rien de modifie",
           f"rc={rc} {out[:200]}")
finally:
    r.close()

# --- 8. Confinement (revue securite LOT-7, BAS) : lien symbolique et chemin hors depot refuses, cible intacte ---------
outside = tempfile.TemporaryDirectory(prefix="spdx-outside-")
try:
    target = os.path.join(outside.name, "cible.sh")
    with open(target, "w", encoding="utf-8", newline="") as f:
        f.write("#!/bin/sh\n" + SH_BODY)
    before = open(target, encoding="utf-8").read()

    # 8a. lien symbolique suivi par git (mode 120000) vers un fichier hors depot
    r = Repo()
    try:
        os.symlink(target, os.path.join(r.root, "lien.sh"))
        r.git("add", "--", "lien.sh")
        rc, out = r.run("--fix")
        after = open(target, encoding="utf-8").read()
        report(rc == 1 and any("lien symbolique" in e for e in errors_for(out, "lien.sh")) and after == before,
               "confinement : lien symbolique refuse (--fix), cible hors depot intacte", f"rc={rc} {out[:300]}")
    finally:
        r.close()

    # 8b. argument explicite hors de la racine du depot (chemin absolu)
    r = Repo()
    try:
        r.write("ok.go", GO_HDR + "\n" + GO_BODY)
        rc, out = r.run("--fix", target)
        after = open(target, encoding="utf-8").read()
        report(rc == 1 and any("hors de la racine" in e for e in errors_for(out, "cible.sh")) and after == before,
               "confinement : chemin hors depot refuse (--fix), fichier intact", f"rc={rc} {out[:300]}")
    finally:
        r.close()
finally:
    outside.cleanup()

sys.exit(1 if bad else 0)
