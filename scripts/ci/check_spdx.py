#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Garde des en-tetes SPDX (#237 / LOT-7, D17) sur les sources .go, .py et .sh suivies par git.

Usage : check_spdx.py [--fix] [--root DIR] [chemin ...]   (python3 -I ; stdlib seule)
  Sans chemin : tous les fichiers `git ls-files -- '*.go' '*.py' '*.sh'` de la racine (--root, sinon
  `git rev-parse --show-toplevel`). Un chemin est soit un fichier existant (pris tel quel, suivi ou non), soit un
  repertoire/pathspec passe a `git ls-files` (ex. `GO/cmd/secagent-server`). Code 0 = OK, 1 = au moins une erreur
  (toutes listees en `::error::`), 2 = usage/environnement.

En-tete attendu (format REUSE fige par le plan LOT-7), prefixe `//` (Go) ou `#` (Python, shell) :
    SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
    SPDX-License-Identifier: AGPL-3.0-or-later
  - Go : lignes 1-2, puis une ligne VIDE (sinon l'en-tete fusionne dans le commentaire de package / le godoc) ;
    `//go:build` et le commentaire de package viennent apres cette ligne vide.
  - Python / shell : apres le preambule eventuel, dans cet ordre : shebang `#!` (ligne 1), ligne d'encodage
    PEP 263 (`# -*- coding: ... -*-`, ligne 1 ou 2), directive `# shellcheck shell=...`. Puis une ligne vide.
  L'en-tete doit donc commencer au plus tard a la ligne 4 (dans les 5 premieres lignes), avant tout code.

Exclusions (D17) : scripts/ci/testdata/, .claude/, TEMPLATE_claude/, docs/, RELEASE/, _work/, tout __pycache__/,
et tout fichier genere (ligne `// Code generated ... DO NOT EDIT.` ou `# Code generated ... DO NOT EDIT.`).

--fix : corrige UNIQUEMENT les cas surs, de facon idempotente (un second passage ne change rien) :
  - fichier sans aucune ligne SPDX : insertion de l'en-tete apres le preambule, suivie d'une ligne vide si la ligne
    suivante n'est pas deja vide ; shebang, coding, shellcheck et `//go:build` restent a leur place relative ;
  - en-tete correct mais sans ligne vide apres : insertion de la ligne vide.
  Jamais corrige (erreur restante, a traiter a la main) : identifiant ou copyright different, en-tete mal place
  (apres `package` ou du code), doublon, fichier CRLF / non UTF-8. Un identifiant different peut etre une licence
  tierce legitime : la garde ne la reecrit pas. Fins de ligne : LF uniquement ; le mode du fichier est conserve.
"""
import os
import re
import subprocess
import sys

COPYRIGHT = "SPDX-FileCopyrightText: 2025-2026 Cyril Coupel"
LICENSE = "SPDX-License-Identifier: AGPL-3.0-or-later"
EXTENSIONS = {".go": "//", ".py": "#", ".sh": "#"}
EXCLUDED_PREFIXES = ("scripts/ci/testdata/", ".claude/", "TEMPLATE_claude/", "docs/", "RELEASE/", "_work/")
EXCLUDED_COMPONENTS = ("__pycache__",)
MAX_HEADER_START = 4  # 0-based index max de la 1re ligne d'en-tete (=> en-tete dans les 5 premieres lignes)

GENERATED_RE = re.compile(r"^(?://|#) Code generated .* DO NOT EDIT\.?$")
CODING_RE = re.compile(r"^#.*coding[:=]\s*[-\w.]+")
SHELLCHECK_RE = re.compile(r"^#\s*shellcheck\s+shell=")
SPDX_ANY_RE = re.compile(r"SPDX-(?:FileCopyrightText|License-Identifier)\s*:")


def is_excluded(rel: str) -> bool:
    rel = rel.replace("\\", "/")
    if rel.startswith("./"):
        rel = rel[2:]
    if rel.startswith(EXCLUDED_PREFIXES):
        return True
    return any(part in EXCLUDED_COMPONENTS for part in rel.split("/"))


def preamble_len(lines: list, prefix: str) -> int:
    """Nombre de lignes de preambule a conserver AVANT l'en-tete (0 pour Go)."""
    if prefix != "#":
        return 0
    i = 0
    if i < len(lines) and lines[i].startswith("#!"):
        i += 1
    if i < len(lines) and i <= 1 and CODING_RE.match(lines[i]):
        i += 1
    if i < len(lines) and SHELLCHECK_RE.match(lines[i]):
        i += 1
    return i


def analyse(text: str, prefix: str):
    """Retourne (erreurs, texte_corrige_ou_None). Les numeros de ligne des erreurs sont 1-based."""
    lines = text.split("\n")
    if any(GENERATED_RE.match(line) for line in lines):
        return [], None
    head1, head2 = f"{prefix} {COPYRIGHT}", f"{prefix} {LICENSE}"
    spdx_idx = [i for i, line in enumerate(lines) if SPDX_ANY_RE.search(line)]
    start = preamble_len(lines, prefix)

    if not spdx_idx:
        insert = [head1, head2]
        if start >= len(lines) or lines[start] != "":
            insert.append("")
        if text == "":
            fixed = head1 + "\n" + head2 + "\n"
        else:
            fixed = "\n".join(lines[:start] + insert + lines[start:])
        return [(start + 1, "en-tete SPDX absent")], fixed

    errs = []
    lic = [i for i in spdx_idx if "SPDX-License-Identifier" in lines[i]]
    cop = [i for i in spdx_idx if "SPDX-FileCopyrightText" in lines[i]]
    for i in lic:
        if lines[i] != head2:
            errs.append((i + 1, f"identifiant de licence attendu `{head2}`, trouve `{lines[i].strip()}`"))
    for i in cop:
        if lines[i] != head1:
            errs.append((i + 1, f"copyright attendu `{head1}`, trouve `{lines[i].strip()}`"))
    if len(lic) != 1 or len(cop) != 1:
        errs.append((spdx_idx[0] + 1, f"exactement une ligne de copyright et une ligne de licence SPDX attendues "
                                      f"(trouve {len(cop)} et {len(lic)})"))
    if errs:
        return errs, None

    c, l = cop[0], lic[0]
    if l != c + 1:
        return [(c + 1, "la ligne de licence SPDX doit suivre immediatement la ligne de copyright")], None
    if c != start or c > MAX_HEADER_START:
        what = "avant `package` et tout commentaire" if prefix == "//" else "juste apres shebang/coding/shellcheck"
        return [(c + 1, f"en-tete SPDX mal place (ligne {c + 1}, attendu ligne {start + 1}, {what})")], None
    if l + 1 < len(lines) and lines[l + 1] != "":
        fixed = "\n".join(lines[:l + 1] + [""] + lines[l + 1:])
        return [(l + 2, "ligne vide attendue apres l'en-tete SPDX")], fixed
    return [], None


def git_files(root: str, specs: list) -> list:
    cmd = ["git", "-C", root, "ls-files", "-z", "--", *specs]
    out = subprocess.run(cmd, check=True, capture_output=True).stdout.decode("utf-8", "surrogateescape")
    return [p for p in out.split("\0") if p]


def collect(root: str, args: list) -> list:
    if not args:
        return git_files(root, ["*.go", "*.py", "*.sh"])
    files, specs = [], []
    for a in args:
        if os.path.isfile(os.path.join(root, a)):
            files.append(a)
        else:
            specs.append(a)
    if specs:
        files += git_files(root, specs)
    return files


def main(argv) -> int:
    fix, root, args = False, None, []
    it = iter(argv)
    for a in it:
        if a == "--fix":
            fix = True
        elif a == "--root":
            root = next(it, None)
            if root is None:
                print("::error::--root attend un repertoire")
                return 2
        elif a in ("-h", "--help"):
            print(__doc__)
            return 0
        else:
            args.append(a)
    if root is None:
        try:
            root = subprocess.run(["git", "rev-parse", "--show-toplevel"], check=True, capture_output=True,
                                  text=True).stdout.strip()
        except (OSError, subprocess.CalledProcessError):
            print("::error::pas de depot git (utiliser --root)")
            return 2
    try:
        candidates = collect(root, args)
    except (OSError, subprocess.CalledProcessError) as exc:
        print(f"::error::git ls-files a echoue : {exc}")
        return 2

    errors, checked, fixed_count = [], 0, 0
    for rel in sorted(set(candidates)):
        prefix = EXTENSIONS.get(os.path.splitext(rel)[1])
        if prefix is None or is_excluded(rel):
            continue
        path = os.path.join(root, rel)
        if not os.path.isfile(path):  # suivi mais supprime de l'arbre de travail
            continue
        checked += 1
        with open(path, "rb") as fh:
            raw = fh.read()
        if b"\r" in raw:
            errors.append(f"{rel}:1: fin de ligne CR/CRLF (LF attendu) ; non corrige automatiquement")
            continue
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            errors.append(f"{rel}:1: fichier non UTF-8")
            continue
        if text.startswith("﻿"):
            errors.append(f"{rel}:1: BOM UTF-8 present ; non corrige automatiquement")
            continue
        errs, fixed = analyse(text, prefix)
        if fix and fixed is not None:
            with open(path, "wb") as fh:  # reouverture en ecriture : mode et proprietaire conserves
                fh.write(fixed.encode("utf-8"))
            fixed_count += 1
            errs, _ = analyse(fixed, prefix)
        errors += [f"{rel}:{n}: {msg}" for n, msg in errs]

    for e in errors:
        print(f"::error::{e}")
    suffix = f", {fixed_count} corrige(s)" if fix else ""
    if errors:
        print(f"FAIL spdx : {len(errors)} erreur(s) sur {checked} fichier(s){suffix}")
        return 1
    print(f"OK spdx : {checked} fichier(s) conforme(s){suffix}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
