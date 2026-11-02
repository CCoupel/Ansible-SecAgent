#!/usr/bin/env python3
"""Garde des workflows GitHub Actions (#227 / LOT-2.2, et point ouvert de #224).

Usage : check_actions_pinned.py .github/workflows/*.yml   (code 0 = OK, 1 = au moins une erreur, toutes listees)

Echec si :
  - une ligne `uses:` n'est pas `<owner>/<repo>[/<chemin>]@<SHA de 40 hex>  # vX.Y.Z` (tag ou branche flottants,
    SHA court, commentaire de version absent ou mal forme). Exceptions : action locale `./...` ; image
    `docker://...@sha256:<64 hex>` (epinglee par digest, commentaire non exige) ;
  - une expression `${{ ... }}` apparait dans un script `run:` (en ligne ou bloc `|` / `>`), commentaires shell
    compris : Actions l'interpole AVANT le shell, c'est une injection de commande potentielle. Les valeurs passent
    par `env:` puis "$VAR".

Analyse ligne a ligne (aucune dependance : pas de PyYAML sur tous les postes) ; suffisante pour le style des
workflows du depot (cles `uses:` / `run:` sur une ligne, scripts en bloc indente).
"""
import re
import sys

USES_RE = re.compile(r"^(\s*)(?:-\s+)?uses:\s*(?P<ref>[^\s#]+)\s*(?:#\s*(?P<comment>.*))?$")
RUN_RE = re.compile(r"^(?P<indent>\s*)(?:-\s+)?run:\s*(?P<rest>.*)$")
PINNED_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[^@\s]+)?@[0-9a-f]{40}$")
DOCKER_RE = re.compile(r"^docker://[^@\s]+@sha256:[0-9a-f]{64}$")
VERSION_RE = re.compile(r"^v\d+\.\d+\.\d+$")


def check_text(text: str, name: str) -> list:
    errs = []
    lines = text.splitlines()
    block_indent = None  # indentation de la cle `run:` dont on lit le bloc
    for n, line in enumerate(lines, 1):
        if block_indent is not None:
            stripped = line.strip()
            indent = len(line) - len(line.lstrip(" "))
            if stripped == "" or indent > block_indent:
                if "${{" in line:
                    errs.append(f"{name}:{n}: expression ${{{{ }}}} dans un script run: (passer la valeur par env:)")
                continue
            block_indent = None
        m = RUN_RE.match(line)
        if m:
            rest = m.group("rest").strip()
            if rest[:1] in ("|", ">"):
                # `- run: |` : le contenu est indente au-dela du tiret ; `run: |` : au-dela de la cle
                block_indent = len(m.group("indent")) + (2 if line.lstrip().startswith("-") else 0)
            elif "${{" in rest:
                errs.append(f"{name}:{n}: expression ${{{{ }}}} dans un script run: (passer la valeur par env:)")
            continue
        m = USES_RE.match(line)
        if m:
            ref, comment = m.group("ref").strip("'\""), (m.group("comment") or "").strip()
            if ref.startswith("./"):
                continue
            if ref.startswith("docker://"):
                if not DOCKER_RE.match(ref):
                    errs.append(f"{name}:{n}: image {ref!r} non epinglee par digest @sha256:<64 hex>")
                continue
            if not PINNED_RE.match(ref):
                errs.append(f"{name}:{n}: action {ref!r} non epinglee par un SHA de 40 hex")
            elif not VERSION_RE.match(comment.split()[0] if comment else ""):
                errs.append(f"{name}:{n}: action {ref.split('@')[0]!r} sans commentaire de version `# vX.Y.Z`")
    return errs


def main(argv) -> int:
    if not argv:
        print(__doc__)
        return 2
    errs = []
    for path in argv:
        with open(path, encoding="utf-8") as fh:
            errs += check_text(fh.read(), path)
    for e in errs:
        print(f"::error::{e}")
    print("FAIL workflows" if errs else f"OK {len(argv)} workflow(s) : actions epinglees, aucun ${{{{ }}}} dans run:")
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
