#!/usr/bin/env python3
"""Controle des scripts lances par les workflows (WSL/NTFS : bits d'execution et CRLF ne sont pas fiables).

Pour chaque chemin `*.sh` / `*.py` du depot cite dans un workflow, echec si :
  - il est lance DIRECTEMENT (sans `bash`/`sh`/`python3`) : l'appel doit passer par l'interpreteur ;
  - son mode git n'est pas 100755 (`git ls-files -s`) ;
  - il contient des CRLF.
Usage : check_scripts.py .github/workflows/*.yml   (depuis la racine du depot)"""
import re, subprocess, sys

PATH_RE = re.compile(r"(?<![\w./-])((?:[\w.-]+/)*[\w.-]+\.(?:sh|py))\b")
# Un chemin est un LANCEMENT DIRECT s'il est en tete de commande (arguments de cp, chmod, cat... ignores).
DIRECT = ("", "run:", "&&", ";", "|", "||", "then", "do", "-", "|")


def analyze(text, mode_of, read):
    errs = []
    for n, line in enumerate(text.splitlines(), 1):
        code = line.split("#", 1)[0]
        for m in PATH_RE.finditer(code):
            path = m.group(1)
            if mode_of(path) is None:           # pas un fichier du depot (ex. script genere, option)
                continue
            before = code[:m.start()].split()
            last = before[-1].lstrip("(\"'") if before else ""
            if last in DIRECT:
                errs.append((n, f"{path} lance sans interpreteur (utiliser `bash` ou `python3`)"))
            if mode_of(path) != "100755":
                errs.append((n, f"{path} n'est pas 100755 dans git ({mode_of(path)})"))
            if b"\r\n" in read(path):
                errs.append((n, f"{path} contient des CRLF"))
    return errs


def git_modes():
    out = subprocess.check_output(["git", "ls-files", "-s"], text=True)
    return {l.split("\t", 1)[1]: l.split()[0] for l in out.splitlines()}


if __name__ == "__main__":
    modes = git_modes()
    rc = 0
    for f in sys.argv[1:]:
        for n, msg in analyze(open(f, encoding="utf-8").read(), modes.get, lambda p: open(p, "rb").read()):
            print(f"::error file={f},line={n}::{msg}")
            rc = 1
    print("FAIL" if rc else "OK scripts des workflows")
    sys.exit(rc)
