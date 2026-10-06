#!/usr/bin/env python3
"""Garde-fou : un workflow de push/PR ne publie rien. Echoue si le fichier contient (hors commentaires)
`packages: write`, `docker/login-action`, `push: true`, `push=true` ou `pull_request_target`.
Usage : check_no_publish.py workflow.yml [...]"""
import re, sys

FORBIDDEN = [r"packages:\s*write", r"docker/login-action", r"\bpush:\s*true\b", r"\bpush=true\b", r"pull_request_target"]


def violations(text):
    out = []
    for n, line in enumerate(text.splitlines(), 1):
        code = line.split("#", 1)[0]
        for pat in FORBIDDEN:
            if re.search(pat, code):
                out.append((n, pat, line.strip()))
    return out


if __name__ == "__main__":
    rc = 0
    for f in sys.argv[1:]:
        for n, pat, line in violations(open(f, encoding="utf-8").read()):
            print(f"::error file={f},line={n}::publication interdite dans un workflow de push : {line}")
            rc = 1
        print(("FAIL " if rc else "OK ") + f)
    sys.exit(rc)
