#!/usr/bin/env python3
"""Test (positif et negatif) de check_scripts.py."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from check_scripts import analyze
modes = {"a/ok.sh": "100755", "a/noexec.sh": "100644", "a/crlf.sh": "100755", "t/x.py": "100755"}
files = {"a/crlf.sh": b"#!/bin/bash\r\necho\r\n"}
mode_of = modes.get
read = lambda p: files.get(p, b"echo\n")
cases = [
    ("run: bash a/ok.sh run stop", 0),
    ("run: python3 t/x.py", 0),
    ("run: a/ok.sh run", 1),                 # direct, sans interpreteur
    ("run: bash a/noexec.sh", 1),            # mode 100644
    ("run: bash a/crlf.sh", 1),              # CRLF
    ("run: bash inconnu/zz.sh", 0),          # hors depot : ignore
    ("# run: a/noexec.sh", 0),               # commentaire
]
bad = 0
for text, want in cases:
    got = len(analyze(text, mode_of, read))
    if bool(got) != bool(want):
        print("KO ", text, got); bad += 1
print("ok" if not bad else "FAIL"); sys.exit(1 if bad else 0)
