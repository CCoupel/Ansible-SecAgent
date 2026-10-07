#!/usr/bin/env python3
"""Test (negatif et positif) de check_no_publish.py."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from check_no_publish import violations
cases = [
    ("permissions:\n  contents: read\n", False),
    ("with:\n  push: false\n", False),
    ("# packages: write (commentaire)\n", False),
    ("permissions:\n  packages: write\n", True),
    ("- uses: docker/login-action@abc\n", True),
    ("with:\n  push: true\n", True),
    ("outputs: type=image,push=true\n", True),
    ("on:\n  pull_request_target:\n", True),
    ("- uses: actions/upload-artifact@abc # v4\n  with:\n    retention-days: 7\n", False),   # artefact de run : autorise
    ("run: docker save x | gzip > o.tar.gz\n", False),
]
bad = 0
for text, want in cases:
    if bool(violations(text)) != want:
        print("KO ", repr(text)); bad += 1
print("ok" if not bad else "FAIL"); sys.exit(1 if bad else 0)
