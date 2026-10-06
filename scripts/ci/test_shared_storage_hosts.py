#!/usr/bin/env python3
"""Test de l'assainissement de --host/--hosts de test_shared_storage.py (liste blanche, pas de separateur)."""
import importlib.util, os, subprocess, sys
here = os.path.dirname(os.path.abspath(__file__))
tool = os.path.join(here, "..", "..", "DEPLOYMENT", "prod", "tools", "test_shared_storage.py")
spec = importlib.util.spec_from_file_location("tss", tool); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
bad = 0
for h, ok in [("h1", True), ("node-1.example_x", True), ("a" * 64, True), ("a" * 65, False), ("", False), ("..", False),
              (".", False), ("../evil", False), ("a/b", False), ("a\\b", False), ("a b", False), ("h1\n", False)]:
    if m.valid_host(h) != ok:
        print("KO ", repr(h)); bad += 1
r = subprocess.run([sys.executable, tool, "verify", "--dir", "/nonexistent", "--hosts", "h1,../x"], capture_output=True)
if r.returncode != 2:
    print("KO exit code", r.returncode); bad += 1
print("ok" if not bad else "FAIL"); sys.exit(1 if bad else 0)
