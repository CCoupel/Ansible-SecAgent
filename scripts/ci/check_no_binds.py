#!/usr/bin/env python3
"""Lit un rendu `docker compose config --format json` sur stdin : exit 1 si un service monte un BIND MOUNT.
Contre un demon Docker distant, la source d'un bind est resolue sur l'hote distant (pas sur le poste) : interdit."""
import json
import sys

bad = [f"{n}:{v.get('source')}->{v.get('target')}"
       for n, s in json.load(sys.stdin).get("services", {}).items()
       for v in s.get("volumes", []) if v.get("type") == "bind"]
if bad:
    print("bind mounts : " + ", ".join(bad), file=sys.stderr)
    sys.exit(1)
