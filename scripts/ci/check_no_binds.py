#!/usr/bin/env python3
"""Lit un rendu `docker compose config --format json` sur stdin : exit 1 si un service monte un BIND MOUNT ou un SECRET
`file:` Compose (hors Swarm, Compose le monte en bind du fichier de l'hote : uid/gid/mode ignores, et contre un demon
distant le chemin est resolu sur l'hote distant, pas sur le poste) : interdit contre un demon distant."""
import json
import sys

doc = json.load(sys.stdin)
bad = [f"{n}:{v.get('source')}->{v.get('target')}"
       for n, s in doc.get("services", {}).items()
       for v in s.get("volumes", []) if v.get("type") == "bind"]
file_secrets = {k for k, v in (doc.get("secrets") or {}).items() if isinstance(v, dict) and v.get("file")}
bad += [f"{n}:secret '{(x if isinstance(x, str) else x.get('source'))}' (file:)"
        for n, s in doc.get("services", {}).items()
        for x in s.get("secrets", []) or []
        if (x if isinstance(x, str) else x.get("source")) in file_secrets]
if bad:
    print("bind mounts / secrets file: " + ", ".join(bad), file=sys.stderr)
    sys.exit(1)
