#!/usr/bin/env python3
"""Lit un rendu `docker compose config --format json` sur stdin : exit 1 si le rendu reference un CHEMIN DU CLIENT, ce qui
est interdit contre un demon Docker DISTANT (le chemin serait resolu sur l'hote distant, pas sur le poste) :

  - un BIND MOUNT dans `volumes` d'un service ;
  - un SECRET `file:` ou un CONFIG `file:` (hors Swarm, Compose les monte en bind mount du fichier du client ; uid/gid/mode
    sont ignores) utilise par un service ;
  - un `build:` (le contexte est un repertoire du client).

Acceptes : volumes nommes (type volume, y compris `external`), tmpfs, `env_file:` (lu cote CLIENT et injecte dans
l'environnement : le rendu l'inline dans `environment`, il n'y a donc rien a refuser), secrets/configs a source
`environment:` ou `content:`.
"""
import json
import sys


def source_of(entry):
    return entry if isinstance(entry, str) else entry.get("source")


def find_client_paths(doc: dict) -> list:
    bad = []
    services = doc.get("services") or {}
    for name, svc in services.items():
        for v in svc.get("volumes") or []:
            if isinstance(v, dict) and v.get("type") == "bind":
                bad.append(f"{name}: bind mount {v.get('source')} -> {v.get('target')}")
        if "build" in svc:
            bad.append(f"{name}: build (contexte du client)")
    for kind in ("secrets", "configs"):
        defs = doc.get(kind) or {}
        file_based = {k for k, d in defs.items() if isinstance(d, dict) and d.get("file")}
        for name, svc in services.items():
            for entry in svc.get(kind) or []:
                src = source_of(entry)
                if src in file_based:
                    bad.append(f"{name}: {kind[:-1]} '{src}' (file:, bind du chemin du client)")
    return bad


def main() -> int:
    bad = find_client_paths(json.load(sys.stdin))
    if bad:
        print("chemins du client interdits contre un demon distant : " + " ; ".join(bad), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
