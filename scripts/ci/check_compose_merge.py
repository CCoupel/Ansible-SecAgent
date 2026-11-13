#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Controle des SOURCES Compose avant podman-compose (#267, LOT-4, T48 2026-11-13).

podman-compose 1.5 fusionne les fichiers -f par `rec_merge_one` : une meme cle presente des deux cotes avec des TYPES
differents est refusee (« can't merge value of [child_state] of type NoneType and dict »), alors que docker compose
l'accepte. Ce script :
  1. refuse toute ressource de premier niveau (volumes, networks, secrets, configs) declaree avec une valeur NULLE
     (`nom:` sans valeur) : ecrire `nom: {}` ;
  2. reproduit la fusion de podman-compose sur une combinaison de fichiers (-f, dans l'ordre, `include:` compris) et
     refuse tout conflit de types.
Usage :
  check_compose_merge.py --no-null <fichier.yml>...        regle 1 sur chaque fichier
  check_compose_merge.py -f a.yml -f b.yml [-f c.yml]...    regle 2 sur la combinaison (et regle 1 sur ses fichiers)
Code 0 = conforme, 1 = non conforme, 2 = usage."""
import os, sys

try:
    import yaml
except ImportError:  # pragma: no cover
    print("::error::PyYAML requis (python3-yaml)", file=sys.stderr)
    sys.exit(2)

RESOURCES = ("volumes", "networks", "secrets", "configs")


class MergeError(ValueError):
    pass


def load(path):
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def null_resources(doc, name):
    errs = []
    for sec in RESOURCES:
        for key, val in (doc.get(sec) or {}).items():
            if val is None:
                errs.append(f"{name} : {sec}.{key} declare sans valeur (nul) : ecrire `{key}: {{}}` (podman-compose 1.5)")
    return errs


def rec_merge_one(target, source, path=""):
    """Meme regle que podman_compose.rec_merge_one (1.5) : type identique exige quand la cle existe des deux cotes."""
    for key, value2 in source.items():
        where = f"{path}.{key}" if path else key
        if key not in target:
            target[key] = value2
            continue
        value = target[key]
        if key in ("command", "entrypoint"):
            target[key] = value2
            continue
        if not isinstance(value2, type(value)):
            raise MergeError(f"can't merge value of [{where}] of type {type(value).__name__} and {type(value2).__name__}")
        if isinstance(value2, list):
            value.extend(value2)
        elif isinstance(value2, dict):
            rec_merge_one(value, value2, where)
        else:
            target[key] = value2
    return target


def expand(files):
    """Fichiers dans l'ordre de fusion : chaque fichier puis ses `include:` (chemins relatifs a lui)."""
    out = []
    for f in files:
        doc = load(f)
        out.append((f, doc))
        for inc in doc.get("include") or []:
            p = inc if isinstance(inc, str) else (inc.get("path") if isinstance(inc, dict) else None)
            if isinstance(p, list):
                p = p[0] if p else None
            if p:
                out.extend(expand([os.path.join(os.path.dirname(f), p)]))
    return out


def check_merge(files):
    errs, merged = [], {}
    for name, doc in expand(files):
        errs += null_resources(doc, name)
        body = {k: v for k, v in doc.items() if k != "include"}
        try:
            rec_merge_one(merged, body)
        except MergeError as e:
            errs.append(f"{' + '.join(files)} : {e} (en fusionnant {name})")
    return errs


def main(argv):
    args = argv[1:]
    errs = []
    if args[:1] == ["--no-null"] and len(args) > 1:
        for f in args[1:]:
            errs += null_resources(load(f), f)
        label = f"{len(args) - 1} fichier(s)"
    elif args and len(args) % 2 == 0 and all(a == "-f" for a in args[0::2]):
        files = args[1::2]
        errs = check_merge(files)
        label = " + ".join(files)
    else:
        print(__doc__, file=sys.stderr)
        return 2
    for e in errs:
        print(f"::error::{e}")
    if not errs:
        print(f"OK fusion podman-compose : {label}")
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
