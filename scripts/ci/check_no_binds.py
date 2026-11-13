#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Lit un rendu `docker compose config --format json` sur stdin : exit 1 si le rendu reference un CHEMIN DU CLIENT, ce qui
est interdit contre un demon Docker DISTANT (le chemin serait resolu sur l'hote distant, pas sur le poste) :

  - un BIND MOUNT dans `volumes` d'un service ;
  - un SECRET `file:` ou un CONFIG `file:` (hors Swarm, Compose les monte en bind mount du fichier du client ; uid/gid/mode
    sont ignores) utilise par un service ;
  - un `build:` (le contexte est un repertoire du client) ;
  - un VOLUME NOMME local dont `driver_opts` fait un bind (`o` contient `bind`, ou `type: none`) d'un `device:` : c'est
    un bind mount deguise (#267), soumis aux memes regles que `type: bind`.

Option `--allow-prefix <chemin absolu>` (Podman rootless, #267 : SECAGENT_HOST_PREFIX, ex.
/share/MFS/ROOT/CLAUDE_PROJETS/PROJETS/PRO/Ansible_SecAgent/PRIVATE/PROD, PRIVATE/<ENV>/ vu par le montage autofs du NOEUD) : un bind mount ou un secret/config `file:` est accepte
UNIQUEMENT si sa source, normalisee, designe un des sous-chemins permis de ce prefixe :
  repertoires (eux-memes ou dessous) : state/root, state/child, secrets, pki (ca.key est rangee a part dans pki-ca/,
                                       #267 ; pki/ca.key reste refuse explicitement) ;
  fichiers (exacts)                 : pki/tls.crt, pki/tls.key, pki/ca.crt.
Tout le reste du prefixe est refuse, notamment le prefixe lui-meme, state/, pki/ca.key, pki-ca/ (cle de la CA),
poste-cyril/ (cle SSH d'acces aux noeuds) et
<srvX>/ (fichiers de deploiement des noeuds : Compose, garde, unites ; jamais lies dans un conteneur). Prefixe relatif, avec `..`, ou de moins de 4 composants
(`/`, `/etc`, `/home/cyril`...) : refuse (code 2). Une source relative ou qui sort du prefixe par `..` reste refusee ;
`build:` reste toujours refuse. Les liens symboliques ne sont PAS resolus (normpath seul) : le noeud est maitrise par
l'utilisateur rootless, un lien pose sous le prefixe est hors du modele de menace de ce controle statique.

Acceptes : volumes nommes (type volume, y compris `external`), tmpfs, `env_file:` (lu cote CLIENT et injecte dans
l'environnement : le rendu l'inline dans `environment`, il n'y a donc rien a refuser), secrets/configs a source
`environment:` ou `content:`.
"""
import json
import os
import sys


def source_of(entry):
    return entry if isinstance(entry, str) else entry.get("source")


ALLOWED_DIRS = ("state/root", "state/child", "secrets", "pki")
ALLOWED_FILES = ("pki/tls.crt", "pki/tls.key", "pki/ca.crt")
DENIED = ("pki/ca.key",)   # refuse meme sous un repertoire permis
MIN_PREFIX_PARTS = 4


def under(src, prefix) -> bool:
    """True si `src` (chemin absolu, normalise) est un sous-chemin PERMIS de `prefix` ; jamais pour un chemin relatif."""
    if not prefix or not isinstance(src, str) or not src.startswith("/"):
        return False
    norm = os.path.normpath(src)
    if any(norm == f"{prefix}/{d}" or norm.startswith(f"{prefix}/{d}/") for d in DENIED):
        return False
    if any(norm == f"{prefix}/{d}" or norm.startswith(f"{prefix}/{d}/") for d in ALLOWED_DIRS):
        return True
    return any(norm == f"{prefix}/{f}" for f in ALLOWED_FILES)


def bind_volumes(doc: dict) -> dict:
    """Volumes nommes dont driver_opts realise un bind : {cle du volume: device}."""
    out = {}
    for key, d in (doc.get("volumes") or {}).items():
        if not isinstance(d, dict) or d.get("external"):
            continue
        opts = d.get("driver_opts") or {}
        o = str(opts.get("o", "")).replace(" ", "").split(",")
        if "device" in opts and ("bind" in o or "rbind" in o or str(opts.get("type", "")) == "none"):
            out[key] = str(opts["device"])
    return out


def find_client_paths(doc: dict, prefix: str = "") -> list:
    bad = []
    services = doc.get("services") or {}
    bvols = bind_volumes(doc)
    for name, svc in services.items():
        for v in svc.get("volumes") or []:
            if isinstance(v, dict) and v.get("type") == "bind" and not under(v.get("source"), prefix):
                bad.append(f"{name}: bind mount {v.get('source')} -> {v.get('target')}")
            elif isinstance(v, dict) and v.get("type") == "volume" and v.get("source") in bvols \
                    and not under(bvols[v["source"]], prefix):
                bad.append(f"{name}: volume '{v['source']}' = bind de {bvols[v['source']]} (driver_opts) -> {v.get('target')}")
        if "build" in svc:
            bad.append(f"{name}: build (contexte du client)")
    for kind in ("secrets", "configs"):
        defs = doc.get(kind) or {}
        file_based = {k for k, d in defs.items() if isinstance(d, dict) and d.get("file") and not under(d.get("file"), prefix)}
        for name, svc in services.items():
            for entry in svc.get(kind) or []:
                src = source_of(entry)
                if src in file_based:
                    bad.append(f"{name}: {kind[:-1]} '{src}' (file:, bind du chemin du client)")
    return bad


def parse_prefix(argv: list) -> str:
    """`--allow-prefix P` : P absolu, different de `/`, sans composant `..` ; renvoie P normalise ('' sans option)."""
    if not argv:
        return ""
    if len(argv) != 2 or argv[0] != "--allow-prefix":
        raise ValueError("usage : check_no_binds.py [--allow-prefix <chemin absolu>] < rendu.json")
    p = argv[1]
    if not p.startswith("/") or ".." in p.split("/"):
        raise ValueError(f"--allow-prefix {p!r} : chemin absolu attendu, sans '..'")
    norm = os.path.normpath(p)
    if len([c for c in norm.split("/") if c]) < MIN_PREFIX_PARTS:
        raise ValueError(f"--allow-prefix {p!r} : au moins {MIN_PREFIX_PARTS} composants attendus "
                         "(ex. /home/cyril/secagent/<env>)")
    return norm


def main(argv=None) -> int:
    try:
        prefix = parse_prefix(sys.argv[1:] if argv is None else argv)
    except ValueError as e:
        print(f"REFUS: {e}", file=sys.stderr)
        return 2
    bad = find_client_paths(json.load(sys.stdin), prefix)
    if bad:
        print("chemins du client interdits contre un demon distant : " + " ; ".join(bad), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
