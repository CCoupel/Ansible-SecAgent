#!/usr/bin/env python3
"""Controles de securite sur le RENDU d'un Compose (`docker compose config --format json`).

Usage : check_compose.py [--allow-build] [--require-memory-limit] rendu.json [rendu2.json ...]
        docker compose -f X config --format json | check_compose.py -

Echec (exit 1) si, pour un service :
  - le port conteneur 7771 est publie sans host_ip, ou sur 0.0.0.0 / :: ;
  - ADMIN_ADDR (defaut ":7771") n'est pas loopback sans ADMIN_TLS=true NI derogation complete
    (ADMIN_INSECURE_HTTP=true + ADMIN_INSECURE_HTTP_ACK=i-understand-the-risk) — meme regle que le serveur ;
  - TLS_DISABLE vaut true ;
  - une image est `latest` ou sans tag, ou un `build:` est present (sauf --allow-build : qualif locale) ;
  - --require-memory-limit : pas de limite memoire de conteneur, ou GOMEMLIMIT absent ;
  - la configuration mentionne NATS / JetStream / Caddy.
"""
import json
import sys

ACK = "i-understand-the-risk"
LOOPBACK = {"127.0.0.1", "localhost", "::1"}
WILDCARD = {"", "0.0.0.0", "::", "[::]"}


def admin_host(addr: str) -> str:
    addr = addr.strip()
    if addr.startswith("["):
        return addr[1:addr.index("]")]
    return addr.rsplit(":", 1)[0] if ":" in addr else addr


def env_of(svc: dict) -> dict:
    env = svc.get("environment") or {}
    if isinstance(env, list):
        env = dict(e.split("=", 1) for e in env if "=" in e)
    return {k: ("" if v is None else str(v)) for k, v in env.items()}


def check(doc: dict, allow_build: bool, require_mem: bool = False) -> list:
    errs = []
    for name, svc in (doc.get("services") or {}).items():
        where = f"service '{name}'"
        env = env_of(svc)
        for p in svc.get("ports") or []:
            if isinstance(p, dict):
                target, ip = int(p.get("target", 0)), p.get("host_ip", "")
            else:  # forme courte, au cas ou
                parts = str(p).split(":")
                target = int(parts[-1].split("/")[0])
                ip = ":".join(parts[:-2]) if len(parts) > 2 else ""
            if target == 7771 and (ip in WILDCARD or ip is None):
                errs.append(f"{where}: port admin 7771 publie sans host_ip ou sur 0.0.0.0/:: (host_ip={ip!r})")
            elif target == 7771 and ip not in LOOPBACK:
                print(f"INFO {where}: 7771 publie sur {ip} (reseau d'administration, a valider)", file=sys.stderr)
        admin = env.get("ADMIN_ADDR", ":7771")
        if admin_host(admin) not in LOOPBACK:
            tls = env.get("ADMIN_TLS", "").lower() == "true"
            derog = env.get("ADMIN_INSECURE_HTTP", "").lower() == "true" and env.get("ADMIN_INSECURE_HTTP_ACK") == ACK
            if not (tls or derog):
                errs.append(f"{where}: ADMIN_ADDR={admin!r} non loopback sans ADMIN_TLS=true ni derogation complete")
        if env.get("TLS_DISABLE", "").lower() in ("1", "true", "yes"):
            errs.append(f"{where}: TLS_DISABLE interdit")
        image = svc.get("image", "")
        if image:
            ref = image.split("@")[0]
            tag = ref.rsplit(":", 1)[1] if ":" in ref.rsplit("/", 1)[-1] else ""
            if tag in ("", "latest"):
                errs.append(f"{where}: image {image!r} sans tag fixe ou 'latest'")
        elif "build" not in svc:
            errs.append(f"{where}: ni image ni build")
        if require_mem:
            lim = ((svc.get("deploy") or {}).get("resources") or {}).get("limits", {}).get("memory") or svc.get("mem_limit")
            if not lim or str(lim) in ("0", ""):
                errs.append(f"{where}: limite memoire de conteneur absente")
            if not env.get("GOMEMLIMIT"):
                errs.append(f"{where}: GOMEMLIMIT absent")
        if "build" in svc and not allow_build:
            errs.append(f"{where}: 'build:' interdit")
    blob = json.dumps(doc).lower()
    for word in ("nats", "jetstream", "caddy"):
        if word in blob:
            errs.append(f"mention interdite de '{word}' dans le rendu")
    return errs


def main(argv):
    allow = "--allow-build" in argv
    req = "--require-memory-limit" in argv
    files = [a for a in argv if not a.startswith("--")]
    if not files:
        print(__doc__)
        return 2
    rc = 0
    for f in files:
        doc = json.load(sys.stdin if f == "-" else open(f, encoding="utf-8"))
        errs = check(doc, allow, req)
        for e in errs:
            print(f"::error::{f}: {e}")
        print(f"{'FAIL' if errs else 'OK'} {f}")
        rc |= bool(errs)
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
