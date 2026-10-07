#!/usr/bin/env python3
"""Controles de securite sur le RENDU d'un Compose (`docker compose config --format json`).

Usage : check_compose.py [--allow-build] [--require-memory-limit] [--require-digest] rendu.json [rendu2.json ...]
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
import re
import sys

ACK = "i-understand-the-risk"
LOOPBACK_NAMES = {"localhost", "::1"}  # + 127.0.0.0/8 (is_loopback)
WILDCARD = {"", "0.0.0.0", "::", "[::]"}


def is_loopback(host: str) -> bool:
    """Meme regle que le serveur : 127.0.0.0/8, ::1, localhost ; ':7771', 0.0.0.0, [::] = non loopback."""
    h = host.strip().strip("[]")
    return h == "localhost" or h == "::1" or h.startswith("127.") and h.count(".") == 3 and all(
        p.isdigit() and int(p) < 256 for p in h.split("."))


def strict_bool(env: dict, name: str, where: str, errs: list) -> bool:
    """Booleen strict du serveur : seuls "", "true", "false" sont acceptes ; `1`/`yes`/`TRUE`/`on` = refus au demarrage."""
    v = env.get(name, "")
    if v not in ("", "true", "false"):
        errs.append(f"{where}: {name}={v!r} invalide (seuls 'true' et 'false' exacts sont acceptes, le serveur refuse de demarrer)")
    return v == "true"


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


def check(doc: dict, allow_build: bool, require_mem: bool = False, require_digest: bool = False) -> list:
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
            elif target == 7771 and not is_loopback(ip):
                print(f"INFO {where}: 7771 publie sur {ip} (reseau d'administration, a valider)", file=sys.stderr)
        is_server = "secagent-server" in svc.get("image", "") or "ADMIN_ADDR" in env
        admin = env.get("ADMIN_ADDR", ":7771")
        tls = strict_bool(env, "ADMIN_TLS", where, errs)
        insecure = strict_bool(env, "ADMIN_INSECURE_HTTP", where, errs)
        tls_disable = strict_bool(env, "TLS_DISABLE", where, errs)
        if tls and not (env.get("TLS_CERT") and env.get("TLS_KEY")):
            errs.append(f"{where}: ADMIN_TLS=true exige TLS_CERT et TLS_KEY")
        if is_server and not is_loopback(admin_host(admin)):
            derog = insecure and env.get("ADMIN_INSECURE_HTTP_ACK") == ACK
            if not (tls or derog):
                errs.append(f"{where}: ADMIN_ADDR={admin!r} non loopback sans ADMIN_TLS=true ni derogation complete")
        if tls_disable:
            errs.append(f"{where}: TLS_DISABLE interdit")
        image = svc.get("image", "")
        if image:
            ref = image.split("@")[0]
            tag = ref.rsplit(":", 1)[1] if ":" in ref.rsplit("/", 1)[-1] else ""
            if tag in ("", "latest"):
                errs.append(f"{where}: image {image!r} sans tag fixe ou 'latest'")
            # Prod (archive de release) : `tag@sha256:<64 hex>` obligatoire. Qualif : un tag local `secagent-*:ci-<sha12>`
            # (image chargee par docker load) est accepte, car --require-digest n'y est pas demande.
            if require_digest and not re.search(r"@sha256:[0-9a-f]{64}$", image):
                errs.append(f"{where}: image {image!r} sans digest @sha256:<64 hex> (exige en production)")
        elif "build" not in svc:
            errs.append(f"{where}: ni image ni build")
        if require_mem:
            lim = ((svc.get("deploy") or {}).get("resources") or {}).get("limits", {}).get("memory") or svc.get("mem_limit")
            if not lim or str(lim) in ("0", ""):
                errs.append(f"{where}: limite memoire de conteneur absente")
            if is_server and not env.get("GOMEMLIMIT"):
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
    reqd = "--require-digest" in argv
    files = [a for a in argv if not a.startswith("--")]
    if not files:
        print(__doc__)
        return 2
    rc = 0
    for f in files:
        doc = json.load(sys.stdin if f == "-" else open(f, encoding="utf-8"))
        errs = check(doc, allow, req, reqd)
        for e in errs:
            print(f"::error::{f}: {e}")
        print(f"{'FAIL' if errs else 'OK'} {f}")
        rc |= bool(errs)
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
