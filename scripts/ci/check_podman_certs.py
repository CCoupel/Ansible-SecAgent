#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Controle du rendu Compose de la chaine QUALIF sous Podman (#267, LOT-4) : hypotheses de securite de la garde
check-private.sh (pki/ en 0711, ca.crt/tls.crt 0644, tls.key 0600). Les services SERVEUR sont en keep-id (uid 10001 du
conteneur = proprietaire des fichiers : ils lisent tls.key) ; les MINIONS ne sont PAS en keep-id (uid `relay` = un uid
secondaire de l'hote : ils ne lisent que les certificats publics) ; tout montage /certs est en lecture seule.
Usage : check_podman_certs.py <rendu.json> ; code 0 = conforme, 1 = non conforme, 2 = usage."""
import json, sys

SERVERS = ("secagent-server-a", "secagent-server-b", "secagent-child")


def check(doc):
    errs = []
    svcs = doc.get("services") or {}
    for name, svc in sorted(svcs.items()):
        keep = str(svc.get("userns_mode", "")).startswith("keep-id")
        if name in SERVERS and not keep:
            errs.append(f"{name} : keep-id attendu (le serveur lit tls.key en proprietaire)")
        if name.startswith("minion") and keep:
            errs.append(f"{name} : keep-id INTERDIT (le minion deviendrait proprietaire et lirait tls.key)")
        for v in svc.get("volumes") or []:
            if isinstance(v, dict) and v.get("target") == "/certs" and not v.get("read_only"):
                errs.append(f"{name} : /certs doit etre monte en lecture seule")
    return errs


def main(argv):
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    with open(argv[1], encoding="utf-8") as f:
        errs = check(json.load(f))
    for e in errs:
        print(f"::error::{argv[1]} : {e}")
    if not errs:
        print(f"OK {argv[1]}")
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
