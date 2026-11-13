#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Controle du rendu Compose de la chaine QUALIF sous Podman (#267, LOT-4) : hypotheses de securite de la garde
check-private.sh (pki/ en 0711, ca.crt/tls.crt 0644, tls.key 0600). Les services SERVEUR sont en keep-id (uid 10001 du
conteneur = proprietaire des fichiers : ils lisent tls.key) ; les MINIONS ne sont PAS en keep-id et ne montent QUE la CA
publique (T49 H1 : leur entrypoint tourne en root, = proprietaire de pki/ sous Podman rootless) ; tout montage /certs est
en lecture seule.
Usage : check_podman_certs.py [--minions-only] <rendu.json>... ; code 0 = conforme, 1 = non conforme, 2 = usage.
--minions-only : seule la regle des minions (rendus Docker : ni keep-id ni Podman)."""
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
        if name.startswith("minion"):
            errs += minion_ca_only(name, svc)
    return errs


def minion_ca_only(name, svc):
    """T49 H1 : un minion ne voit QUE la CA publique. L'entrypoint de l'image tourne en root (avant su-exec relay) et, sous
    Podman rootless, root du conteneur = proprietaire de pki/ sur l'hote : monter le dossier pki/ (ou le volume TLS
    complet) lui donnerait tls.key. Permis : bind du FICHIER ca.crt, ou volume dedie a la CA (`*tls_ca*`), en lecture
    seule ; tout autre montage sous /certs est refuse."""
    errs = []
    for v in svc.get("volumes") or []:
        if not isinstance(v, dict):
            continue
        tgt = str(v.get("target", ""))
        if tgt != "/certs" and not tgt.startswith("/certs/"):
            continue
        src, typ = str(v.get("source", "")), v.get("type")
        ok = (typ == "bind" and src.endswith("/ca.crt") and tgt == "/certs/ca.crt") or \
             (typ == "volume" and "tls_ca" in src and tgt == "/certs")
        if not ok:
            errs.append(f"{name} : {typ} {src} -> {tgt} : un minion ne monte QUE la CA publique (bind du fichier ca.crt "
                        f"ou volume *tls_ca*), jamais pki/ ni le volume TLS complet (tls.key, T49 H1)")
        elif not v.get("read_only"):
            errs.append(f"{name} : {tgt} doit etre monte en lecture seule")
    return errs


def main(argv):
    args = argv[1:]
    minions_only = bool(args) and args[0] == "--minions-only"
    if minions_only:
        args = args[1:]
    if not args:
        print(__doc__, file=sys.stderr)
        return 2
    bad = 0
    for path in args:
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
        if minions_only:
            errs = [e for n, s in sorted((doc.get("services") or {}).items()) if n.startswith("minion") for e in minion_ca_only(n, s)]
        else:
            errs = check(doc)
        for e in errs:
            print(f"::error::{path} : {e}")
        if not errs:
            print(f"OK {path}")
        bad |= bool(errs)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
