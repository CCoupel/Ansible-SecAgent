#!/usr/bin/env python3
"""Auto-test de check_compose.py sur des rendus JSON synthetiques (sans docker). Exit 0 = conforme."""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))
from check_compose import check

def svc(ports, env=None, image="ghcr.io/ccoupel/secagent-server:v1"):
    return {"services": {"s": {"image": image, "environment": env or {}, "ports": ports}}}

P = lambda ip, t=7771: {"target": t, "published": str(t), **({"host_ip": ip} if ip is not None else {})}
ok = {"ADMIN_ADDR": "0.0.0.0:7771", "ADMIN_TLS": "true", "TLS_CERT": "/c/crt", "TLS_KEY": "/c/key"}
cases = [
    ("loopback + TLS", svc([P("127.0.0.1")], ok), False),
    ("sans host_ip", svc([P(None)], ok), True),
    ("0.0.0.0", svc([P("0.0.0.0")], ok), True),
    ("::", svc([P("::")], ok), True),
    ("non loopback sans TLS", svc([P("127.0.0.1")], {"ADMIN_ADDR": "0.0.0.0:7771"}), True),
    ("defaut ADMIN_ADDR sans TLS", svc([P("127.0.0.1")], {}), True),
    ("derogation complete", svc([P("127.0.0.1")], {"ADMIN_ADDR": ":7771", "ADMIN_INSECURE_HTTP": "true", "ADMIN_INSECURE_HTTP_ACK": "i-understand-the-risk"}), False),
    ("derogation sans ack", svc([P("127.0.0.1")], {"ADMIN_ADDR": ":7771", "ADMIN_INSECURE_HTTP": "true"}), True),
    ("admin loopback", svc([P("127.0.0.1")], {"ADMIN_ADDR": "127.0.0.1:7771"}), False),
    ("latest", svc([], ok, "ghcr.io/x/y:latest"), True),
    ("sans tag", svc([], ok, "ghcr.io/x/y"), True),
    ("tag@digest", svc([], ok, "ghcr.io/x/y:v1@sha256:" + "0" * 64), False),
    ("TLS_DISABLE", svc([], {**ok, "TLS_DISABLE": "true"}), True),
    ("ADMIN_TLS=TRUE refuse", svc([P("127.0.0.1")], {**ok, "ADMIN_TLS": "TRUE"}), True),
    ("ADMIN_TLS=1 refuse", svc([P("127.0.0.1")], {**ok, "ADMIN_TLS": "1"}), True),
    ("ADMIN_TLS sans certificats", svc([P("127.0.0.1")], {"ADMIN_ADDR": ":7771", "ADMIN_TLS": "true"}), True),
    ("derogation ack faux", svc([P("127.0.0.1")], {"ADMIN_ADDR": ":7771", "ADMIN_INSECURE_HTTP": "true", "ADMIN_INSECURE_HTTP_ACK": "yes"}), True),
    ("derogation valeur 1", svc([P("127.0.0.1")], {"ADMIN_ADDR": ":7771", "ADMIN_INSECURE_HTTP": "1", "ADMIN_INSECURE_HTTP_ACK": "i-understand-the-risk"}), True),
    ("admin 127.0.0.2", svc([P("127.0.0.2")], {"ADMIN_ADDR": "127.0.0.2:7771"}), False),
    ("admin [::1]", svc([P("::1")], {"ADMIN_ADDR": "[::1]:7771"}), False),
    ("admin localhost", svc([P("127.0.0.1")], {"ADMIN_ADDR": "localhost:7771"}), False),
    ("admin [::] sans TLS", svc([P("127.0.0.1")], {"ADMIN_ADDR": "[::]:7771"}), True),
    ("TLS_DISABLE=1 invalide", svc([], {**ok, "TLS_DISABLE": "1"}), True),
    ("nats", {"services": {"nats": {"image": "nats:2"}}}, True),
]
m = svc([], {**ok, "GOMEMLIMIT": "1638MiB"}); m["services"]["s"]["deploy"] = {"resources": {"limits": {"memory": "2147483648"}}}
for name, doc, want_fail in [("mem ok", m, False), ("mem absente", svc([], ok), True)]:
    got = bool(check(doc, False, True))
    print(("ok  " if got == want_fail else "KO  ") + name)
    if got != want_fail:
        sys.exit(1)
dg = svc([], ok, "ghcr.io/x/y:v1@sha256:" + "0" * 64)
loc = svc([], ok, "secagent-server:ci-0123456789ab")
for name, doc, want_fail, rd in [("digest exige : tag@digest OK", dg, False, True), ("digest exige : tag local refuse", loc, True, True),
                                 ("qualif : tag local accepte", loc, False, False)]:
    got = bool(check(doc, False, False, rd))
    print(("ok  " if got == want_fail else "KO  ") + name)
    if got != want_fail:
        sys.exit(1)
bad = 0
for name, doc, want_fail in cases:
    got = bool(check(doc, False))
    print(("ok  " if got == want_fail else "KO  ") + name)
    bad += got != want_fail
# #232 : REPEATER_UPSTREAM_URL doit etre en wss:// (le serveur refuse tout autre schema : « must use the wss:// scheme »).
# Un service qui porte un REPEATER_ID est un relay ENFANT : son REPEATER_UPSTREAM_URL ne peut pas etre vide.
def child(url, **extra):
    env = {**ok, "REPEATER_ID": "dmz1", "REPEATER_UPSTREAM_TOKEN_FILE": "/run/secagent-link/upstream-token"}
    if url is not None:
        env["REPEATER_UPSTREAM_URL"] = url
    return svc([], {**env, **extra})


WSS_A, WSS_B = "wss://relay-a.example:7772", "wss://relay-b.example:7772"
upstream_cases = [
    ("upstream : wss://...:7772", child(WSS_A), False),
    ("upstream : deux adresses wss://", child(WSS_A + "," + WSS_B), False),
    ("upstream : adresses separees par des espaces", child(WSS_A + ", " + WSS_B), False),
    ("upstream : wss:// sans port (7772 est une convention)", child("wss://relay-a.example"), False),
    ("upstream : https://...:7770 refuse", child("https://relay-a.example:7770"), True),
    ("upstream : ws:// refuse (TLS obligatoire)", child("ws://relay-a.example:7772"), True),
    ("upstream : http:// refuse", child("http://relay-a.example:7770"), True),
    ("upstream : sans schema refuse", child("relay-a.example:7772"), True),
    ("upstream : vide pour un enfant refuse", child(""), True),
    ("upstream : absent pour un enfant refuse", child(None), True),
    ("upstream : une adresse non wss:// dans la liste suffit a refuser", child(WSS_A + ",https://relay-b.example:7770"), True),
    ("upstream : la mauvaise adresse en premier", child("https://relay-a.example:7770," + WSS_B), True),
    ("upstream : schema en majuscules refuse comme le serveur (sensible a la casse)", child("WSS://relay-a.example:7772"), None),
    ("upstream : racine sans REPEATER_ID ni URL accepte", svc([], ok), False),
    ("upstream : racine avec URL non wss:// refuse aussi", svc([], {**ok, "REPEATER_UPSTREAM_URL": "https://r:7770"}), True),
]
for name, doc, want_fail in upstream_cases:
    errs = check(doc, False)
    if want_fail is None:  # comportement a documenter, pas a figer : le test ne tranche pas
        print("info " + name + " -> " + ("refuse" if errs else "accepte"))
        continue
    if want_fail:
        good = any("REPEATER_UPSTREAM_URL" in e for e in errs)  # refuse POUR CETTE RAISON, pas pour une autre regle
    else:
        good = not errs
    print(("ok  " if good else "KO  ") + name + ("" if good else "  -> " + repr(errs)))
    bad += not good

# le message d'erreur nomme le service, la variable et le schema attendu (l'operateur doit pouvoir corriger sans lire le code)
msg = " ".join(check(child("https://relay-a.example:7770"), False))
for want in ("service 's'", "REPEATER_UPSTREAM_URL", "wss://"):
    if want not in msg:
        print("KO  message d'erreur sans " + repr(want) + " : " + msg)
        bad += 1
        break
else:
    print("ok  message d'erreur upstream : service, variable, schema attendu")

# bout en bout : le CLI sort en 1 avec ::error:: pour https://, en 0 pour wss://
import json, subprocess, tempfile
HERE = os.path.dirname(os.path.abspath(__file__))
with tempfile.TemporaryDirectory() as tmp:
    for name, url, want_rc in [("cli : https:// -> exit 1", "https://relay-a.example:7770", 1), ("cli : wss:// -> exit 0", WSS_A, 0)]:
        f = os.path.join(tmp, "r.json")
        with open(f, "w", encoding="utf-8") as fh:
            json.dump(child(url), fh)
        r = subprocess.run([sys.executable, "-I", os.path.join(HERE, "check_compose.py"), f], capture_output=True, text=True)
        good = r.returncode == want_rc and (want_rc == 0 or "::error::" in r.stdout and "REPEATER_UPSTREAM_URL" in r.stdout)
        print(("ok  " if good else "KO  ") + name + ("" if good else "  -> rc=%d %s" % (r.returncode, r.stdout)))
        bad += not good

# les exemples livres (.env.example, README prod) respectent la regle : decommentes, ils seraient acceptes par le serveur
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
def urls_in(path):
    out = []
    with open(os.path.join(ROOT, path), encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            m = re.match(r"^\s*#?\s*REPEATER_UPSTREAM_URL=(\S+)", line)
            if m:
                out += [(n, u) for u in m.group(1).split(",") if u]
    return out
import re
for path in ("DEPLOYMENT/prod/.env.example", "DEPLOYMENT/prod/prod.env.example"):
    if not os.path.exists(os.path.join(ROOT, path)):
        continue
    found = urls_in(path)
    badu = [(n, u) for n, u in found if not u.startswith("wss://")]
    good = not badu
    print(("ok  " if good else "KO  ") + "exemple %s : REPEATER_UPSTREAM_URL en wss:// (%d adresse(s))" % (path, len(found)) + ("" if good else "  -> " + repr(badu)))
    bad += not good
readme = open(os.path.join(ROOT, "DEPLOYMENT/prod/README.md"), encoding="utf-8").read()
lines = [l for l in readme.splitlines() if "REPEATER_UPSTREAM_URL" in l]
good = any("wss://" in l for l in lines) and not re.search(r"REPEATER_UPSTREAM_URL[^\n]*https?://", readme)
print(("ok  " if good else "KO  ") + "README prod : une ligne de REPEATER_UPSTREAM_URL precise le schema wss:// (jamais http(s)://)")
bad += not good

sys.exit(1 if bad else 0)
