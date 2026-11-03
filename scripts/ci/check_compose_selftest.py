#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
# SPDX-License-Identifier: AGPL-3.0-or-later

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

# --- #197 : un service serveur ne recoit aucun secret en variable d'environnement ni par env_file ---------------------
FILES = {"JWT_SECRET_KEY_FILE": "/run/secrets/jwt", "ADMIN_TOKEN_FILE": "/run/secrets/adm", "RSA_MASTER_KEY_FILE": "/run/secrets/rsa"}


def srv(env=None, **extra):
    d = svc([], {**ok, **(env or {})})
    d["services"]["s"].update(extra)
    return d


def why(doc, needle, **kw):
    """True si check() refuse POUR CETTE RAISON (une erreur contient `needle`), pas pour une autre regle."""
    return any(needle in e for e in check(doc, False, **kw))


secret_cases = [
    ("secrets : *_FILE seuls acceptes", srv(FILES), lambda d: not check(d, False, require_secret_files=True)),
    ("secrets : JWT_SECRET_KEY en environnement refuse", srv({**FILES, "JWT_SECRET_KEY": "x"}), lambda d: why(d, "JWT_SECRET_KEY fourni en variable")),
    ("secrets : ADMIN_TOKEN en environnement refuse", srv({**FILES, "ADMIN_TOKEN": "x"}), lambda d: why(d, "ADMIN_TOKEN fourni en variable")),
    ("secrets : RSA_MASTER_KEY en environnement refuse", srv({**FILES, "RSA_MASTER_KEY": "x"}), lambda d: why(d, "RSA_MASTER_KEY fourni en variable")),
    ("secrets : valeur vide en environnement refusee aussi", srv({**FILES, "ADMIN_TOKEN": ""}), lambda d: why(d, "ADMIN_TOKEN fourni en variable")),
    ("secrets : le message cite *_FILE, jamais la valeur", srv({**FILES, "ADMIN_TOKEN": "valeur-secrete-xyz"}),
     lambda d: why(d, "ADMIN_TOKEN_FILE") and not any("valeur-secrete-xyz" in e for e in check(d, False))),
    ("secrets : env_file qualif.env refuse (forme chaine)", srv(FILES, env_file="./qualif.env"), lambda d: why(d, "env_file 'qualif.env' interdit")),
    ("secrets : env_file qualif.env refuse (forme {path, required})", srv(FILES, env_file=[{"path": "./qualif.env", "required": True}]), lambda d: why(d, "env_file 'qualif.env' interdit")),
    ("secrets : env_file prod.env refuse", srv(FILES, env_file=["/opt/secagent/prod.env"]), lambda d: why(d, "env_file 'prod.env' interdit")),
    ("secrets : env_file child.env (sans secret) tolere", srv(FILES, env_file=[{"path": "./chain/child.env", "required": False}]), lambda d: not check(d, False, require_secret_files=True)),
    ("secrets : un env_file tolere ne masque pas un env_file interdit", srv(FILES, env_file=["./chain/child.env", "./qualif.env"]), lambda d: why(d, "env_file 'qualif.env' interdit")),
    ("secrets : sans *_FILE accepte par defaut (rendu synthetique)", srv(), lambda d: not check(d, False)),
    ("secrets : --require-secret-files refuse l'absence de JWT_SECRET_KEY_FILE", srv({k: v for k, v in FILES.items() if k != "JWT_SECRET_KEY_FILE"}),
     lambda d: why(d, "JWT_SECRET_KEY_FILE absent", require_secret_files=True)),
    ("secrets : --require-secret-files refuse l'absence totale de *_FILE", srv(), lambda d: len([e for e in check(d, False, require_secret_files=True) if "_FILE absent" in e]) == 3),
    ("secrets : un minion n'est pas un service serveur (pas de regle *_FILE)", {"services": {"minion-root": {"image": "ghcr.io/x/secagent-minion:v1", "cap_drop": ["ALL"], "security_opt": ["no-new-privileges:true"], "env_file": ["./chain/minion-root.env"]}}},
     lambda d: not check(d, False, require_secret_files=True)),
]
for name, doc, pred in secret_cases:
    good = pred(doc)
    print(("ok  " if good else "KO  ") + name + ("" if good else "  -> " + repr(check(doc, False))))
    bad += not good

# --- #238 : un minion de qualif exige cap_drop [ALL] et no-new-privileges ---------------------------------------------
def minion(name="minion-root", image="ghcr.io/ccoupel/secagent-minion:v1", **extra):
    return {"services": {name: {"image": image, **extra}}}


HARD = {"cap_drop": ["ALL"], "cap_add": ["SETUID", "SETGID", "CHOWN"], "security_opt": ["no-new-privileges:true"]}
minion_cases = [
    ("minion : cap_drop ALL + no-new-privileges accepte", minion(**HARD), lambda d: not check(d, False)),
    ("minion : sans cap_drop refuse", minion(security_opt=HARD["security_opt"]), lambda d: why(d, "sans cap_drop")),
    ("minion : cap_drop partiel (NET_RAW) refuse", minion(cap_drop=["NET_RAW"], security_opt=HARD["security_opt"]), lambda d: why(d, "sans cap_drop")),
    ("minion : cap_drop ALL en minuscules accepte (comme Docker)", minion(cap_drop=["all"], security_opt=HARD["security_opt"]), lambda d: not check(d, False)),
    ("minion : sans no-new-privileges refuse", minion(cap_drop=["ALL"]), lambda d: why(d, "no-new-privileges")),
    ("minion : security_opt sans no-new-privileges refuse", minion(cap_drop=["ALL"], security_opt=["seccomp:unconfined"]), lambda d: why(d, "no-new-privileges")),
    ("minion : no-new-privileges:false refuse", minion(cap_drop=["ALL"], security_opt=["no-new-privileges:false"]), lambda d: why(d, "no-new-privileges")),
    ("minion : ni l'un ni l'autre = deux erreurs", minion(), lambda d: why(d, "sans cap_drop") and why(d, "no-new-privileges")),
    ("minion : reconnu par le nom minion-child (image locale)", minion("minion-child", "secagent-minion:ci-0123456789ab"), lambda d: why(d, "sans cap_drop")),
    ("minion : reconnu par l'image (nom libre)", minion("agent-a"), lambda d: why(d, "sans cap_drop")),
    ("minion : cap_add limite a CHOWN/SETUID/SETGID accepte (prefixe CAP_ et minuscules toleres)", minion(cap_drop=["ALL"], cap_add=["cap_chown", "SETUID", "setgid"], security_opt=HARD["security_opt"]), lambda d: not check(d, False)),
    ("minion : cap_add SYS_ADMIN refuse (hors liste blanche)", minion(cap_drop=["ALL"], cap_add=["SETUID", "SYS_ADMIN"], security_opt=HARD["security_opt"]), lambda d: why(d, "cap_add SYS_ADMIN")),
    ("minion : cap_add NET_RAW refuse sur minion-negca", minion("minion-negca", profiles=["negative"], cap_drop=["ALL"], cap_add=["NET_RAW"], security_opt=HARD["security_opt"]), lambda d: why(d, "cap_add NET_RAW")),
    ("minion : minion-negca (profil negative) soumis a la meme regle", minion("minion-negca", profiles=["negative"], restart="no"), lambda d: why(d, "sans cap_drop")),
    ("minion : un service serveur n'est pas soumis a la regle minion", srv(FILES), lambda d: not why(d, "minion")),
]
for name, doc, pred in minion_cases:
    good = pred(doc)
    print(("ok  " if good else "KO  ") + name + ("" if good else "  -> " + repr(check(doc, False))))
    bad += not good

# --- v3.0.5 : ports d'HOTE parametrables (API_PUBLISH_PORT / WS_PUBLISH_PORT / ADMIN_PUBLISH_PORT) -------------------
def pub(t, published, ip=None):
    return {"target": t, "published": str(published), "protocol": "tcp", **({"host_ip": ip} if ip is not None else {})}


def two(p1, p2):
    return {"services": {"a": {"image": "ghcr.io/ccoupel/secagent-server:v1", "environment": ok, "ports": p1},
                         "b": {"image": "ghcr.io/ccoupel/secagent-server:v1", "environment": ok, "ports": p2}}}


PROD_PORTS = [pub(7770, 17770), pub(7772, 17772), pub(7771, 17771, "127.0.0.1")]
port_cases = [
    ("ports PROD 17770/17772/17771 (admin loopback) acceptes", svc(PROD_PORTS, ok), lambda d: not check(d, False)),
    ("admin publie sur un port d'hote non standard mais en 0.0.0.0 refuse (regle sur le port CONTENEUR)",
     svc([pub(7771, 17771, "0.0.0.0")], ok), lambda d: why(d, "port admin 7771")),
    ("admin publie sur un port d'hote non standard sans host_ip refuse", svc([pub(7771, 17771)], ok), lambda d: why(d, "port admin 7771")),
    ("collision : deux services sur le meme port d'hote refuse", two([pub(7770, 7770)], [pub(7770, 7770)]), lambda d: why(d, "meme port d'hote 7770")),
    ("collision : wildcard contre adresse precise refuse", two([pub(7770, 7770, "0.0.0.0")], [pub(7770, 7770, "192.168.1.218")]), lambda d: why(d, "meme port d'hote 7770")),
    ("pas de collision : ports d'hote distincts (qualif a 7770 / b 8770)", two([pub(7770, 7770)], [pub(7770, 8770)]), lambda d: not why(d, "meme port d'hote")),
    ("pas de collision : meme port sur deux loopbacks distinctes", two([pub(7771, 7771, "127.0.0.1")], [pub(7771, 7771, "127.0.0.2")]), lambda d: not why(d, "meme port d'hote")),
    ("pas de collision : port non publie (ephemere)", two([{"target": 7770}], [{"target": 7770}]), lambda d: not why(d, "meme port d'hote")),
]
for name, doc, pred in port_cases:
    good = pred(doc)
    print(("ok  " if good else "KO  ") + name + ("" if good else "  -> " + repr(check(doc, False))))
    bad += not good

# bout en bout : le CLI sort en 1 avec ::error:: (secret en environnement, minion non durci), en 0 sinon
with tempfile.TemporaryDirectory() as tmp:
    for name, doc, flags, want_rc, word in [
        ("cli : secret en environnement -> exit 1", srv({**FILES, "ADMIN_TOKEN": "x"}), [], 1, "ADMIN_TOKEN"),
        ("cli : *_FILE seuls + --require-secret-files -> exit 0", srv(FILES), ["--require-secret-files"], 0, ""),
        ("cli : --require-secret-files sans *_FILE -> exit 1", srv(), ["--require-secret-files"], 1, "_FILE absent"),
        ("cli : minion sans cap_drop -> exit 1", minion(security_opt=HARD["security_opt"]), [], 1, "cap_drop"),
        ("cli : minion durci -> exit 0", minion(**HARD), [], 0, ""),
    ]:
        f = os.path.join(tmp, "r.json")
        with open(f, "w", encoding="utf-8") as fh:
            json.dump(doc, fh)
        r = subprocess.run([sys.executable, "-I", os.path.join(HERE, "check_compose.py"), *flags, f], capture_output=True, text=True)
        good = r.returncode == want_rc and (want_rc == 0 or "::error::" in r.stdout and word in r.stdout)
        print(("ok  " if good else "KO  ") + name + ("" if good else "  -> rc=%d %s" % (r.returncode, r.stdout)))
        bad += not good

# Compose de PROD livres (secrets deja en *_FILE) : acceptes avec --require-secret-files. Pas de docker ici : rendu approche
# (YAML + interpolation ${VAR:-defaut} -> defaut, ${VAR:?msg} -> "x") ; les regles testees ne dependent que de
# `environment`, `env_file`, `cap_drop` et `security_opt`. Les Compose de QUALIF sont controles par le job CI
# `docker compose config` (check_compose.py sur le rendu reel), pas ici.
try:
    import yaml
except ImportError:  # PyYAML absent : le controle des fichiers livres est ignore (signale, jamais silencieux)
    yaml = None
    print("info PyYAML absent : Compose de prod non controles par ce selftest")


def render(path):
    text = open(os.path.join(ROOT, path), encoding="utf-8").read()
    text = re.sub(r"\$\{[A-Za-z_0-9]+:-([^}]*)\}", r"\1", text)
    text = re.sub(r"\$\{[A-Za-z_0-9]+(?::\?[^}]*)?\}", "x", text)
    return yaml.safe_load(text)


if yaml:
    for path in ("DEPLOYMENT/prod/docker-compose.server.yml", "DEPLOYMENT/prod/docker-compose.child.yml"):
        doc = render(path)
        errs = [e for e in check(doc, False, require_secret_files=True) if "_FILE" in e or "env_file" in e or "fourni en variable" in e]
        # docker-compose.child.yml est une surcharge de la racine : ses services n'ont pas tous leur environnement complet
        if path.endswith("child.yml"):
            errs = [e for e in errs if "fourni en variable" in e or "env_file" in e]
        print(("ok  " if not errs else "KO  ") + "prod %s : secrets serveur par *_FILE" % path + ("" if not errs else "  -> " + repr(errs)))
        bad += bool(errs)

sys.exit(1 if bad else 0)
