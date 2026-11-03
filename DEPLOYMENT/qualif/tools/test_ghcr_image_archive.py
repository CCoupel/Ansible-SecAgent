#!/usr/bin/env python3
"""Autotest de ghcr_image_archive.py : un faux serveur prouve que l'en-tete Authorization n'est JAMAIS recopie apres une
redirection, que les redirections vers http / hote hors liste blanche sont refusees, et que le plafond de lecture tient.
Usage : python3 -I DEPLOYMENT/qualif/tools/test_ghcr_image_archive.py"""
import http.server, importlib.util, os, sys, threading

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("ghcr_image_archive", os.path.join(HERE, "ghcr_image_archive.py"))
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)

seen = {}


class B(http.server.BaseHTTPRequestHandler):      # serveur de destination : enregistre les en-tetes recus
    def do_GET(self):
        seen["auth"] = self.headers.get("Authorization")
        body = b"x" * (5000 if self.path == "/big" else 10)
        self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def log_message(self, *a): pass


def make_a(port_b, location=None):
    class A(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            seen["auth_a"] = self.headers.get("Authorization")
            self.send_response(307); self.send_header("Location", location or f"http://127.0.0.1:{port_b}/blob")
            self.send_header("Content-Length", "0"); self.end_headers()
        def log_message(self, *a): pass
    return A


def serve(handler):
    s = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=s.serve_forever, daemon=True).start()
    return s, s.server_address[1]


sb, pb = serve(B)
fails = []
lenient = dict(schemes=("http", "https"), hosts=("127.0.0.1",), redirect_hosts=("127.0.0.1",), redirect_suffixes=())

# 1. redirection autorisee : le corps arrive, l'en-tete Authorization ne suit PAS
sa, pa = serve(make_a(pb))
data = m.http_get(f"http://127.0.0.1:{pa}/x", {"Authorization": "Bearer SECRET"}, 100, **lenient)
if seen.get("auth_a") != "Bearer SECRET": fails.append("le serveur d'origine n'a pas recu l'en-tete")
if seen.get("auth") is not None: fails.append(f"Authorization recopie apres redirection: {seen['auth']!r}")
if data != b"x" * 10: fails.append("corps inattendu")

# 2. redirection vers un hote hors liste blanche : refusee (SystemExit), rien n'est envoye a la destination
seen.clear()
sa2, pa2 = serve(make_a(pb, location="https://evil.example/blob"))
try:
    m.http_get(f"http://127.0.0.1:{pa2}/x", {"Authorization": "Bearer SECRET"}, 100, **lenient); fails.append("hote hors liste accepte")
except SystemExit: pass

# 3. redirection https -> http refusee avec la politique stricte par defaut ; URL initiale http refusee
sa3, pa3 = serve(make_a(pb))
for call in (lambda: m.http_get(f"http://127.0.0.1:{pa3}/x", {"Authorization": "Bearer S"}, 100),
             lambda: m.http_get("http://ghcr.io/v2/", {}, 100),
             lambda: m.http_get("https://evil.example/v2/", {}, 100)):
    try: call(); fails.append("politique stricte non appliquee")
    except SystemExit: pass
if seen.get("auth") is not None: fails.append("requete envoyee malgre la politique stricte")

# 4. plafond de lecture
try:
    m.http_get(f"http://127.0.0.1:{pb}/big", {}, 100, **lenient); fails.append("plafond de lecture ignore")
except SystemExit: pass

# 4b. liste blanche des redirections REELLE : un seul hote de stockage ; ghcr.io lui-meme, un autre sous-domaine
#     githubusercontent, http, un domaine voisin sont refuses ; l'hote attendu est accepte
ok = lambda u: m._host_ok(u, ("https",), m.REDIRECT_HOSTS, m.REDIRECT_SUFFIXES)
if m.REDIRECT_HOSTS != ("pkg-containers.githubusercontent.com",) or m.REDIRECT_SUFFIXES != (): fails.append("liste blanche elargie")
if not ok("https://pkg-containers.githubusercontent.com/ghcr1/blobs/sha256:abc?x=1"): fails.append("hote de stockage refuse")
for bad in ("https://ghcr.io/v2/x", "https://objects.githubusercontent.com/x", "https://evilgithubusercontent.com/x",
            "https://pkg-containers.githubusercontent.com.evil.example/x", "http://pkg-containers.githubusercontent.com/x"):
    if ok(bad): fails.append(f"redirection acceptee: {bad}")
# redirection reelle (faux serveur) vers ghcr.io (hote d'origine autorise, mais PAS hote de redirection) : refusee AVANT toute requete
seen.clear()
sa4, pa4 = serve(make_a(pb, location="https://ghcr.io/v2/"))
try:
    m.http_get(f"http://127.0.0.1:{pa4}/x", {"Authorization": "Bearer S"}, 100, schemes=("http", "https"), hosts=("127.0.0.1", "ghcr.io"))
    fails.append("redirection vers ghcr.io suivie")
except SystemExit: pass
except Exception as e: fails.append(f"redirection vers ghcr.io tentee ({type(e).__name__})")

# 4c. attestation : le signataire est contraint au workflow candidate-images.yml du depot
import stat, subprocess, tempfile
with tempfile.TemporaryDirectory() as td:
    fake = os.path.join(td, "gh"); log = os.path.join(td, "args")
    open(fake, "w").write(f'#!/bin/sh\nprintf "%s\\n" "$@" > {log}\nexit 0\n'); os.chmod(fake, 0o700)
    os.environ["GH_BIN"] = fake
    m.attest("secagent-server", "sha256:" + "a" * 64)
    args = open(log).read().split("\n")
    if "--signer-workflow" not in args or args[args.index("--signer-workflow") + 1] != "CCoupel/Ansible-SecAgent/.github/workflows/candidate-images.yml":
        fails.append(f"signer-workflow absent ou different: {args}")
    if "--repo" not in args or args[args.index("--repo") + 1] != "CCoupel/Ansible-SecAgent": fails.append("--repo absent")

# 5. filtre du depot et du digest
for args in (("a/b", "sha256:" + "0" * 64), ("ok", "sha256:zz"), ("a:b", "sha256:" + "0" * 64), ("UP", "sha256:" + "0" * 64)):
    try: m.main(*args, "t:t", "/nonexistent/x.tar"); fails.append(f"arguments acceptes: {args}")
    except SystemExit: pass

# 6. attestation absente/fausse => arret avant tout (GH_BIN factice qui echoue)
os.environ["GH_BIN"] = "/bin/false"
try: m.main("secagent-server", "sha256:" + "0" * 64, "t:t", "/nonexistent/x.tar"); fails.append("attestation non exigee")
except SystemExit as e:
    if "attestation" not in str(e.code): fails.append(f"mauvais motif d'arret: {e.code}")

print("ECHEC: " + "; ".join(fails) if fails else "OK (en-tete jamais recopie, hotes/schemas controles, plafond, filtres, attestation exigee)")
sys.exit(1 if fails else 0)
