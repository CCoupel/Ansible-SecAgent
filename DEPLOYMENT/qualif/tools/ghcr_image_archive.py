#!/usr/bin/env python3
"""Archive `docker load` d'une image GHCR privee, assemblee SUR LE POSTE (aucun jeton ne va sur l'hote Docker).

Usage : python3 -I ghcr_image_archive.py <depot> <digest_index> <tag_local> <sortie.tar>
  ex. : ghcr_image_archive.py secagent-server sha256:<digest-de-l-index-attesté> secagent-server:cand-<sha12> server.tar

Garde-fous :
  * l'ATTESTATION de l'index est verifiee AVANT toute requete authentifiee et toute ecriture (`gh attestation verify`,
    gh >= 2.49 ; variable GH_BIN pour un binaire autre que `gh`) : echec => arret ;
  * le jeton vient de `gh auth token` (jamais affiche ni ecrit) ; Basic uniquement vers https://ghcr.io/token ;
    Bearer uniquement vers https://ghcr.io/ ; AUCUNE redirection automatique : sur un 30x l'hote est controle (liste
    blanche, https seulement) et la requete est refaite SANS en-tete Authorization (les URL de blob sont deja signees) ;
  * chaque blob est verifie par son sha256, lu avec un plafond (taille du descripteur) et un delai ;
  * `depot` filtre par ^[a-z0-9-]+$.
Archive : format `docker save` (manifest.json) ET mise en page OCI ; chargement : `docker -H <hote> load < sortie.tar`.
"""
import base64, hashlib, io, json, os, re, subprocess, sys, tarfile, urllib.error, urllib.parse, urllib.request

OWNER = "ccoupel"
ATTEST_REPO = "CCoupel/Ansible-SecAgent"
REGISTRY = "https://ghcr.io/"
# Hotes autorises pour une redirection (stockage des blobs de GHCR) ; https obligatoire.
REDIRECT_HOSTS = ("ghcr.io", "pkg-containers.githubusercontent.com")
REDIRECT_SUFFIXES = (".githubusercontent.com",)
ACCEPT = "application/vnd.oci.image.index.v1+json,application/vnd.oci.image.manifest.v1+json"
TIMEOUT = 60
MAX_REDIRECTS = 3
MAX_JSON = 1 << 20      # plafond d'un index / manifeste / reponse de jeton quand la taille n'est pas annoncee


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):   # jamais de suivi automatique : l'en-tete Authorization serait recopie
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def _host_ok(url, schemes, hosts, suffixes):
    u = urllib.parse.urlsplit(url)
    return u.scheme in schemes and (u.hostname in hosts or any((u.hostname or "").endswith(s) for s in suffixes))


def _read(resp, limit):
    data = resp.read(limit + 1)
    if len(data) > limit:
        sys.exit(f"reponse trop grande (> {limit} octets)")
    return data


def http_get(url, headers, limit, *, schemes=("https",), hosts=("ghcr.io",), redirect_hosts=REDIRECT_HOSTS,
             redirect_suffixes=REDIRECT_SUFFIXES, timeout=TIMEOUT):
    """GET sans redirection automatique. Premiere requete : ``headers`` (dont Authorization) vers un hote de ``hosts`` ;
    sur 301/302/303/307/308 : hote de ``Location`` controle, requete refaite SANS Authorization."""
    if not _host_ok(url, schemes, hosts, ()):
        sys.exit(f"URL refusee (schema/hote): {urllib.parse.urlsplit(url).scheme}://{urllib.parse.urlsplit(url).hostname}")
    hdrs = dict(headers)
    for _ in range(MAX_REDIRECTS + 1):
        req = urllib.request.Request(url, headers=hdrs)
        try:
            with _OPENER.open(req, timeout=timeout) as r:
                return _read(r, limit)
        except urllib.error.HTTPError as e:
            if e.code not in (301, 302, 303, 307, 308):
                raise
            loc = urllib.parse.urljoin(url, e.headers.get("Location", ""))
            if not _host_ok(loc, schemes, tuple(redirect_hosts) + tuple(hosts), redirect_suffixes):
                sys.exit(f"redirection refusee vers {urllib.parse.urlsplit(loc).scheme}://{urllib.parse.urlsplit(loc).hostname}")
            url = loc
            hdrs = {k: v for k, v in hdrs.items() if k.lower() not in ("authorization", "cookie")}   # jamais recopie
    sys.exit("trop de redirections")


def attest(repo, index_digest):
    gh = os.environ.get("GH_BIN", "gh")
    r = subprocess.run([gh, "attestation", "verify", f"oci://ghcr.io/{OWNER}/{repo}@{index_digest}", "--repo", ATTEST_REPO],
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if r.returncode != 0:
        sys.exit("attestation NON verifiee (gh attestation verify, gh >= 2.49 requis) :\n" + r.stdout[-800:])


def main(repo, index_digest, tag, out):
    if not re.fullmatch(r"[a-z0-9-]+", repo) or not re.fullmatch(r"sha256:[0-9a-f]{64}", index_digest):
        sys.exit("usage: depot (^[a-z0-9-]+$) sha256:<64 hex> tag sortie.tar")
    attest(repo, index_digest)      # AVANT toute requete authentifiee et toute ecriture
    gh = os.environ.get("GH_BIN", "gh")
    token = subprocess.check_output([gh, "auth", "token"]).decode().strip()
    login = subprocess.check_output([gh, "api", "user", "-q", ".login"]).decode().strip()
    basic = base64.b64encode(f"{login}:{token}".encode()).decode()
    tok = json.loads(http_get(f"{REGISTRY}token?service=ghcr.io&scope=repository:{OWNER}/{repo}:pull",
                              {"Authorization": "Basic " + basic}, MAX_JSON))["token"]
    h = {"Authorization": "Bearer " + tok, "Accept": ACCEPT}
    base = f"{REGISTRY}v2/{OWNER}/{repo}"

    def verified(kind, digest, size=None):
        data = http_get(f"{base}/{kind}/{digest}", h, size if size is not None else MAX_JSON)
        if size is not None and len(data) != size:
            sys.exit(f"taille inattendue pour {digest}")
        if "sha256:" + hashlib.sha256(data).hexdigest() != digest:
            sys.exit(f"digest invalide pour {digest}")
        return data

    index = verified("manifests", index_digest)
    entry = next(m for m in json.loads(index)["manifests"]
                 if m.get("platform", {}).get("os") == "linux" and m["platform"].get("architecture") == "amd64")
    mbytes = verified("manifests", entry["digest"], entry["size"])
    manifest = json.loads(mbytes)
    blobs = {entry["digest"]: mbytes}
    for d in [manifest["config"]] + manifest["layers"]:
        blobs[d["digest"]] = verified("blobs", d["digest"], d["size"])

    def add(t, name, data):
        ti = tarfile.TarInfo(name)
        ti.size, ti.mtime = len(data), 0
        t.addfile(ti, io.BytesIO(data))

    sha = lambda d: "blobs/sha256/" + d.split(":")[1]
    with tarfile.open(out, "w") as t:      # ecriture seulement apres attestation et verification de tous les blobs
        add(t, "oci-layout", b'{"imageLayoutVersion":"1.0.0"}')
        add(t, "index.json", json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [{"mediaType": entry["mediaType"], "digest": entry["digest"], "size": entry["size"],
                           "annotations": {"org.opencontainers.image.ref.name": tag}}]}).encode())
        for d, b in blobs.items():
            add(t, sha(d), b)
        add(t, "manifest.json", json.dumps([{"Config": sha(manifest["config"]["digest"]), "RepoTags": [tag],
            "Layers": [sha(l["digest"]) for l in manifest["layers"]]}]).encode())
    print(f"ok {repo} manifeste {entry['digest']} couches {len(manifest['layers'])} (attestation verifiee)")


if __name__ == "__main__":
    if len(sys.argv) != 5:
        sys.exit(__doc__)
    main(*sys.argv[1:])
