#!/usr/bin/env python3
"""Archive `docker load` d'une image GHCR privee, assemblee SUR LE POSTE (aucun jeton ne va sur l'hote Docker).

Usage : python3 -I ghcr_image_archive.py <depot> <digest_index> <tag_local> <sortie.tar>
  ex. : ghcr_image_archive.py secagent-server sha256:<digest-de-l-index-attesté> secagent-server:cand-<sha12> server.tar

Le jeton vient de `gh auth token` (jamais affiche ni ecrit) et n'est envoye qu'a ghcr.io. Chaque blob (index, manifeste
linux/amd64, configuration, couches) est verifie par son sha256 avant d'etre ecrit. L'archive contient le format
`docker save` (manifest.json) ET une mise en page OCI ; chargement : `docker -H <hote> load < sortie.tar`.
Les images chargees portent le digest de manifeste attesté : `gh attestation verify oci://ghcr.io/ccoupel/<depot>@<digest_index>`.
"""
import base64, hashlib, io, json, subprocess, sys, tarfile, urllib.request

OWNER = "ccoupel"
ACCEPT = "application/vnd.oci.image.index.v1+json,application/vnd.oci.image.manifest.v1+json"


def get(url, headers):
    req = urllib.request.Request(url)
    for k, v in headers.items():
        req.add_header(k, v)
    return urllib.request.urlopen(req).read()


def main(repo, index_digest, tag, out):
    if not index_digest.startswith("sha256:") or "/" in repo:
        sys.exit("usage: depot sha256:<digest> tag sortie.tar")
    gh = subprocess.check_output(["gh", "auth", "token"]).decode().strip()
    login = subprocess.check_output(["gh", "api", "user", "-q", ".login"]).decode().strip()
    basic = base64.b64encode(f"{login}:{gh}".encode()).decode()
    tok = json.loads(get(f"https://ghcr.io/token?service=ghcr.io&scope=repository:{OWNER}/{repo}:pull",
                         {"Authorization": "Basic " + basic}))["token"]
    h = {"Authorization": "Bearer " + tok, "Accept": ACCEPT}
    base = f"https://ghcr.io/v2/{OWNER}/{repo}"

    def verified(kind, digest):
        url = f"{base}/{kind}/{digest}"
        data = get(url, h)
        if "sha256:" + hashlib.sha256(data).hexdigest() != digest:
            sys.exit(f"digest invalide pour {digest}")
        return data

    index = verified("manifests", index_digest)
    entry = next(m for m in json.loads(index)["manifests"]
                 if m.get("platform", {}).get("os") == "linux" and m["platform"].get("architecture") == "amd64")
    mbytes = verified("manifests", entry["digest"])
    manifest = json.loads(mbytes)
    blobs = {entry["digest"]: mbytes}
    for d in [manifest["config"]] + manifest["layers"]:
        blobs[d["digest"]] = verified("blobs", d["digest"])

    def add(t, name, data):
        ti = tarfile.TarInfo(name)
        ti.size, ti.mtime = len(data), 0
        t.addfile(ti, io.BytesIO(data))

    sha = lambda d: "blobs/sha256/" + d.split(":")[1]
    with tarfile.open(out, "w") as t:
        add(t, "oci-layout", b'{"imageLayoutVersion":"1.0.0"}')
        add(t, "index.json", json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [{"mediaType": entry["mediaType"], "digest": entry["digest"], "size": entry["size"],
                           "annotations": {"org.opencontainers.image.ref.name": tag}}]}).encode())
        for d, b in blobs.items():
            add(t, sha(d), b)
        add(t, "manifest.json", json.dumps([{"Config": sha(manifest["config"]["digest"]), "RepoTags": [tag],
            "Layers": [sha(l["digest"]) for l in manifest["layers"]]}]).encode())
    print(f"ok {repo} manifeste {entry['digest']} couches {len(manifest['layers'])}")


if __name__ == "__main__":
    if len(sys.argv) != 5:
        sys.exit(__doc__)
    main(*sys.argv[1:])
