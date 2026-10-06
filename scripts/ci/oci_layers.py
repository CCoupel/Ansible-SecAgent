#!/usr/bin/env python3
"""Affiche les digests des couches du premier manifeste d'une image OCI extraite (diagnostic de non-reproductibilite).
Usage : oci_layers.py <repertoire_extrait>"""
import json, os, sys
d = sys.argv[1]
idx = json.load(open(os.path.join(d, "index.json")))
mf = json.load(open(os.path.join(d, "blobs", "sha256", idx["manifests"][0]["digest"].split(":")[1])))
for layer in mf["layers"]:
    print(layer["digest"])
