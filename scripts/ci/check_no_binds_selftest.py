#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Autotest de check_no_binds.py : chaque cas doit etre accepte ou refuse comme attendu (mutation : un cas refuse qui
passe ou un cas valide qui echoue fait echouer le script)."""
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
CHECK = os.path.join(HERE, "check_no_binds.py")
failures = 0


def run(doc: dict, args=()) -> int:
    return subprocess.run([sys.executable, CHECK, *args], input=json.dumps(doc), text=True,
                          capture_output=True).returncode


def expect(name: str, doc: dict, want: int, args=()) -> None:
    global failures
    got = run(doc, args)
    print(("ok   " if got == want else "KO   ") + f"{name} (rc={got}, attendu {want})")
    if got != want:
        failures += 1


def svc(**kw) -> dict:
    return {"services": {"s": kw}}


expect("rendu vide", {}, 0)
expect("volume nomme", svc(volumes=[{"type": "volume", "source": "v", "target": "/d"}]), 0)
expect("volume externe en lecture seule", {**svc(volumes=[{"type": "volume", "source": "v", "target": "/d", "read_only": True}]),
                                            "volumes": {"v": {"external": True, "name": "p_v"}}}, 0)
expect("tmpfs", svc(volumes=[{"type": "tmpfs", "target": "/tmp"}]), 0)
expect("bind mount", svc(volumes=[{"type": "bind", "source": "/home/x/f", "target": "/f"}]), 1)
expect("secret file: utilise", {**svc(secrets=[{"source": "t"}]), "secrets": {"t": {"file": "/x/t"}}}, 1)
expect("secret file: forme courte", {**svc(secrets=["t"]), "secrets": {"t": {"file": "/x/t"}}}, 1)
expect("secret file: declare mais inutilise", {**svc(), "secrets": {"t": {"file": "/x/t"}}}, 0)
expect("secret environment:", {**svc(secrets=[{"source": "t"}]), "secrets": {"t": {"environment": "TOK"}}}, 0)
expect("config file: utilise", {**svc(configs=[{"source": "c", "target": "/c"}]), "configs": {"c": {"file": "./hooks.json"}}}, 1)
expect("config content:", {**svc(configs=[{"source": "c", "target": "/c"}]), "configs": {"c": {"content": "{}"}}}, 0)
expect("build", svc(build={"context": "."}), 1)
expect("env_file inline (rendu)", svc(environment={"A": "b"}), 0)

# --allow-prefix (#267, Podman rootless : chemins du NOEUD sous SECAGENT_HOST_PREFIX, sous-chemins permis seulement)
R = "/share/MFS/ROOT/CLAUDE_PROJETS/PROJETS/PRO/Ansible_SecAgent/PRIVATE/PROD"
P = ("--allow-prefix", R)


def bind(src):
    return svc(volumes=[{"type": "bind", "source": src, "target": "/x"}])


def secret(path):
    return {**svc(secrets=["t"]), "secrets": {"t": {"file": path}}}


expect("prefixe : state/root accepte", bind(R + "/state/root"), 0, P)
expect("prefixe : state/child accepte", bind(R + "/state/child"), 0, P)
expect("prefixe : sous state/root accepte", bind(R + "/state/root/journal"), 0, P)
expect("prefixe : secrets (repertoire) accepte", bind(R + "/secrets"), 0, P)
expect("prefixe : secret file: sous secrets accepte", secret(R + "/secrets/admin_token"), 0, P)
expect("prefixe : pki/tls.crt accepte", bind(R + "/pki/tls.crt"), 0, P)
expect("prefixe : pki/tls.key accepte", bind(R + "/pki/tls.key"), 0, P)
expect("prefixe : pki/ca.crt accepte", bind(R + "/pki/ca.crt"), 0, P)
expect("prefixe : prefixe avec / final", bind(R + "/state/root"), 0, ("--allow-prefix", R + "/"))
expect("prefixe : le prefixe lui-meme refuse", bind(R), 1, P)
expect("prefixe : state/ entier refuse", bind(R + "/state"), 1, P)
expect("prefixe : pki/ entier refuse (ca.key)", bind(R + "/pki"), 1, P)
expect("prefixe : pki/ca.key refuse", bind(R + "/pki/ca.key"), 1, P)
expect("prefixe : secret file: pki/ca.key refuse", secret(R + "/pki/ca.key"), 1, P)
expect("prefixe : poste-cyril/id_ed25519 refuse", bind(R + "/poste-cyril/id_ed25519"), 1, P)
expect("prefixe : secret file: poste-cyril refuse", secret(R + "/poste-cyril/id_ed25519"), 1, P)
expect("prefixe : faux sous-chemin state/rootx refuse", bind(R + "/state/rootx"), 1, P)
expect("prefixe : faux fichier pki/tls.crt.bak refuse", bind(R + "/pki/tls.crt.bak"), 1, P)
expect("prefixe : bind hors prefixe refuse", bind("/home/cyril/autre"), 1, P)
expect("prefixe : prefixe frere refuse (prod2)", bind(R + "2/state/root"), 1, P)
expect("prefixe : evasion par .. refusee", bind(R + "/state/root/../../../qualif/state/root"), 1, P)
expect("prefixe : retour par .. vers ca.key refuse", bind(R + "/secrets/../pki/ca.key"), 1, P)
expect("prefixe : source relative refusee", bind("secagent/prod/state/root"), 1, P)
expect("prefixe : secret file: hors prefixe refuse", secret("/root/t"), 1, P)
expect("prefixe : build toujours refuse", svc(build={"context": R}), 1, P)
expect("prefixe : sans option, state/root refuse", bind(R + "/state/root"), 1)
expect("prefixe : '/' refuse (code 2)", {}, 2, ("--allow-prefix", "/"))
expect("prefixe : '/etc' refuse (code 2, < 4 composants)", {}, 2, ("--allow-prefix", "/etc"))
expect("prefixe : '/home/cyril' refuse (code 2)", {}, 2, ("--allow-prefix", "/home/cyril"))
expect("prefixe : '/home/cyril/secagent' refuse (code 2, 3 composants)", {}, 2, ("--allow-prefix", "/home/cyril/secagent"))
expect("prefixe : relatif refuse (code 2)", {}, 2, ("--allow-prefix", R.lstrip("/")))
expect("prefixe : '..' refuse (code 2)", {}, 2, ("--allow-prefix", "/home/cyril/../root/x/y"))
expect("prefixe : option sans valeur refusee (code 2)", {}, 2, ("--allow-prefix",))
sys.exit(1 if failures else 0)
