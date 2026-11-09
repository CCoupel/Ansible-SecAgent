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

# --allow-prefix (#267, Podman rootless : chemins du NOEUD sous SECAGENT_HOST_PREFIX)
P = ("--allow-prefix", "/home/cyril/secagent/prod")
expect("prefixe : bind sous le prefixe accepte", svc(volumes=[{"type": "bind", "source": "/home/cyril/secagent/prod/state/root", "target": "/data"}]), 0, P)
expect("prefixe : bind = prefixe accepte", svc(volumes=[{"type": "bind", "source": "/home/cyril/secagent/prod", "target": "/p"}]), 0, P)
expect("prefixe : prefixe avec / final accepte", svc(volumes=[{"type": "bind", "source": "/home/cyril/secagent/prod/pki", "target": "/certs"}]), 0, ("--allow-prefix", "/home/cyril/secagent/prod/"))
expect("prefixe : secret file: sous le prefixe accepte", {**svc(secrets=["t"]), "secrets": {"t": {"file": "/home/cyril/secagent/prod/secrets/admin_token"}}}, 0, P)
expect("prefixe : bind hors prefixe refuse", svc(volumes=[{"type": "bind", "source": "/home/cyril/autre", "target": "/x"}]), 1, P)
expect("prefixe : prefixe frere refuse (prod2)", svc(volumes=[{"type": "bind", "source": "/home/cyril/secagent/prod2/x", "target": "/x"}]), 1, P)
expect("prefixe : evasion par .. refusee", svc(volumes=[{"type": "bind", "source": "/home/cyril/secagent/prod/../qualif/state", "target": "/x"}]), 1, P)
expect("prefixe : source relative refusee", svc(volumes=[{"type": "bind", "source": "secagent/prod/x", "target": "/x"}]), 1, P)
expect("prefixe : secret file: hors prefixe refuse", {**svc(secrets=["t"]), "secrets": {"t": {"file": "/root/t"}}}, 1, P)
expect("prefixe : build toujours refuse", svc(build={"context": "/home/cyril/secagent/prod"}), 1, P)
expect("prefixe : sans option, bind sous le prefixe refuse", svc(volumes=[{"type": "bind", "source": "/home/cyril/secagent/prod/x", "target": "/x"}]), 1)
expect("prefixe : '/' refuse (code 2)", {}, 2, ("--allow-prefix", "/"))
expect("prefixe : relatif refuse (code 2)", {}, 2, ("--allow-prefix", "home/cyril"))
expect("prefixe : '..' refuse (code 2)", {}, 2, ("--allow-prefix", "/home/cyril/../root"))
expect("prefixe : option sans valeur refusee (code 2)", {}, 2, ("--allow-prefix",))
sys.exit(1 if failures else 0)
