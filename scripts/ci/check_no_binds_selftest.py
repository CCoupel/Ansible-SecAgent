#!/usr/bin/env python3
"""Autotest de check_no_binds.py : chaque cas doit etre accepte ou refuse comme attendu (mutation : un cas refuse qui
passe ou un cas valide qui echoue fait echouer le script)."""
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
CHECK = os.path.join(HERE, "check_no_binds.py")
failures = 0


def run(doc: dict) -> int:
    return subprocess.run([sys.executable, CHECK], input=json.dumps(doc), text=True,
                          capture_output=True).returncode


def expect(name: str, doc: dict, want: int) -> None:
    global failures
    got = run(doc)
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
sys.exit(1 if failures else 0)
