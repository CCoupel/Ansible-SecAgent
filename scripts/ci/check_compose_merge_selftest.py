#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Autotest de check_compose_merge.py : regle de fusion de podman-compose 1.5 (types), ressources nulles, et les
combinaisons reelles du depot (chaine QUALIF + Podman, PROD + Podman)."""
import os, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from check_compose_merge import MergeError, check_merge, null_resources, rec_merge_one  # noqa: E402

REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
D = lambda *p: os.path.join(REPO, "DEPLOYMENT", *p)  # noqa: E731
bad = 0


def expect(name, cond):
    global bad
    print(("ok   " if cond else "KO   ") + name)
    bad |= not cond


def raises(target, source):
    try:
        rec_merge_one(target, source)
        return False
    except MergeError:
        return True


expect("nul puis dict refuse (cas T48 : child_state)", raises({"volumes": {"child_state": None}}, {"volumes": {"child_state": {"driver": "local"}}}))
expect("dict puis nul refuse", raises({"volumes": {"v": {"driver": "local"}}}, {"volumes": {"v": None}}))
expect("{} puis dict accepte", not raises({"volumes": {"v": {}}}, {"volumes": {"v": {"driver": "local"}}}))
expect("liste puis chaine refuse", raises({"services": {"s": {"env_file": ["a"]}}}, {"services": {"s": {"env_file": "b"}}}))
m = rec_merge_one({"services": {"s": {"volumes": ["a:/a"], "image": "x"}}}, {"services": {"s": {"volumes": ["b:/b"], "image": "y"}}})
expect("listes concatenees, scalaire remplace", m["services"]["s"]["volumes"] == ["a:/a", "b:/b"] and m["services"]["s"]["image"] == "y")
expect("ressource nulle signalee", bool(null_resources({"volumes": {"v": None}}, "x")))
expect("ressource {} acceptee", not null_resources({"volumes": {"v": {}}, "networks": {"n": {"driver": "bridge"}}}, "x"))

# combinaisons reelles du depot (fichiers sources, include: compris)
CHAIN = [D("qualif", "docker-compose.chain.yml"), D("qualif", "docker-compose.hooks.yml")]
expect("depot : chaine + hooks + surcharge Podman QUALIF", not check_merge(CHAIN + [D("podman", "docker-compose.podman.qualif.yml")]))
expect("depot : PROD serveur + surcharge Podman", not check_merge([D("prod", "docker-compose.server.yml"), D("podman", "docker-compose.podman.yml")]))
expect("depot : PROD serveur + enfant + surcharge Podman", not check_merge([D("prod", "docker-compose.server.yml"), D("prod", "docker-compose.child.yml"), D("podman", "docker-compose.podman.yml")]))

# temoin : l'ancienne declaration nulle de child_state est refusee (regles 1 et 2)
with tempfile.TemporaryDirectory() as t:
    src = open(CHAIN[0], encoding="utf-8").read()
    old = os.path.join(t, "docker-compose.chain.yml")
    with open(old, "w", encoding="utf-8") as f:
        f.write(src.replace("  child_state: {}", "  child_state:"))
    for inc in ("docker-compose.server.yml",):
        with open(os.path.join(t, inc), "w", encoding="utf-8") as f:
            f.write(open(D("qualif", inc), encoding="utf-8").read())
    errs = check_merge([old, CHAIN[1], D("podman", "docker-compose.podman.qualif.yml")])
    expect("temoin : child_state nul + surcharge Podman refuse", any("child_state" in e and "NoneType and dict" in e for e in errs))
sys.exit(1 if bad else 0)
