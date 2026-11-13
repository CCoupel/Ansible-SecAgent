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

# combinaisons reelles du depot (fichiers sources, include: compris) ; sous Podman SECAGENT_TMPFS_OPTS=U (release.env)
os.environ["SECAGENT_TMPFS_OPTS"] = "U"
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
# temoin T48 n°2 : l'ancienne redefinition de secagent_secrets (external: false + bind) dans la surcharge Podman est
# ecrasee par l'include (external: true) => refus ; et un include qui fixe la MEME valeur que la surcharge est accepte
with tempfile.TemporaryDirectory() as t:
    podman_old = os.path.join(t, "docker-compose.podman.qualif.yml")
    with open(podman_old, "w", encoding="utf-8") as f:
        f.write(open(D("podman", "docker-compose.podman.qualif.yml"), encoding="utf-8").read()
                + "  secagent_secrets:\n    external: false\n    name: ${SECAGENT_SECRETS_VOLUME:-secagent-qualif_secrets}\n"
                  "    driver: local\n")
    errs = check_merge(CHAIN + [podman_old])
    expect("temoin : secagent_secrets external:false ecrase par l'include (external:true) refuse",
           any("volumes.secagent_secrets.external" in e and "EN DERNIER" in e for e in errs))
# temoin T48 n°3 : surcharge Podman sans `x-podman: {in_pod: false}` (keep-id dans le pod par defaut) refusee ; regle 4
# lue comme podman-compose (in_pod chaine "false" acceptee, absence = pod)
with tempfile.TemporaryDirectory() as t:
    podman_pod = os.path.join(t, "docker-compose.podman.qualif.yml")
    with open(podman_pod, "w", encoding="utf-8") as f:
        f.write(open(D("podman", "docker-compose.podman.qualif.yml"), encoding="utf-8").read().replace("x-podman:\n  in_pod: false\n", ""))
    errs = check_merge(CHAIN + [podman_pod])
    expect("temoin : userns_mode dans le pod par defaut refuse (--userns and --pod)", any("--userns and --pod" in e for e in errs))
from check_compose_merge import userns_without_podless  # noqa: E402
svc = {"services": {"s": {"userns_mode": "keep-id"}}}
expect("in_pod: 'false' (chaine) accepte", not userns_without_podless({**svc, "x-podman": {"in_pod": "false"}}))
expect("in_pod: true refuse", bool(userns_without_podless({**svc, "x-podman": {"in_pod": True}})))
expect("sans userns_mode : pod accepte", not userns_without_podless({"services": {"s": {}}}))
# temoin T48 n°4 : tmpfs uid=/gid= refuse sous Podman (SECAGENT_TMPFS_OPTS absent) ; accepte avec SECAGENT_TMPFS_OPTS=U
os.environ.pop("SECAGENT_TMPFS_OPTS", None)
errs = check_merge(CHAIN + [D("podman", "docker-compose.podman.qualif.yml")])
expect("temoin : tmpfs uid=10001 (SECAGENT_TMPFS_OPTS absent) refuse", any("tmpfs" in e and "uid=10001" in e for e in errs))
os.environ["SECAGENT_TMPFS_OPTS"] = "U"
# temoin T48 n°5 : la surcharge tmpfs `!override` de a (inclus) est refusee (concatenee par podman-compose 1.5)
with tempfile.TemporaryDirectory() as t:
    podman_ovr = os.path.join(t, "docker-compose.podman.qualif.yml")
    src = open(D("podman", "docker-compose.podman.qualif.yml"), encoding="utf-8").read()
    with open(podman_ovr, "w", encoding="utf-8") as f:
        f.write(src.replace('  secagent-server-a:\n', '  secagent-server-a:\n    tmpfs: !override ["/tmp:U,mode=1777"]\n', 1))
    errs = check_merge(CHAIN + [podman_ovr])
    expect("temoin : tmpfs !override sur a (inclus) refuse", any("secagent-server-a.tmpfs" in e and "EN DERNIER" in e for e in errs))
from check_compose_merge import Loader, plain  # noqa: E402
import yaml  # noqa: E402
m = rec_merge_one({"s": {"tmpfs": ["/a:uid=1"], "ports": ["1:1"]}}, yaml.load("s: {tmpfs: !override ['/a:U'], ports: !reset []}", Loader=Loader))
expect("!override remplace la liste, !reset retire la cle", m == {"s": {"tmpfs": ["/a:U"]}})
expect("plain sans etiquette", plain(yaml.load("a: !override [1]", Loader=Loader)) == {"a": [1]})
from check_compose_merge import expand  # noqa: E402
names = [os.path.basename(n) + ("(inclus)" if inc else "") for n, _d, inc in expand(CHAIN + [D("podman", "docker-compose.podman.qualif.yml")])]
expect("ordre podman-compose : include ajoute APRES les -f", names[-1] == "docker-compose.server.yml(inclus)" and names[:3] == ["docker-compose.chain.yml", "docker-compose.hooks.yml", "docker-compose.podman.qualif.yml"])
sys.exit(1 if bad else 0)
