#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Autotest de check_podman_certs.py : rendu conforme accepte, minion en keep-id / serveur sans keep-id / /certs en
ecriture refuses."""
import copy, os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from check_podman_certs import check  # noqa: E402

KEEP = "keep-id:uid=10001,gid=10001"
CERTS = {"type": "bind", "source": "/p/QUALIF/pki", "target": "/certs", "read_only": True}
GOOD = {"services": {
    "secagent-server-a": {"userns_mode": KEEP, "volumes": [dict(CERTS)]},
    "secagent-server-b": {"userns_mode": KEEP, "volumes": [dict(CERTS)]},
    "secagent-child": {"userns_mode": KEEP, "volumes": [dict(CERTS)]},
    "minion-root": {"volumes": [dict(CERTS)]},
    "minion-child": {"volumes": [dict(CERTS)]},
}}
bad = 0


def expect(name, doc, want_errors):
    global bad
    got = check(doc)
    if bool(got) == want_errors:
        print(f"ok   {name}")
    else:
        print(f"KO   {name} : {got}")
        bad = 1


expect("rendu conforme", GOOD, False)
d = copy.deepcopy(GOOD); d["services"]["minion-child"]["userns_mode"] = KEEP
expect("minion en keep-id refuse", d, True)
d = copy.deepcopy(GOOD); del d["services"]["secagent-server-b"]["userns_mode"]
expect("serveur sans keep-id refuse", d, True)
d = copy.deepcopy(GOOD); d["services"]["minion-root"]["volumes"][0]["read_only"] = False
expect("/certs en ecriture refuse", d, True)
sys.exit(bad)
