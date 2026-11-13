#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Autotest de check_podman_certs.py : rendu conforme accepte, minion en keep-id / serveur sans keep-id / /certs en
ecriture refuses."""
import copy, os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from check_podman_certs import check, minion_ca_only  # noqa: E402

KEEP = "keep-id:uid=10001,gid=10001"
CERTS = {"type": "bind", "source": "/p/QUALIF/pki", "target": "/certs", "read_only": True}
CA = {"type": "bind", "source": "/p/QUALIF/pki/ca.crt", "target": "/certs/ca.crt", "read_only": True}   # minions (T49 H1)
GOOD = {"services": {
    "secagent-server-a": {"userns_mode": KEEP, "volumes": [dict(CERTS)]},
    "secagent-server-b": {"userns_mode": KEEP, "volumes": [dict(CERTS)]},
    "secagent-child": {"userns_mode": KEEP, "volumes": [dict(CERTS)]},
    "minion-root": {"volumes": [dict(CA)]},
    "minion-child": {"volumes": [dict(CA)]},
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
expect("/certs/ca.crt en ecriture refuse", d, True)
# temoins T49 H1 : un minion qui monte le dossier pki/ (tls.key) ou le volume TLS complet est refuse
d = copy.deepcopy(GOOD); d["services"]["minion-root"]["volumes"] = [dict(CERTS)]
expect("temoin T49 H1 : minion avec le dossier pki/ entier (tls.key) refuse", d, True)
d = copy.deepcopy(GOOD); d["services"]["minion-child"]["volumes"].append({"type": "bind", "source": "/p/QUALIF/pki/tls.key", "target": "/certs/tls.key", "read_only": True})
expect("temoin : minion avec tls.key en fichier refuse", d, True)
d = copy.deepcopy(GOOD); d["services"]["minion-root"]["volumes"] = [{"type": "volume", "source": "secagent_tls", "target": "/certs", "read_only": True}]
expect("temoin : minion avec le volume TLS complet refuse", d, True)
ok_vol = minion_ca_only("minion-root", {"volumes": [{"type": "volume", "source": "secagent_tls_ca", "target": "/certs", "read_only": True}]})
print(("ok   " if not ok_vol else f"KO   {ok_vol} ") + "volume de la CA seule (TLS distant Docker) accepte"); bad |= bool(ok_vol)
sys.exit(bad)
