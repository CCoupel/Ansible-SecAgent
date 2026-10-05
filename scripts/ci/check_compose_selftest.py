#!/usr/bin/env python3
"""Auto-test de check_compose.py sur des rendus JSON synthetiques (sans docker). Exit 0 = conforme."""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))
from check_compose import check

def svc(ports, env=None, image="ghcr.io/ccoupel/secagent-server:v1"):
    return {"services": {"s": {"image": image, "environment": env or {}, "ports": ports}}}

P = lambda ip, t=7771: {"target": t, "published": str(t), **({"host_ip": ip} if ip is not None else {})}
ok = {"ADMIN_ADDR": "0.0.0.0:7771", "ADMIN_TLS": "true"}
cases = [
    ("loopback + TLS", svc([P("127.0.0.1")], ok), False),
    ("sans host_ip", svc([P(None)], ok), True),
    ("0.0.0.0", svc([P("0.0.0.0")], ok), True),
    ("::", svc([P("::")], ok), True),
    ("non loopback sans TLS", svc([P("127.0.0.1")], {"ADMIN_ADDR": "0.0.0.0:7771"}), True),
    ("defaut ADMIN_ADDR sans TLS", svc([P("127.0.0.1")], {}), True),
    ("derogation complete", svc([P("127.0.0.1")], {"ADMIN_ADDR": ":7771", "ADMIN_INSECURE_HTTP": "true", "ADMIN_INSECURE_HTTP_ACK": "i-understand-the-risk"}), False),
    ("derogation sans ack", svc([P("127.0.0.1")], {"ADMIN_ADDR": ":7771", "ADMIN_INSECURE_HTTP": "true"}), True),
    ("admin loopback", svc([P("127.0.0.1")], {"ADMIN_ADDR": "127.0.0.1:7771"}), False),
    ("latest", svc([], ok, "ghcr.io/x/y:latest"), True),
    ("sans tag", svc([], ok, "ghcr.io/x/y"), True),
    ("tag@digest", svc([], ok, "ghcr.io/x/y:v1@sha256:" + "0" * 64), False),
    ("TLS_DISABLE", svc([], {**ok, "TLS_DISABLE": "true"}), True),
    ("nats", {"services": {"nats": {"image": "nats:2"}}}, True),
]
m = svc([], {**ok, "GOMEMLIMIT": "1638MiB"}); m["services"]["s"]["deploy"] = {"resources": {"limits": {"memory": "2147483648"}}}
for name, doc, want_fail in [("mem ok", m, False), ("mem absente", svc([], ok), True)]:
    got = bool(check(doc, False, True))
    print(("ok  " if got == want_fail else "KO  ") + name)
    if got != want_fail:
        sys.exit(1)
bad = 0
for name, doc, want_fail in cases:
    got = bool(check(doc, False))
    print(("ok  " if got == want_fail else "KO  ") + name)
    bad += got != want_fail
sys.exit(1 if bad else 0)
