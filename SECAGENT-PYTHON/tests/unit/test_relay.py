# -*- coding: utf-8 -*-
"""Tests of the relay connection plugin: multi-address failover (#168)."""
import datetime
import io
import json
import socket
import ssl
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

pytest.importorskip("httpx")
pytest.importorskip("ansible")

from ansible.errors import AnsibleConnectionFailure
from ansible.playbook.play_context import PlayContext

from ansible_plugins.connection_plugins import relay

TOKEN = "SECRET-JWT-TOKEN-xyz"


class Counter:
    """Thread-safe request counter shared with a test server."""

    def __init__(self):
        self.n = 0
        self.lock = threading.Lock()

    def hit(self):
        with self.lock:
            self.n += 1


def _make_handler(counter, behaviour):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            counter.hit()
            length = int(self.headers.get("Content-Length", 0))
            self.rfile.read(length)
            if behaviour == "ok":
                body = json.dumps({"rc": 0, "stdout": "hello", "stderr": ""}).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            elif behaviour == "drop":
                # Request fully received, then connection cut without answer.
                self.connection.shutdown(socket.SHUT_RDWR)
                self.connection.close()
            elif behaviour == "5xx":
                self.send_response(503)
                self.send_header("Content-Length", "0")
                self.end_headers()

    return Handler


def _start(behaviour, tls_ctx=None):
    counter = Counter()
    srv = HTTPServer(("127.0.0.1", 0), _make_handler(counter, behaviour))
    if tls_ctx:
        srv.socket = tls_ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, counter


def _url(srv, scheme="http"):
    return f"{scheme}://127.0.0.1:{srv.server_address[1]}"


def _dead_url():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return f"http://127.0.0.1:{port}"


@pytest.fixture(autouse=True)
def _reset_last_good():
    relay._LAST_GOOD_URL = None
    yield
    relay._LAST_GOOD_URL = None


@pytest.fixture
def servers():
    started = []

    def start(*a, **kw):
        srv, c = _start(*a, **kw)
        started.append(srv)
        return srv, c

    yield start
    for s in started:
        s.shutdown()
        s.server_close()


@pytest.fixture
def make_conn(tmp_path, monkeypatch):
    """Build a plugin instance; options go through the env-var fallback."""
    tok = tmp_path / "tok.jwt"
    tok.write_text(TOKEN)
    monkeypatch.setenv("RELAY_TOKEN_FILE", str(tok))
    monkeypatch.setenv("RELAY_TIMEOUT", "5")
    monkeypatch.setenv("RELAY_CONNECT_TIMEOUT", "2")

    def make(server_opt):
        monkeypatch.setenv("RELAY_SERVER_URL", server_opt)
        pc = PlayContext()
        pc.remote_addr = "host1"
        return relay.Connection(pc, io.StringIO())

    return make


def _exec(conn):
    return conn.exec_command("echo hello", sudoable=False)


def test_single_address_still_works(servers, make_conn):
    srv, c = servers("ok")
    rc, out, _ = _exec(make_conn(_url(srv)))
    assert (rc, out) == (0, b"hello")
    assert c.n == 1


def test_first_refuses_connection_second_serves(servers, make_conn):
    srv, c = servers("ok")
    rc, out, _ = _exec(make_conn(f"{_dead_url()},{_url(srv)}"))
    assert rc == 0 and out == b"hello"
    assert c.n == 1


def test_last_good_address_tried_first(servers, make_conn):
    a, ca = servers("ok")
    b, cb = servers("ok")
    conn = make_conn(f"{_url(a)},{_url(b)}")
    relay._LAST_GOOD_URL = _url(b)
    _exec(conn)
    assert (ca.n, cb.n) == (0, 1)


def test_last_good_remembered_after_failover(servers, make_conn):
    srv, c = servers("ok")
    conn = make_conn(f"{_dead_url()},{_url(srv)}")
    _exec(conn)
    assert relay._LAST_GOOD_URL == _url(srv)


def test_no_replay_when_connection_cut_after_send(servers, make_conn):
    first, c1 = servers("drop")
    second, c2 = servers("ok")
    conn = make_conn(f"{_url(first)},{_url(second)}")
    with pytest.raises(AnsibleConnectionFailure):
        _exec(conn)
    assert c1.n == 1
    assert c2.n == 0


def test_no_replay_on_5xx(servers, make_conn):
    first, c1 = servers("5xx")
    second, c2 = servers("ok")
    with pytest.raises(AnsibleConnectionFailure):
        _exec(make_conn(f"{_url(first)},{_url(second)}"))
    assert (c1.n, c2.n) == (1, 0)


def test_no_replay_on_read_timeout(servers, make_conn, monkeypatch):
    hang = socket.socket()
    hang.bind(("127.0.0.1", 0))
    hang.listen(5)  # accepts at kernel level, never answers
    second, c2 = servers("ok")
    conn = make_conn(f"http://127.0.0.1:{hang.getsockname()[1]},{_url(second)}")
    monkeypatch.setenv("RELAY_TIMEOUT", "1")
    try:
        with pytest.raises(AnsibleConnectionFailure):
            _exec(conn)
    finally:
        hang.close()
    assert c2.n == 0


def _self_signed(tmp_path):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .sign(key, hashes.SHA256()))
    crt, k = Path(tmp_path / "c.pem"), Path(tmp_path / "k.pem")
    crt.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    k.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(crt), str(k))
    return ctx


def test_tls_failure_on_first_tries_second(servers, make_conn, tmp_path):
    bad, c1 = servers("ok", tls_ctx=_self_signed(tmp_path))  # untrusted cert
    good, c2 = servers("ok")
    rc, out, _ = _exec(make_conn(f"{_url(bad, 'https')},{_url(good)}"))
    assert rc == 0 and out == b"hello"
    assert (c1.n, c2.n) == (0, 1)


def test_all_addresses_down_raises_without_token(make_conn):
    conn = make_conn(f"{_dead_url()},{_dead_url()}")
    with pytest.raises(AnsibleConnectionFailure) as ei:
        _exec(conn)
    assert TOKEN not in str(ei.value)


def test_no_token_in_logs(servers, make_conn, monkeypatch):
    logged = []
    monkeypatch.setattr(relay.display, "vvv", lambda msg, *a, **k: logged.append(msg))
    srv, _ = servers("ok")
    _exec(make_conn(f"{_dead_url()},{_url(srv)}"))
    assert logged and all(TOKEN not in m for m in logged)
    assert any(f"127.0.0.1:{srv.server_address[1]}" in m for m in logged)


def test_parse_urls():
    assert relay._parse_urls(" http://a:1/ , http://b:2,, ") == ["http://a:1", "http://b:2"]
