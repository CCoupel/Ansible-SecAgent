# -*- coding: utf-8 -*-
"""Tests of the relay connection plugin: multi-address failover (#168)."""
import base64
import datetime
import io
import json
import shutil
import socket
import os
import ssl
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

pytest.importorskip("httpx")
pytest.importorskip("ansible")

from ansible.errors import AnsibleConnectionFailure, AnsibleError
from ansible.playbook.play_context import PlayContext

from ansible_plugins.connection_plugins import relay

TOKEN = "SECRET-JWT-TOKEN-xyz"
SEEN = []  # JSON bodies received by the "echo-stdin" test server


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
            raw = self.rfile.read(length)
            if behaviour == "echo-stdin":
                req = json.loads(raw)
                SEEN.append(req)
                body = json.dumps({"rc": 0, "stdout": "", "stderr": ""}).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            elif behaviour == "ok":
                body = json.dumps({"rc": 0, "stdout": "hello", "stderr": ""}).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            elif behaviour == "drop":
                # Request fully received, then connection cut without answer.
                self.connection.shutdown(socket.SHUT_RDWR)
                self.connection.close()
            elif behaviour == "4xx":
                body = b'<html>proxy says token=' + TOKEN.encode() + b'</html>'
                self.send_response(400)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            elif behaviour == "4xx-json":
                body = json.dumps({"error": "bad\x00 request" + "x" * 500}).encode()
                self.send_response(400)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
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
    tok.chmod(0o600)
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
    bad_url = _url(bad, "https")
    assert bad_url.startswith("https://")
    rc, out, _ = _exec(make_conn(f"{bad_url},{_url(good)}"))
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


# --- review fixes (#168b) ---------------------------------------------------

def test_userinfo_rejected_without_echo(make_conn):
    conn = make_conn("https://admin:hunter2@relay.example:7770")
    with pytest.raises(AnsibleError) as ei:
        _exec(conn)
    msg = str(ei.value)
    assert "hunter2" not in msg and "admin" not in msg and "#1" in msg


@pytest.mark.parametrize("entry,cause", [
    ("ftp://relay:1", "scheme"),
    ("http://:7770", "missing host"),
    ("http://relay:notaport", "port"),
    ("http://relay:99999", "port"),
    ("relay:7770", "scheme"),
])
def test_invalid_entry_names_position(make_conn, entry, cause):
    conn = make_conn(f"http://127.0.0.1:1,{entry}")
    with pytest.raises(AnsibleError) as ei:
        _exec(conn)
    assert "#2" in str(ei.value) and cause in str(ei.value)
    assert entry not in str(ei.value)


def test_cleartext_http_non_loopback_warns(make_conn, monkeypatch):
    warned = []
    monkeypatch.setattr(relay.display, "warning", lambda m, *a, **k: warned.append(m))
    relay._WARNED_CLEARTEXT.clear()
    conn = make_conn("http://192.0.2.10:7770,https://192.0.2.11:7770")
    conn._secagent_servers()
    assert len(warned) == 1 and "192.0.2.10:7770" in warned[0]
    assert TOKEN not in warned[0]


@pytest.mark.parametrize("url", ["http://localhost:7770", "http://127.0.0.1:1",
                                 "http://[::1]:7770"])
def test_loopback_http_no_warning(make_conn, monkeypatch, url):
    warned = []
    monkeypatch.setattr(relay.display, "warning", lambda m, *a, **k: warned.append(m))
    relay._WARNED_CLEARTEXT.clear()
    make_conn(url)._secagent_servers()
    assert warned == []


def test_empty_value_falls_back_with_warning(make_conn, monkeypatch):
    warned = []
    monkeypatch.setattr(relay.display, "warning", lambda m, *a, **k: warned.append(m))
    assert make_conn(" , ")._secagent_servers() == ["http://localhost:7770"]
    assert len(warned) == 1


def test_4xx_body_not_echoed(servers, make_conn):
    srv, _ = servers("4xx")
    with pytest.raises(AnsibleError) as ei:
        _exec(make_conn(_url(srv)))
    assert TOKEN not in str(ei.value) and "proxy" not in str(ei.value)
    assert "400" in str(ei.value)


def test_4xx_json_error_field_bounded_and_sanitized(servers, make_conn):
    srv, _ = servers("4xx-json")
    with pytest.raises(AnsibleError) as ei:
        _exec(make_conn(_url(srv)))
    msg = str(ei.value)
    assert "bad" in msg and "\x00" not in msg and len(msg) < 200


def test_5xx_address_not_remembered(servers, make_conn):
    srv, _ = servers("5xx")
    with pytest.raises(AnsibleConnectionFailure):
        _exec(make_conn(_url(srv)))
    assert relay._LAST_GOOD_URL is None


# --- #190: stdin travels base64-encoded --------------------------------------

def test_stdin_is_base64_encoded(servers, make_conn):
    SEEN.clear()
    srv, _ = servers("echo-stdin")
    module = b"#!/usr/bin/env python3\nprint('x & y')\n\xff\x00binary"
    make_conn(_url(srv)).exec_command("python3 -", in_data=module, sudoable=False)
    assert base64.b64decode(SEEN[0]["stdin"], validate=True) == module


def test_no_stdin_field_without_in_data(servers, make_conn):
    SEEN.clear()
    srv, _ = servers("echo-stdin")
    conn = make_conn(_url(srv))
    conn.exec_command("true", sudoable=False)
    conn.exec_command("true", in_data=b"", sudoable=False)
    assert all("stdin" not in r for r in SEEN) and len(SEEN) == 2


# --- #191: token file location and permissions --------------------------------

def test_default_token_file_is_not_tmp(monkeypatch):
    monkeypatch.delenv("RELAY_TOKEN_FILE", raising=False)
    conn = relay.Connection(PlayContext(), io.StringIO())
    assert conn._secagent_token_file() == "/etc/ansible/secagent_plugin.jwt"


def test_token_file_group_or_other_accessible_refused(make_conn, tmp_path):
    conn = make_conn("http://127.0.0.1:1")
    tok = Path(os.environ["RELAY_TOKEN_FILE"])
    for mode in (0o640, 0o604, 0o644, 0o660):
        tok.chmod(mode)
        with pytest.raises(AnsibleConnectionFailure) as ei:
            conn._load_jwt()
        assert TOKEN not in str(ei.value) and str(tok) in str(ei.value)


def test_token_file_0600_owned_accepted(make_conn):
    assert make_conn("http://127.0.0.1:1")._load_jwt() == TOKEN
    Path(os.environ["RELAY_TOKEN_FILE"]).chmod(0o400)
    assert make_conn("http://127.0.0.1:1")._load_jwt() == TOKEN


def test_token_file_other_owner_refused(make_conn, monkeypatch):
    conn = make_conn("http://127.0.0.1:1")
    other = os.geteuid() + 1
    monkeypatch.setattr(relay.os, "geteuid", lambda: other)
    with pytest.raises(AnsibleConnectionFailure) as ei:
        conn._load_jwt()
    assert "not owned" in str(ei.value) and TOKEN not in str(ei.value)


def test_missing_token_file_empty(make_conn, monkeypatch):
    conn = make_conn("http://127.0.0.1:1")
    monkeypatch.setenv("RELAY_TOKEN_FILE", "/nonexistent/x.jwt")
    assert conn._load_jwt() == ""


def test_exec_refused_with_insecure_token_file_no_request(servers, make_conn):
    srv, c = servers("ok")
    conn = make_conn(_url(srv))
    Path(os.environ["RELAY_TOKEN_FILE"]).chmod(0o644)
    with pytest.raises(AnsibleConnectionFailure):
        _exec(conn)
    assert c.n == 0


# --- #191b: symlinks are not followed -------------------------------------------

def test_token_file_symlink_refused(make_conn, tmp_path, monkeypatch):
    conn = make_conn("http://127.0.0.1:1")
    real = Path(os.environ["RELAY_TOKEN_FILE"])  # regular 0600 file owned by us
    link = tmp_path / "link.jwt"
    link.symlink_to(real)
    monkeypatch.setenv("RELAY_TOKEN_FILE", str(link))
    with pytest.raises(AnsibleConnectionFailure) as ei:
        conn._load_jwt()
    assert "symbolic link" in str(ei.value) and str(link) in str(ei.value)
    assert TOKEN not in str(ei.value)


def test_token_file_regular_still_accepted(make_conn):
    assert make_conn("http://127.0.0.1:1")._load_jwt() == TOKEN


def test_exec_refused_with_symlinked_token_no_request(servers, make_conn, tmp_path, monkeypatch):
    srv, c = servers("ok")
    conn = make_conn(_url(srv))
    link = tmp_path / "l.jwt"
    link.symlink_to(os.environ["RELAY_TOKEN_FILE"])
    monkeypatch.setenv("RELAY_TOKEN_FILE", str(link))
    with pytest.raises(AnsibleConnectionFailure):
        _exec(conn)
    assert c.n == 0


# --- #191c: special files (FIFO, socket, device) are refused, never block -------

def _load_with_timeout(conn, timeout=5):
    """Run _load_jwt in a daemon thread; fail the test if it blocks."""
    box = {}

    def run():
        try:
            box["value"] = conn._load_jwt()
        except Exception as exc:  # noqa: BLE001 - reported to the test
            box["error"] = exc

    th = threading.Thread(target=run, daemon=True)
    th.start()
    th.join(timeout)
    assert not th.is_alive(), "_load_jwt blocked"
    return box


def test_token_file_fifo_refused_without_blocking(make_conn, tmp_path, monkeypatch):
    conn = make_conn("http://127.0.0.1:1")
    fifo = tmp_path / "tok.fifo"
    os.mkfifo(fifo, 0o600)
    monkeypatch.setenv("RELAY_TOKEN_FILE", str(fifo))
    box = _load_with_timeout(conn)
    assert isinstance(box.get("error"), AnsibleConnectionFailure)
    assert "not a regular file" in str(box["error"])


def test_token_file_socket_refused(make_conn, tmp_path, monkeypatch):
    conn = make_conn("http://127.0.0.1:1")
    path = str(tmp_path / "tok.sock")
    sock = socket.socket(socket.AF_UNIX)
    sock.bind(path)
    try:
        monkeypatch.setenv("RELAY_TOKEN_FILE", path)
        box = _load_with_timeout(conn)
    finally:
        sock.close()
    assert isinstance(box.get("error"), AnsibleConnectionFailure)
    assert "not a regular file" in str(box["error"])


def test_token_file_device_refused(make_conn, monkeypatch):
    conn = make_conn("http://127.0.0.1:1")
    monkeypatch.setenv("RELAY_TOKEN_FILE", "/dev/null")
    box = _load_with_timeout(conn)
    assert isinstance(box.get("error"), AnsibleConnectionFailure)
    assert "not a regular file" in str(box["error"])


def test_token_file_regular_ok_with_nonblock(make_conn):
    box = _load_with_timeout(make_conn("http://127.0.0.1:1"))
    assert box.get("value") == TOKEN


# --- host variables / cfg / env are honoured by Ansible's option resolution ------

def test_plugin_type_is_connection():
    """Ansible derives the plugin type from the class name; it must be 'connection'."""
    assert relay.Connection(PlayContext(), io.StringIO()).plugin_type == "connection"
    assert relay.ConnectionPlugin is relay.Connection


def _loaded_conn():
    from ansible.plugins.loader import connection_loader
    connection_loader.add_directory(str(Path(relay.__file__).parent))
    return connection_loader.get("relay", PlayContext(), None)


def test_hostvars_override_env(monkeypatch, tmp_path):
    monkeypatch.setenv("RELAY_SERVER_URL", "http://127.0.0.1:18003")
    conn = _loaded_conn()
    conn.set_options(var_options={"ansible_secagent_server": "http://127.0.0.1:18001"})
    assert conn._secagent_servers() == ["http://127.0.0.1:18001"]
    conn.set_options(var_options={})
    assert conn._secagent_servers() == ["http://127.0.0.1:18003"]  # env when no hostvar


def test_hostvar_token_file_and_timeouts(tmp_path):
    conn = _loaded_conn()
    conn.set_options(var_options={
        "ansible_secagent_token_file": "/x/tok", "ansible_secagent_timeout": 7,
        "ansible_secagent_connect_timeout": 3,
    })
    assert conn._secagent_token_file() == "/x/tok"
    assert (conn._timeout(), conn._connect_timeout()) == (7, 3)


@pytest.mark.skipif(not shutil.which("ansible-playbook"), reason="ansible-playbook not installed")
def test_ansible_playbook_reads_hostvars(servers, tmp_path, monkeypatch):
    """Real ansible-playbook: inventory variables select the server and the token."""
    srv, c = servers("ok")
    tok = tmp_path / "tok"
    tok.write_text(TOKEN)
    tok.chmod(0o600)
    (tmp_path / "inv.ini").write_text(
        f"[g]\nh1 ansible_connection=relay ansible_secagent_server={_url(srv)} "
        f"ansible_secagent_token_file={tok}\n")
    (tmp_path / "pb.yml").write_text(
        "- hosts: h1\n  gather_facts: false\n  tasks:\n    - raw: echo hi\n")
    (tmp_path / "ansible.cfg").write_text("[defaults]\ninventory = inv.ini\n")
    for var in ("RELAY_SERVER_URL", "RELAY_TOKEN_FILE"):
        monkeypatch.delenv(var, raising=False)
    env = dict(os.environ, ANSIBLE_CONFIG=str(tmp_path / "ansible.cfg"), HOME=str(tmp_path),
               ANSIBLE_CONNECTION_PLUGINS=str(Path(relay.__file__).parent))
    res = subprocess.run(["ansible-playbook", "pb.yml"], cwd=tmp_path, env=env,
                         capture_output=True, text=True, timeout=120)
    assert res.returncode == 0, res.stdout + res.stderr
    assert c.n == 1
