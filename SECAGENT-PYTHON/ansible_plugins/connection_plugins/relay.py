# -*- coding: utf-8 -*-
# connection_plugins/secagent.py
#
# Ansible-SecAgent — Custom Connection Plugin
#
# Remplace SSH par un canal WebSocket géré par le secagent-minion côté client.
# Le serveur FastAPI agit comme broker : il relaie les commandes Ansible
# vers le bon agent via le WebSocket persistant ouvert par le client.
#
# Usage dans l'inventaire :
#   ansible_connection: relay
#   ansible_secagent_server: http://localhost:8000   (ou via ansible.cfg)
#
# Protocole broker (JSON) :
#   → { "task_id": "...", "type": "exec", "command": "...", "stdin": "" }
#   ← { "task_id": "...", "rc": 0, "stdout": "...", "stderr": "..." }
#
#   → { "task_id": "...", "type": "put_file", "dst": "...", "data_b64": "..." }
#   ← { "task_id": "...", "rc": 0 }
#
#   → { "task_id": "...", "type": "fetch_file", "src": "..." }
#   ← { "task_id": "...", "rc": 0, "data_b64": "..." }

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r"""
name: relay
short_description: Ansible-SecAgent WebSocket connection plugin
description:
  - Connects to hosts via the Ansible-SecAgent broker instead of SSH.
  - Requires the secagent-minion daemon to be running on the target host
    and connected to the relay server.
author: Ansible-SecAgent Project
version_added: "1.0"
options:
  secagent_server:
    description:
      - Base URL of the Ansible-SecAgent server (HTTP or HTTPS), or a
        comma-separated list of URLs (active/passive relay).
      - Addresses are tried in order, the last good one first. The plugin
        moves to the next address ONLY when the connection fails before the
        request is sent (connect error, connect timeout, TLS failure). Any
        failure after the request was sent (read timeout, protocol error,
        HTTP 5xx) raises an error WITHOUT replaying the request elsewhere.
      - Each entry must be http:// or https:// with a host and a valid port,
        and must NOT contain credentials (user:pass@host is rejected).
        Plain http:// outside loopback sends the token in clear text and
        triggers a warning; use https:// (see SECURITY.md section 1).
      - The "last good address" memory only lives inside one Ansible process.
        Every fork starts again from the configured order, so a dead address
        costs one connect timeout (secagent_connect_timeout) per fork. List
        the most probable address first.
    default: http://localhost:7770
    ini:
      - section: secagent_connection
        key: server
    env:
      - name: RELAY_SERVER_URL
    vars:
      - name: ansible_secagent_server
  secagent_token_file:
    description:
      - Path to file containing JWT token for plugin role authentication.
    default: /etc/ansible/secagent_plugin.jwt
    ini:
      - section: secagent_connection
        key: token_file
    env:
      - name: RELAY_TOKEN_FILE
    vars:
      - name: ansible_secagent_token_file
  secagent_ca_bundle:
    description:
      - Path to CA bundle for TLS verification (HTTPS only).
    default: null
    ini:
      - section: secagent_connection
        key: ca_bundle
    env:
      - name: RELAY_CA_BUNDLE
    vars:
      - name: ansible_secagent_ca_bundle
  secagent_timeout:
    description:
      - Seconds to wait for a task result before timing out.
    default: 30
    type: integer
    ini:
      - section: secagent_connection
        key: timeout
    env:
      - name: RELAY_TIMEOUT
    vars:
      - name: ansible_secagent_timeout
  secagent_connect_timeout:
    description:
      - Seconds to wait for the connection to each address to be established.
    default: 5
    type: integer
    ini:
      - section: secagent_connection
        key: connect_timeout
    env:
      - name: RELAY_CONNECT_TIMEOUT
    vars:
      - name: ansible_secagent_connect_timeout
"""

import base64
import json
import os
import uuid
from urllib.parse import urlsplit

try:
    import httpx
except ImportError:
    httpx = None

from ansible.errors import AnsibleConnectionFailure, AnsibleError
from ansible.plugins.connection import ConnectionBase
from ansible.utils.display import Display

display = Display()

# Last address that answered, kept for the lifetime of the Ansible run
# (module level: shared by every Connection instance of the process).
# Limit: this memory is per process. Ansible forks workers, so each fork
# starts again from the configured order (no file cache on purpose: it would
# add an attack surface in a shared tmp). The cost of a dead address is one
# connect timeout per fork, bounded by secagent_connect_timeout.
_LAST_GOOD_URL = None

# Same default as the DOCUMENTATION above (never a world-writable directory like /tmp).
DEFAULT_TOKEN_FILE = "/etc/ansible/secagent_plugin.jwt"

_LOOPBACK_HOSTS = ("localhost", "::1")
_WARNED_CLEARTEXT = set()


def _is_loopback(host):
    """Return True for localhost, 127.0.0.0/8 and ::1."""
    host = (host or "").lower()
    return host in _LOOPBACK_HOSTS or host.startswith("127.")


def _validate_url(url, position):
    """Validate one server URL; raise AnsibleError naming only its position.

    The URL itself is never echoed: it could contain a secret.
    """
    def bad(cause):
        return AnsibleError(f"secagent_server: invalid entry #{position}: {cause}")

    try:
        parts = urlsplit(url)
        host = parts.hostname
        parts.port  # noqa: B018 - raises ValueError on an invalid port
    except ValueError:
        raise bad("malformed URL or invalid port")
    if parts.scheme not in ("http", "https"):
        raise bad("scheme must be http or https")
    if not host:
        raise bad("missing host")
    if "@" in parts.netloc:
        raise bad("credentials (user:pass@host) are not allowed in the URL")


def _parse_urls(raw):
    """Split a comma-separated server option into validated base URLs.

    Raises AnsibleError on any invalid entry (position and cause only).
    """
    urls = []
    for pos, item in enumerate(str(raw).split(","), start=1):
        item = item.strip()
        if not item:
            continue
        _validate_url(item, pos)
        urls.append(item.rstrip("/"))
    return urls


def _warn_if_cleartext(url):
    """Warn once per address when http:// targets a non-loopback host."""
    parts = urlsplit(url)
    if parts.scheme == "http" and not _is_loopback(parts.hostname):
        key = _host_port(url)
        if key not in _WARNED_CLEARTEXT:
            _WARNED_CLEARTEXT.add(key)
            display.warning(
                f"secagent_server {key} uses http://: the plugin token is sent in "
                "clear text. WSS/HTTPS is required outside localhost (SECURITY.md section 1)."
            )


def _error_detail(resp):
    """Extract a short, sanitized error field from a JSON server response.

    Only a known field of a JSON object is used (never the raw body, which
    could come from an intermediate proxy). Returns "" when none.
    """
    try:
        data = resp.json()
    except ValueError:
        return ""
    if not isinstance(data, dict):
        return ""
    for key in ("error", "detail", "message"):
        val = data.get(key)
        if isinstance(val, str) and val:
            return "".join(c for c in val[:100] if c.isprintable())
    return ""


def _order_urls(urls):
    """Return urls with the last good one first (if it is in the list)."""
    last = _LAST_GOOD_URL
    if last in urls:
        return [last] + [u for u in urls if u != last]
    return list(urls)


def _host_port(url):
    """Return 'host:port' of a URL, without scheme, userinfo or path."""
    try:
        u = httpx.URL(url)
        port = u.port or (443 if u.scheme == "https" else 80)
        return f"{u.host}:{port}"
    except Exception:
        return "<invalid-address>"


class ConnectionPlugin(ConnectionBase):
    """Ansible-SecAgent connection plugin — routes commands through the relay server via HTTP/REST."""

    transport = "relay"
    has_pipelining = True
    has_tty = False

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_opt(self, name, env_var, default=""):
        """Get option via get_option() with fallback to env var and default.

        Ansible 2.19 may not register plugin config definitions for custom
        plugins loaded via ansible.cfg paths, causing get_option() to raise
        AnsibleUndefinedConfigEntry. This fallback ensures the plugin works.
        """
        try:
            val = self.get_option(name)
            if val is not None:
                return val
        except (KeyError, Exception):
            pass
        return os.environ.get(env_var, default)

    def _secagent_servers(self):
        """Return the configured server base URLs (list, at least one)."""
        urls = _parse_urls(
            self._get_opt("secagent_server", "RELAY_SERVER_URL", "http://localhost:7770")
        )
        if not urls:
            display.warning(
                "secagent_server is empty: falling back to http://localhost:7770"
            )
            return ["http://localhost:7770"]
        for url in urls:
            _warn_if_cleartext(url)
        return urls

    def _secagent_server(self):
        """Return the first configured server URL (single-address compatibility)."""
        return self._secagent_servers()[0]

    def _secagent_token_file(self):
        return self._get_opt("secagent_token_file", "RELAY_TOKEN_FILE", DEFAULT_TOKEN_FILE)

    def _secagent_ca_bundle(self):
        return self._get_opt("secagent_ca_bundle", "RELAY_CA_BUNDLE", "")

    def _headers(self):
        token = self._load_jwt()
        h = {"Content-Type": "application/json"}
        if token:
            h["Authorization"] = f"Bearer {token}"
        return h

    def _timeout(self):
        return int(self._get_opt("secagent_timeout", "RELAY_TIMEOUT", "30"))

    def _connect_timeout(self):
        return int(self._get_opt("secagent_connect_timeout", "RELAY_CONNECT_TIMEOUT", "5"))

    def _hostname(self):
        return self._play_context.remote_addr

    def _load_jwt(self):
        """Load the JWT from the token file.

        Returns "" when the file is missing or unreadable. Raises
        AnsibleConnectionFailure when the file is not owned by the current
        user or is accessible by group/others (mode & 0o077): the message
        names the path and the problem, never the token.
        """
        token_file = self._secagent_token_file()
        if not token_file:
            return ""
        try:
            fd = os.open(token_file, os.O_RDONLY)
        except OSError:
            return ""
        try:
            st = os.fstat(fd)  # on the opened file: no check/use race
            if hasattr(os, "geteuid") and st.st_uid != os.geteuid():
                raise AnsibleConnectionFailure(
                    f"JWT token file {token_file} is not owned by the current user; refusing to use it"
                )
            if st.st_mode & 0o077:
                raise AnsibleConnectionFailure(
                    f"JWT token file {token_file} is accessible by group/others "
                    f"(mode {st.st_mode & 0o777:04o}); run: chmod 600 {token_file}"
                )
            with os.fdopen(fd, "r") as f:
                fd = -1
                return f.read().strip()
        except OSError:
            return ""
        finally:
            if fd != -1:
                os.close(fd)

    def _get_client(self):
        """Create httpx client with proper TLS configuration."""
        verify = True
        ca_bundle = self._secagent_ca_bundle()
        if ca_bundle:
            verify = ca_bundle

        return httpx.Client(
            verify=verify,
            timeout=httpx.Timeout(self._timeout(), connect=self._connect_timeout()),
        )

    def _post_relay(self, endpoint: str, payload: dict) -> dict:
        """POST a task to relay server and parse result."""
        if httpx is None:
            raise AnsibleConnectionFailure(
                "httpx library is required. Install with: pip install httpx"
            )

        global _LAST_GOOD_URL
        hostname = self._hostname()
        headers = self._headers()
        servers = _order_urls(self._secagent_servers())

        display.vvv(f"RELAY: POST {endpoint} (host={hostname})", host=hostname)

        resp = None
        used = None
        failed = []
        client = self._get_client()
        try:
            for base in servers:
                addr = _host_port(base)
                try:
                    resp = client.post(f"{base}{endpoint}", headers=headers, json=payload)
                except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
                    # Failure BEFORE the request was sent (incl. TLS handshake):
                    # safe to try the next address.
                    display.vvv(
                        f"RELAY: {addr} unreachable ({type(exc).__name__}), trying next",
                        host=hostname,
                    )
                    failed.append(f"{addr} ({type(exc).__name__})")
                    continue
                except httpx.TimeoutException:
                    # ReadTimeout / WriteTimeout / PoolTimeout: request may have been
                    # sent — never replay on another address.
                    raise AnsibleConnectionFailure(
                        f"Relay timeout ({self._timeout()}s) waiting for host "
                        f"'{hostname}' via {addr}; request not retried"
                    )
                except httpx.HTTPError as exc:
                    # RemoteProtocolError, ReadError, ... after send: no replay.
                    raise AnsibleConnectionFailure(
                        f"Relay connection to {addr} failed after sending the request "
                        f"({type(exc).__name__}); request not retried"
                    )
                used = base
                display.vvv(f"RELAY: using {addr}", host=hostname)
                break
        finally:
            client.close()

        if resp is None:
            raise AnsibleConnectionFailure(
                "Cannot reach any relay server address: " + ", ".join(failed)
            )

        if resp.status_code >= 500:
            raise AnsibleConnectionFailure(
                f"Relay server error {resp.status_code} from {_host_port(used)}; "
                "request not retried"
            )

        # A server that answers (non-5xx) is a good address; a 5xx is not remembered.
        _LAST_GOOD_URL = used

        if resp.status_code == 404:
            raise AnsibleConnectionFailure(
                f"Host '{hostname}' not registered or not connected to relay server (HTTP 404)"
            )

        if resp.status_code != 200:
            detail = _error_detail(resp)
            raise AnsibleError(
                f"Relay server error {resp.status_code}" + (f": {detail}" if detail else "")
            )

        try:
            result = resp.json()
        except ValueError:
            raise AnsibleError("Relay server returned a non-JSON response")

        display.vvv(
            f"RELAY: result rc={result.get('rc', '?')}",
            host=hostname,
        )
        return result

    # ------------------------------------------------------------------
    # ConnectionBase interface
    # ------------------------------------------------------------------

    def _connect(self):
        """Check that the target host is connected to the relay server via WebSocket."""
        if self._connected:
            return self

        hostname = self._hostname()
        display.vvv(f"RELAY: checking connection to {hostname}", host=hostname)

        # For now, just verify we can reach the relay server and have a valid JWT.
        # The actual host connectivity is checked when exec_command is called.
        if not self._secagent_token_file():
            raise AnsibleConnectionFailure(
                "secagent_token_file is not set. Set it via ansible.cfg or RELAY_TOKEN_FILE env var."
            )

        jwt = self._load_jwt()
        if not jwt:
            raise AnsibleConnectionFailure(
                f"JWT token file is empty or not readable: {self._secagent_token_file()}"
            )

        self._connected = True
        display.vvv(f"RELAY: connection to {hostname} verified", host=hostname)
        return self

    def exec_command(self, cmd, in_data=None, sudoable=True):
        """Execute a shell command on the remote host via the relay server.

        Returns: (return_code, stdout_bytes, stderr_bytes)
        """
        super().exec_command(cmd, in_data=in_data, sudoable=sudoable)

        hostname = self._hostname()
        payload = {"cmd": cmd}
        if in_data:
            # The server contract (handlers/exec.go) expects stdin base64-encoded;
            # raw bytes (pipelined module, binary data) must survive untouched.
            if isinstance(in_data, str):
                in_data = in_data.encode("utf-8")
            payload["stdin"] = base64.b64encode(in_data).decode("ascii")

        result = self._post_relay(f"/api/exec/{hostname}", payload)

        rc = int(result.get("rc", 1))
        stdout = result.get("stdout", "").encode("utf-8")
        stderr = result.get("stderr", "").encode("utf-8")
        return rc, stdout, stderr

    def put_file(self, in_path, out_path):
        """Transfer a local file to the remote host via the relay server (base64)."""
        super().put_file(in_path, out_path)

        hostname = self._hostname()
        display.vvv(f"RELAY: put_file {in_path} → {out_path}", host=hostname)

        if not os.path.exists(in_path):
            raise AnsibleError(f"put_file: local file not found: {in_path}")

        with open(in_path, "rb") as fh:
            data = fh.read()

        # Check MVP file size limit (500KB)
        if len(data) > 500 * 1024:
            raise AnsibleError(
                f"put_file: file too large ({len(data)} bytes, max 500KB for MVP)"
            )

        payload = {
            "dest": out_path,
            "data": base64.b64encode(data).decode("ascii"),
            "mode": "0644",
        }

        result = self._post_relay(f"/api/upload/{hostname}", payload)
        if int(result.get("rc", 1)) != 0:
            raise AnsibleError(
                f"put_file failed on remote host: {result.get('stderr', '')}"
            )

    def fetch_file(self, in_path, out_path):
        """Fetch a remote file via the relay server (base64) to a local path."""
        super().fetch_file(in_path, out_path)

        hostname = self._hostname()
        display.vvv(f"RELAY: fetch_file {in_path} → {out_path}", host=hostname)

        payload = {
            "src": in_path,
        }

        result = self._post_relay(f"/api/fetch/{hostname}", payload)

        if int(result.get("rc", 1)) != 0:
            raise AnsibleError(
                f"fetch_file failed on remote host: {result.get('stderr', '')}"
            )

        data_b64 = result.get("data", "")
        if not data_b64:
            raise AnsibleError(f"fetch_file: relay returned empty data for '{in_path}'")

        os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
        with open(out_path, "wb") as fh:
            fh.write(base64.b64decode(data_b64))

    def close(self):
        """Nothing persistent to close — HTTP is stateless."""
        self._connected = False


# Ansible expects a class named "Connection", not "ConnectionPlugin"
Connection = ConnectionPlugin
