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
      - Base URL of the Ansible-SecAgent FastAPI server (HTTP or HTTPS).
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
"""

import base64
import json
import os
import uuid

try:
    import httpx
except ImportError:
    httpx = None

from ansible.errors import AnsibleConnectionFailure, AnsibleError
from ansible.plugins.connection import ConnectionBase
from ansible.utils.display import Display

display = Display()


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

    def _secagent_server(self):
        return self._get_opt("secagent_server", "RELAY_SERVER_URL", "http://localhost:7770").rstrip("/")

    def _secagent_token_file(self):
        return self._get_opt("secagent_token_file", "RELAY_TOKEN_FILE", "/tmp/secagent_token.jwt")

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

    def _hostname(self):
        return self._play_context.remote_addr

    def _load_jwt(self):
        """Load JWT token from file."""
        token_file = self._secagent_token_file()
        if not token_file or not os.path.exists(token_file):
            return ""

        try:
            with open(token_file, "r") as f:
                return f.read().strip()
        except Exception:
            return ""

    def _get_client(self):
        """Create httpx client with proper TLS configuration."""
        verify = True
        ca_bundle = self._secagent_ca_bundle()
        if ca_bundle:
            verify = ca_bundle

        return httpx.Client(verify=verify, timeout=self._timeout())

    def _post_relay(self, endpoint: str, payload: dict) -> dict:
        """POST a task to relay server and parse result."""
        if httpx is None:
            raise AnsibleConnectionFailure(
                "httpx library is required. Install with: pip install httpx"
            )

        hostname = self._hostname()
        url = f"{self._secagent_server()}{endpoint}"

        display.vvv(f"RELAY: POST {endpoint} (host={hostname})", host=hostname)

        client = self._get_client()
        try:
            resp = client.post(url, headers=self._headers(), json=payload)
        except httpx.TimeoutException:
            raise AnsibleConnectionFailure(
                f"Relay timeout ({self._timeout()}s) waiting for host '{hostname}'"
            )
        except httpx.ConnectError as exc:
            raise AnsibleConnectionFailure(
                f"Cannot reach relay server at '{self._secagent_server()}': {exc}"
            )
        finally:
            client.close()

        if resp.status_code == 404:
            raise AnsibleConnectionFailure(
                f"Host '{hostname}' not registered or not connected to relay server (HTTP 404)"
            )

        if resp.status_code != 200:
            raise AnsibleError(
                f"Relay server error {resp.status_code}: {resp.text[:200]}"
            )

        try:
            result = resp.json()
        except ValueError:
            raise AnsibleError(f"Relay server returned non-JSON response: {resp.text[:200]}")

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
        payload = {
            "cmd": cmd,
            "stdin": (in_data or b"").decode("utf-8", errors="replace"),
        }

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
