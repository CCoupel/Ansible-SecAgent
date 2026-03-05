# -*- coding: utf-8 -*-
# ansible_plugins/inventory_plugins/relay_inventory.py
#
# Ansible Dynamic Inventory Plugin for AnsibleRelay
#
# Fetches list of enrolled agents from relay server and exposes them
# as dynamic inventory in Ansible format.

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = """
name: relay_inventory
short_description: AnsibleRelay dynamic inventory plugin
description:
  - Fetches the list of enrolled agents from the AnsibleRelay server.
  - Returns agents in Ansible-compatible inventory format.
options:
  relay_server:
    description: Base URL of the AnsibleRelay FastAPI server (HTTP or HTTPS).
    default: http://localhost:7770
    required: true
  relay_token_file:
    description: Path to file containing JWT token for plugin role authentication.
    default: /etc/ansible/relay_plugin.jwt
  relay_ca_bundle:
    description: Path to CA bundle for TLS verification (HTTPS only).
    default: null
  only_connected:
    description: If true, return only agents with status=connected.
    default: false
    type: boolean
"""

import os

try:
    import httpx
except ImportError:
    httpx = None

from ansible.plugins.inventory import BaseInventoryPlugin


class InventoryModule(BaseInventoryPlugin):
    NAME = 'relay_inventory'
    PLUGIN_TYPE = 'inventory'

    def __init__(self):
        super(InventoryModule, self).__init__()
        self._relay_server = None
        self._relay_token_file = None
        self._relay_ca_bundle = None
        self._only_connected = False

    def verify_file(self, path):
        return path.endswith('relay_inventory.py')

    def parse(self, inventory, loader, path, cache=True):
        super(InventoryModule, self).parse(inventory, loader, path, cache)

        if httpx is None:
            raise Exception("httpx library is required. Install with: pip install httpx")

        self._read_config()

        # Fetch agents from relay server
        agents = self._fetch_agents()

        # Add them to inventory
        for agent in agents:
            hostname = agent.get('hostname')
            if not hostname:
                continue

            self.inventory.add_host(hostname)

            # Set host variables from agent data
            self.inventory.set_variable(hostname, 'ansible_connection', 'relay')
            self.inventory.set_variable(hostname, 'ansible_relay_server', self._relay_server)
            self.inventory.set_variable(hostname, 'relay_status', agent.get('status', 'unknown'))
            self.inventory.set_variable(hostname, 'relay_last_seen', agent.get('last_seen'))

            # Add to 'all' group
            self.inventory.add_group('all')
            self.inventory.add_host(hostname, group='all')

    def _read_config(self):
        self._relay_server = self.get_option('relay_server')
        self._relay_token_file = self.get_option('relay_token_file')
        self._relay_ca_bundle = self.get_option('relay_ca_bundle')
        self._only_connected = self.get_option('only_connected')

    def _load_jwt(self):
        if not self._relay_token_file or not os.path.exists(self._relay_token_file):
            return None

        try:
            with open(self._relay_token_file, 'r') as f:
                return f.read().strip()
        except Exception:
            return None

    def _fetch_agents(self):
        jwt = self._load_jwt()
        if not jwt:
            raise Exception(
                f"JWT token not found: {self._relay_token_file}. "
                "Ensure relay_token_file is set and the file exists."
            )

        url = f"{self._relay_server.rstrip('/')}/api/inventory"
        if self._only_connected:
            url += "?only_connected=true"

        verify = True
        if self._relay_ca_bundle:
            verify = self._relay_ca_bundle

        headers = {
            "Authorization": f"Bearer {jwt}",
            "Content-Type": "application/json",
        }

        try:
            client = httpx.Client(verify=verify, timeout=30)
            resp = client.get(url, headers=headers)
            client.close()
        except Exception as e:
            raise Exception(f"Failed to connect to relay server at {url}: {e}")

        if resp.status_code != 200:
            raise Exception(
                f"Relay server returned {resp.status_code}: {resp.text[:200]}"
            )

        try:
            data = resp.json()
        except Exception:
            raise Exception(f"Relay server returned non-JSON response: {resp.text[:200]}")

        # Extract agents from Ansible-format inventory response
        # Format: { "all": { "hosts": [...] }, "_meta": { "hostvars": { hostname: {...} } } }
        hostvars = data.get('_meta', {}).get('hostvars', {})

        agents = []
        for hostname, hostvars_data in hostvars.items():
            agent = {
                'hostname': hostname,
                'status': hostvars_data.get('relay_status', 'unknown'),
                'last_seen': hostvars_data.get('relay_last_seen'),
            }
            agents.append(agent)

        return agents
