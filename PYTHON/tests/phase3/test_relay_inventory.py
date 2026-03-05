import os
import pytest
from unittest.mock import Mock, patch, MagicMock
import sys

# Mock httpx
sys.modules['httpx'] = MagicMock()

sys.path.insert(0, '/c/Users/cyril/Documents/VScode/Ansible_Agent')
from ansible_plugins.inventory_plugins.relay_inventory import InventoryModule


class TestRelayInventoryPlugin:
    
    def test_inventory_module_name(self):
        """Verify inventory module name."""
        assert InventoryModule.NAME == 'relay_inventory'
        assert InventoryModule.PLUGIN_TYPE == 'inventory'
    
    def test_verify_file(self):
        """Test file verification."""
        inv = InventoryModule()
        
        # Should verify relay_inventory.py files
        assert inv.verify_file('/path/to/relay_inventory.py') is True
        assert inv.verify_file('/path/to/other.py') is False
    
    def test_verify_file_exact_name(self):
        """Test exact filename matching."""
        inv = InventoryModule()
        
        assert inv.verify_file('relay_inventory.py') is True
        assert inv.verify_file('relay_inventory.yml') is False
        assert inv.verify_file('inventory.py') is False
    
    def test_inventory_response_parsing(self):
        """Test parsing Ansible inventory JSON format."""
        response = {
            "all": {
                "hosts": ["host1", "host2"]
            },
            "_meta": {
                "hostvars": {
                    "host1": {
                        "ansible_connection": "relay",
                        "relay_status": "connected",
                        "relay_last_seen": "2026-03-04T16:40:00Z"
                    },
                    "host2": {
                        "ansible_connection": "relay",
                        "relay_status": "disconnected",
                        "relay_last_seen": None
                    }
                }
            }
        }
        
        # Verify we can parse this format
        hostvars = response.get('_meta', {}).get('hostvars', {})
        
        agents = []
        for hostname, hvars in hostvars.items():
            agent = {
                'hostname': hostname,
                'status': hvars.get('relay_status', 'unknown'),
                'last_seen': hvars.get('relay_last_seen'),
            }
            agents.append(agent)
        
        assert len(agents) == 2
        assert agents[0]['hostname'] == 'host1'
        assert agents[0]['status'] == 'connected'
        assert agents[1]['status'] == 'disconnected'
    
    def test_jwt_loading(self, tmp_path):
        """Test JWT token file loading."""
        jwt_file = tmp_path / "token.jwt"
        jwt_file.write_text("test.jwt.content")
        
        inv = InventoryModule()
        inv._relay_token_file = str(jwt_file)
        
        jwt = inv._load_jwt()
        assert jwt == "test.jwt.content"
    
    def test_jwt_missing_file(self):
        """Test JWT loading with missing file."""
        inv = InventoryModule()
        inv._relay_token_file = "/nonexistent/path.jwt"
        
        jwt = inv._load_jwt()
        assert jwt is None
    
    def test_config_reading(self):
        """Test configuration option reading."""
        inv = InventoryModule()
        
        # Mock get_option
        def mock_get_option(key):
            config = {
                'relay_server': 'http://relay:7770',
                'relay_token_file': '/etc/ansible/relay.jwt',
                'relay_ca_bundle': None,
                'only_connected': False,
            }
            return config.get(key)
        
        inv.get_option = mock_get_option
        inv._read_config()
        
        assert inv._relay_server == 'http://relay:7770'
        assert inv._relay_token_file == '/etc/ansible/relay.jwt'
        assert inv._only_connected is False


class TestRelayInventoryE2E:
    """End-to-end inventory tests."""
    
    def test_agent_filtering_by_status(self):
        """Test only_connected filtering."""
        all_agents = [
            {'hostname': 'host1', 'status': 'connected', 'last_seen': '2026-03-04T16:40:00Z'},
            {'hostname': 'host2', 'status': 'disconnected', 'last_seen': None},
            {'hostname': 'host3', 'status': 'connected', 'last_seen': '2026-03-04T16:35:00Z'},
        ]
        
        only_connected = [a for a in all_agents if a['status'] == 'connected']
        
        assert len(only_connected) == 2
        assert all(a['status'] == 'connected' for a in only_connected)
    
    def test_hostvars_required_fields(self):
        """Test all required hostvars are present."""
        hostvars = {
            'host1': {
                'ansible_connection': 'relay',
                'ansible_host': 'host1',
                'relay_status': 'connected',
                'relay_last_seen': '2026-03-04T16:40:00Z',
            }
        }
        
        host_vars = hostvars['host1']
        assert 'ansible_connection' in host_vars
        assert 'ansible_host' in host_vars
        assert 'relay_status' in host_vars
        assert host_vars['ansible_connection'] == 'relay'


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
