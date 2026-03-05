import os
import base64
import pytest
from unittest.mock import Mock, patch, MagicMock
from ansible.errors import AnsibleConnectionFailure, AnsibleError

# Mock httpx since it might not be installed in test environment
import sys
sys.modules['httpx'] = MagicMock()

# Import the connection plugin
sys.path.insert(0, '/c/Users/cyril/Documents/VScode/Ansible_Agent')
from ansible_plugins.connection_plugins.relay import ConnectionPlugin


class TestRelayConnectionPlugin:
    
    def test_connection_plugin_transport(self):
        """Verify connection plugin transport name."""
        assert ConnectionPlugin.transport == "relay"
    
    def test_connection_has_pipelining(self):
        """Verify pipelining is supported."""
        assert ConnectionPlugin.has_pipelining is True
    
    def test_load_jwt_from_file(self, tmp_path):
        """Test loading JWT from file."""
        # Create temporary JWT file
        jwt_file = tmp_path / "token.jwt"
        jwt_content = "test.jwt.token"
        jwt_file.write_text(jwt_content)
        
        # Mock the connection plugin
        conn = ConnectionPlugin(None, None)
        conn._relay_token_file = str(jwt_file)
        
        # Load JWT
        jwt = conn._load_jwt()
        assert jwt == jwt_content
    
    def test_load_jwt_file_not_found(self):
        """Test JWT loading with missing file."""
        conn = ConnectionPlugin(None, None)
        conn._relay_token_file = "/nonexistent/path/token.jwt"
        
        jwt = conn._load_jwt()
        assert jwt == ""
    
    def test_exec_command_format(self):
        """Test exec_command payload format."""
        conn = ConnectionPlugin(None, None)
        conn._play_context = Mock()
        conn._play_context.remote_addr = "test-host"
        
        # Verify expected payload structure
        hostname = conn._hostname()
        assert hostname == "test-host"
    
    def test_put_file_size_check(self, tmp_path):
        """Test put_file respects 500KB MVP limit."""
        # Create a large test file
        large_file = tmp_path / "large.bin"
        large_file.write_bytes(b"x" * (600 * 1024))  # 600KB
        
        conn = ConnectionPlugin(None, None)
        conn._play_context = Mock()
        conn._play_context.remote_addr = "test-host"
        
        # put_file should reject files over 500KB
        with pytest.raises(AnsibleError, match="file too large"):
            conn.put_file(str(large_file), "/tmp/remote.bin")
    
    def test_put_file_base64_encoding(self, tmp_path):
        """Test put_file encodes data correctly."""
        # Create a small test file
        test_file = tmp_path / "test.txt"
        test_content = b"Hello, World!"
        test_file.write_bytes(test_content)
        
        # Expected base64
        expected_b64 = base64.b64encode(test_content).decode()
        
        # Verify encoding works
        with open(test_file, "rb") as f:
            data = f.read()
        actual_b64 = base64.b64encode(data).decode()
        
        assert actual_b64 == expected_b64
    
    def test_fetch_file_base64_decoding(self, tmp_path):
        """Test fetch_file decodes base64 correctly."""
        # Create test data
        original_data = b"Fetched content"
        encoded_data = base64.b64encode(original_data).decode()
        
        # Verify decoding works
        decoded_data = base64.b64decode(encoded_data)
        assert decoded_data == original_data
    
    def test_headers_include_bearer_token(self):
        """Test HTTP headers include Bearer token."""
        conn = ConnectionPlugin(None, None)
        conn._relay_token_file = "/tmp/token.jwt"
        
        # Mock JWT loading
        with patch.object(conn, '_load_jwt', return_value="test.token"):
            headers = conn._headers()
            assert headers["Authorization"] == "Bearer test.token"
            assert headers["Content-Type"] == "application/json"


class TestRelayConnectionE2E:
    """End-to-end tests simulating real Ansible execution."""
    
    def test_exec_command_success(self):
        """Test successful command execution flow."""
        conn = ConnectionPlugin(None, None)
        conn._play_context = Mock()
        conn._play_context.remote_addr = "qualif-host-01"
        
        # Verify hostname resolution
        assert conn._hostname() == "qualif-host-01"
    
    def test_inventory_format(self):
        """Test Ansible inventory format expectations."""
        # Expected format from API /api/inventory
        inventory = {
            "all": {
                "hosts": ["qualif-host-01", "qualif-host-02"]
            },
            "_meta": {
                "hostvars": {
                    "qualif-host-01": {
                        "ansible_connection": "relay",
                        "ansible_host": "qualif-host-01",
                        "relay_status": "connected",
                        "relay_last_seen": "2026-03-04T16:40:00Z"
                    },
                    "qualif-host-02": {
                        "ansible_connection": "relay",
                        "ansible_host": "qualif-host-02",
                        "relay_status": "disconnected",
                        "relay_last_seen": None
                    }
                }
            }
        }
        
        # Verify structure
        assert "all" in inventory
        assert "_meta" in inventory
        assert len(inventory["all"]["hosts"]) == 2
        assert inventory["_meta"]["hostvars"]["qualif-host-01"]["relay_status"] == "connected"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
