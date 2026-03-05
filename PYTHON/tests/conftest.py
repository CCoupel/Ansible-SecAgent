"""
conftest.py — Configuration pytest globale pour les tests AnsibleRelay.

- asyncio_mode = "auto" pour pytest-asyncio
- Fixtures partagées entre tous les modules de test
"""

import pytest


# ---------------------------------------------------------------------------
# Configuration pytest-asyncio
# ---------------------------------------------------------------------------

# Mode auto : tous les tests async sont automatiquement traités
# Peut aussi être défini dans pytest.ini : asyncio_mode = auto
def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "asyncio: mark test as async (handled by pytest-asyncio)"
    )
