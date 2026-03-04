"""
routes_inventory.py — Dynamic Ansible inventory endpoint.

Endpoints:
    GET /api/inventory   — Return all enrolled agents in Ansible JSON inventory format

Auth: Bearer JWT with role "plugin" (enforced by require_role dependency).

Format matches ARCHITECTURE.md §6 and §14 exactly:
    {
      "all": { "hosts": ["host-A", "host-B"] },
      "_meta": {
        "hostvars": {
          "host-A": {
            "ansible_connection": "relay",
            "ansible_host": "host-A",
            "relay_status": "connected",
            "relay_last_seen": "2026-03-03T10:00:00Z"
          }
        }
      }
    }
"""

import logging
from typing import Optional

from fastapi import APIRouter, Depends, Query, Request

from server.api.routes_register import require_role

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get(
    "/api/inventory",
    summary="Dynamic Ansible inventory — all enrolled agents",
    dependencies=[Depends(require_role("plugin"))],
)
async def get_inventory(
    request: Request,
    only_connected: Optional[bool] = Query(
        default=False,
        description="If true, return only agents with status=connected",
    ),
) -> dict:
    """
    Return the relay inventory in Ansible dynamic inventory JSON format.

    Query parameters:
        only_connected (bool): Filter to connected agents only. Default false.

    Returns Ansible-compatible dict:
        {
          "all": { "hosts": [...] },
          "_meta": { "hostvars": { hostname: {...} } }
        }

    Auth: Bearer JWT, role "plugin".
    """
    store = request.app.state.store
    agents = await store.list_agents(only_connected=only_connected or False)

    hosts = [a["hostname"] for a in agents]
    hostvars = {
        a["hostname"]: {
            "ansible_connection": "relay",
            "ansible_host": a["hostname"],
            "relay_status": a["status"],
            "relay_last_seen": a.get("last_seen"),
        }
        for a in agents
    }

    logger.debug(
        "Inventory requested",
        extra={"only_connected": only_connected, "count": len(hosts)},
    )

    return {
        "all": {"hosts": hosts},
        "_meta": {"hostvars": hostvars},
    }
