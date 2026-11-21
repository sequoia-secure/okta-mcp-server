# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Okta Network Zones API tools (read-only).

Exposes the [Network Zone API](
https://developer.okta.com/docs/api/openapi/okta-management/management/tag/NetworkZone/)
so an investigator can see what a zone id in a policy rule or system-log event
actually covers: IP ``gateways`` and ``proxies`` for IP zones, ``asns`` /
``locations`` / ``ipServiceCategories`` for dynamic zones, and the zone
``usage`` (``POLICY`` or ``BLOCKLIST``).

Only read tools are provided. Zone changes are made by a person in the Admin
Console.
"""

from typing import Optional

from loguru import logger
from mcp.server.fastmcp import Context

from okta_mcp_server.server import mcp
from okta_mcp_server.utils.client import get_okta_client
from okta_mcp_server.utils.raw_api import okta_get, okta_get_all, strip_links
from okta_mcp_server.utils.scope_guard import require_scopes
from okta_mcp_server.utils.serialization import json_response
from okta_mcp_server.utils.validation import validate_ids


@mcp.tool()
@require_scopes("okta.networkZones.read")
@json_response
async def list_network_zones(ctx: Context, filter: Optional[str] = None) -> dict:
    """List all network zones in the Okta org, with the IP ranges and locations each covers.

    Use this to resolve a zone id seen in a policy rule (``conditions.network.include``)
    or a system-log event to its name and contents, or to answer "which zones
    are trusted / blocked".

    Parameters:
        filter (str, optional): Okta filter expression. Supported:
            ``id eq "nzo..."``, ``usage eq "POLICY"`` or ``usage eq "BLOCKLIST"``,
            ``system eq true``. Combine with ``or``.

    Examples:
        - All zones: ``list_network_zones()``
        - Block lists only: ``list_network_zones(filter='usage eq "BLOCKLIST"')``

    Returns:
        Dict with ``items`` (each zone: ``id``, ``name``, ``type`` such as
        ``IP``, ``DYNAMIC`` or ``DYNAMIC_V2``, ``status``, ``usage``, ``system``,
        and per type ``gateways``, ``proxies``, ``asns``, ``locations``,
        ``ipServiceCategories``), ``total``, and ``truncated``.
    """
    logger.info(f"Listing network zones (filter={filter!r})")
    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        zones, truncated, err = await okta_get_all(client, "/api/v1/zones", {"filter": filter})
        if err:
            logger.error(f"Okta API error while listing network zones: {err}")
            return {"error": f"Error: {err}"}
        logger.info(f"Retrieved {len(zones)} network zones")
        return {"items": strip_links(zones), "total": len(zones), "truncated": truncated}
    except Exception as e:
        logger.error(f"Exception while listing network zones: {type(e).__name__}: {e}")
        return {"error": f"Exception: {e}"}


@mcp.tool()
@require_scopes("okta.networkZones.read")
@validate_ids("zone_id", error_return_type="dict")
@json_response
async def get_network_zone(zone_id: str, ctx: Context = None) -> dict:
    """Get one network zone by id, including its gateways, proxies, ASNs and locations.

    Parameters:
        zone_id (str, required): The zone id, for example ``nzo1abc...``.

    Returns:
        The zone object (``_links`` removed), or ``{"error": ...}``.
    """
    logger.info(f"Getting network zone {zone_id}")
    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        _, zone, err = await okta_get(client, f"/api/v1/zones/{zone_id}")
        if err:
            logger.error(f"Okta API error while getting network zone {zone_id}: {err}")
            return {"error": f"Error: {err}"}
        return strip_links(zone) if zone else {"error": f"Network zone {zone_id} returned an empty body"}
    except Exception as e:
        logger.error(f"Exception while getting network zone {zone_id}: {type(e).__name__}: {e}")
        return {"error": f"Exception: {e}"}
