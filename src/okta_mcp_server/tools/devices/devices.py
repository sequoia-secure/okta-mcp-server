# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2025-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Okta Devices API tools.

Exposes read-only access to the [Okta Devices API](
https://developer.okta.com/docs/api/openapi/okta-management/management/tag/Device/),
which returns the enrolled-device inventory that Okta maintains in Universal
Directory. These are the same `UDDevice` records that appear in system-log
events when a sign-on policy evaluates device posture.

Three tools are provided:

* ``list_devices`` — paginated list with optional SCIM ``search`` filter
* ``get_device`` — fetch a single device by id
* ``list_device_users`` — show which users are associated with a device
"""

from typing import Optional

from loguru import logger
from mcp.server.fastmcp import Context

from okta_mcp_server.server import mcp
from okta_mcp_server.utils.client import get_okta_client
from okta_mcp_server.utils.pagination import (
    build_query_params,
    create_paginated_response,
    extract_after_cursor,
    paginate_all_results,
)
from okta_mcp_server.utils.scope_guard import require_scopes
from okta_mcp_server.utils.validation import validate_ids


@mcp.tool()
@require_scopes("okta.devices.read", error_return_type="list")
async def list_devices(
    ctx: Context,
    search: str = "",
    expand: Optional[str] = None,
    fetch_all: bool = False,
    after: Optional[str] = None,
    limit: Optional[int] = None,
) -> dict:
    """List all enrolled devices in the Okta organization with pagination support.

    This returns devices Okta has on record (the Universal Directory device
    inventory) — the same records referenced as `UDDevice` targets in
    `policy.evaluate_sign_on` system-log events. It is NOT the device
    *assurance policies* tool — for those, use ``list_device_assurance_policies``.

    Parameters:
        search (str, optional): A SCIM filter expression. Supported attributes
            for the contains (`co`) operator: ``profile.displayName``,
            ``profile.serialNumber``, ``profile.imei``, ``profile.meid``,
            ``profile.udid``, ``profile.sid``. You may also filter on
            ``status`` (e.g. ``ACTIVE``, ``SUSPENDED``, ``DEACTIVATED``) and
            ``lastUpdated``. Searches are case-insensitive and eventually
            consistent.
        expand (str, optional): Set to ``user`` to include the associated user
            (and management status) under the device's ``_embedded`` field.
        fetch_all (bool, optional): If True, automatically follow `Link: next`
            until exhausted. Default: False. Capped at the same per-call limits
            as the other list_* tools.
        after (str, optional): Pagination cursor for fetching the next page.
        limit (int, optional): Per-page size (min 1, max 200). Default: 20.

    Examples:
        - First call: ``list_devices(search='profile.displayName co "mbp14"')``
        - Specific Mac:
          ``list_devices(search='profile.serialNumber eq "M4FFWTCQ10"')``
        - With user expansion: ``list_devices(expand="user")``
        - Auto-paginate: ``list_devices(fetch_all=True)``

    Returns:
        Dict with ``items``, ``total_fetched``, ``has_more``, ``next_cursor``,
        ``fetch_all_used`` (and ``pagination_info`` when fetch_all=True).
    """
    logger.info("Listing devices from Okta organization")
    logger.debug(
        f"Search: '{search}', expand: '{expand}', fetch_all: {fetch_all}, "
        f"after: '{after}', limit: {limit}"
    )

    # Enforce a consistent default page size when no limit is provided.
    if limit is None:
        limit = 20

    # Validate limit parameter range (Okta caps devices list at 200).
    if limit < 1:
        logger.warning(f"Limit {limit} is below minimum (1), setting to 1")
        limit = 1
    elif limit > 200:
        logger.warning(f"Limit {limit} exceeds maximum (200), setting to 200")
        limit = 200

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        query_params = build_query_params(
            search=search,
            after=after,
            limit=limit,
            expand=expand,
        )

        logger.debug("Calling Okta API to list devices")
        devices, response, err = await client.list_devices(**query_params)

        if err:
            logger.error(f"Okta API error while listing devices: {err}")
            return {"error": f"Error: {err}"}

        if not devices:
            logger.info("No devices found")
            return create_paginated_response([], response, fetch_all)

        _has_more = (hasattr(response, "has_next") and response.has_next()) or bool(
            extract_after_cursor(response)
        )
        if fetch_all and response and _has_more:
            logger.info(
                f"fetch_all=True, auto-paginating from initial {len(devices)} devices"
            )

            async def _next_page(cursor):
                p = dict(query_params)
                p["after"] = cursor
                return await client.list_devices(**p)

            async def _on_page(pages, total):
                await ctx.info(
                    f"Fetching devices... {total} fetched so far ({pages} pages)"
                )

            all_devices, pagination_info = await paginate_all_results(
                response, devices, next_page_fn=_next_page, on_page=_on_page
            )

            logger.info(
                f"Successfully retrieved {len(all_devices)} devices across "
                f"{pagination_info['pages_fetched']} pages"
            )
            return create_paginated_response(
                all_devices,
                response,
                fetch_all_used=True,
                pagination_info=pagination_info,
            )

        logger.info(f"Successfully retrieved {len(devices)} devices")
        return create_paginated_response(devices, response, fetch_all_used=fetch_all)

    except Exception as e:
        logger.error(f"Exception while listing devices: {type(e).__name__}: {e}")
        return {"error": f"Exception: {e}"}


@mcp.tool()
@require_scopes("okta.devices.read", error_return_type="list")
@validate_ids("device_id")
async def get_device(device_id: str, ctx: Context = None) -> list:
    """Retrieve a single device by its Okta `deviceId`.

    Parameters:
        device_id (str, required): The Okta device id (`guo...`). You can
            obtain device ids from ``list_devices`` or from the
            ``target[type=UDDevice].id`` field on
            ``policy.evaluate_sign_on`` system-log events.

    Returns:
        List with one element: the device object (profile, status, lastUpdated,
        registered/managed flags, embedded user if available).
    """
    logger.info(f"Getting device with ID: {device_id}")

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        logger.debug(f"Calling Okta API to get device {device_id}")

        device, _, err = await client.get_device(device_id)

        if err:
            logger.error(f"Okta API error while getting device {device_id}: {err}")
            return [f"Error: {err}"]

        logger.info(f"Successfully retrieved device: {device_id}")
        return [device]
    except Exception as e:
        logger.error(
            f"Exception while getting device {device_id}: {type(e).__name__}: {e}"
        )
        return [f"Exception: {e}"]


@mcp.tool()
@require_scopes("okta.devices.read", error_return_type="list")
@validate_ids("device_id")
async def list_device_users(device_id: str, ctx: Context = None) -> list:
    """List all users associated with a device.

    A single Okta device can have multiple ``DeviceUser`` associations (for
    example, a shared loaner laptop). Each entry includes the linked user, the
    management status of the device for that user, and screen-lock metadata.

    Parameters:
        device_id (str, required): The Okta device id.

    Returns:
        List of ``DeviceUser`` objects, or a single error string on failure.
    """
    logger.info(f"Listing users for device with ID: {device_id}")

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        logger.debug(f"Calling Okta API to list users for device {device_id}")

        users, _, err = await client.list_device_users(device_id)

        if err:
            logger.error(
                f"Okta API error while listing users for device {device_id}: {err}"
            )
            return [f"Error: {err}"]

        if not users:
            logger.info(f"No users found for device: {device_id}")
            return []

        logger.info(
            f"Successfully retrieved {len(users)} users for device {device_id}"
        )
        return list(users)
    except Exception as e:
        logger.error(
            f"Exception while listing users for device {device_id}: "
            f"{type(e).__name__}: {e}"
        )
        return [f"Exception: {e}"]
