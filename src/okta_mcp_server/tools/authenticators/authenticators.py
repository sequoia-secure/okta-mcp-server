# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Okta Authenticators API tools (read-only).

Exposes the [Authenticator API](
https://developer.okta.com/docs/api/openapi/okta-management/management/tag/Authenticator/)
so an investigator can see how each authenticator (password, Okta Verify,
Duo, phone, email, security key, temporary access code, ...) is configured at
the org level: its status, ``settings`` and, for authenticators with methods
such as Okta Verify, the per-method settings (push, number challenge, TOTP).

Only read tools are provided. Authenticator changes are made by a person in
the Admin Console.
"""

from loguru import logger
from mcp.server.fastmcp import Context

from okta_mcp_server.server import mcp
from okta_mcp_server.utils.client import get_okta_client
from okta_mcp_server.utils.raw_api import okta_get, strip_links
from okta_mcp_server.utils.scope_guard import require_scopes
from okta_mcp_server.utils.serialization import json_response
from okta_mcp_server.utils.validation import validate_ids


@mcp.tool()
@require_scopes("okta.authenticators.read")
@json_response
async def list_authenticators(ctx: Context) -> dict:
    """List all authenticators configured in the Okta org and their settings.

    Use this to see which authenticators are ACTIVE, how each is configured
    (``settings``), and its ``key`` (``okta_password``, ``okta_verify``,
    ``duo``, ``phone_number``, ``okta_email``, ``webauthn``,
    ``temporary_access_code``, ``custom_otp``, ...). For per-method settings
    of one authenticator, call ``get_authenticator``.

    Returns:
        Dict with ``items`` (authenticator objects, ``_links`` removed) and ``total``.
    """
    logger.info("Listing authenticators")
    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        _, authenticators, err = await okta_get(client, "/api/v1/authenticators")
        if err:
            logger.error(f"Okta API error while listing authenticators: {err}")
            return {"error": f"Error: {err}"}
        authenticators = authenticators or []
        logger.info(f"Retrieved {len(authenticators)} authenticators")
        return {"items": strip_links(authenticators), "total": len(authenticators)}
    except Exception as e:
        logger.error(f"Exception while listing authenticators: {type(e).__name__}: {e}")
        return {"error": f"Exception: {e}"}


@mcp.tool()
@require_scopes("okta.authenticators.read")
@validate_ids("authenticator_id", error_return_type="dict")
@json_response
async def get_authenticator(authenticator_id: str, include_methods: bool = True, ctx: Context = None) -> dict:
    """Get one authenticator by id, with its settings and (optionally) its method settings.

    Parameters:
        authenticator_id (str, required): The authenticator id (``aut...``),
            as returned by ``list_authenticators``.
        include_methods (bool, optional): Also fetch
            ``/authenticators/{id}/methods`` and return it under ``methods``.
            Methods carry the detail that matters for Okta Verify (push,
            number-challenge, TOTP) and phone (SMS, voice). Default: True.

    Returns:
        The authenticator object (``_links`` removed), plus ``methods`` when
        requested. If only the methods call fails, ``methods_error`` explains
        why and the authenticator is still returned.
    """
    logger.info(f"Getting authenticator {authenticator_id} (include_methods={include_methods})")
    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        _, authenticator, err = await okta_get(client, f"/api/v1/authenticators/{authenticator_id}")
        if err:
            logger.error(f"Okta API error while getting authenticator {authenticator_id}: {err}")
            return {"error": f"Error: {err}"}
        if not authenticator:
            return {"error": f"Authenticator {authenticator_id} returned an empty body"}

        result = strip_links(authenticator)
        if include_methods:
            _, methods, m_err = await okta_get(client, f"/api/v1/authenticators/{authenticator_id}/methods")
            if m_err:
                logger.warning(f"Could not list methods for authenticator {authenticator_id}: {m_err}")
                result["methods_error"] = str(m_err)
            else:
                result["methods"] = strip_links(methods or [])
        return result
    except Exception as e:
        logger.error(f"Exception while getting authenticator {authenticator_id}: {type(e).__name__}: {e}")
        return {"error": f"Exception: {e}"}
