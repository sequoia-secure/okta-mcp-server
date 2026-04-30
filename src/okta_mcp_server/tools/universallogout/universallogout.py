# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2025-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

from loguru import logger
from mcp.server.fastmcp import Context

from okta_mcp_server.server import mcp
from okta_mcp_server.utils.client import get_okta_client
from okta_mcp_server.utils.elicitation import GlobalLogoutConfirmation, elicit_or_fallback
from okta_mcp_server.utils.messages import GLOBAL_LOGOUT_USER


@mcp.tool()
async def global_logout_user(login: str, ctx: Context = None) -> list:
    """Revoke all active tokens for an Okta user via the Global Token Revocation endpoint.

    This performs a universal logout: all access tokens and refresh tokens for the
    specified user are immediately invalidated across all authorization servers. The
    user must re-authenticate on their next request.

    The login (email or username) is resolved to an Okta user ID before the revocation
    is performed.

    Parameters:
        login (str, required): The user's Okta login (email or username).

    Returns:
        List containing the result of the global logout operation.
    """
    logger.info(f"Global logout requested for login: {login}")

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    # Resolve login to Okta user ID.
    try:
        client = await get_okta_client(manager)
        users, _, err = await client.list_users({"search": f'profile.login eq "{login}"', "limit": 1})

        if err:
            logger.error(f"Okta API error resolving login {login}: {err}")
            return [{"error": f"Failed to resolve login: {err}"}]

        if not users:
            logger.warning(f"No user found with login: {login}")
            return [{"error": f"No user found with login '{login}'."}]

        user = users[0]
        user_id = user.id
        display = getattr(user.profile, "email", login)
        logger.info(f"Resolved login '{login}' to user ID: {user_id}")
    except Exception as e:
        logger.error(f"Exception resolving login {login}: {type(e).__name__}: {e}")
        return [f"Exception: {e}"]

    outcome = await elicit_or_fallback(
        ctx,
        message=GLOBAL_LOGOUT_USER.format(login_or_id=display),
        schema=GlobalLogoutConfirmation,
        auto_confirm_on_fallback=True,
    )

    if not outcome.confirmed:
        logger.info(f"Global logout cancelled for {display}")
        return [{"message": "Global logout cancelled by user."}]

    try:
        url = f"{manager.org_url}/oauth2/v1/global-token-revocation"
        body = {"sub_id": {"format": "opaque", "id": user_id}}

        request, err = await client.get_request_executor().create_request(
            "POST", url, body, {}
        )
        if err:
            logger.error(f"Failed to create revocation request for {display}: {err}")
            return [{"error": f"Failed to create request: {err}"}]

        response, _, err = await client.get_request_executor().execute(request)
        if err:
            logger.error(f"Global token revocation failed for {display}: {err}")
            return [{"error": f"Revocation failed: {err}"}]

        status = response.get_status()
        if status in (200, 204):
            logger.info(f"Global logout successful for user: {display} ({user_id})")
            return [f"Global logout successful: all tokens revoked for {display}."]

        logger.error(f"Unexpected status {status} for global logout of {display}")
        return [{"error": f"Unexpected HTTP status: {status}"}]

    except Exception as e:
        logger.error(f"Exception during global logout for {display}: {type(e).__name__}: {e}")
        return [f"Exception: {e}"]
