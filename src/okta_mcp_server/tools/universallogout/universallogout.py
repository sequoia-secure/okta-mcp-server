# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2025-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Session and token revocation tools ("sign this person out of Okta").

Two Okta operations are involved, and neither subsumes the other:

* ``DELETE /api/v1/users/{id}/sessions`` (``revoke_user_sessions``) — clears
  the user's Okta IdP sessions and, with ``oauth_tokens=True``, the OIDC/OAuth
  access and refresh tokens issued to them. Per Okta's own docs this does
  *not* clear sessions created for web or native apps.
* ``DELETE /api/v1/users/{id}/grants`` (``revoke_user_grants``) — revokes
  OAuth consent grants. The session revocation above does not touch these.

``logout_user`` runs both; ``logout_group`` fans that out across the members of
an Okta group. Both need only ``okta.users.manage`` (plus ``okta.groups.read``
for the group fan-out).

Universal Logout (deferred)
---------------------------
A third operation exists — ``POST /oauth2/v1/global-token-revocation``, which
propagates sign-out to third-party OIN/SAML/OIDC apps implementing the
Universal Logout spec, the one gap the two operations above leave open. It is
gated on ``okta.universalLogout.manage``, which ships with Okta Identity Threat
Protection: an org without ITP does not advertise that scope in
``/.well-known/oauth-authorization-server``, and its org authorization server
rejects a client-credentials token request for it with ``invalid_scope``.

Wiring Universal Logout into ``logout_user`` / ``logout_group`` is deliberately
deferred until that licensing question is settled. ``global_logout_user`` below
is the pre-existing single-call tool for it; it is scope-gated correctly, so on
an org without the scope it is pruned at startup rather than advertised and
failing at call time.
"""

import asyncio
from typing import Optional

from loguru import logger
from mcp.server.fastmcp import Context

from okta_mcp_server.server import mcp
from okta_mcp_server.utils.client import get_okta_client
from okta_mcp_server.utils.elicitation import (
    GlobalLogoutConfirmation,
    GroupLogoutConfirmation,
    elicit_or_fallback,
)
from okta_mcp_server.utils.messages import GLOBAL_LOGOUT_USER, LOGOUT_GROUP, LOGOUT_USER
from okta_mcp_server.utils.pagination import build_query_params, extract_after_cursor, paginate_all_results
from okta_mcp_server.utils.scope_guard import require_scopes
from okta_mcp_server.utils.serialization import json_response
from okta_mcp_server.utils.validation import validate_ids

# ---------------------------------------------------------------------------
# Module constants
# ---------------------------------------------------------------------------

#: Scope gating the Global Token Revocation endpoint. Deliberately NOT
#: ``okta.users.manage`` — see https://developer.okta.com/docs/api/oauth2.
#: Ships with Okta Identity Threat Protection; see the module docstring.
UNIVERSAL_LOGOUT_SCOPE = "okta.universalLogout.manage"

#: Maximum number of member logouts run concurrently by ``logout_group``.
#: Okta enforces per-org API rate limits; a wide fan-out trips them and the
#: 429s surface as per-member failures. Kept deliberately low — the group
#: logout is an incident-response action, not a throughput-sensitive one.
LOGOUT_CONCURRENCY = 5

#: Refuse to fan out beyond this many members. A group logout is irreversible
#: for everyone it touches, so an over-broad ``group_id`` must fail loudly
#: rather than sign out half the org.
MAX_GROUP_MEMBERS = 500

#: Page size used when enumerating group members (Okta's documented maximum).
_GROUP_PAGE_SIZE = 100


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _escape_scim(value: str) -> str:
    """Escape a value for interpolation into a SCIM double-quoted string literal.

    Escape backslashes first and double-quotes second. Without this, a login
    like ``x" or true or "`` injects filter clauses and resolves to a
    different (possibly admin) user — which, combined with an auto-confirming
    elicitation fallback, would revoke the wrong user's sessions. SCIM string
    literals are double-quote delimited per RFC 7644 §3.4.2.2; escape order
    matters, so the backslashes just inserted are not themselves re-escaped.
    """
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _sdk_error(result):
    """Extract the error from an Okta SDK response tuple of either arity.

    The generated SDK is inconsistent: the revoke/delete operations return a
    3-tuple ``(None, resp, None)`` on 204, but 2-tuples ``(None, error)`` and
    ``(response, error)`` on the two failure paths. Unpacking into three names
    therefore raises ``ValueError`` on exactly the paths the caller wrote the
    unpack to handle. The error is always last, so index from the end — the
    same idiom the groups tools use.
    """
    return result[-1]


def _step(status: str, detail: str) -> dict:
    """Build one entry in a logout result's ``steps`` map."""
    return {"status": status, "detail": detail}


async def _resolve_login(client, login: str) -> tuple[Optional[str], Optional[str], Optional[dict]]:
    """Resolve an Okta login (email or username) to ``(user_id, display, error)``.

    On success ``error`` is ``None``; on failure the first two are ``None`` and
    ``error`` is a caller-returnable ``{"error": ...}`` dict.
    """
    safe_login = _escape_scim(login)

    users, _, err = await client.list_users(
        {"search": f'profile.login eq "{safe_login}"', "limit": 1}
    )

    if err:
        logger.error(f"Okta API error resolving login {login}: {err}")
        return None, None, {"error": f"Failed to resolve login: {err}"}

    if not users:
        logger.warning(f"No user found with login: {login}")
        return None, None, {"error": f"No user found with login '{login}'."}

    user = users[0]
    display = getattr(user.profile, "email", None) or login
    logger.info(f"Resolved login '{login}' to user ID: {user.id}")
    return user.id, display, None


async def _revoke_sessions(client, user_id: str, forget_devices: bool) -> dict:
    """Revoke Okta IdP sessions plus issued OAuth/OIDC tokens for one user."""
    try:
        result = await client.revoke_user_sessions(
            user_id, oauth_tokens=True, forget_devices=forget_devices
        )
        err = _sdk_error(result)
        if err:
            logger.error(f"revoke_user_sessions failed for {user_id}: {err}")
            return _step("error", str(err))
        return _step("ok", "Okta sessions and issued OAuth/OIDC tokens revoked.")
    except Exception as e:
        logger.error(f"Exception revoking sessions for {user_id}: {type(e).__name__}: {e}")
        return _step("error", f"{type(e).__name__}: {e}")


async def _revoke_grants(client, user_id: str) -> dict:
    """Revoke all OAuth consent grants for one user."""
    try:
        result = await client.revoke_user_grants(user_id)
        err = _sdk_error(result)
        if err:
            logger.error(f"revoke_user_grants failed for {user_id}: {err}")
            return _step("error", str(err))
        return _step("ok", "OAuth consent grants revoked.")
    except Exception as e:
        logger.error(f"Exception revoking grants for {user_id}: {type(e).__name__}: {e}")
        return _step("error", f"{type(e).__name__}: {e}")


async def _logout_one(
    client,
    user_id: str,
    display: str,
    *,
    include_grants: bool,
    forget_devices: bool,
) -> dict:
    """Run every enabled revocation for one user and return a result row.

    Steps run sequentially and independently: a failure in one is recorded and
    the rest still run, so a partial outcome is never silently reported as a
    clean logout. ``ok`` is True only when no step errored.
    """
    steps: dict[str, dict] = {}

    steps["sessions"] = await _revoke_sessions(client, user_id, forget_devices)

    if include_grants:
        steps["grants"] = await _revoke_grants(client, user_id)
    else:
        steps["grants"] = _step("skipped", "Not requested (include_grants=False).")

    return {
        "user": display,
        "user_id": user_id,
        "ok": all(s["status"] != "error" for s in steps.values()),
        "steps": steps,
    }


async def _list_all_group_users(client, group_id: str) -> tuple[list, Optional[dict]]:
    """Enumerate every member of a group, following pagination.

    Returns ``(users, error)`` where ``error`` is a caller-returnable dict.
    """
    query_params = build_query_params(limit=_GROUP_PAGE_SIZE)
    users, response, err = await client.list_group_users(group_id, **query_params)

    if err:
        logger.error(f"Okta API error listing users in group {group_id}: {err}")
        return [], {"error": f"Failed to list group members: {err}"}

    if not users:
        return [], None

    has_more = (hasattr(response, "has_next") and response.has_next()) or bool(
        extract_after_cursor(response)
    )
    if not has_more:
        return list(users), None

    async def _next_page(cursor):
        params = dict(query_params)
        params["after"] = cursor
        return await client.list_group_users(group_id, **params)

    all_users, pagination_info = await paginate_all_results(
        response, users, next_page_fn=_next_page
    )
    logger.info(
        f"Enumerated {len(all_users)} members of group {group_id} across "
        f"{pagination_info['pages_fetched']} pages"
    )
    return list(all_users), None


async def _run_group_logout(
    ctx: Context,
    group_id: str,
    *,
    include_grants: bool,
    forget_devices: bool,
) -> dict:
    """Fan the per-user logout out across a group's members.

    Shared by ``logout_group`` (elicitation path) and ``confirm_logout_group``
    (legacy two-tool path) so both behave identically once confirmed.
    """
    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
    except Exception as e:
        logger.error(f"Failed to build Okta client: {type(e).__name__}: {e}")
        return {"error": f"Exception: {e}"}

    members, err = await _list_all_group_users(client, group_id)
    if err:
        return err

    if not members:
        return {
            "group_id": group_id,
            "total": 0,
            "succeeded": 0,
            "failed": 0,
            "results": [],
            "message": "Group has no members; nothing to do.",
        }

    if len(members) > MAX_GROUP_MEMBERS:
        logger.error(
            f"Refusing group logout for {group_id}: {len(members)} members exceeds "
            f"the {MAX_GROUP_MEMBERS} cap"
        )
        return {
            "error": (
                f"Group {group_id} has {len(members)} members, above the "
                f"{MAX_GROUP_MEMBERS}-member safety cap for a single logout. "
                "Narrow the group, or sign members out in smaller batches."
            )
        }

    logger.warning(f"Signing out {len(members)} members of group {group_id}")

    semaphore = asyncio.Semaphore(LOGOUT_CONCURRENCY)

    async def _one(user) -> dict:
        display = getattr(user.profile, "email", None) or user.id
        async with semaphore:
            return await _logout_one(
                client,
                user.id,
                display,
                include_grants=include_grants,
                forget_devices=forget_devices,
            )

    # return_exceptions=True so one member blowing up cannot abandon the rest
    # mid-fan-out and leave the operator without a record of who was signed out.
    raw = await asyncio.gather(*(_one(u) for u in members), return_exceptions=True)

    results: list[dict] = []
    for user, outcome in zip(members, raw):
        if isinstance(outcome, BaseException):
            display = getattr(user.profile, "email", None) or user.id
            logger.error(f"Logout task failed for {display}: {outcome!r}")
            results.append(
                {
                    "user": display,
                    "user_id": user.id,
                    "ok": False,
                    "steps": {
                        "sessions": _step("error", f"{type(outcome).__name__}: {outcome}")
                    },
                }
            )
        else:
            results.append(outcome)

    succeeded = sum(1 for r in results if r["ok"])
    failed = len(results) - succeeded
    logger.info(f"Group {group_id} logout complete: {succeeded} succeeded, {failed} failed")

    summary = {
        "group_id": group_id,
        "total": len(results),
        "succeeded": succeeded,
        "failed": failed,
        "results": results,
    }
    if failed:
        summary["message"] = (
            f"{failed} of {len(results)} members did not fully sign out. Each revocation "
            "is idempotent, so re-running for the failed members is safe."
        )
    return summary


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------

@mcp.tool()
@require_scopes("okta.users.manage", error_return_type="list")
@json_response
async def logout_user(
    login: str,
    include_grants: bool = True,
    forget_devices: bool = False,
    ctx: Context = None,
) -> list:
    """Sign one user out of Okta: sessions, issued tokens, and consent grants.

    Runs both revocations Okta offers for a single user, because neither covers
    the other:

    1. ``revoke_user_sessions`` — Okta IdP sessions plus the OIDC/OAuth access
       and refresh tokens issued to the user. Does not clear sessions created
       for web or native apps.
    2. ``revoke_user_grants`` — the user's OAuth consent grants, so previously
       authorized apps must be re-consented.

    Both steps run even if the first fails, and the per-step outcome is
    reported, so a partial logout is never reported as a clean one. Both
    operations are idempotent — re-running after a partial failure is safe.

    Note: this does NOT propagate sign-out to third-party apps that implement
    the Universal Logout spec. That requires Okta's Global Token Revocation
    endpoint, which is gated on a scope that ships with Identity Threat
    Protection. See ``global_logout_user``.

    Parameters:
        login (str, required): The user's Okta login (email or username).
        include_grants (bool, optional): Revoke OAuth consent grants. Default: True.
        forget_devices (bool, optional): Also clear the user's remembered MFA
            factors on all devices, forcing re-enrollment prompts at next
            sign-in. Default: False.

    Returns:
        List containing one result object with a per-step breakdown.
    """
    logger.info(f"Logout requested for login: {login}")

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        user_id, display, err = await _resolve_login(client, login)
    except Exception as e:
        logger.error(f"Exception resolving login {login}: {type(e).__name__}: {e}")
        return [{"error": f"Exception: {e}"}]

    if err:
        return [err]

    outcome = await elicit_or_fallback(
        ctx,
        message=LOGOUT_USER.format(login_or_id=display),
        schema=GlobalLogoutConfirmation,
        auto_confirm_on_fallback=True,
    )

    if not outcome.confirmed:
        logger.info(f"Logout cancelled for {display}")
        return [{"message": "Logout cancelled by user."}]

    logger.warning(f"Signing out user {display} ({user_id})")

    return [
        await _logout_one(
            client,
            user_id,
            display,
            include_grants=include_grants,
            forget_devices=forget_devices,
        )
    ]


@mcp.tool()
@require_scopes("okta.groups.read", "okta.users.manage", error_return_type="dict")
@validate_ids("group_id", error_return_type="dict")
@json_response
async def logout_group(
    group_id: str,
    include_grants: bool = True,
    forget_devices: bool = False,
    ctx: Context = None,
) -> dict:
    """Sign every member of an Okta group out of Okta. Incident-response tool.

    Enumerates the group's members and runs the full ``logout_user`` sequence
    (sessions + issued tokens, then consent grants) against each. Use it to cut
    off a defined population fast — a compromised cohort, a departing
    consultant group — by putting them in an Okta group and pointing this at
    the group ID.

    This is irreversible for everyone it touches: every member is signed out of
    every Okta session and must re-authenticate. The user is asked to confirm,
    with the resolved member count, before anything is revoked. Groups larger
    than 500 members are refused outright.

    Members are processed a few at a time to stay inside Okta's rate limits, so
    a large group takes a while. One member failing does not stop the others;
    failures are reported per member and every revocation is idempotent, so
    re-running for the failures is safe.

    Parameters:
        group_id (str, required): The ID of the Okta group whose members to sign out.
        include_grants (bool, optional): Revoke OAuth consent grants. Default: True.
        forget_devices (bool, optional): Also clear remembered MFA factors on
            all devices for each member. Default: False.

    Returns:
        Dict with total/succeeded/failed counts and a per-member breakdown.
    """
    logger.warning(f"Group logout requested for group {group_id}")

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    # Resolve the member count before prompting: "sign out 4 people" and "sign
    # out 400 people" are different decisions, and the operator must be shown
    # which one they are about to approve.
    #
    # _run_group_logout re-enumerates after confirmation rather than being
    # handed this list. That costs one extra listing, but keeps it self-
    # contained for confirm_logout_group (which has no prior listing to pass),
    # and makes the post-confirmation listing authoritative for who is actually
    # signed out if membership changed while the operator was deciding. The cap
    # is re-checked there for the same reason.
    try:
        client = await get_okta_client(manager)
        members, err = await _list_all_group_users(client, group_id)
    except Exception as e:
        logger.error(f"Exception listing members of group {group_id}: {type(e).__name__}: {e}")
        return {"error": f"Exception: {e}"}

    if err:
        return err

    if not members:
        return {
            "group_id": group_id,
            "total": 0,
            "succeeded": 0,
            "failed": 0,
            "results": [],
            "message": "Group has no members; nothing to do.",
        }

    if len(members) > MAX_GROUP_MEMBERS:
        logger.error(
            f"Refusing group logout for {group_id}: {len(members)} members exceeds "
            f"the {MAX_GROUP_MEMBERS} cap"
        )
        return {
            "error": (
                f"Group {group_id} has {len(members)} members, above the "
                f"{MAX_GROUP_MEMBERS}-member safety cap for a single logout. "
                "Narrow the group, or sign members out in smaller batches."
            )
        }

    fallback_payload = {
        "confirmation_required": True,
        "message": (
            f"This will sign out all {len(members)} members of group {group_id}. "
            f"To proceed, call 'confirm_logout_group' with group_id='{group_id}' "
            f"and confirmation='LOGOUT'."
        ),
        "group_id": group_id,
        "member_count": len(members),
        "tool_to_use": "confirm_logout_group",
    }

    outcome = await elicit_or_fallback(
        ctx,
        message=LOGOUT_GROUP.format(group_id=group_id, member_count=len(members)),
        schema=GroupLogoutConfirmation,
        fallback_payload=fallback_payload,
    )

    # No auto-confirm fallback here, deliberately. logout_user auto-confirms
    # when the client cannot elicit, which is a defensible default for a single
    # named user. Extending that to a whole group would mean a client that
    # merely fails to advertise the elicitation capability silently signs out
    # everyone in it.
    if not outcome.used_elicitation:
        logger.info(
            f"Elicitation unavailable for group {group_id} — returning fallback confirmation prompt"
        )
        return outcome.fallback_response

    if not outcome.confirmed:
        logger.info(f"Group logout cancelled for {group_id}")
        return {"message": "Group logout cancelled by user."}

    return await _run_group_logout(
        ctx,
        group_id,
        include_grants=include_grants,
        forget_devices=forget_devices,
    )


@mcp.tool()
@require_scopes("okta.groups.read", "okta.users.manage", error_return_type="dict")
@validate_ids("group_id", error_return_type="dict")
@json_response
async def confirm_logout_group(
    group_id: str,
    confirmation: str,
    include_grants: bool = True,
    forget_devices: bool = False,
    ctx: Context = None,
) -> dict:
    """Confirm and execute a group logout after receiving explicit confirmation.

    .. deprecated::
        This tool exists for backward compatibility with clients that do not
        support MCP elicitation. New clients should rely on the built-in
        elicitation prompt in ``logout_group`` instead.

    This function MUST ONLY be called after the human user has explicitly typed
    'LOGOUT' as confirmation. NEVER call this function automatically after
    logout_group.

    Parameters:
        group_id (str, required): The ID of the group whose members to sign out.
        confirmation (str, required): Must be 'LOGOUT' to proceed.
        include_grants (bool, optional): Revoke OAuth consent grants. Default: True.
        forget_devices (bool, optional): Also clear remembered MFA factors. Default: False.

    Returns:
        Dict with total/succeeded/failed counts and a per-member breakdown.
    """
    logger.info(f"Processing logout confirmation for group {group_id} (deprecated flow)")

    if confirmation != "LOGOUT":
        logger.warning(f"Group logout cancelled for {group_id} - incorrect confirmation")
        return {"error": "Logout cancelled. Confirmation 'LOGOUT' was not provided correctly."}

    return await _run_group_logout(
        ctx,
        group_id,
        include_grants=include_grants,
        forget_devices=forget_devices,
    )


# ---------------------------------------------------------------------------
# Universal Logout (deferred — see the module docstring)
# ---------------------------------------------------------------------------

@mcp.tool()
@require_scopes(UNIVERSAL_LOGOUT_SCOPE, error_return_type="list")
@json_response
async def global_logout_user(login: str, ctx: Context = None) -> list:
    """Revoke all active tokens for an Okta user via the Global Token Revocation endpoint.

    This performs a universal logout: all access tokens and refresh tokens for the
    specified user are immediately invalidated across all authorization servers. The
    user must re-authenticate on their next request.

    The login (email or username) is resolved to an Okta user ID before the revocation
    is performed.

    Requires the ``okta.universalLogout.manage`` scope, which ships with Okta
    Identity Threat Protection. On an org without ITP that scope is not
    issuable, so this tool is pruned at startup and ``logout_user`` is the tool
    to use instead.

    Parameters:
        login (str, required): The user's Okta login (email or username).

    Returns:
        List containing the result of the global logout operation.
    """
    logger.info(f"Global logout requested for login: {login}")

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        user_id, display, err = await _resolve_login(client, login)
    except Exception as e:
        logger.error(f"Exception resolving login {login}: {type(e).__name__}: {e}")
        return [{"error": f"Exception: {e}"}]

    if err:
        return [err]

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
            return [{"user": display, "ok": True, "message": "All tokens revoked."}]

        logger.error(f"Unexpected status {status} for global logout of {display}")
        return [{"error": f"Unexpected HTTP status: {status}"}]

    except Exception as e:
        logger.error(f"Exception during global logout for {display}: {type(e).__name__}: {e}")
        return [{"error": f"Exception: {e}"}]
