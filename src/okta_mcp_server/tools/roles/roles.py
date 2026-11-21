# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Okta admin role assignment tools (read-only).

Answers "who are the admins": every user holding an admin role, the role type
(``SUPER_ADMIN``, ``ORG_ADMIN``, ``APP_ADMIN``, ``CUSTOM``, ...), whether the
role is held directly or through a group (``assignmentType``), and for custom
roles the role and resource-set ids.

Okta has an endpoint that enumerates users with role assignments
(``GET /api/v1/iam/assignees/users``) but none that enumerates groups, so
group roles are looked up for the group ids the caller names. A user who holds
a role through a group still appears in the user list, with
``assignmentType: "GROUP"``.

Only read tools are provided. Role changes are made by a person in the Admin
Console.
"""

import asyncio
from typing import Optional

from loguru import logger
from mcp.server.fastmcp import Context

from okta_mcp_server.server import mcp
from okta_mcp_server.utils.client import get_okta_client
from okta_mcp_server.utils.raw_api import okta_get, okta_get_all
from okta_mcp_server.utils.scope_guard import require_scopes
from okta_mcp_server.utils.serialization import json_response
from okta_mcp_server.utils.validation import InvalidOktaIdError, validate_okta_id

#: Concurrent per-principal role lookups. Kept low: the role endpoints share
#: the org's management rate limit with every other tool.
_CONCURRENCY = 5

#: Role fields surfaced to the caller; everything else (mostly ``_links``) is noise.
_ROLE_FIELDS = ("id", "type", "label", "status", "assignmentType", "created", "lastUpdated")


def _id_from_href(href: Optional[str]) -> Optional[str]:
    return href.rstrip("/").rsplit("/", 1)[-1] if href else None


def _summarize_role(role: dict) -> dict:
    """Reduce a role assignment to the fields that identify what it grants."""
    summary = {k: role[k] for k in _ROLE_FIELDS if k in role}
    links = role.get("_links") or {}
    # Custom roles are a (role, resource set) binding; the ids live either at
    # the top level or only in _links depending on the endpoint version.
    custom_role = role.get("role") or _id_from_href((links.get("role") or {}).get("href"))
    resource_set = role.get("resource-set") or _id_from_href((links.get("resource-set") or {}).get("href"))
    if custom_role:
        summary["custom_role_id"] = custom_role
    if resource_set:
        summary["resource_set_id"] = resource_set
    return summary


def _matches(role: dict, role_type: Optional[str]) -> bool:
    if not role_type:
        return True
    wanted = role_type.strip().upper()
    return str(role.get("type", "")).upper() == wanted or str(role.get("label", "")).upper() == wanted


@mcp.tool()
@require_scopes("okta.roles.read")
@json_response
async def list_admin_role_assignments(
    ctx: Context,
    role_type: Optional[str] = None,
    group_ids: Optional[list[str]] = None,
    include_user_profile: bool = True,
) -> dict:
    """List users (and named groups) that hold Okta admin roles, with each role's type.

    Use this to answer "who are the super admins", "who can administer apps",
    or "does this account hold any admin role".

    Parameters:
        role_type (str, optional): Keep only roles of this type, for example
            ``SUPER_ADMIN``, ``ORG_ADMIN``, ``APP_ADMIN``, ``USER_ADMIN``,
            ``HELP_DESK_ADMIN``, ``READ_ONLY_ADMIN``, ``GROUP_MEMBERSHIP_ADMIN``,
            ``API_ACCESS_MANAGEMENT_ADMIN``, ``REPORT_ADMIN``, ``MOBILE_ADMIN``,
            or ``CUSTOM``. A custom role's label also matches. Case-insensitive.
            Users with no matching role are left out.
        group_ids (list[str], optional): Group ids whose own role assignments
            should be listed. Okta cannot enumerate groups with roles, so pass
            candidate groups (for example from ``list_groups``).
        include_user_profile (bool, optional): Look up each admin's login,
            name and status (needs ``okta.users.read``; left null when the
            lookup fails). Default: True.

    Returns:
        Dict with ``users`` (each: ``id``, ``login``, ``displayName``,
        ``status``, ``roles``), ``groups`` (each: ``id``, ``roles``),
        ``total_users``, ``truncated`` (the assignee list hit the page cap),
        and ``errors`` (per-principal lookups that failed, so a gap is visible
        rather than silent).
    """
    logger.info(f"Listing admin role assignments (role_type={role_type!r}, groups={group_ids!r})")
    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        for gid in group_ids or []:
            validate_okta_id(gid, "group_id")
    except InvalidOktaIdError as e:
        return {"error": str(e)}

    try:
        client = await get_okta_client(manager)
        assignees, truncated, err = await okta_get_all(
            client, "/api/v1/iam/assignees/users", {"limit": 100}, items_key="value"
        )
        if err:
            logger.error(f"Okta API error while listing role assignees: {err}")
            return {"error": f"Error: {err}"}

        semaphore = asyncio.Semaphore(_CONCURRENCY)
        errors: list[dict] = []

        async def _roles_for(kind: str, principal_id: str) -> Optional[list]:
            async with semaphore:
                _, roles, r_err = await okta_get(client, f"/api/v1/{kind}/{principal_id}/roles")
            if r_err:
                errors.append({"principal": f"{kind}/{principal_id}", "error": str(r_err)})
                return None
            return [_summarize_role(r) for r in (roles or []) if _matches(r, role_type)]

        async def _user_entry(user_id: str) -> Optional[dict]:
            roles = await _roles_for("users", user_id)
            if not roles:
                return None
            entry = {"id": user_id, "login": None, "displayName": None, "status": None, "roles": roles}
            if include_user_profile:
                async with semaphore:
                    _, user, u_err = await okta_get(client, f"/api/v1/users/{user_id}")
                if u_err:
                    errors.append({"principal": f"users/{user_id}", "error": f"profile lookup: {u_err}"})
                elif user:
                    profile = user.get("profile") or {}
                    entry["login"] = profile.get("login")
                    names = " ".join(p for p in (profile.get("firstName"), profile.get("lastName")) if p)
                    entry["displayName"] = profile.get("displayName") or names or None
                    entry["status"] = user.get("status")
            return entry

        async def _group_entry(group_id: str) -> Optional[dict]:
            roles = await _roles_for("groups", group_id)
            return {"id": group_id, "roles": roles} if roles else None

        user_ids = [a.get("id") for a in assignees if a.get("id")]
        users = [u for u in await asyncio.gather(*(_user_entry(u) for u in user_ids)) if u]
        groups = [g for g in await asyncio.gather(*(_group_entry(g) for g in group_ids or [])) if g]

        logger.info(f"{len(users)} users and {len(groups)} groups hold matching admin roles")
        return {
            "role_type_filter": role_type,
            "users": users,
            "groups": groups,
            "total_users": len(users),
            "truncated": truncated,
            "errors": errors,
        }
    except Exception as e:
        logger.error(f"Exception while listing admin role assignments: {type(e).__name__}: {e}")
        return {"error": f"Exception: {e}"}
