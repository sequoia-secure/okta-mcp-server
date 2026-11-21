# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Tests for the read-only security-posture tools.

Covers list_admin_role_assignments, list_user_factors, list_network_zones,
get_network_zone, list_authenticators, get_authenticator, and the raw GET
helpers in utils/raw_api.py they share.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch
from urllib.parse import parse_qs, urlparse

import pytest

from okta_mcp_server.tools.authenticators.authenticators import get_authenticator, list_authenticators
from okta_mcp_server.tools.network_zones.network_zones import get_network_zone, list_network_zones
from okta_mcp_server.tools.roles.roles import list_admin_role_assignments
from okta_mcp_server.tools.user_resources.user_resources import list_user_factors
from okta_mcp_server.utils.raw_api import next_cursor, okta_get_all, strip_links
from okta_mcp_server.utils.scope_registry import TOOL_SCOPE_REGISTRY

NEW_TOOLS = {
    "list_admin_role_assignments": "okta.roles.read",
    "list_user_factors": "okta.users.read",
    "list_network_zones": "okta.networkZones.read",
    "get_network_zone": "okta.networkZones.read",
    "list_authenticators": "okta.authenticators.read",
    "get_authenticator": "okta.authenticators.read",
}


def _make_ctx(scopes: str | None = None):
    from tests.conftest import FakeLifespanContext, FakeOktaAuthManager

    manager = FakeOktaAuthManager()
    if scopes is not None:
        manager.scopes = scopes
    request_context = MagicMock()
    request_context.lifespan_context = FakeLifespanContext(okta_auth_manager=manager)
    ctx = MagicMock()
    ctx.request_context = request_context
    return ctx


def _response(link: str | None = None):
    response = MagicMock()
    response.headers = {"Link": link} if link else {}
    response.has_next = MagicMock(return_value=False)
    return response


class _Routes:
    """Fake Okta client whose request executor answers GETs from a path → result map.

    A result is a JSON-serializable body, a ``(body, link_header)`` tuple, or an
    ``Exception`` instance returned as the SDK error value.
    """

    def __init__(self, routes: dict):
        self.routes = routes
        self.urls: list[str] = []
        self.methods: list[str] = []
        executor = MagicMock()
        executor.create_request = AsyncMock(side_effect=self._create)
        executor.execute = AsyncMock(side_effect=self._execute)
        self.client = MagicMock()
        self.client.get_request_executor = MagicMock(return_value=executor)

    async def _create(self, method, url, body, headers, oauth):
        self.methods.append(method)
        self.urls.append(url)
        return {"url": url}, None

    async def _execute(self, request):
        url = request["url"]
        parsed = urlparse(url)
        key = parsed.path
        after = parse_qs(parsed.query).get("after", [None])[0]
        if after:
            key = f"{key}?after={after}"
        result = self.routes[key]
        if isinstance(result, Exception):
            return None, None, result
        link = None
        if isinstance(result, tuple):
            result, link = result
        return _response(link), json.dumps(result), None


# ---------------------------------------------------------------------------
# Registry / read-only guarantees
# ---------------------------------------------------------------------------

class TestRegistry:
    def test_new_tools_are_registered_with_read_scopes(self):
        for tool, scope in NEW_TOOLS.items():
            assert TOOL_SCOPE_REGISTRY[tool] == scope

    def test_no_manage_tools_for_new_resources(self):
        for scope in ("okta.roles.manage", "okta.networkZones.manage", "okta.authenticators.manage"):
            assert scope not in TOOL_SCOPE_REGISTRY.values()

    @pytest.mark.asyncio
    async def test_helpers_only_issue_get(self):
        routes = _Routes({"/api/v1/zones": [], "/api/v1/authenticators": []})
        with patch("okta_mcp_server.tools.network_zones.network_zones.get_okta_client", return_value=routes.client):
            await list_network_zones(ctx=_make_ctx())
        with patch("okta_mcp_server.tools.authenticators.authenticators.get_okta_client", return_value=routes.client):
            await list_authenticators(ctx=_make_ctx())
        assert set(routes.methods) == {"GET"}


# ---------------------------------------------------------------------------
# raw_api helpers
# ---------------------------------------------------------------------------

class TestRawApi:
    def test_next_cursor_from_link_header(self):
        response = _response('<https://test.okta.com/api/v1/zones?after=nzoB&limit=20>; rel="next"')
        assert next_cursor(response, []) == "nzoB"

    def test_next_cursor_from_body_links(self):
        body = {"value": [], "_links": {"next": {"href": "https://evil.example/api/v1/iam/assignees/users?after=00uB"}}}
        # Only the cursor is taken, never the host.
        assert next_cursor(_response(), body) == "00uB"

    def test_next_cursor_none_on_last_page(self):
        assert next_cursor(_response(), {"value": [], "_links": {}}) is None

    @pytest.mark.asyncio
    async def test_get_all_follows_cursors(self):
        routes = _Routes({
            "/api/v1/zones": ([{"id": "nzoA"}], '<https://test.okta.com/api/v1/zones?after=nzoA>; rel="next"'),
            "/api/v1/zones?after=nzoA": [{"id": "nzoB"}],
        })
        items, truncated, err = await okta_get_all(routes.client, "/api/v1/zones")
        assert [i["id"] for i in items] == ["nzoA", "nzoB"]
        assert truncated is False and err is None

    @pytest.mark.asyncio
    async def test_get_all_reports_truncation(self):
        routes = _Routes({
            "/api/v1/zones": ([{"id": "nzoA"}], '<https://test.okta.com/api/v1/zones?after=nzoA>; rel="next"'),
        })
        items, truncated, _ = await okta_get_all(routes.client, "/api/v1/zones", max_pages=1)
        assert len(items) == 1 and truncated is True

    @pytest.mark.asyncio
    async def test_get_all_discards_partial_results_on_error(self):
        routes = _Routes({
            "/api/v1/zones": ([{"id": "nzoA"}], '<https://test.okta.com/api/v1/zones?after=nzoA>; rel="next"'),
            "/api/v1/zones?after=nzoA": RuntimeError("rate limited"),
        })
        items, _, err = await okta_get_all(routes.client, "/api/v1/zones")
        assert items == [] and err is not None

    def test_strip_links(self):
        assert strip_links([{"id": "a", "_links": {"self": {}}}]) == [{"id": "a"}]


# ---------------------------------------------------------------------------
# Network zones
# ---------------------------------------------------------------------------

ZONE = {
    "id": "nzo1lzsvTEST",
    "name": "Office egress",
    "type": "IP",
    "status": "ACTIVE",
    "usage": "POLICY",
    "gateways": [{"type": "CIDR", "value": "203.0.113.0/24"}],
    "proxies": None,
    "_links": {"self": {"href": "https://test.okta.com/api/v1/zones/nzo1lzsvTEST"}},
}


class TestNetworkZones:
    @pytest.mark.asyncio
    async def test_list_returns_zones_without_links(self):
        routes = _Routes({"/api/v1/zones": [ZONE]})
        with patch("okta_mcp_server.tools.network_zones.network_zones.get_okta_client", return_value=routes.client):
            result = await list_network_zones(ctx=_make_ctx())
        assert result["total"] == 1 and result["truncated"] is False
        zone = result["items"][0]
        assert zone["gateways"] == [{"type": "CIDR", "value": "203.0.113.0/24"}]
        assert "_links" not in zone
        json.dumps(result)

    @pytest.mark.asyncio
    async def test_list_passes_filter(self):
        routes = _Routes({"/api/v1/zones": []})
        with patch("okta_mcp_server.tools.network_zones.network_zones.get_okta_client", return_value=routes.client):
            await list_network_zones(ctx=_make_ctx(), filter='usage eq "BLOCKLIST"')
        assert parse_qs(urlparse(routes.urls[0]).query)["filter"] == ['usage eq "BLOCKLIST"']

    @pytest.mark.asyncio
    async def test_list_surfaces_api_error(self):
        routes = _Routes({"/api/v1/zones": RuntimeError("403 Forbidden")})
        with patch("okta_mcp_server.tools.network_zones.network_zones.get_okta_client", return_value=routes.client):
            result = await list_network_zones(ctx=_make_ctx())
        assert "error" in result

    @pytest.mark.asyncio
    async def test_get_zone(self):
        routes = _Routes({"/api/v1/zones/nzo1lzsvTEST": ZONE})
        with patch("okta_mcp_server.tools.network_zones.network_zones.get_okta_client", return_value=routes.client):
            result = await get_network_zone(zone_id="nzo1lzsvTEST", ctx=_make_ctx())
        assert result["name"] == "Office egress" and "_links" not in result

    @pytest.mark.asyncio
    async def test_get_zone_rejects_path_traversal(self):
        result = await get_network_zone(zone_id="../users", ctx=_make_ctx())
        assert "error" in result

    @pytest.mark.asyncio
    async def test_scope_missing_blocks_call(self):
        result = await list_network_zones(ctx=_make_ctx(scopes="okta.users.read"))
        assert "okta.networkZones.read" in result["error"]


# ---------------------------------------------------------------------------
# Authenticators
# ---------------------------------------------------------------------------

OKTA_VERIFY = {
    "id": "autOVTEST",
    "key": "okta_verify",
    "name": "Okta Verify",
    "status": "ACTIVE",
    "settings": {"compliance": {"fips": "OPTIONAL"}, "userVerification": "PREFERRED"},
    "_links": {"methods": {"href": "https://test.okta.com/api/v1/authenticators/autOVTEST/methods"}},
}
OV_METHODS = [
    {"type": "push", "status": "ACTIVE", "settings": {"algorithms": ["ES256"]}, "_links": {}},
    {"type": "totp", "status": "INACTIVE", "_links": {}},
]


class TestAuthenticators:
    @pytest.mark.asyncio
    async def test_list(self):
        routes = _Routes({"/api/v1/authenticators": [OKTA_VERIFY]})
        with patch("okta_mcp_server.tools.authenticators.authenticators.get_okta_client", return_value=routes.client):
            result = await list_authenticators(ctx=_make_ctx())
        assert result["total"] == 1
        assert result["items"][0]["settings"]["userVerification"] == "PREFERRED"
        assert "_links" not in result["items"][0]

    @pytest.mark.asyncio
    async def test_get_includes_methods(self):
        routes = _Routes({
            "/api/v1/authenticators/autOVTEST": OKTA_VERIFY,
            "/api/v1/authenticators/autOVTEST/methods": OV_METHODS,
        })
        with patch("okta_mcp_server.tools.authenticators.authenticators.get_okta_client", return_value=routes.client):
            result = await get_authenticator(authenticator_id="autOVTEST", ctx=_make_ctx())
        assert [m["type"] for m in result["methods"]] == ["push", "totp"]
        assert all("_links" not in m for m in result["methods"])

    @pytest.mark.asyncio
    async def test_get_without_methods(self):
        routes = _Routes({"/api/v1/authenticators/autOVTEST": OKTA_VERIFY})
        with patch("okta_mcp_server.tools.authenticators.authenticators.get_okta_client", return_value=routes.client):
            result = await get_authenticator(authenticator_id="autOVTEST", include_methods=False, ctx=_make_ctx())
        assert "methods" not in result and len(routes.urls) == 1

    @pytest.mark.asyncio
    async def test_methods_error_does_not_hide_authenticator(self):
        routes = _Routes({
            "/api/v1/authenticators/autOVTEST": OKTA_VERIFY,
            "/api/v1/authenticators/autOVTEST/methods": RuntimeError("404"),
        })
        with patch("okta_mcp_server.tools.authenticators.authenticators.get_okta_client", return_value=routes.client):
            result = await get_authenticator(authenticator_id="autOVTEST", ctx=_make_ctx())
        assert result["key"] == "okta_verify" and "methods_error" in result


# ---------------------------------------------------------------------------
# User factors
# ---------------------------------------------------------------------------

class TestListUserFactors:
    @pytest.mark.asyncio
    async def test_returns_factors_without_embedded_activation(self):
        factors = [
            {
                "id": "opfTEST1",
                "factorType": "push",
                "provider": "OKTA",
                "vendorName": "OKTA",
                "status": "ACTIVE",
                "profile": {"name": "iPhone 15"},
                "_links": {"self": {}},
            },
            {
                "id": "ostTEST2",
                "factorType": "token:software:totp",
                "provider": "GOOGLE",
                "status": "PENDING_ACTIVATION",
                "_embedded": {"activation": {"sharedSecret": "JBSWY3DPEHPK3PXP"}},
            },
        ]
        routes = _Routes({"/api/v1/users/00uTEST1/factors": factors})
        with patch("okta_mcp_server.tools.user_resources.user_resources.get_okta_client", return_value=routes.client):
            result = await list_user_factors(user_id="00uTEST1", ctx=_make_ctx())
        assert [f["factorType"] for f in result] == ["push", "token:software:totp"]
        assert "JBSWY3DPEHPK3PXP" not in json.dumps(result)
        assert all("_links" not in f and "_embedded" not in f for f in result)

    @pytest.mark.asyncio
    async def test_no_factors_is_empty_list(self):
        routes = _Routes({"/api/v1/users/00uTEST1/factors": []})
        with patch("okta_mcp_server.tools.user_resources.user_resources.get_okta_client", return_value=routes.client):
            assert await list_user_factors(user_id="00uTEST1", ctx=_make_ctx()) == []

    @pytest.mark.asyncio
    async def test_api_error(self):
        routes = _Routes({"/api/v1/users/00uTEST1/factors": RuntimeError("Not found: 00uTEST1")})
        with patch("okta_mcp_server.tools.user_resources.user_resources.get_okta_client", return_value=routes.client):
            result = await list_user_factors(user_id="00uTEST1", ctx=_make_ctx())
        assert "error" in result[0]

    @pytest.mark.asyncio
    async def test_rejects_invalid_user_id(self):
        result = await list_user_factors(user_id="00u/../groups", ctx=_make_ctx())
        assert "error" in result[0]


# ---------------------------------------------------------------------------
# Admin role assignments
# ---------------------------------------------------------------------------

def _user(uid, login, first, last, status="ACTIVE"):
    return {"id": uid, "status": status, "profile": {"login": login, "firstName": first, "lastName": last}}


SUPER = {
    "id": "irbSUPER",
    "type": "SUPER_ADMIN",
    "label": "Super Administrator",
    "status": "ACTIVE",
    "assignmentType": "USER",
    "_links": {},
}
ORG_VIA_GROUP = {
    "id": "irbORG",
    "type": "ORG_ADMIN",
    "label": "Organizational Administrator",
    "status": "ACTIVE",
    "assignmentType": "GROUP",
}
CUSTOM = {
    "id": "irbCUSTOM",
    "type": "CUSTOM",
    "label": "Help desk tier 2",
    "status": "ACTIVE",
    "assignmentType": "USER",
    "_links": {
        "role": {"href": "https://test.okta.com/api/v1/iam/roles/cr0CUSTOM"},
        "resource-set": {"href": "https://test.okta.com/api/v1/iam/resource-sets/iamRESSET"},
    },
}


def _role_routes(extra=None):
    routes = {
        "/api/v1/iam/assignees/users": {
            "value": [{"id": "00uALICE"}],
            "_links": {"next": {"href": "https://test.okta.com/api/v1/iam/assignees/users?after=00uALICE&limit=100"}},
        },
        "/api/v1/iam/assignees/users?after=00uALICE": {"value": [{"id": "00uBOB"}], "_links": {}},
        "/api/v1/users/00uALICE/roles": [SUPER],
        "/api/v1/users/00uBOB/roles": [ORG_VIA_GROUP, CUSTOM],
        "/api/v1/users/00uALICE": _user("00uALICE", "alice@example.com", "Alice", "Admin"),
        "/api/v1/users/00uBOB": _user("00uBOB", "bob@example.com", "Bob", "Builder"),
    }
    routes.update(extra or {})
    return routes


class TestListAdminRoleAssignments:
    @pytest.mark.asyncio
    async def test_lists_all_admins_across_pages(self):
        routes = _Routes(_role_routes())
        with patch("okta_mcp_server.tools.roles.roles.get_okta_client", return_value=routes.client):
            result = await list_admin_role_assignments(ctx=_make_ctx())
        assert result["total_users"] == 2 and result["errors"] == [] and result["truncated"] is False
        by_login = {u["login"]: u for u in result["users"]}
        assert by_login["alice@example.com"]["roles"][0]["type"] == "SUPER_ADMIN"
        assert by_login["alice@example.com"]["displayName"] == "Alice Admin"
        bob_roles = {r["type"]: r for r in by_login["bob@example.com"]["roles"]}
        assert bob_roles["ORG_ADMIN"]["assignmentType"] == "GROUP"
        assert bob_roles["CUSTOM"]["custom_role_id"] == "cr0CUSTOM"
        assert bob_roles["CUSTOM"]["resource_set_id"] == "iamRESSET"
        assert "_links" not in json.dumps(result)

    @pytest.mark.asyncio
    async def test_role_type_filter(self):
        routes = _Routes(_role_routes())
        with patch("okta_mcp_server.tools.roles.roles.get_okta_client", return_value=routes.client):
            result = await list_admin_role_assignments(ctx=_make_ctx(), role_type="super_admin")
        assert [u["id"] for u in result["users"]] == ["00uALICE"]
        # Users without a matching role are not looked up further.
        assert "/api/v1/users/00uBOB" not in [urlparse(u).path for u in routes.urls]

    @pytest.mark.asyncio
    async def test_custom_role_label_matches_filter(self):
        routes = _Routes(_role_routes())
        with patch("okta_mcp_server.tools.roles.roles.get_okta_client", return_value=routes.client):
            result = await list_admin_role_assignments(ctx=_make_ctx(), role_type="Help desk tier 2")
        assert [u["id"] for u in result["users"]] == ["00uBOB"]
        assert [r["type"] for r in result["users"][0]["roles"]] == ["CUSTOM"]

    @pytest.mark.asyncio
    async def test_group_roles_for_named_groups(self):
        routes = _Routes(_role_routes({
            "/api/v1/groups/00gADMINS/roles": [dict(ORG_VIA_GROUP, assignmentType="GROUP")],
            "/api/v1/groups/00gPLAIN/roles": [],
        }))
        with patch("okta_mcp_server.tools.roles.roles.get_okta_client", return_value=routes.client):
            result = await list_admin_role_assignments(ctx=_make_ctx(), group_ids=["00gADMINS", "00gPLAIN"])
        assert result["groups"] == [{"id": "00gADMINS", "roles": [ORG_VIA_GROUP]}]

    @pytest.mark.asyncio
    async def test_rejects_invalid_group_id(self):
        result = await list_admin_role_assignments(ctx=_make_ctx(), group_ids=["../users"])
        assert "error" in result

    @pytest.mark.asyncio
    async def test_failed_lookups_are_reported_not_dropped(self):
        routes = _Routes(_role_routes({
            "/api/v1/users/00uBOB/roles": RuntimeError("429 Too Many Requests"),
            "/api/v1/users/00uALICE": RuntimeError("403 Forbidden"),
        }))
        with patch("okta_mcp_server.tools.roles.roles.get_okta_client", return_value=routes.client):
            result = await list_admin_role_assignments(ctx=_make_ctx())
        assert [u["id"] for u in result["users"]] == ["00uALICE"]
        assert result["users"][0]["login"] is None
        principals = sorted(e["principal"] for e in result["errors"])
        assert principals == ["users/00uALICE", "users/00uBOB"]

    @pytest.mark.asyncio
    async def test_skip_profile_lookup(self):
        routes = _Routes(_role_routes())
        with patch("okta_mcp_server.tools.roles.roles.get_okta_client", return_value=routes.client):
            result = await list_admin_role_assignments(ctx=_make_ctx(), include_user_profile=False)
        assert all(u["login"] is None for u in result["users"])
        assert not any(urlparse(u).path in ("/api/v1/users/00uALICE", "/api/v1/users/00uBOB") for u in routes.urls)

    @pytest.mark.asyncio
    async def test_assignee_list_error(self):
        routes = _Routes({"/api/v1/iam/assignees/users": RuntimeError("403 Forbidden")})
        with patch("okta_mcp_server.tools.roles.roles.get_okta_client", return_value=routes.client):
            result = await list_admin_role_assignments(ctx=_make_ctx())
        assert "error" in result

    @pytest.mark.asyncio
    async def test_scope_missing_blocks_call(self):
        result = await list_admin_role_assignments(ctx=_make_ctx(scopes="okta.users.read"))
        assert "okta.roles.read" in result["error"]
