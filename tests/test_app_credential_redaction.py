# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Application tools never return credential values.

When the service token can read app client credentials, Okta includes
``credentials.oauthClient.client_secret`` on app objects.  These tests feed
populated secrets through every tool that returns an app and assert the value
is gone while identifying fields remain.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import okta.models as okta_models
import pytest

from okta_mcp_server.tools.applications.applications import (
    create_application,
    get_application,
    list_applications,
    update_application,
)
from okta_mcp_server.tools.groups.groups import list_group_apps
from okta_mcp_server.utils.app_projection import APPLICATION_SUMMARY_FIELDS
from okta_mcp_server.utils.serialization import REDACTED, to_jsonable

CLIENT_SECRET = "oidc-client-secret-0123456789abcdef"
SCHEME_PASSWORD = "scheme-app-password-0123456789"
APP_ID = "0oa1abcdefGHIJKLM697"
GROUP_ID = "00g1abcdefGHIJKLM697"
_BOOKMARK_CONFIG = {
    "name": "bookmark",
    "label": "x",
    "signOnMode": "BOOKMARK",
    "settings": {"app": {"url": "https://example.test"}},
}


def _oidc_app():
    return okta_models.OpenIdConnectApplication.from_dict({
        "id": APP_ID,
        "name": "oidc_client",
        "label": "Confidential client",
        "status": "ACTIVE",
        "signOnMode": "OPENID_CONNECT",
        "credentials": {
            "oauthClient": {
                "client_id": "0oaclientid",
                "client_secret": CLIENT_SECRET,
                "token_endpoint_auth_method": "client_secret_basic",
            }
        },
        "settings": {
            "oauthClient": {
                "redirect_uris": ["https://example.test/cb"],
                "grant_types": ["client_credentials"],
                "response_types": ["token"],
                "application_type": "service",
            }
        },
    })


def _scheme_app():
    return okta_models.BasicAuthApplication.from_dict({
        "id": "0oa2abcdefGHIJKLM697",
        "name": "template_basic_auth",
        "label": "Shared login",
        "status": "ACTIVE",
        "signOnMode": "BASIC_AUTH",
        "credentials": {
            "scheme": "SHARED_USERNAME_AND_PASSWORD",
            "userName": "svc-account",
            "password": {"value": SCHEME_PASSWORD},
        },
        "settings": {"app": {"url": "https://example.test", "authURL": "https://example.test/login"}},
    })


def _ctx():
    from tests.conftest import FakeLifespanContext, FakeOktaAuthManager

    ctx = MagicMock()
    ctx.request_context.lifespan_context = FakeLifespanContext(okta_auth_manager=FakeOktaAuthManager())
    ctx.info = AsyncMock()
    return ctx


def _last_page():
    response = MagicMock()
    response.headers = {}
    response.has_next = MagicMock(return_value=False)
    return response


def _assert_no_secrets(result):
    text = json.dumps(result)
    assert CLIENT_SECRET not in text
    assert SCHEME_PASSWORD not in text


# ---------------------------------------------------------------------------
# Serializer
# ---------------------------------------------------------------------------

class TestRedaction:
    def test_oidc_client_secret_redacted_and_identifiers_kept(self):
        out = to_jsonable(_oidc_app())
        oauth = out["credentials"]["oauthClient"]
        assert oauth["client_secret"] == REDACTED
        assert oauth["client_id"] == "0oaclientid"
        assert oauth["token_endpoint_auth_method"] == "client_secret_basic"

    def test_scheme_password_value_redacted(self):
        out = to_jsonable(_scheme_app())
        assert out["credentials"]["password"] == {"value": REDACTED}
        assert out["credentials"]["userName"] == "svc-account"

    @pytest.mark.parametrize("key", ["client_secret", "clientSecret", "sharedSecret", "privateKey",
                                     "private_key", "password", "api_token", "accessToken", "token"])
    def test_secret_keys_redacted_at_any_depth(self, key):
        out = to_jsonable({"a": [{"b": {key: "value-1234"}}]})
        assert out["a"][0]["b"][key] == REDACTED

    @pytest.mark.parametrize("key", ["token_endpoint_auth_method", "passwordChanged", "secretHash",
                                     "client_id", "kid", "tokenLifetimeMinutes"])
    def test_lookalike_keys_kept(self, key):
        assert to_jsonable({key: "keep-me"}) == {key: "keep-me"}

    def test_password_policy_settings_stay_readable(self):
        policy = {"settings": {"password": {"complexity": {"minLength": 12}, "age": {"maxAgeDays": 90}}}}
        assert to_jsonable(policy) == policy

    def test_jwk_private_members_redacted_public_kept(self):
        jwk = {"kty": "RSA", "kid": "k1", "e": "AQAB", "n": "modulus", "d": "private-exponent", "p": "prime"}
        out = to_jsonable({"jwks": {"keys": [jwk]}})["jwks"]["keys"][0]
        assert out["d"] == REDACTED and out["p"] == REDACTED
        assert out["n"] == "modulus" and out["e"] == "AQAB" and out["kid"] == "k1"

    def test_short_keys_outside_jwk_untouched(self):
        assert to_jsonable({"d": "x", "p": "y"}) == {"d": "x", "p": "y"}

    def test_redaction_is_idempotent(self):
        once = to_jsonable(_oidc_app())
        assert to_jsonable(once) == once


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_get_application_redacts():
    client = MagicMock()
    client.get_application = AsyncMock(return_value=(_oidc_app(), _last_page(), None))
    with patch("okta_mcp_server.tools.applications.applications.get_okta_client", return_value=client):
        result = await get_application(ctx=_ctx(), app_id=APP_ID)
    _assert_no_secrets(result)
    assert result["credentials"]["oauthClient"]["client_id"] == "0oaclientid"
    assert result["credentials"]["oauthClient"]["token_endpoint_auth_method"] == "client_secret_basic"


@pytest.mark.asyncio
async def test_get_application_redacts_scheme_password():
    client = MagicMock()
    client.get_application = AsyncMock(return_value=(_scheme_app(), _last_page(), None))
    with patch("okta_mcp_server.tools.applications.applications.get_okta_client", return_value=client):
        result = await get_application(ctx=_ctx(), app_id=APP_ID)
    assert result["credentials"]["userName"] == "svc-account"
    _assert_no_secrets(result)


@pytest.mark.asyncio
@pytest.mark.parametrize("fetch_all", [False, True])
async def test_list_applications_returns_allowlisted_summaries(fetch_all):
    client = MagicMock()
    client.list_applications = AsyncMock(return_value=([_oidc_app(), _scheme_app()], _last_page(), None))
    with patch("okta_mcp_server.tools.applications.applications.get_okta_client", return_value=client):
        result = await list_applications(ctx=_ctx(), fetch_all=fetch_all)
    _assert_no_secrets(result)
    assert len(result["items"]) == 2
    for item in result["items"]:
        assert set(item) <= set(APPLICATION_SUMMARY_FIELDS)
        assert "credentials" not in item and "settings" not in item
    assert result["items"][0]["id"] == APP_ID
    assert result["items"][0]["signOnMode"] == "OPENID_CONNECT"


@pytest.mark.asyncio
@pytest.mark.parametrize("fetch_all", [False, True])
async def test_list_group_apps_returns_allowlisted_summaries(fetch_all):
    client = MagicMock()
    client.list_assigned_applications_for_group = AsyncMock(
        return_value=([_oidc_app(), _scheme_app()], _last_page(), None)
    )
    with patch("okta_mcp_server.tools.groups.groups.get_okta_client", return_value=client):
        result = await list_group_apps(group_id=GROUP_ID, ctx=_ctx(), fetch_all=fetch_all)
    _assert_no_secrets(result)
    for item in result["items"]:
        assert set(item) <= set(APPLICATION_SUMMARY_FIELDS)


def test_summary_field_set_is_pinned():
    # A new field here must be reviewed for credential content first.
    assert APPLICATION_SUMMARY_FIELDS == (
        "id", "name", "label", "status", "signOnMode", "created", "lastUpdated", "features", "visibility",
    )


@pytest.mark.asyncio
async def test_create_application_echo_redacted():
    client = MagicMock()
    client.create_application = AsyncMock(return_value=(_oidc_app(), _last_page(), None))
    with patch("okta_mcp_server.tools.applications.applications.get_okta_client", return_value=client):
        result = await create_application(
            ctx=_ctx(), app_config=_BOOKMARK_CONFIG
        )
    assert result["id"] == APP_ID
    _assert_no_secrets(result)


@pytest.mark.asyncio
async def test_update_application_echo_redacted():
    client = MagicMock()
    client.replace_application = AsyncMock(return_value=(_oidc_app(), _last_page(), None))
    with patch("okta_mcp_server.tools.applications.applications.get_okta_client", return_value=client):
        result = await update_application(
            ctx=_ctx(), app_id=APP_ID, app_config=_BOOKMARK_CONFIG
        )
    assert result["id"] == APP_ID
    _assert_no_secrets(result)
