# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Tests for the session/token revocation tools.

Coverage focuses on the three things that are easy to get wrong and expensive
to get wrong in production:

* the Okta SDK's inconsistent 2-tuple/3-tuple return arity on the revoke
  operations (``_sdk_error``),
* the confirmation gate on ``logout_group`` — a client that cannot elicit must
  NOT silently sign out a whole group,
* partial failure reporting — a step that fails must not be reported as a
  clean logout, and must not stop the remaining steps or members.
"""

from __future__ import annotations

from typing import ClassVar
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from okta_mcp_server.tools.universallogout.universallogout import (
    MAX_GROUP_MEMBERS,
    _escape_scim,
    _sdk_error,
    confirm_logout_group,
    global_logout_user,
    logout_group,
    logout_user,
)

MODULE = "okta_mcp_server.tools.universallogout.universallogout"

GROUP_ID = "00gTEST000000001"
USER_ID = "00uTEST000000001"
LOGIN = "ada@example.com"


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

class _FakeResponse:
    """A single-page Okta response: no Link header, no next page."""

    headers: ClassVar[dict] = {}

    def has_next(self) -> bool:
        return False


class _FakeManager:
    """Auth manager stand-in whose ``scopes`` the scope guard can read."""

    def __init__(self, scopes: str | None = None):
        self.org_url = "https://test.okta.com"
        if scopes is not None:
            self.scopes = scopes


def _make_ctx(*, scopes: str | None = None, elicitation: bool = True, confirm: bool = True):
    """Build a fake Context.

    ``scopes=None`` leaves the manager without a ``scopes`` attribute, which is
    how the scope guard signals "cannot determine" — every scope check is then
    skipped and Universal Logout is attempted.
    """
    from mcp.server.elicitation import AcceptedElicitation

    capabilities = MagicMock()
    capabilities.elicitation = {} if elicitation else None
    client_params = MagicMock()
    client_params.capabilities = capabilities
    session = MagicMock()
    session.client_params = client_params

    request_context = MagicMock()
    request_context.session = session
    request_context.lifespan_context = MagicMock()
    request_context.lifespan_context.okta_auth_manager = _FakeManager(scopes)

    ctx = MagicMock()
    ctx.request_context = request_context

    data = MagicMock()
    data.confirm = confirm
    ctx.elicit = AsyncMock(return_value=AcceptedElicitation.model_construct(action="accept", data=data))
    return ctx


def _make_user(user_id: str = USER_ID, email: str = LOGIN):
    user = MagicMock()
    user.id = user_id
    user.profile = MagicMock()
    user.profile.email = email
    return user


def _make_client(*, users=None, group_members=None, revocation_status: int = 204):
    """Build an Okta client mock with all revocation paths succeeding."""
    client = AsyncMock()
    client.list_users.return_value = (users if users is not None else [_make_user()], None, None)
    client.list_group_users.return_value = (
        group_members if group_members is not None else [_make_user()],
        _FakeResponse(),
        None,
    )
    # 204 success shape: the 3-tuple arm of the SDK's inconsistent return
    client.revoke_user_sessions.return_value = (None, _FakeResponse(), None)
    client.revoke_user_grants.return_value = (None, _FakeResponse(), None)

    response = MagicMock()
    response.get_status.return_value = revocation_status
    executor = MagicMock()
    executor.create_request = AsyncMock(return_value=(MagicMock(), None))
    executor.execute = AsyncMock(return_value=(response, None, None))
    client.get_request_executor = MagicMock(return_value=executor)
    return client


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class TestSdkErrorArity:
    """The SDK returns 2-tuples on failure and 3-tuples on 204; the error is
    always last. Unpacking into three names raises ValueError on exactly the
    failure paths a caller writes the unpack to handle."""

    def test_three_tuple_success(self):
        assert _sdk_error((None, _FakeResponse(), None)) is None

    def test_two_tuple_create_request_failure(self):
        assert _sdk_error((None, "boom")) == "boom"

    def test_two_tuple_execute_failure(self):
        assert _sdk_error((MagicMock(), "boom")) == "boom"


class TestEscapeScim:
    def test_escapes_quotes_and_backslashes_in_order(self):
        # Backslash first, so the backslashes just inserted are not re-escaped.
        assert _escape_scim(r'x" or true or "') == r'x\" or true or \"'
        assert _escape_scim(r"back\slash") == r"back\\slash"


# ---------------------------------------------------------------------------
# logout_user
# ---------------------------------------------------------------------------

class TestLogoutUser:
    @pytest.mark.asyncio
    @patch(f"{MODULE}.get_okta_client")
    async def test_runs_both_revocations(self, mock_get_client):
        client = _make_client()
        mock_get_client.return_value = client

        result = await logout_user(login=LOGIN, ctx=_make_ctx())

        row = result[0]
        assert row["ok"] is True
        assert row["user"] == LOGIN
        assert row["steps"]["sessions"]["status"] == "ok"
        assert row["steps"]["grants"]["status"] == "ok"

        client.revoke_user_sessions.assert_awaited_once_with(
            USER_ID, oauth_tokens=True, forget_devices=False
        )
        client.revoke_user_grants.assert_awaited_once_with(USER_ID)

    @pytest.mark.asyncio
    @patch(f"{MODULE}.get_okta_client")
    async def test_does_not_call_global_token_revocation(self, mock_get_client):
        """Universal Logout is deferred: logout_user must not touch the
        global-token-revocation endpoint, whose scope this org cannot issue."""
        client = _make_client()
        mock_get_client.return_value = client

        result = await logout_user(login=LOGIN, ctx=_make_ctx())

        assert "global_logout" not in result[0]["steps"]
        client.get_request_executor.assert_not_called()

    @pytest.mark.asyncio
    @patch(f"{MODULE}.get_okta_client")
    async def test_grant_failure_reports_not_ok_without_stopping_sessions(self, mock_get_client):
        client = _make_client()
        client.revoke_user_grants.return_value = (None, "grants exploded")
        mock_get_client.return_value = client

        result = await logout_user(login=LOGIN, ctx=_make_ctx())

        row = result[0]
        assert row["ok"] is False
        assert row["steps"]["grants"]["status"] == "error"
        # A failure mid-sequence must not abandon the remaining revocations.
        assert row["steps"]["sessions"]["status"] == "ok"

    @pytest.mark.asyncio
    @patch(f"{MODULE}.get_okta_client")
    async def test_unknown_login_revokes_nothing(self, mock_get_client):
        client = _make_client(users=[])
        mock_get_client.return_value = client

        result = await logout_user(login="nobody@example.com", ctx=_make_ctx())

        assert "error" in result[0]
        client.revoke_user_sessions.assert_not_awaited()

    @pytest.mark.asyncio
    @patch(f"{MODULE}.get_okta_client")
    async def test_declined_confirmation_revokes_nothing(self, mock_get_client):
        client = _make_client()
        mock_get_client.return_value = client

        result = await logout_user(login=LOGIN, ctx=_make_ctx(confirm=False))

        assert "cancelled" in result[0]["message"].lower()
        client.revoke_user_sessions.assert_not_awaited()

    @pytest.mark.asyncio
    @patch(f"{MODULE}.get_okta_client")
    async def test_forget_devices_is_forwarded(self, mock_get_client):
        client = _make_client()
        mock_get_client.return_value = client

        await logout_user(login=LOGIN, forget_devices=True, ctx=_make_ctx())

        client.revoke_user_sessions.assert_awaited_once_with(
            USER_ID, oauth_tokens=True, forget_devices=True
        )


# ---------------------------------------------------------------------------
# global_logout_user
# ---------------------------------------------------------------------------

class TestGlobalLogoutUser:
    """The pre-existing Universal Logout tool, left in place but not wired into
    logout_user / logout_group. It is scope-gated on okta.universalLogout.manage,
    which an org without Identity Threat Protection cannot issue."""

    @pytest.mark.asyncio
    @patch(f"{MODULE}.get_okta_client")
    async def test_opaque_subject_from_login(self, mock_get_client):
        client = _make_client()
        mock_get_client.return_value = client

        result = await global_logout_user(login=LOGIN, ctx=_make_ctx())

        assert result[0]["ok"] is True
        _, _, body, _ = client.get_request_executor().create_request.await_args.args
        assert body["sub_id"] == {"format": "opaque", "id": USER_ID}

    @pytest.mark.asyncio
    @patch(f"{MODULE}.get_okta_client")
    async def test_pruned_when_universal_logout_scope_absent(self, mock_get_client):
        """With the scope missing, the guard short-circuits before any API call."""
        result = await global_logout_user(
            login=LOGIN, ctx=_make_ctx(scopes="okta.users.manage okta.groups.read")
        )

        assert "error" in result[0]
        assert "okta.universalLogout.manage" in result[0]["error"]
        mock_get_client.assert_not_called()

    @pytest.mark.asyncio
    @patch(f"{MODULE}.get_okta_client")
    async def test_unexpected_status_is_an_error(self, mock_get_client):
        mock_get_client.return_value = _make_client(revocation_status=500)

        result = await global_logout_user(login=LOGIN, ctx=_make_ctx())

        assert "error" in result[0]


# ---------------------------------------------------------------------------
# logout_group
# ---------------------------------------------------------------------------

class TestLogoutGroup:
    @pytest.mark.asyncio
    @patch(f"{MODULE}.get_okta_client")
    async def test_signs_out_every_member(self, mock_get_client):
        members = [_make_user(f"00uTEST00000000{i}", f"user{i}@example.com") for i in range(3)]
        client = _make_client(group_members=members)
        mock_get_client.return_value = client

        result = await logout_group(group_id=GROUP_ID, ctx=_make_ctx())

        assert result["total"] == 3
        assert result["succeeded"] == 3
        assert result["failed"] == 0
        assert client.revoke_user_sessions.await_count == 3
        assert client.revoke_user_grants.await_count == 3
        # Universal Logout is deferred — no group logout may hit that endpoint.
        client.get_request_executor.assert_not_called()
        assert {r["user"] for r in result["results"]} == {
            "user0@example.com",
            "user1@example.com",
            "user2@example.com",
        }

    @pytest.mark.asyncio
    @patch(f"{MODULE}.get_okta_client")
    async def test_no_elicitation_support_does_not_sign_anyone_out(self, mock_get_client):
        """The security property this whole tool hangs on: unlike the
        single-user tools, a client that cannot elicit must get a confirmation
        prompt back, never a completed mass logout."""
        client = _make_client(group_members=[_make_user()])
        mock_get_client.return_value = client

        result = await logout_group(group_id=GROUP_ID, ctx=_make_ctx(elicitation=False))

        assert result["confirmation_required"] is True
        assert result["tool_to_use"] == "confirm_logout_group"
        assert result["member_count"] == 1
        client.revoke_user_sessions.assert_not_awaited()

    @pytest.mark.asyncio
    @patch(f"{MODULE}.get_okta_client")
    async def test_declined_confirmation_signs_no_one_out(self, mock_get_client):
        client = _make_client(group_members=[_make_user()])
        mock_get_client.return_value = client

        result = await logout_group(group_id=GROUP_ID, ctx=_make_ctx(confirm=False))

        assert "cancelled" in result["message"].lower()
        client.revoke_user_sessions.assert_not_awaited()

    @pytest.mark.asyncio
    @patch(f"{MODULE}.get_okta_client")
    async def test_group_over_cap_is_refused(self, mock_get_client):
        members = [_make_user(f"00uTEST{i:09d}") for i in range(MAX_GROUP_MEMBERS + 1)]
        client = _make_client(group_members=members)
        mock_get_client.return_value = client

        result = await logout_group(group_id=GROUP_ID, ctx=_make_ctx())

        assert "error" in result
        assert str(MAX_GROUP_MEMBERS) in result["error"]
        client.revoke_user_sessions.assert_not_awaited()

    @pytest.mark.asyncio
    @patch(f"{MODULE}.get_okta_client")
    async def test_empty_group_is_a_no_op(self, mock_get_client):
        client = _make_client(group_members=[])
        mock_get_client.return_value = client

        result = await logout_group(group_id=GROUP_ID, ctx=_make_ctx())

        assert result["total"] == 0
        client.revoke_user_sessions.assert_not_awaited()

    @pytest.mark.asyncio
    @patch(f"{MODULE}.get_okta_client")
    async def test_one_member_failing_does_not_stop_the_others(self, mock_get_client):
        members = [_make_user(f"00uTEST00000000{i}", f"user{i}@example.com") for i in range(3)]
        client = _make_client(group_members=members)

        async def _sessions(user_id, **kwargs):
            if user_id == "00uTEST000000001":
                return (None, "rate limited")
            return (None, _FakeResponse(), None)

        client.revoke_user_sessions.side_effect = _sessions
        mock_get_client.return_value = client

        result = await logout_group(group_id=GROUP_ID, ctx=_make_ctx())

        assert result["total"] == 3
        assert result["succeeded"] == 2
        assert result["failed"] == 1
        assert "idempotent" in result["message"]
        failed = [r for r in result["results"] if not r["ok"]]
        assert failed[0]["user"] == "user1@example.com"

    @pytest.mark.asyncio
    @patch(f"{MODULE}.get_okta_client")
    async def test_list_failure_is_reported_not_swallowed(self, mock_get_client):
        client = _make_client()
        client.list_group_users.return_value = (None, None, "no such group")
        mock_get_client.return_value = client

        result = await logout_group(group_id=GROUP_ID, ctx=_make_ctx())

        assert "error" in result
        client.revoke_user_sessions.assert_not_awaited()


class TestConfirmLogoutGroup:
    @pytest.mark.asyncio
    @patch(f"{MODULE}.get_okta_client")
    async def test_wrong_confirmation_signs_no_one_out(self, mock_get_client):
        client = _make_client(group_members=[_make_user()])
        mock_get_client.return_value = client

        result = await confirm_logout_group(
            group_id=GROUP_ID, confirmation="yes", ctx=_make_ctx(elicitation=False)
        )

        assert "error" in result
        client.revoke_user_sessions.assert_not_awaited()

    @pytest.mark.asyncio
    @patch(f"{MODULE}.get_okta_client")
    async def test_correct_confirmation_runs_the_logout(self, mock_get_client):
        client = _make_client(group_members=[_make_user()])
        mock_get_client.return_value = client

        result = await confirm_logout_group(
            group_id=GROUP_ID, confirmation="LOGOUT", ctx=_make_ctx(elicitation=False)
        )

        assert result["succeeded"] == 1
        client.revoke_user_sessions.assert_awaited_once()


# ---------------------------------------------------------------------------
# SDK call-shape contract
# ---------------------------------------------------------------------------

class TestListUsersCallShape:
    """The mocks above accept any arguments, so a call the real Okta SDK would
    reject looks correct in every other test here. This replays the call our
    code actually makes against the SDK's own pydantic validation layer.

    The bug this exists for: ``list_users({"search": ..., "limit": 1})`` passes
    a dict positionally, and the SDK's first positional parameter after
    ``self`` is ``content_type`` (a strict str). Validation fails with "Input
    should be a valid string" before any request is issued, so login resolution
    raised and no revocation ever ran. It reached production because it was
    inherited from ``global_logout_user``, which is always scope-pruned and so
    never exercised it.

    Validation fires when the coroutine is awaited, not when it is created,
    which is why these await rather than inspecting the signature.
    """

    @staticmethod
    async def _validation_error_for(*args, **kwargs):
        """Await the real SDK method against a dummy self; return the
        ValidationError if its argument validation rejects the call, else None.
        Any other exception means validation passed and the body failed on the
        dummy, which is not what we are testing."""
        from okta.client import Client
        from pydantic import ValidationError

        try:
            await Client.list_users(MagicMock(), *args, **kwargs)
        except ValidationError as exc:
            return exc
        except Exception:
            return None
        return None

    @pytest.mark.asyncio
    @patch(f"{MODULE}.get_okta_client")
    async def test_resolve_login_call_survives_real_sdk_validation(self, mock_get_client):
        client = _make_client()
        mock_get_client.return_value = client

        await logout_user(login=LOGIN, ctx=_make_ctx())

        # Replay exactly what the tool called, rather than asserting a literal,
        # so this keeps checking whatever the call becomes.
        args, kwargs = client.list_users.await_args
        assert kwargs, "list_users must be called with keyword arguments, not a positional query dict"

        exc = await self._validation_error_for(*args, **kwargs)
        assert exc is None, f"the real Okta SDK rejects this call: {exc}"

    @pytest.mark.asyncio
    async def test_the_old_positional_dict_form_would_be_caught(self):
        """Guards the guard: proves the check above is not vacuous."""
        exc = await self._validation_error_for({"search": 'profile.login eq "x"', "limit": 1})
        assert exc is not None, "a positional query dict should fail SDK validation"
