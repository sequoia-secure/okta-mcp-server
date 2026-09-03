# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Unit tests for OktaAuthManager.

Tokens are held in-memory (self._api_token / self._refresh_token), not in
the OS keyring: keyring/keyrings.alt fall back to an encrypted-file backend
in Docker that blocks on an interactive password prompt for ~20s then
crashes, and re-authenticating on every process restart is correct for a
containerised deployment. Tests set/read those instance attributes directly
instead of mocking a keyring backend.
"""

from __future__ import annotations

import time
from unittest.mock import AsyncMock, MagicMock, patch

import jwt
import pytest

from okta_mcp_server.utils.auth.auth_manager import OktaAuthManager


@pytest.fixture(autouse=True)
def _okta_env(monkeypatch):
    monkeypatch.setenv("OKTA_ORG_URL", "https://test.okta.com")
    monkeypatch.setenv("OKTA_CLIENT_ID", "test-client-id")
    monkeypatch.delenv("OKTA_PRIVATE_KEY", raising=False)
    monkeypatch.delenv("OKTA_KEY_ID", raising=False)
    monkeypatch.delenv("OKTA_SCOPES", raising=False)


def _jwt_with_exp(exp_offset_seconds: int) -> str:
    return jwt.encode({"exp": int(time.time()) + exp_offset_seconds}, "test-secret", algorithm="HS256")


def _jwt_without_exp() -> str:
    return jwt.encode({"sub": "x"}, "test-secret", algorithm="HS256")


class TestIsValidToken:
    @pytest.mark.asyncio
    async def test_cold_start_with_valid_cached_jwt_skips_auth(self):
        manager = OktaAuthManager()
        manager._api_token = _jwt_with_exp(3600)
        with (
            patch.object(OktaAuthManager, "authenticate", new=AsyncMock()) as mock_auth,
            patch.object(OktaAuthManager, "refresh_access_token", new=MagicMock()) as mock_refresh,
        ):
            result = await manager.is_valid_token()
        assert result is True
        mock_auth.assert_not_called()
        mock_refresh.assert_not_called()

    @pytest.mark.asyncio
    async def test_expired_jwt_with_refresh_token_uses_refresh(self):
        manager = OktaAuthManager()
        manager._api_token = _jwt_with_exp(-60)
        manager._refresh_token = "refresh-abc"
        with (
            patch.object(OktaAuthManager, "authenticate", new=AsyncMock()) as mock_auth,
            patch.object(OktaAuthManager, "refresh_access_token", new=MagicMock(return_value=True)) as mock_refresh,
        ):
            result = await manager.is_valid_token()
        assert result is True
        mock_refresh.assert_called_once()
        mock_auth.assert_not_called()

    @pytest.mark.asyncio
    async def test_expired_jwt_without_refresh_token_invokes_authenticate(self):
        manager = OktaAuthManager()
        manager._api_token = _jwt_with_exp(-60)
        manager._refresh_token = None
        with (
            patch.object(OktaAuthManager, "authenticate", new=AsyncMock()) as mock_auth,
            patch.object(OktaAuthManager, "refresh_access_token", new=MagicMock(return_value=False)) as mock_refresh,
        ):
            await manager.is_valid_token()
        mock_refresh.assert_called_once()
        mock_auth.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_expired_jwt_with_failed_refresh_invokes_authenticate(self):
        manager = OktaAuthManager()
        manager._api_token = _jwt_with_exp(-60)
        manager._refresh_token = "refresh-abc"
        with (
            patch.object(OktaAuthManager, "authenticate", new=AsyncMock()) as mock_auth,
            patch.object(OktaAuthManager, "refresh_access_token", new=MagicMock(return_value=False)) as mock_refresh,
        ):
            await manager.is_valid_token()
        mock_refresh.assert_called_once()
        mock_auth.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_no_cached_token_triggers_device_flow(self):
        manager = OktaAuthManager()
        manager._api_token = None
        manager._refresh_token = None
        with (
            patch.object(OktaAuthManager, "authenticate", new=AsyncMock()) as mock_auth,
            patch.object(OktaAuthManager, "refresh_access_token", new=MagicMock(return_value=False)) as mock_refresh,
        ):
            await manager.is_valid_token()
        mock_refresh.assert_called_once()
        mock_auth.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_opaque_token_falls_through_to_refresh(self):
        manager = OktaAuthManager()
        manager._api_token = "opaque-abc-123"
        manager._refresh_token = "refresh-abc"
        with (
            patch.object(OktaAuthManager, "authenticate", new=AsyncMock()),
            patch.object(OktaAuthManager, "refresh_access_token", new=MagicMock(return_value=True)) as mock_refresh,
        ):
            await manager.is_valid_token()
        mock_refresh.assert_called_once()

    @pytest.mark.asyncio
    async def test_malformed_jwt_falls_through_to_refresh(self):
        manager = OktaAuthManager()
        manager._api_token = "a.b.c"
        manager._refresh_token = "refresh-abc"
        with (
            patch.object(OktaAuthManager, "authenticate", new=AsyncMock()),
            patch.object(OktaAuthManager, "refresh_access_token", new=MagicMock(return_value=True)) as mock_refresh,
        ):
            await manager.is_valid_token()
        mock_refresh.assert_called_once()

    @pytest.mark.asyncio
    async def test_jwt_without_exp_claim_falls_through(self):
        manager = OktaAuthManager()
        manager._api_token = _jwt_without_exp()
        manager._refresh_token = "refresh-abc"
        with (
            patch.object(OktaAuthManager, "authenticate", new=AsyncMock()),
            patch.object(OktaAuthManager, "refresh_access_token", new=MagicMock(return_value=True)) as mock_refresh,
        ):
            await manager.is_valid_token()
        mock_refresh.assert_called_once()

    @pytest.mark.asyncio
    async def test_browserless_with_valid_cached_jwt_skips_auth(self, monkeypatch):
        monkeypatch.setenv("OKTA_PRIVATE_KEY", "fake-key")
        monkeypatch.setenv("OKTA_KEY_ID", "fake-kid")
        manager = OktaAuthManager()
        assert manager.use_browserless_auth is True
        manager._api_token = _jwt_with_exp(3600)
        with (
            patch.object(OktaAuthManager, "authenticate", new=AsyncMock()) as mock_auth,
            patch.object(OktaAuthManager, "refresh_access_token", new=MagicMock()) as mock_refresh,
        ):
            result = await manager.is_valid_token()
        assert result is True
        mock_auth.assert_not_called()
        mock_refresh.assert_not_called()

    @pytest.mark.asyncio
    async def test_browserless_with_expired_jwt_reauths_without_refresh(self, monkeypatch):
        monkeypatch.setenv("OKTA_PRIVATE_KEY", "fake-key")
        monkeypatch.setenv("OKTA_KEY_ID", "fake-kid")
        manager = OktaAuthManager()
        assert manager.use_browserless_auth is True
        manager._api_token = _jwt_with_exp(-60)
        with (
            patch.object(OktaAuthManager, "authenticate", new=AsyncMock()) as mock_auth,
            patch.object(OktaAuthManager, "refresh_access_token", new=MagicMock()) as mock_refresh,
        ):
            await manager.is_valid_token()
        mock_auth.assert_awaited_once()
        mock_refresh.assert_not_called()


class TestTokenIsUnexpired:
    @patch("okta_mcp_server.utils.auth.auth_manager.time.time")
    def test_token_expiring_within_safety_margin_is_treated_as_expired(self, mock_time):
        mock_time.return_value = 1_000_000.0
        token = jwt.encode({"exp": 1_000_030}, "test-secret", algorithm="HS256")
        assert OktaAuthManager._token_is_unexpired(token) is False

    @patch("okta_mcp_server.utils.auth.auth_manager.time.time")
    def test_token_expiring_outside_safety_margin_is_valid(self, mock_time):
        mock_time.return_value = 1_000_000.0
        token = jwt.encode({"exp": 1_000_090}, "test-secret", algorithm="HS256")
        assert OktaAuthManager._token_is_unexpired(token) is True

    def test_empty_string_returns_false(self):
        assert OktaAuthManager._token_is_unexpired("") is False


class TestIsCachedTokenValid:
    def test_returns_true_for_valid_cached_jwt(self):
        manager = OktaAuthManager()
        manager._api_token = _jwt_with_exp(3600)
        assert manager.is_cached_token_valid() is True

    def test_returns_false_when_no_token_cached(self):
        manager = OktaAuthManager()
        manager._api_token = None
        assert manager.is_cached_token_valid() is False

    def test_returns_false_for_expired_jwt(self):
        manager = OktaAuthManager()
        manager._api_token = _jwt_with_exp(-60)
        assert manager.is_cached_token_valid() is False

    def test_returns_false_for_opaque_token(self):
        manager = OktaAuthManager()
        manager._api_token = "opaque-not-a-jwt"
        assert manager.is_cached_token_valid() is False


class TestClearTokens:
    def test_clears_both_tokens(self):
        manager = OktaAuthManager()
        manager._api_token = _jwt_with_exp(3600)
        manager._refresh_token = "refresh-abc"
        manager.clear_tokens()
        assert manager._api_token is None
        assert manager._refresh_token is None
