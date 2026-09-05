# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Tests for the DPoP request executor.

Centred on the two ways a DPoP proof goes wrong against Okta, both of which
surface as the same opaque 400: ``invalid_dpop_proof`` / "'htu' claim in the
DPoP proof JWT is invalid".

1. htu carrying the query string (RFC 9449 §4.2 requires it stripped).
2. A proof outliving the single request it was minted for.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from okta_mcp_server.utils.dpop_executor import make_dpop_executor

ORG = "https://test.okta.com"


def _make_executor():
    """Build the executor class against a stub auth manager.

    ``_generate_dpop_proof`` is stubbed to echo its inputs so a test can read
    back exactly which (htm, htu, nonce) a proof was minted for.
    """
    manager = MagicMock()
    manager._api_token = "fake-token"
    manager._generate_dpop_proof = MagicMock(
        side_effect=lambda m, u, nonce=None, access_token=None: f"proof:{m}:{u}:{nonce}"
    )

    cls = make_dpop_executor(manager)
    ex = cls.__new__(cls)  # bypass RequestExecutor.__init__ (needs real config)
    ex._default_headers = {"Authorization": "DPoP fake-token"}
    ex._dpop_api_nonce = None
    return ex, manager


class TestHtu:
    """htu must be scheme + authority + path — no query, no fragment."""

    def test_strips_the_query_string(self):
        ex, _ = _make_executor()
        url = f"{ORG}/api/v1/users?search=profile.login%20eq%20%22a%40b.com%22&limit=1"
        assert ex._htu(url) == f"{ORG}/api/v1/users"

    def test_strips_a_pagination_cursor(self):
        # The shape that broke okta/okta-sdk-golang#468: a `next` link whose
        # query carries the cursor.
        ex, _ = _make_executor()
        assert ex._htu(f"{ORG}/api/v1/users?after=00uABC&limit=200") == f"{ORG}/api/v1/users"

    def test_strips_a_fragment(self):
        ex, _ = _make_executor()
        assert ex._htu(f"{ORG}/api/v1/groups#frag") == f"{ORG}/api/v1/groups"

    def test_leaves_a_bare_url_alone(self):
        ex, _ = _make_executor()
        assert ex._htu(f"{ORG}/api/v1/users") == f"{ORG}/api/v1/users"

    def test_proof_is_minted_for_the_stripped_url(self):
        ex, manager = _make_executor()
        ex._make_dpop_proof("get", f"{ORG}/api/v1/users?limit=1")
        htm, htu = manager._generate_dpop_proof.call_args.args
        assert htm == "GET", "htm must be upper-cased"
        assert "?" not in htu and htu == f"{ORG}/api/v1/users"


class TestNonceRetryDoesNotLeakTheProof:
    """A DPoP proof is single-use and bound to one htm/htu pair.

    The nonce-retry path used to do ``self._default_headers.update(
    request["headers"])``, persisting that request's proof into the executor's
    defaults. Every later request built from those defaults then carried a
    proof minted for the *previous* URL — rejected by Okta with the very
    "'htu' claim ... is invalid" error this retry exists to recover from.
    """

    @pytest.mark.asyncio
    async def test_default_headers_do_not_retain_the_proof(self, monkeypatch):
        ex, _ = _make_executor()

        challenge = MagicMock()
        challenge.status = 400
        challenge.headers = {"DPoP-Nonce": "nonce-from-okta"}

        ok = MagicMock()
        ok.status = 200
        ok.headers = {}

        # Patched on the base class, so it is invoked unbound via super() —
        # it receives self as the first argument.
        async def _super_helper(_self, request, attempts, start):
            return (request, challenge, "", None)

        monkeypatch.setattr(
            "okta.request_executor.RequestExecutor.fire_request_helper",
            _super_helper,
            raising=True,
        )
        ex._http_client = MagicMock()
        ex._http_client.send_request = AsyncMock(return_value=(None, ok, "", None))

        request = {
            "method": "GET",
            "url": f"{ORG}/api/v1/users?limit=1",
            "headers": {"Authorization": "DPoP fake-token", "DPoP": "stale-proof"},
        }

        await ex.fire_request_helper(request, 1, 0)

        # The nonce is what should persist across requests.
        assert ex._dpop_api_nonce == "nonce-from-okta"
        # The proof must not.
        assert "DPoP" not in ex._default_headers, (
            "a single-use DPoP proof leaked into the executor's default headers; "
            "the next request to a different URL would carry the wrong htu"
        )

    @pytest.mark.asyncio
    async def test_retry_proof_is_bound_to_the_same_request_url(self, monkeypatch):
        ex, _ = _make_executor()

        challenge = MagicMock()
        challenge.status = 400
        challenge.headers = {"DPoP-Nonce": "n1"}
        ok = MagicMock()
        ok.status = 200
        ok.headers = {}

        # Patched on the base class, so it is invoked unbound via super() —
        # it receives self as the first argument.
        async def _super_helper(_self, request, attempts, start):
            return (request, challenge, "", None)

        monkeypatch.setattr(
            "okta.request_executor.RequestExecutor.fire_request_helper",
            _super_helper,
            raising=True,
        )
        ex._http_client = MagicMock()
        ex._http_client.send_request = AsyncMock(return_value=(None, ok, "", None))

        request = {
            "method": "GET",
            "url": f"{ORG}/api/v1/users?after=cursor&limit=200",
            "headers": {"DPoP": "stale"},
        }
        await ex.fire_request_helper(request, 1, 0)

        # Re-minted for this request's URL, query stripped, carrying the nonce.
        assert request["headers"]["DPoP"] == f"proof:GET:{ORG}/api/v1/users:n1"
