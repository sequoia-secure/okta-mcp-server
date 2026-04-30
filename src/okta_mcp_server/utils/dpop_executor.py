# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2025-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import time
from urllib.parse import urlsplit, urlunsplit

from loguru import logger
from okta.request_executor import RequestExecutor


def make_dpop_executor(auth_manager):
    """Return a RequestExecutor subclass that attaches DPoP proofs to every API request.

    Okta issues DPoP-bound access tokens when DPoP is used at the token endpoint
    (RFC 9449). Such tokens cannot be presented as plain Bearer tokens — the resource
    server requires `Authorization: DPoP <token>` plus a fresh `DPoP` proof header on
    each request.  The stock Okta SDK only supports Bearer / SSWS, so we subclass
    RequestExecutor to inject the correct headers after the base class builds the request.
    """

    class DPoPRequestExecutor(RequestExecutor):
        def __init__(self, config, cache, http_client=None):
            super().__init__(config, cache, http_client)
            # super().__init__ sets Authorization: Bearer <token>; override to DPoP.
            self._default_headers["Authorization"] = f"DPoP {auth_manager._api_token}"
            self._dpop_api_nonce = None

        def _make_dpop_proof(self, method: str, url: str, nonce: str | None = None) -> str:
            """Generate a DPoP proof with htu stripped of query/fragment (RFC 9449 §4.2).

            Includes ath (access token hash) as required by RFC 9449 §4.2 when
            presenting a DPoP-bound token to a resource server.
            """
            parsed = urlsplit(url)
            htu = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))
            return auth_manager._generate_dpop_proof(
                method.upper(), htu, nonce=nonce, access_token=auth_manager._api_token
            )

        async def create_request(
            self,
            method: str,
            url: str,
            body: dict = None,
            headers: dict = {},
            form: dict = {},
            oauth: bool = False,
            keep_empty_params: bool = False,
        ):
            request, error = await super().create_request(
                method, url, body, headers, form, oauth, keep_empty_params
            )
            if error:
                return (request, error)

            full_url = request["url"]
            dpop_proof = self._make_dpop_proof(method, full_url, nonce=self._dpop_api_nonce)
            request["headers"]["DPoP"] = dpop_proof
            # Ensure Authorization stays DPoP even if super() merged in Bearer default.
            request["headers"]["Authorization"] = f"DPoP {auth_manager._api_token}"
            return (request, None)

        async def fire_request_helper(self, request, attempts, request_start_time):
            _, res_details, resp_body, error = await super().fire_request_helper(
                request, attempts, request_start_time
            )

            if res_details is None:
                return (request, res_details, resp_body, error)

            status = res_details.status
            if status not in range(200, 300):
                # Log full response so we can diagnose Okta error codes
                logger.error(
                    f"DPoP executor: Okta API returned {status} — "
                    f"body={resp_body!r} headers={dict(res_details.headers)}"
                )

                # Handle server-supplied DPoP nonce (token endpoint uses 400;
                # resource server may use 400 or 401 — handle both).
                dpop_nonce = (
                    res_details.headers.get("DPoP-Nonce")
                    or res_details.headers.get("dpop-nonce")
                )
                if dpop_nonce and status in (400, 401):
                    logger.info(f"DPoP executor: retrying with server nonce={dpop_nonce!r}")
                    self._dpop_api_nonce = dpop_nonce
                    method = request["method"]
                    url = request["url"]
                    new_proof = self._make_dpop_proof(method, url, nonce=dpop_nonce)
                    request["headers"]["DPoP"] = new_proof
                    self._default_headers.update(request["headers"])
                    _, res_details, resp_body, error = await self._http_client.send_request(request)
                    if res_details and res_details.status not in range(200, 300):
                        logger.error(
                            f"DPoP executor: retry also failed: {res_details.status} body={resp_body!r}"
                        )
                    return (request, res_details, resp_body, error)

            return (request, res_details, resp_body, error)

    return DPoPRequestExecutor
