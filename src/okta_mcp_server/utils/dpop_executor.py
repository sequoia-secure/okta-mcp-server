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


# Headers whose values are credential-equivalent and must NEVER appear in
# logs. Matched case-insensitively. Anything with one of these names is
# replaced by "<redacted>" before logging.
_SENSITIVE_RESPONSE_HEADERS = frozenset({
    "set-cookie",
    "cookie",
    "authorization",
    "proxy-authorization",
    "x-okta-request-id",  # operational, but contains tenant-internal request UUID
    "x-okta-identifier",
    "x-okta-session-id",
})

# Max length of response body to emit in error logs. Real Okta error
# payloads are well under this; user-data leak surface is bounded.
_MAX_BODY_LOG_BYTES = 1024


def _sanitize_headers(headers) -> dict:
    """Return a copy of ``headers`` with credential-bearing fields masked.

    Header keys are normalised to lowercase for comparison; the original
    case of non-sensitive keys is preserved in the output.
    """
    safe: dict = {}
    try:
        items = headers.items() if hasattr(headers, "items") else dict(headers).items()
    except Exception:
        return {"<unloggable-headers>": "<error>"}
    for k, v in items:
        if str(k).lower() in _SENSITIVE_RESPONSE_HEADERS:
            safe[k] = "<redacted>"
        else:
            safe[k] = v
    return safe


def _truncate_body(body) -> str:
    """Return a bounded repr of ``body`` for safe logging.

    Limits output to ``_MAX_BODY_LOG_BYTES`` characters and notes truncation
    explicitly so an analyst reading the log knows the content was clipped.
    """
    s = repr(body) if body is not None else "<no body>"
    if len(s) <= _MAX_BODY_LOG_BYTES:
        return s
    return f"{s[:_MAX_BODY_LOG_BYTES]}... (truncated, original {len(s)} chars)"


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
                # Log enough to diagnose Okta error codes WITHOUT leaking
                # credentials or bulk PII. Strip credential-bearing headers
                # (Set-Cookie etc.) and bound the body length.
                logger.error(
                    f"DPoP executor: Okta API returned {status} — "
                    f"body={_truncate_body(resp_body)} "
                    f"headers={_sanitize_headers(res_details.headers)}"
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
                            f"DPoP executor: retry also failed: {res_details.status} "
                            f"body={_truncate_body(resp_body)}"
                        )
                    return (request, res_details, resp_body, error)

            return (request, res_details, resp_body, error)

    return DPoPRequestExecutor
