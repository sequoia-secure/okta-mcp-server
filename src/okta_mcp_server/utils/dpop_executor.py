# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2025-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

from urllib.parse import urlsplit, urlunsplit

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
            # RFC 9449 §4.2: htu MUST NOT include query or fragment components.
            parsed = urlsplit(full_url)
            htu = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))
            dpop_proof = auth_manager._generate_dpop_proof(method.upper(), htu)
            request["headers"]["DPoP"] = dpop_proof
            # Ensure Authorization stays DPoP even if super() merged in Bearer default.
            request["headers"]["Authorization"] = f"DPoP {auth_manager._api_token}"
            return (request, None)

    return DPoPRequestExecutor
