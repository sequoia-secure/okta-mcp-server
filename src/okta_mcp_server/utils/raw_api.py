# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Read-only raw GET helpers for Okta endpoints served as plain JSON.

The roles, network-zone, authenticator and factor tools go through the request
executor instead of the typed SDK methods. Those resources are polymorphic
(zone ``type``, authenticator ``key``, factor ``factorType``, role ``type``)
and the SDK's pydantic models drop or reject fields they do not know, which
is exactly the configuration detail an investigator needs. Plain JSON keeps
every field Okta returns.

Only ``GET`` is exposed here on purpose: these helpers back read-only tools.
"""

import json
from typing import Any, Optional
from urllib.parse import parse_qs, urlencode, urlparse

from okta_mcp_server.utils.pagination import extract_after_cursor

#: Upper bound on pages followed by :func:`okta_get_all`, so a runaway cursor
#: cannot keep a tool call open indefinitely.
DEFAULT_MAX_PAGES = 50


async def okta_get(client: Any, path: str, params: Optional[dict] = None) -> tuple:
    """Issue ``GET path?params`` and return ``(response, parsed_body, error)``.

    ``path`` is relative to the org URL (for example ``/api/v1/zones``); the
    request executor prefixes the configured org URL. ``parsed_body`` is
    ``None`` for an empty body. ``response`` and ``parsed_body`` are ``None``
    whenever ``error`` is set.
    """
    query = {k: v for k, v in (params or {}).items() if v is not None and v != ""}
    url = path + (f"?{urlencode(query)}" if query else "")
    executor = client.get_request_executor()
    request, err = await executor.create_request(method="GET", url=url, body={}, headers={}, oauth=False)
    if err:
        return None, None, err
    response, response_body, err = await executor.execute(request)
    if err:
        return None, None, err
    if not response_body:
        return response, None, None
    if isinstance(response_body, (bytes, bytearray)):
        response_body = response_body.decode("utf-8")
    return response, json.loads(response_body) if isinstance(response_body, str) else response_body, None


def next_cursor(response: Any, body: Any) -> Optional[str]:
    """Return the ``after`` cursor for the next page, or ``None``.

    Okta signals the next page with a ``Link: <...>; rel="next"`` header on
    most list endpoints, and with ``_links.next.href`` in the body on the IAM
    endpoints (``/api/v1/iam/...``). Only the ``after`` value is taken from
    either, never the URL itself, so a page cannot redirect the next request
    to another host.
    """
    cursor = extract_after_cursor(response)
    if cursor:
        return cursor
    if isinstance(body, dict):
        href = (((body.get("_links") or {}).get("next")) or {}).get("href")
        if href:
            return parse_qs(urlparse(href).query).get("after", [None])[0]
    return None


async def okta_get_all(
    client: Any,
    path: str,
    params: Optional[dict] = None,
    items_key: Optional[str] = None,
    max_pages: int = DEFAULT_MAX_PAGES,
) -> tuple:
    """Follow ``after`` cursors and return ``(items, truncated, error)``.

    ``items_key`` names the list inside a wrapper object (``"value"`` for the
    IAM endpoints); leave it ``None`` when the body is the list itself.
    ``truncated`` is True when ``max_pages`` was reached with pages left.
    Items gathered before an error on a later page are discarded, so a partial
    list is never mistaken for a complete one.
    """
    items: list = []
    page_params = dict(params or {})
    for _ in range(max_pages):
        response, body, err = await okta_get(client, path, page_params)
        if err:
            return [], False, err
        page = (body or {}).get(items_key) if items_key else body
        items.extend(page or [])
        cursor = next_cursor(response, body)
        if not cursor or not page:
            return items, False, None
        page_params["after"] = cursor
    return items, True, None


def strip_links(obj: Any) -> Any:
    """Drop ``_links`` (HATEOAS URLs) from an object or list of objects."""
    if isinstance(obj, list):
        return [strip_links(o) for o in obj]
    if isinstance(obj, dict):
        return {k: v for k, v in obj.items() if k != "_links"}
    return obj
