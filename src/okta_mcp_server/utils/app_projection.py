# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Directory-listing projection of Okta Application objects.

``list_applications`` and ``list_group_apps`` can return every app in the org
in one call (``fetch_all=True``).  A directory listing needs to identify apps,
not carry their ``credentials`` or ``settings`` blocks, so the list tools emit
only an explicit allowlist of top-level fields.  New SDK fields therefore stay
out of list output until someone adds them here; ``get_application`` remains
the way to see one app in full (credentials redacted by ``to_jsonable``).
"""

from typing import Any, Dict, List

from okta_mcp_server.utils.serialization import to_jsonable

#: Top-level Application fields the list tools return.  ``credentials``,
#: ``settings`` and ``_links`` are deliberately absent.
APPLICATION_SUMMARY_FIELDS = (
    "id",
    "name",
    "label",
    "status",
    "signOnMode",
    "created",
    "lastUpdated",
    "features",
    "visibility",
)


def application_summary(app: Any) -> Dict[str, Any]:
    """Return the allowlisted fields of one Application (SDK model or dict)."""
    data = to_jsonable(app)
    if not isinstance(data, dict):
        return {}
    return {k: data[k] for k in APPLICATION_SUMMARY_FIELDS if k in data}


def application_summaries(apps: List[Any]) -> List[Dict[str, Any]]:
    return [application_summary(a) for a in apps]
