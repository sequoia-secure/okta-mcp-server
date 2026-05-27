# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2025-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Runtime monkey-patches for the upstream Okta Python SDK.

The auto-generated Pydantic models in ``okta.models`` are derived from the
OpenAPI spec and occasionally over-narrow a field's type relative to what the
live Okta API actually returns. When that happens, the SDK raises a
``pydantic.ValidationError`` and the entire response is discarded, which
breaks otherwise-working tools.

This module applies focused, minimal patches to relax those types so the MCP
tools keep working. Each patch is documented with the symptom it addresses.

Patches are applied at import time. ``server.py`` imports this module before
any ``tools/*`` module so all subsequent SDK calls see the loosened models.
"""

from typing import Any, Dict, Optional

from loguru import logger
from okta.models.policy import Policy


# ---------------------------------------------------------------------------
# Policy._embedded — loosen value type
#
# Symptom (observed 2026-05-19):
#   1 validation error for AccessPolicy
#   _embedded.resourceType
#     Input should be a valid dictionary
#       [type=dict_type, input_value='APP', input_type=str]
#
# Root cause:
#   ``okta.models.policy.Policy`` declares
#       embedded: Optional[Dict[str, Dict[str, Any]]] = Field(alias="_embedded")
#   which requires every value under ``_embedded`` to itself be a dict. The
#   live API returns mixed structures — e.g.
#   ``{"mappings": [...], "resourceType": "APP"}`` — where some children are
#   plain strings. Pydantic rejects the whole response.
#
# Fix:
#   Relax the inner type from ``Dict[str, Any]`` to ``Any`` for every Policy
#   subclass (AccessPolicy, OktaSignOnPolicy, PasswordPolicy, …). The field
#   still parses as a dict-of-anything, which is what callers actually want.
# ---------------------------------------------------------------------------

_LOOSE_EMBEDDED = Optional[Dict[str, Any]]


def _relax_embedded(cls: type) -> None:
    """Replace the ``embedded`` field's annotation on a Policy subclass.

    Idempotent — safe to call repeatedly.
    """
    field = cls.model_fields.get("embedded")
    if field is None:
        return
    if field.annotation == _LOOSE_EMBEDDED:
        return  # already patched
    field.annotation = _LOOSE_EMBEDDED
    cls.model_rebuild(force=True)


def apply_patches() -> None:
    """Apply all SDK patches. Called at server startup."""
    # Patch the base class and every subclass currently loaded.
    _relax_embedded(Policy)
    patched = [Policy.__name__]
    for sub in Policy.__subclasses__():
        _relax_embedded(sub)
        patched.append(sub.__name__)
    logger.info(
        "[sdk-patches] Loosened Policy._embedded on {} class(es): {}",
        len(patched),
        patched,
    )


apply_patches()
