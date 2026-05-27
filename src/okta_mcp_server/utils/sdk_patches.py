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
from okta.models.knowledge_constraint import KnowledgeConstraint
from okta.models.platform_condition_evaluator_platform_operating_system import (
    PlatformConditionEvaluatorPlatformOperatingSystem,
)
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


# ---------------------------------------------------------------------------
# KnowledgeConstraint.{methods,types} — drop case-sensitive enum validators
#
# Symptom (observed 2026-05-27):
#   1 validation error for KnowledgeConstraint
#   types
#     Value error, each list item must be one of
#     ('SECURITY_KEY', 'PHONE', 'EMAIL', 'PASSWORD', 'SECURITY_QUESTION',
#      'APP', 'FEDERATED')
#     [type=value_error, input_value=['password'], input_type=list]
#
# Root cause:
#   The auto-generated KnowledgeConstraint declares two strict, UPPERCASE-only
#   field_validators (`methods_validate_enum`, `types_validate_enum`). The
#   live API returns lowercase strings (e.g. ``['password']``), so the entire
#   list_policy_rules response is rejected.
#
# Fix:
#   Drop both validators. We accept whatever string Okta returns; consumers
#   that care about canonical casing can normalize themselves.
# ---------------------------------------------------------------------------

_DROPPED_VALIDATORS = ("methods_validate_enum", "types_validate_enum")


def _drop_knowledge_constraint_validators() -> None:
    validators = KnowledgeConstraint.__pydantic_decorators__.field_validators
    removed = [n for n in _DROPPED_VALIDATORS if validators.pop(n, None) is not None]
    if removed:
        KnowledgeConstraint.model_rebuild(force=True)
    return removed


# ---------------------------------------------------------------------------
# PlatformConditionEvaluatorPlatformOperatingSystem.type — open the OS enum
#
# Symptom (observed 2026-05-27):
#   Input should be 'ANDROID', 'ANY', 'IOS', 'OSX', 'OTHER' or 'WINDOWS'
#     [type=enum, input_value='MACOS',    input_type=str]
#     [type=enum, input_value='CHROMEOS', input_type=str]
#
# Root cause:
#   The ``type`` field is annotated with the closed enum
#   ``PolicyPlatformOperatingSystemType``, which only declares the six legacy
#   values. The live API now returns ``MACOS`` (Okta's renaming of OSX) and
#   ``CHROMEOS``, with ``LINUX`` likely on the horizon. Each new value breaks
#   list_policy_rules for any rule whose conditions reference that platform.
#
# Fix:
#   Loosen the field annotation to ``Optional[str]``. We never branch on the
#   value inside this server (it's serialized through to the MCP client), so
#   accepting any string is future-proof against further Okta expansions
#   without paying the maintenance cost of mirroring every new enum addition.
# ---------------------------------------------------------------------------


def _relax_os_type() -> bool:
    """Open the platform OS ``type`` field's enum to plain ``Optional[str]``.

    Returns True if a patch was applied, False if already loose.
    """
    cls = PlatformConditionEvaluatorPlatformOperatingSystem
    field = cls.model_fields.get("type")
    if field is None:
        return False
    if field.annotation == Optional[str]:
        return False
    field.annotation = Optional[str]
    cls.model_rebuild(force=True)
    return True


def apply_patches() -> None:
    """Apply all SDK patches. Called at server startup."""
    # Patch 1: Policy._embedded loosening (base + subclasses)
    _relax_embedded(Policy)
    relaxed = [Policy.__name__]
    for sub in Policy.__subclasses__():
        _relax_embedded(sub)
        relaxed.append(sub.__name__)
    logger.info(
        "[sdk-patches] Loosened Policy._embedded on {} class(es): {}",
        len(relaxed),
        relaxed,
    )

    # Patch 2: KnowledgeConstraint case-sensitive enum validators
    removed = _drop_knowledge_constraint_validators()
    if removed:
        logger.info(
            "[sdk-patches] Removed strict enum validators from KnowledgeConstraint: {}",
            removed,
        )

    # Patch 3: PlatformConditionEvaluatorPlatformOperatingSystem.type enum
    if _relax_os_type():
        logger.info(
            "[sdk-patches] Loosened PlatformConditionEvaluatorPlatformOperatingSystem.type"
            " from PolicyPlatformOperatingSystemType to Optional[str]"
        )


apply_patches()
