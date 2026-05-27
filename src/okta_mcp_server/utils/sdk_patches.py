# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2025-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Runtime monkey-patches for the upstream Okta Python SDK.

The auto-generated Pydantic models in ``okta.models`` are derived from a
historical snapshot of the OpenAPI spec and routinely over-narrow field
types relative to what the live Okta API actually returns. Two failure
shapes have surfaced repeatedly while iterating across policy/rule data:

  1. **Wrong field type** — e.g. ``Policy._embedded`` is declared as
     ``Dict[str, Dict[str, Any]]`` but the API returns mixed children
     (``{"mappings": [...], "resourceType": "APP"}``).

  2. **Closed enum, open API** — a field is typed as a strict Enum or
     guarded by a ``*_validate_enum`` ``field_validator``, but Okta
     returns values not in that enum (lowercase variants like ``'duo'``,
     new platforms like ``'MACOS'``/``'CHROMEOS'``, expanded factor modes
     like ``'2FA_If_Possible'``, …).

Each individual occurrence breaks an entire SDK response with a
``pydantic.ValidationError`` and an unhelpful 500 from the MCP tool.
Patching them one-by-one has been a steady drip of new bugs; this module
takes a broader sweep:

  * **Class-specific patches** (rare, surgical) for cases that can't be
    generalized — currently only ``Policy._embedded``.
  * **Generic enum loosening** across every loaded ``okta.models.*``
    Pydantic model: drop all ``*_validate_enum`` field_validators and
    replace every ``Enum``-typed field annotation (including under
    ``Optional[...]`` / ``List[...]`` wrappers) with ``str``. We never
    branch on these values inside this server — they're serialized
    through to the MCP client — so accepting any string is strictly
    safer than rejecting valid-but-unknown values.

Patches are applied at import time. ``server.py`` imports this module
before any ``tools/*`` module so all subsequent SDK calls see the
loosened models.
"""

from __future__ import annotations

import importlib
import inspect
import pkgutil
import sys
import typing
from enum import Enum
from typing import Any, Dict, List, Optional, Union

import okta.models
from loguru import logger
from pydantic import BaseModel
from pydantic.fields import FieldInfo


# ---------------------------------------------------------------------------
# Patch 1 — Policy._embedded: wrong field type (Dict vs scalar children)
#
# Symptom (first observed 2026-05-19):
#   1 validation error for AccessPolicy
#   _embedded.resourceType
#     Input should be a valid dictionary
#       [type=dict_type, input_value='APP', input_type=str]
#
# The SDK requires every value under ``_embedded`` to itself be a dict.
# The live API returns mixed structures (e.g.
# ``{"mappings": [...], "resourceType": "APP"}``).
# ---------------------------------------------------------------------------

_LOOSE_EMBEDDED = Optional[Dict[str, Any]]


def _relax_policy_embedded(cls: type) -> bool:
    field = cls.model_fields.get("embedded")
    if field is None:
        return False
    if field.annotation == _LOOSE_EMBEDDED:
        return False
    field.annotation = _LOOSE_EMBEDDED
    cls.model_rebuild(force=True)
    return True


# ---------------------------------------------------------------------------
# Patch 2 — Generic enum loosening across every Okta model.
#
# Two flavours of enum strictness exist in the SDK and we handle both:
#
#   A. ``@field_validator("foo") def foo_validate_enum`` — manual list
#      check using ``raise ValueError("each list item must be one of …")``.
#      These cause:
#        Value error, each list item must be one of (...)
#          [type=value_error, input_value=['duo'], input_type=list]
#      Fix: drop the validator.
#
#   B. Field annotated as a closed Enum subclass (or ``Optional[Enum]`` /
#      ``List[Enum]``). Causes:
#        Input should be 'ANDROID', 'ANY', 'IOS', 'OSX', 'OTHER' or 'WINDOWS'
#          [type=enum, input_value='MACOS', input_type=str]
#      Fix: replace the Enum with ``str`` in the annotation tree.
# ---------------------------------------------------------------------------


def _replace_enum_in_annotation(ann: Any) -> Any:
    """Return ``ann`` with every ``Enum`` subclass swapped for ``str``.

    Handles direct Enum, ``Optional[Enum]``, ``List[Enum]``, and arbitrary
    nestings (``Optional[List[Enum]]``, ``Union[Enum, OtherEnum, None]``,
    etc.). Returns the original annotation unchanged when no Enum appears.
    """
    if inspect.isclass(ann) and issubclass(ann, Enum):
        return str

    origin = typing.get_origin(ann)
    if origin is None:
        return ann

    args = typing.get_args(ann)
    new_args = tuple(_replace_enum_in_annotation(a) for a in args)
    if new_args == args:
        return ann

    # Re-construct the wrapper. Unions need special handling because
    # typing.Union[a, b] uses subscription; list / dict do as well.
    if origin is Union:
        return Union[new_args]  # type: ignore[return-value]
    try:
        return origin[new_args] if len(new_args) > 1 else origin[new_args[0]]
    except TypeError:
        # Some origins (eg `types.UnionType` on 3.10+) don't accept
        # subscription. Fall back to ``Union[...]``.
        return Union[new_args]  # type: ignore[return-value]


def _annotation_contains_enum(ann: Any) -> bool:
    """True if ``ann`` references at least one ``Enum`` subclass."""
    if inspect.isclass(ann) and issubclass(ann, Enum):
        return True
    if typing.get_origin(ann) is None:
        return False
    return any(_annotation_contains_enum(a) for a in typing.get_args(ann))


def _loosen_class_enums(cls: type) -> tuple[int, int]:
    """Drop strict validators and loosen Enum fields on one model class.

    Returns ``(validators_dropped, fields_loosened)``.
    """
    # A. Drop any *_validate_enum field validators.
    validators_dropped = 0
    if hasattr(cls, "__pydantic_decorators__"):
        field_validators = cls.__pydantic_decorators__.field_validators
        for name in list(field_validators.keys()):
            if name.endswith("_validate_enum"):
                del field_validators[name]
                validators_dropped += 1

    # B. Walk every model field; if its annotation references an Enum,
    #    replace the Enum with str (preserving any Optional/List wrappers).
    fields_loosened = 0
    for fname, finfo in cls.model_fields.items():
        if not _annotation_contains_enum(finfo.annotation):
            continue
        finfo.annotation = _replace_enum_in_annotation(finfo.annotation)
        fields_loosened += 1

    if validators_dropped or fields_loosened:
        cls.model_rebuild(force=True)
    return validators_dropped, fields_loosened


def _iter_okta_model_classes():
    """Yield every Pydantic BaseModel subclass under ``okta.models.*``."""
    # Force-import every submodule so we see lazy-loaded model classes.
    for _, mod_name, _ in pkgutil.iter_modules(okta.models.__path__, prefix="okta.models."):
        try:
            importlib.import_module(mod_name)
        except Exception:
            # Some sub-modules in older SDK builds are broken; skip them
            # rather than fail-fast at server start.
            pass

    seen: set[type] = set()
    for name, mod in list(sys.modules.items()):
        if not name.startswith("okta.models"):
            continue
        for attr in dir(mod):
            obj = getattr(mod, attr, None)
            if (
                inspect.isclass(obj)
                and issubclass(obj, BaseModel)
                and obj is not BaseModel
                and obj not in seen
            ):
                seen.add(obj)
                yield obj


def _sweep_strict_enums() -> tuple[int, int, int]:
    """Run the generic enum loosening across every Okta model.

    Returns ``(classes_touched, validators_dropped, fields_loosened)``.
    """
    classes_touched = 0
    validators_dropped = 0
    fields_loosened = 0
    for cls in _iter_okta_model_classes():
        v, f = _loosen_class_enums(cls)
        if v or f:
            classes_touched += 1
            validators_dropped += v
            fields_loosened += f
    return classes_touched, validators_dropped, fields_loosened


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def apply_patches() -> None:
    """Apply all SDK patches. Called at server startup."""
    # Patch 1: surgical fix to Policy._embedded type (not an enum issue).
    from okta.models.policy import Policy  # imported lazily for clarity

    relaxed = []
    if _relax_policy_embedded(Policy):
        relaxed.append(Policy.__name__)
    for sub in Policy.__subclasses__():
        if _relax_policy_embedded(sub):
            relaxed.append(sub.__name__)
    if relaxed:
        logger.info(
            "[sdk-patches] Loosened Policy._embedded on {} class(es): {}",
            len(relaxed),
            relaxed,
        )

    # Patch 2: generic enum sweep across all loaded Okta models.
    classes, validators, fields = _sweep_strict_enums()
    logger.info(
        "[sdk-patches] Enum sweep: touched {} class(es); "
        "dropped {} strict validator(s); loosened {} Enum-typed field(s).",
        classes,
        validators,
        fields,
    )


apply_patches()
