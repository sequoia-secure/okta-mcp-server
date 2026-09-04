# Changelog
All notable changes to this project will be documented in this file.

## Unreleased

### Features
- Added session-revocation tooling in `tools/universallogout/`, so "sign this person out of Okta" is one tool call rather than two the caller has to know to combine:
  - `logout_user` — runs both Okta revocations for one user: `revoke_user_sessions` (Okta IdP sessions + issued OIDC/OAuth tokens, with optional `forget_devices`) and `revoke_user_grants` (OAuth consent grants). Neither subsumes the other: `revoke_user_sessions` does not touch consent grants, and revoking grants does not end sessions. Both steps run even if the first fails, and each step's outcome is reported separately, so a partial logout is never reported as a clean one.
  - `logout_group` — fans `logout_user` out across the members of an Okta group, for incident response against a defined population. Members are enumerated and counted **before** the confirmation prompt so the operator approves a blast radius rather than a group ID; groups above 500 members are refused; members are processed `LOGOUT_CONCURRENCY`-at-a-time to stay inside Okta's per-org rate limits; and one member failing neither stops the others nor is lost from the report. All revocations are idempotent, so re-running for the failures is safe.
  - `confirm_logout_group` — deprecated two-tool fallback for clients without elicitation support, matching the existing `confirm_delete_group` pattern.

  Universal Logout is deliberately **not** wired into these tools — see below.

### Security
- **Fixed the required scope on `global_logout_user`.** It was gated on `okta.users.manage`, but `POST /oauth2/v1/global-token-revocation` is gated on `okta.universalLogout.manage` (see [OAuth 2.0 Scopes](https://developer.okta.com/docs/api/oauth2)). The tool was therefore advertised to — and prunable only by — the wrong scope: a token with `okta.users.manage` but not `okta.universalLogout.manage` saw the tool in `tools/list` and got a 403 from Okta on call, while a token holding exactly the right scope had the tool pruned away at startup. Both the `@require_scopes` decorator and `TOOL_SCOPE_REGISTRY` now name `okta.universalLogout.manage`.
- `logout_group` deliberately does **not** auto-confirm when the client lacks elicitation support, unlike `logout_user` / `global_logout_user`. Auto-confirming is a defensible default for one named user; extending it to a group would mean a client that merely fails to advertise the elicitation capability silently signs out everyone in it. It returns the `confirm_logout_group` prompt instead.
- The SCIM filter escaping already applied to `global_logout_user`'s `login` is now a shared `_escape_scim` helper used by every login resolution in the module, so the new tools cannot regress it.

### Known limitations
- **Universal Logout is not part of `logout_user` / `logout_group`.** `revoke_user_sessions` explicitly does not clear sessions created for web or native apps; closing that gap requires the Global Token Revocation endpoint, whose `okta.universalLogout.manage` scope ships with Okta Identity Threat Protection. An org without ITP does not advertise that scope in `/.well-known/oauth-authorization-server`, so its org authorization server rejects a client-credentials token request for it with `invalid_scope` — it cannot be enabled by editing `OKTA_SCOPES` and granting it in the Admin Console. Rather than carry a step that can never run on such an org, the group and per-user tools omit it entirely; `global_logout_user` remains as the standalone tool for orgs that do license ITP, and is pruned at startup elsewhere.
- `logout_group` deliberately does **not** auto-confirm when the client lacks elicitation support, unlike `logout_user` / `global_logout_user`. Auto-confirming is a defensible default for one named user; extending it to a group would mean a client that merely fails to advertise the elicitation capability silently signs out everyone in it. It returns the `confirm_logout_group` prompt instead.
- The SCIM filter escaping already applied to `global_logout_user`'s `login` is now factored into a shared `_escape_scim` helper used by every login resolution in the module, so the new tools cannot regress it.

### Bug Fixes
- Revocation calls now read the SDK error via `result[-1]` rather than unpacking three names. The generated Okta SDK returns a 3-tuple `(None, resp, None)` on 204 but 2-tuples `(None, error)` / `(response, error)` on its two failure paths, so a three-name unpack raises `ValueError` on exactly the paths the caller wrote it to handle. This matches the idiom already used in `groups.py`.

### Documentation
- Documented the sign-out tools, the three-operation distinction, and the `okta.universalLogout.manage` scope in the README — `global_logout_user` had never been documented there.

## v1.1.5

### Security
- Bumped vulnerable dependencies and pinned the Docker base images by digest to raise the Docker Scout health score of the published `mcp/okta-mcp-server` image ([#94](https://github.com/okta/okta-mcp-server/pull/94)):
  - Raised the `mcp[cli]` SDK floor to **1.28.1**.
  - Added `[tool.uv]` `constraint-dependencies` floors for `urllib3>=2.7.0`, `cryptography>=48.0.1`, `starlette>=1.3.1`, `python-multipart>=0.0.31`, `click>=8.3.3`, `jaraco.context>=6.1.0`, `python-dotenv>=1.2.2`, and `idna>=3.15` to close the CVEs Docker Scout flagged transitively.
  - Pinned both Dockerfile base images by digest for reproducibility: `python:3.13-slim` and `ghcr.io/astral-sh/uv:0.11.31` (uv 0.11.31 carries the quick-xml 0.41.0 fix for RUSTSEC-2026-0194/0195).
  - Result: Docker Scout Critical/High/Medium dropped from 1/21/13 to only the residual base-image `perl` CVEs (no upstream fix available yet). All 529 existing tests pass unchanged.

### Improvements
- Upgraded the `pytest` dev dependency floor to **9.0.3**.

### Documentation
- Updated the logo thumbnail image ([#97](https://github.com/okta/okta-mcp-server/pull/97)).

## v1.1.4

### Documentation
- Renamed the self-hosted server to **"Okta Open Source MCP Server"** and updated all existing references from "Okta MCP Server" to "Okta Open Source MCP Server" ([#91](https://github.com/okta/okta-mcp-server/pull/91)).

### Bug Fixes
- Standardized MCP tool responses to valid JSON per RFC 8259 across all 109 tools; fixes [#14](https://github.com/okta/okta-mcp-server/issues/14). Tool responses no longer leak raw Python `repr` for `ApplicationSignOnMode.SAML_2_0`, `OktaAPIResponse` objects, SDK tuples, or other non-JSON types.
- Standardized error return shape for `@validate_ids` / `@validate_os_version_params` and every tool that previously emitted `[f"Error: {e}"]` — errors are now returned as `[{"error": "..."}]` / `[{"exception": "..."}]` so callers always parse valid JSON.
- Fixed `create_custom_domain` and `create_email_domain` to handle Okta's 204 / empty-body response by refetching the newly created resource via `list_custom_domains` / `list_email_domains`. FQDN comparison is case-insensitive per RFC 1035, applied consistently across **both** the pre-create duplicate check and the post-create refetch lookup in **both** tools (all four comparisons were audited; the email-domains fallback and both modules' duplicate-check loops were previously case-sensitive).
- Fixed the `create_email_customization` duplicate-language pre-check in `custom_templates.py` to compare BCP 47 (RFC 5646) language tags case-insensitively, matching the FQDN fix above.
- Extended the `(None, response, None)` empty-body guard — previously applied only to the customization tool family — to every other `get_*`/`create_*`/`update_*`/`replace_*`/`verify_*` tool that unpacks an Okta SDK 3-tuple and dereferences the result: `applications.py` (`get_application`, `create_application`, `update_application`), `groups.py` (`get_group`, `create_group`, `update_group`), `users.py` (`get_user`, `create_user`, `update_user`), `policies.py` (all 6 of `get_policy`, `create_policy`, `update_policy`, `get_policy_rule`, `create_policy_rule`, `update_policy_rule`), `device_assurance.py` (`get_device_assurance_policy`, `create_device_assurance_policy`, `replace_device_assurance_policy` — the latter two previously returned bare `None` instead of an error dict), and `custom_domains.py` (`verify_custom_domain`). Two of these (`groups.create_group`, `users.create_user`) previously crashed with an unguarded `AttributeError` on `group.id` / `user.id` when the SDK quirk fired, masked into a confusing `{"exception": "'NoneType' object has no attribute 'id'"}`.
- Fixed the dynamically-registered scope-info stub tools in `utils/scope_stubs.py` (registered via `mcp.tool()(stub_fn)` rather than `@mcp.tool()` decorator syntax) to also pass through `@json_response` — previously the only MCP-tool-registered callables in the server that bypassed the single JSON boundary.

### Improvements
- Added `okta_mcp_server.utils.serialization` as the single normalization boundary for tool returns. `to_jsonable()` flattens Pydantic v2 models (`model_dump(by_alias=True, exclude_none=True, mode="json")`), Okta SDK v2 models (`to_dict()`), `Enum` values (`.value`), and drops transport-only `OktaAPIResponse` / `ApiResponse` objects. `Enum` unwrapping is checked before the scalar branch so `(str, Enum)` / `(int, Enum)` mixins (e.g. `ApplicationSignOnMode`) serialize to their `.value`.
- Added `@json_response` decorator, applied innermost on every `@mcp.tool` so every response passes through the canonical serializer exactly once. Note: the decorator catches *any* exception raised while running the wrapped tool, not only a serialization failure — see the module and decorator docstrings in `serialization.py` for the resulting `isError=False` tradeoff.
- Added `okta_mcp_server.utils.serialization.none_body_error()`, a shared helper for the `(None, response, None)` guard above — builds the `{"error": "..."}` envelope and logs a warning in one call instead of repeating the same six lines at every call site.
- Added a structured failure envelope (`{"ok": false, "error": {...}, "status_code": null, "raw": {}}`) returned when serialization itself raises, so callers always receive valid JSON. The full traceback is written to the server log via `logger.exception`; the last 4096 chars can additionally be surfaced to the caller as `raw.traceback_tail` by setting `OKTA_MCP_INCLUDE_RAW=1` (accepted truthy values: `1`, `true`, `yes`, `on`). Default is off to avoid leaking server-side stack frames to MCP clients.
- Centralized JSON normalization in `create_paginated_response()` — the paginated payload is returned untouched and flattened once by the outer `@json_response` decorator, removing the redundant lazy import back into `serialization.py`.
- Removed redundant per-tool `_serialize_*` helpers in `brands.py`, `custom_domains.py`, `email_domains.py`, and `themes.py`. `custom_templates.py` intentionally retains its local `_serialize()` helper because the SDK's `to_dict()` drops server-readOnly preview fields (e.g. `EmailPreview.body`, `.subject`) that `model_dump()` preserves. `custom_pages.py` retains its helper to preserve the legacy `{}` return for legitimate empty-body responses on preview endpoints; the helper now uses `mode="json"` so nested `datetime` / `UUID` / `Enum` fields still meet the RFC 3339 guarantee.
- Reworked `create_device_assurance_policy` and `replace_device_assurance_policy` so `policy_data` is typed as `Dict[str, Any]` at the FastMCP boundary and any `PolicyDataInput` validation error is surfaced as `{"error": "..."}` instead of leaking a plain-text `pydantic.ValidationError`.
- Added `tests/test_serialization.py` (44 tests), `tests/test_custom_domains.py` (7 tests), `tests/test_none_body_guards.py` (28 tests, covering all None-body guards across 9 modules), and `tests/test_scope_stubs.py` (4 tests). Extended `tests/test_device_assurance.py` (136 tests total) and `tests/test_custom_templates.py` (51 tests total).

## v1.1.3

### Bug Fixes
- Upgraded Okta SDK from **3.4.1 → 3.4.4** to fix an upstream deserialization error on `GET /api/v1/policies/{policyId}/rules`. The 3.4.1 SDK modeled the `AccessPolicyConstraint.methods` / `AccessPolicyConstraint.types` enums as uppercase-only (`PASSWORD`, `PUSH`, `SECURITY_KEY`, …), while the live API returns lowercase values (`password`, `push`, `security_key`, …), causing the `list_policy_rules` MCP tool to fail on Access Policy rules that carry authenticator constraints.

## v1.1.2

### Features
- PyPI Release changes

## v1.1.1

### Features
- GA Release changes

## v1.1.0

### Features
- Added Device Assurance Policy tools (`list_device_assurance_policies`, `get_device_assurance_policy`, `create_device_assurance_policy`, `replace_device_assurance_policy`, `delete_device_assurance_policy`) with support for Android, iOS, macOS, Windows, and ChromeOS platforms.
- Upgraded Okta SDK dependency to v3.4.1.
- Added customization tools for brands, custom domains, custom pages, custom templates, email domains, and themes.
- Added scope-based tool loading — tools are now dynamically enabled based on the OAuth scopes available to the configured API token.
- Added `login_failures` system log tool for querying recent authentication failures.

### Bug Fixes
- Fixed pagination bug introduced by Okta SDK v3 upgrade.
- Fixed `add_user_to_group` to be idempotent (no longer errors if user is already a member).
- Fixed `get_logs` to support filtering by `DENY` outcome.
- Added `fetch_all` support to `list_applications`.

### Improvements
- Pagination improvements with better handling of large result sets.

## v1.0.0

- Initial release of the self hosted okta-mcp-server.
