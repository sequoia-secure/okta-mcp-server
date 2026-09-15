# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""
Unit tests for the SDK patches applied to the upstream Okta Python SDK.

``sdk_patches`` is only imported lazily inside ``server.py``'s startup
path (deliberately, so it runs before any ``tools/*`` module touches the
SDK) — plain ``import okta_mcp_server`` does not trigger it. Tests that
exercise patched model behavior must import it explicitly, as done below;
applying the patches more than once is a no-op (model_rebuild is
idempotent), so this is safe regardless of what else has already run.
"""

from okta.models.access_policy import AccessPolicy
from okta.models.saml_application import SamlApplication

import okta_mcp_server.utils.sdk_patches  # noqa: F401  (applies patches on import)


class TestRequiredBoolSweep:
    """Regression tests for Patch 3 (required bool fields the live API omits).

    First observed 2026-09-15: ``application.get`` on a legacy SAML app
    (Egnyte) threw ``4 validation errors for SamlApplication`` because
    ``settings.signOn`` declares five boolean flags as required with no
    default, and the live app config omitted four of them.
    """

    def _minimal_saml_app(self, **sign_on_overrides):
        sign_on = {
            "ssoAcsUrl": "https://example.egnyte.com/sso",
            "idpIssuer": "http://www.okta.com/xyz",
            "audience": "https://example.egnyte.com",
            "recipient": "https://example.egnyte.com/sso",
            "destination": "https://example.egnyte.com/sso",
            "subjectNameIdTemplate": "${user.userName}",
            "subjectNameIdFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
            "attributeStatements": [],
            **sign_on_overrides,
        }
        return {
            "id": "0oaTestApp00000000001",
            "name": "egnyte",
            "label": "Egnyte",
            "status": "ACTIVE",
            "signOnMode": "SAML_2_0",
            "settings": {"app": {}, "notifications": {}, "signOn": sign_on},
        }

    def test_saml_app_with_all_sign_on_bools_omitted(self):
        """The exact failure shape: none of the five bool flags present."""
        app = SamlApplication.from_dict(self._minimal_saml_app())

        assert app.settings.sign_on.allow_multiple_acs_endpoints is None
        assert app.settings.sign_on.assertion_signed is None
        assert app.settings.sign_on.honor_force_authn is None
        assert app.settings.sign_on.request_compressed is None
        assert app.settings.sign_on.response_signed is None

    def test_saml_app_preserves_explicit_bool_values(self):
        """A present flag's real value must survive, not just the omitted case."""
        app = SamlApplication.from_dict(
            self._minimal_saml_app(
                honorForceAuthn=False,
                assertionSigned=True,
                responseSigned=True,
            )
        )

        assert app.settings.sign_on.honor_force_authn is False
        assert app.settings.sign_on.assertion_signed is True
        assert app.settings.sign_on.response_signed is True
        # still omitted -> still None, not defaulted to False
        assert app.settings.sign_on.allow_multiple_acs_endpoints is None
        assert app.settings.sign_on.request_compressed is None

    def test_sweep_does_not_affect_unrelated_required_fields(self):
        """The sweep must only touch bare-bool fields, not other required ones."""
        # AccessPolicy has non-bool required fields (e.g. type/status via
        # its base Policy class); constructing one with those present but
        # with no bool fields supplied should still fail if a genuinely
        # required non-bool field is missing, proving the sweep is scoped
        # to `bool` and hasn't turned every required field optional.
        import pytest
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            AccessPolicy.model_validate({})
