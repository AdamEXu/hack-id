import os
from contextlib import contextmanager

import pytest

os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("WORKOS_API_KEY", "test-workos-key")
os.environ.setdefault("WORKOS_CLIENT_ID", "test-workos-client")

from services import saml_service  # noqa: E402


def _sample_app():
    return {
        "id": "app_123",
        "saml_entity_id": "https://sp.example.com/metadata",
        "saml_acs_url": "https://sp.example.com/saml/acs",
        "saml_nameid_format": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        "saml_attribute_mapping_obj": [
            {
                "source_field": "email",
                "saml_name": "email",
                "required": True,
                "multi_valued": False,
                "transform": "identity",
            }
        ],
    }


def _sample_user():
    return {
        "email": "admin@example.com",
        "preferred_name": "Admin",
        "legal_name": "Admin User",
        "pronouns": "they/them/theirs",
        "dob": "01/01/2000",
        "events": [],
    }


def test_idp_initiated_response_uses_unsolicited_in_response_to_none(monkeypatch):
    captured_kwargs = {}

    class FakeServer:
        def create_authn_response(self, **kwargs):
            captured_kwargs.update(kwargs)
            return "<Response xmlns:saml2='urn:oasis:names:tc:SAML:2.0:assertion'/>"

    @contextmanager
    def fake_idp_server(_app):
        yield FakeServer()

    monkeypatch.setattr(saml_service, "_idp_server_for_app", fake_idp_server)
    monkeypatch.setattr(saml_service, "get_user_by_email", lambda _email: _sample_user())
    monkeypatch.setattr(saml_service, "record_sp_session", lambda **_kwargs: None)
    monkeypatch.setattr(saml_service, "log_saml_event", lambda **_kwargs: None)

    payload = saml_service.create_idp_initiated_response(
        app=_sample_app(),
        user_email="admin@example.com",
        relay_state="relay-123",
    )

    assert "in_response_to" in captured_kwargs
    assert captured_kwargs["in_response_to"] is None
    assert payload["destination"] == "https://sp.example.com/saml/acs"
    assert payload["relay_state"] == "relay-123"


def test_idp_initiated_response_wraps_server_errors(monkeypatch):
    class FakeServer:
        def create_authn_response(self, **_kwargs):
            raise TypeError("missing required positional argument")

    @contextmanager
    def fake_idp_server(_app):
        yield FakeServer()

    monkeypatch.setattr(saml_service, "_idp_server_for_app", fake_idp_server)
    monkeypatch.setattr(saml_service, "get_user_by_email", lambda _email: _sample_user())
    monkeypatch.setattr(saml_service, "record_sp_session", lambda **_kwargs: None)
    monkeypatch.setattr(saml_service, "log_saml_event", lambda **_kwargs: None)

    with pytest.raises(saml_service.SamlProtocolError, match="Failed to create IdP-initiated SAML response"):
        saml_service.create_idp_initiated_response(
            app=_sample_app(),
            user_email="admin@example.com",
            relay_state="relay-err",
        )


def test_apply_transform_name_splitting():
    values = ["Adam Xu"]

    assert saml_service._apply_transform(values, "first_word") == ["Adam"]
    assert saml_service._apply_transform(values, "rest_words") == ["Xu"]
