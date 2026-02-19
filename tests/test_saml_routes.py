import os

import pytest

os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("WORKOS_API_KEY", "test-workos-key")
os.environ.setdefault("WORKOS_CLIENT_ID", "test-workos-client")

import app as app_module  # noqa: E402
from routes import saml as saml_routes  # noqa: E402


def _admin_session(client):
    with client.session_transaction() as flask_session:
        flask_session["user_email"] = "admin@example.com"
        flask_session["user_name"] = "Admin"


@pytest.fixture
def client(monkeypatch):
    app = app_module.app
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False

    monkeypatch.setattr("routes.admin.is_admin", lambda _email: True)
    monkeypatch.setattr(
        "routes.admin.has_page_permission",
        lambda _email, _page_name, _access_level="read": True,
    )
    monkeypatch.setattr(
        "routes.admin.write_universal_admin_snapshot",
        lambda _email, _session: True,
    )
    monkeypatch.setattr(
        "models.user.get_user_by_email",
        lambda _email: {
            "email": "admin@example.com",
            "preferred_name": "Admin",
            "legal_name": "Admin User",
            "pronouns": "they/them/theirs",
            "dob": "01/01/2000",
            "events": [],
        },
    )
    return app.test_client()


def test_saml_metadata_endpoint_public(client):
    response = client.get("/saml/metadata")
    assert response.status_code == 200
    assert b"EntityDescriptor" in response.data


def test_saml_continue_without_pending_redirects_home(client):
    response = client.get("/saml/continue")
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/")


def test_admin_rejects_allow_anyone_for_saml_app(client):
    _admin_session(client)

    response = client.post(
        "/admin/apps",
        json={
            "name": "SAML app",
            "app_type": "saml",
            "allow_anyone": True,
            "saml_entity_id": "https://sp.example.com/metadata",
            "saml_acs_url": "https://sp.example.com/acs",
        },
    )

    assert response.status_code == 400
    payload = response.get_json()
    assert payload["success"] is False
    assert "allow_anyone" in payload["error"]


def test_admin_rejects_saml_fields_for_oauth_app(client):
    _admin_session(client)

    response = client.post(
        "/admin/apps",
        json={
            "name": "OAuth app",
            "app_type": "oauth",
            "redirect_uris": ["https://app.example.com/callback"],
            "allowed_scopes": ["profile", "email"],
            "saml_entity_id": "https://sp.example.com/metadata",
        },
    )

    assert response.status_code == 400
    payload = response.get_json()
    assert payload["success"] is False
    assert "cannot include SAML fields" in payload["error"]


def test_saml_launch_same_site_accepts_base_url_origin(monkeypatch):
    monkeypatch.setattr(saml_routes, "BASE_URL", "https://id.hack.sv")

    with app_module.app.test_request_context(
        "/saml/apps/recdQ9A46ledCePmMlQ/launch",
        method="POST",
        base_url="http://internal:3000",
        headers={"Origin": "https://id.hack.sv"},
    ):
        assert saml_routes._same_site_request() is True


def test_saml_launch_same_site_accepts_forwarded_origin():
    with app_module.app.test_request_context(
        "/saml/apps/recdQ9A46ledCePmMlQ/launch",
        method="POST",
        base_url="http://internal:3000",
        headers={
            "Origin": "https://id.hack.sv",
            "X-Forwarded-Proto": "https",
            "X-Forwarded-Host": "id.hack.sv",
        },
    ):
        assert saml_routes._same_site_request() is True


def test_saml_launch_same_site_rejects_cross_origin():
    with app_module.app.test_request_context(
        "/saml/apps/recdQ9A46ledCePmMlQ/launch",
        method="POST",
        base_url="https://id.hack.sv",
        headers={"Origin": "https://evil.example"},
    ):
        assert saml_routes._same_site_request() is False
