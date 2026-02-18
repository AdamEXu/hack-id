import os
from pathlib import Path

os.environ.setdefault("SECRET_KEY", "test-secret")

from flask import Flask
import routes.auth as auth_routes


def create_auth_app():
    template_dir = Path(__file__).resolve().parents[1] / "templates"
    app = Flask(__name__, template_folder=str(template_dir))
    app.secret_key = "test-secret"
    app.jinja_env.globals["csrf_token"] = lambda: "test-csrf"
    app.register_blueprint(auth_routes.auth_bp)
    return app


def test_index_unauthenticated_renders_login_page():
    app = create_auth_app()
    client = app.test_client()

    response = client.get("/")

    assert response.status_code == 200
    assert b"Sign in" in response.data


def test_auth_google_redirects_to_google_provider(monkeypatch):
    app = create_auth_app()
    client = app.test_client()
    monkeypatch.setattr(
        auth_routes,
        "get_google_auth_url",
        lambda: "https://accounts.google.com/o/oauth2/auth?state=test",
    )

    response = client.get("/auth/google")

    assert response.status_code == 302
    assert response.location.startswith("https://accounts.google.com/o/oauth2/auth")


def test_auth_google_callback_rejects_invalid_state():
    app = create_auth_app()
    client = app.test_client()

    with client.session_transaction() as sess:
        sess["oauth_state"] = "expected-state"

    response = client.get("/auth/google/callback?state=wrong-state&code=abc")

    assert response.status_code == 200
    assert b"Invalid OAuth state" in response.data


def test_send_code_json_requires_email():
    app = create_auth_app()
    client = app.test_client()

    response = client.post("/send-code", json={})

    assert response.status_code == 200
    assert response.get_json()["success"] is False
    assert response.get_json()["error"] == "Email is required"


def test_send_code_json_success(monkeypatch):
    app = create_auth_app()
    client = app.test_client()

    monkeypatch.setattr(auth_routes, "send_email_verification", lambda _email: True)

    response = client.post("/send-code", json={"email": "test@example.com"})

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["success"] is True
    assert "Magic link sent" in payload["message"]


def test_email_callback_without_code_returns_error():
    app = create_auth_app()
    client = app.test_client()

    response = client.get("/auth/email/callback")

    assert response.status_code == 200
    assert b"No code provided" in response.data


def test_email_callback_logs_in_existing_user(monkeypatch):
    app = create_auth_app()
    client = app.test_client()

    monkeypatch.setattr(
        auth_routes,
        "verify_email_code",
        lambda _code: {"success": True, "email": "test@example.com", "name": "Test User"},
    )
    monkeypatch.setattr(
        auth_routes,
        "get_user_by_email",
        lambda _email: {"email": "test@example.com", "legal_name": "Test User", "preferred_name": ""},
    )

    response = client.get("/auth/email/callback?code=valid-code")

    assert response.status_code == 302
    assert response.location.endswith("/")
    with client.session_transaction() as sess:
        assert sess["user_email"] == "test@example.com"


def test_oauth_authorize_missing_required_params_shows_error():
    app = create_auth_app()
    client = app.test_client()

    response = client.get("/oauth/authorize")

    assert response.status_code == 200
    assert b"Missing required OAuth parameters" in response.data


def test_oauth_authorize_unauthenticated_user_sees_login(monkeypatch):
    app = create_auth_app()
    client = app.test_client()

    monkeypatch.setattr(
        auth_routes,
        "get_app_by_client_id",
        lambda _client_id: {
            "id": "app_1",
            "is_active": True,
            "redirect_uris": '["https://example.com/callback"]',
            "allowed_scopes": '["profile", "email"]',
            "allow_anyone": True,
        },
    )
    monkeypatch.setattr(auth_routes, "validate_redirect_uri", lambda _uri, _allowed: True)

    response = client.get(
        "/oauth/authorize?client_id=client_1&redirect_uri=https://example.com/callback&scope=profile%20email&response_type=code"
    )

    assert response.status_code == 200
    assert b"Sign in" in response.data


def test_oauth_authorize_logged_in_with_skip_consent_redirects_with_code(monkeypatch):
    app = create_auth_app()
    client = app.test_client()

    monkeypatch.setattr(
        auth_routes,
        "get_app_by_client_id",
        lambda _client_id: {
            "id": "app_1",
            "is_active": True,
            "redirect_uris": '["https://example.com/callback"]',
            "allowed_scopes": '["profile", "email"]',
            "allow_anyone": True,
            "skip_consent_screen": True,
        },
    )
    monkeypatch.setattr(auth_routes, "validate_redirect_uri", lambda _uri, _allowed: True)
    monkeypatch.setattr(
        auth_routes,
        "get_user_by_email",
        lambda _email: {"email": "test@example.com", "legal_name": "Test User"},
    )
    monkeypatch.setattr(auth_routes, "create_authorization_code", lambda **_kwargs: "auth-code-123")

    with client.session_transaction() as sess:
        sess["user_email"] = "test@example.com"

    response = client.get(
        "/oauth/authorize?client_id=client_1&redirect_uri=https://example.com/callback&scope=profile%20email&state=abc&response_type=code"
    )

    assert response.status_code == 302
    assert response.location == "https://example.com/callback?code=auth-code-123&state=abc"


def test_oauth_authorize_consent_denied_redirects_with_access_denied(monkeypatch):
    app = create_auth_app()
    client = app.test_client()

    monkeypatch.setattr(
        auth_routes,
        "get_app_by_client_id",
        lambda _client_id: {"id": "app_1", "is_active": True, "allow_anyone": True},
    )

    with client.session_transaction() as sess:
        sess["user_email"] = "test@example.com"
        sess["oauth2_client_id"] = "client_1"
        sess["oauth2_redirect_uri"] = "https://example.com/callback"
        sess["oauth2_scope"] = "profile email"
        sess["oauth2_state"] = "xyz"

    response = client.post("/oauth/authorize", data={"action": "deny"})

    assert response.status_code == 302
    assert response.location == "https://example.com/callback?error=access_denied&state=xyz"
