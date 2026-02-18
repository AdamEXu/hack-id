import os
from pathlib import Path

os.environ.setdefault("SECRET_KEY", "test-secret")

from flask import Flask
import routes.auth as auth_routes


def create_oauth_app():
    template_dir = Path(__file__).resolve().parents[1] / "templates"
    app = Flask(__name__, template_folder=str(template_dir))
    app.secret_key = "test-secret"
    app.jinja_env.globals["csrf_token"] = lambda: "test-csrf"
    app.register_blueprint(auth_routes.auth_bp)
    app.register_blueprint(auth_routes.oauth_bp)
    return app


def test_oauth_token_rejects_unsupported_grant_type():
    app = create_oauth_app()
    client = app.test_client()

    response = client.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "code": "abc",
            "redirect_uri": "https://example.com/callback",
            "client_id": "client_1",
            "client_secret": "secret_1",
        },
    )

    assert response.status_code == 400
    payload = response.get_json()
    assert payload["error"] == "unsupported_grant_type"


def test_oauth_token_requires_all_parameters():
    app = create_oauth_app()
    client = app.test_client()

    response = client.post("/oauth/token", data={"grant_type": "authorization_code"})

    assert response.status_code == 400
    payload = response.get_json()
    assert payload["error"] == "invalid_request"


def test_oauth_token_returns_access_token_payload(monkeypatch):
    app = create_oauth_app()
    client = app.test_client()

    monkeypatch.setattr(
        auth_routes,
        "exchange_code_for_token",
        lambda code, client_id, client_secret, redirect_uri: {
            "success": True,
            "access_token": "access_123",
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": "profile email",
        },
    )

    response = client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": "code_123",
            "redirect_uri": "https://example.com/callback",
            "client_id": "client_1",
            "client_secret": "secret_1",
        },
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["access_token"] == "access_123"
    assert payload["token_type"] == "Bearer"


def test_oauth_token_maps_invalid_grant_error(monkeypatch):
    app = create_oauth_app()
    client = app.test_client()

    monkeypatch.setattr(
        auth_routes,
        "exchange_code_for_token",
        lambda code, client_id, client_secret, redirect_uri: {
            "success": False,
            "error": "invalid_grant",
        },
    )

    response = client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": "expired_code",
            "redirect_uri": "https://example.com/callback",
            "client_id": "client_1",
            "client_secret": "secret_1",
        },
    )

    assert response.status_code == 400
    payload = response.get_json()
    assert payload["error"] == "invalid_grant"
    assert "expired" in payload["error_description"]


def test_oauth_revoke_requires_token():
    app = create_oauth_app()
    client = app.test_client()

    response = client.post("/oauth/revoke", data={})

    assert response.status_code == 400
    assert response.get_json()["error"] == "invalid_request"


def test_oauth_revoke_returns_success_even_for_invalid_tokens(monkeypatch):
    app = create_oauth_app()
    client = app.test_client()

    monkeypatch.setattr(auth_routes, "revoke_access_token", lambda _token: False)

    response = client.post("/oauth/revoke", data={"token": "already-invalid"})

    assert response.status_code == 200
    assert response.get_json()["success"] is True


def test_oauth_legacy_requires_redirect_parameter():
    app = create_oauth_app()
    client = app.test_client()

    response = client.get("/oauth")

    assert response.status_code == 200
    assert b"Missing redirect parameter" in response.data


def test_oauth_legacy_rejects_unregistered_redirect(monkeypatch):
    app = create_oauth_app()
    client = app.test_client()

    monkeypatch.setattr(auth_routes, "validate_app_redirect", lambda _redirect: None)

    response = client.get("/oauth?redirect=https://example.com/callback")

    assert response.status_code == 200
    assert b"Invalid redirect URL" in response.data


def test_oauth_legacy_logged_in_user_redirects_with_token(monkeypatch):
    app = create_oauth_app()
    client = app.test_client()

    monkeypatch.setattr(
        auth_routes,
        "validate_app_redirect",
        lambda _redirect: {"id": "app_1", "is_active": True, "allow_anyone": True},
    )
    monkeypatch.setattr(
        auth_routes,
        "get_user_by_email",
        lambda _email: {"email": "test@example.com", "legal_name": "Test User"},
    )
    monkeypatch.setattr(auth_routes, "create_oauth_token", lambda _email, expires_in_seconds: "oauth_token_123")

    with client.session_transaction() as sess:
        sess["user_email"] = "test@example.com"

    response = client.get("/oauth?redirect=https://example.com/callback")

    assert response.status_code == 302
    assert response.location == "https://example.com/callback?token=oauth_token_123"


def test_logout_clears_session_and_redirects_home():
    app = create_oauth_app()
    client = app.test_client()

    with client.session_transaction() as sess:
        sess["user_email"] = "test@example.com"
        sess["user_name"] = "Tester"

    response = client.get("/logout")

    assert response.status_code == 302
    assert response.location.endswith("/")

    with client.session_transaction() as sess:
        assert "user_email" not in sess
        assert "user_name" not in sess
