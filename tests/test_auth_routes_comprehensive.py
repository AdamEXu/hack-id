import os
from pathlib import Path

os.environ.setdefault("SECRET_KEY", "test-secret")

from flask import Flask

import routes.auth as auth_routes


def create_auth_app(register_oauth=False):
    template_dir = Path(__file__).resolve().parents[1] / "templates"
    app = Flask(__name__, template_folder=str(template_dir))
    app.secret_key = "test-secret"
    app.jinja_env.globals["csrf_token"] = lambda: "test-csrf"
    app.register_blueprint(auth_routes.auth_bp)
    if register_oauth:
        app.register_blueprint(auth_routes.oauth_bp)
    return app


def login_session(client, email="test@example.com", name="Tester"):
    with client.session_transaction() as sess:
        sess["user_email"] = email
        sess["user_name"] = name


def oauth2_session(client):
    with client.session_transaction() as sess:
        sess["oauth2_client_id"] = "client_1"
        sess["oauth2_redirect_uri"] = "https://example.com/callback"
        sess["oauth2_scope"] = "profile email"
        sess["oauth2_state"] = "abc"


def test_index_logged_in_profile_incomplete_redirects_to_register(monkeypatch):
    app = create_auth_app()
    client = app.test_client()
    login_session(client)

    monkeypatch.setattr("models.admin.is_admin", lambda _email: False)
    monkeypatch.setattr(
        "services.dashboard_service.get_user_dashboard_data",
        lambda _email: {"profile_complete": False},
    )

    response = client.get("/")

    assert response.status_code == 302
    assert response.location.endswith("/register")


def test_index_logged_in_profile_complete_renders_dashboard(monkeypatch):
    app = create_auth_app()
    client = app.test_client()
    login_session(client)

    monkeypatch.setattr("models.admin.is_admin", lambda _email: True)
    monkeypatch.setattr(
        "services.dashboard_service.get_user_dashboard_data",
        lambda _email: {"profile_complete": True},
    )
    monkeypatch.setattr(
        auth_routes,
        "render_template",
        lambda template, **ctx: f"{template}:{ctx.get('is_admin')}",
    )

    response = client.get("/")

    assert response.status_code == 200
    assert b"dashboard.html:True" in response.data


def test_auth_google_callback_missing_code_renders_error():
    app = create_auth_app()
    client = app.test_client()

    with client.session_transaction() as sess:
        sess["oauth_state"] = "state-1"

    response = client.get("/auth/google/callback?state=state-1")

    assert response.status_code == 200
    assert b"No authentication code received" in response.data


def test_auth_google_callback_provider_error_renders_error(monkeypatch):
    app = create_auth_app()
    client = app.test_client()

    with client.session_transaction() as sess:
        sess["oauth_state"] = "state-1"

    monkeypatch.setattr(
        auth_routes,
        "handle_google_oauth_callback",
        lambda _code: {"success": False, "error": "oauth failed"},
    )

    response = client.get("/auth/google/callback?state=state-1&code=abc")

    assert response.status_code == 200
    assert b"oauth failed" in response.data


def test_auth_google_callback_new_user_redirects_register(monkeypatch):
    app = create_auth_app()
    client = app.test_client()

    with client.session_transaction() as sess:
        sess["oauth_state"] = "state-1"

    monkeypatch.setattr(
        auth_routes,
        "handle_google_oauth_callback",
        lambda _code: {
            "success": True,
            "user": {"email": "new@example.com", "name": "New User"},
        },
    )
    monkeypatch.setattr(auth_routes, "get_user_by_email", lambda _email: None)

    response = client.get("/auth/google/callback?state=state-1&code=abc")

    assert response.status_code == 302
    assert response.location.endswith("/register")


def test_auth_google_callback_verification_flow_redirects_verify_complete(monkeypatch):
    app = create_auth_app()
    client = app.test_client()

    with client.session_transaction() as sess:
        sess["oauth_state"] = "state-1"
        sess["verification_token"] = "verify-123"

    monkeypatch.setattr(
        auth_routes,
        "handle_google_oauth_callback",
        lambda _code: {
            "success": True,
            "user": {"email": "test@example.com", "name": "Test User"},
        },
    )
    monkeypatch.setattr(
        auth_routes,
        "get_user_by_email",
        lambda _email: {"email": "test@example.com", "legal_name": "Test User"},
    )

    response = client.get("/auth/google/callback?state=state-1&code=abc")

    assert response.status_code == 302
    assert response.location.endswith("/verify/complete")


def test_auth_google_callback_oauth2_session_redirects_authorize(monkeypatch):
    app = create_auth_app()
    client = app.test_client()

    with client.session_transaction() as sess:
        sess["oauth_state"] = "state-1"
        sess["oauth2_client_id"] = "client_1"
        sess["oauth2_redirect_uri"] = "https://example.com/callback"

    monkeypatch.setattr(
        auth_routes,
        "handle_google_oauth_callback",
        lambda _code: {
            "success": True,
            "user": {"email": "test@example.com", "name": "Test User"},
        },
    )
    monkeypatch.setattr(
        auth_routes,
        "get_user_by_email",
        lambda _email: {"email": "test@example.com", "legal_name": "Test User"},
    )

    response = client.get("/auth/google/callback?state=state-1&code=abc")

    assert response.status_code == 302
    assert response.location.endswith("/oauth/authorize")


def test_auth_google_callback_legacy_flow_inactive_app_clears_session(monkeypatch):
    app = create_auth_app()
    client = app.test_client()

    with client.session_transaction() as sess:
        sess["oauth_state"] = "state-1"
        sess["oauth_redirect"] = "https://example.com/callback"
        sess["oauth_app_id"] = "app_1"

    monkeypatch.setattr(
        auth_routes,
        "handle_google_oauth_callback",
        lambda _code: {
            "success": True,
            "user": {"email": "test@example.com", "name": "Test User"},
        },
    )
    monkeypatch.setattr(
        auth_routes,
        "get_user_by_email",
        lambda _email: {"email": "test@example.com", "legal_name": "Test User"},
    )
    monkeypatch.setattr("models.app.get_app_by_id", lambda _app_id: {"is_active": False})

    response = client.get("/auth/google/callback?state=state-1&code=abc")

    assert response.status_code == 200
    assert b"no longer available" in response.data
    with client.session_transaction() as sess:
        assert "oauth_redirect" not in sess
        assert "oauth_app_id" not in sess


def test_auth_google_callback_legacy_restricted_non_admin_denied(monkeypatch):
    app = create_auth_app()
    client = app.test_client()

    with client.session_transaction() as sess:
        sess["oauth_state"] = "state-1"
        sess["oauth_redirect"] = "https://example.com/callback"
        sess["oauth_app_id"] = "app_1"

    monkeypatch.setattr(
        auth_routes,
        "handle_google_oauth_callback",
        lambda _code: {
            "success": True,
            "user": {"email": "test@example.com", "name": "Test User"},
        },
    )
    monkeypatch.setattr(
        auth_routes,
        "get_user_by_email",
        lambda _email: {"email": "test@example.com", "legal_name": "Test User"},
    )
    monkeypatch.setattr(
        "models.app.get_app_by_id",
        lambda _app_id: {"id": "app_1", "is_active": True, "allow_anyone": False},
    )
    monkeypatch.setattr(auth_routes, "is_admin", lambda _email: False)

    response = client.get("/auth/google/callback?state=state-1&code=abc")

    assert response.status_code == 200
    assert b"permission to access this app" in response.data
    with client.session_transaction() as sess:
        assert "oauth_redirect" not in sess
        assert "oauth_app_id" not in sess


def test_auth_google_callback_legacy_restricted_no_explicit_permission_denied(
    monkeypatch,
):
    app = create_auth_app()
    client = app.test_client()

    with client.session_transaction() as sess:
        sess["oauth_state"] = "state-1"
        sess["oauth_redirect"] = "https://example.com/callback"
        sess["oauth_app_id"] = "app_1"

    monkeypatch.setattr(
        auth_routes,
        "handle_google_oauth_callback",
        lambda _code: {
            "success": True,
            "user": {"email": "test@example.com", "name": "Test User"},
        },
    )
    monkeypatch.setattr(
        auth_routes,
        "get_user_by_email",
        lambda _email: {"email": "test@example.com", "legal_name": "Test User"},
    )
    monkeypatch.setattr(
        "models.app.get_app_by_id",
        lambda _app_id: {"id": "app_1", "is_active": True, "allow_anyone": False},
    )
    monkeypatch.setattr(auth_routes, "is_admin", lambda _email: True)
    monkeypatch.setattr(auth_routes, "has_app_permission", lambda *_args: False)

    response = client.get("/auth/google/callback?state=state-1&code=abc")

    assert response.status_code == 200
    assert b"permission to access this app" in response.data


def test_auth_google_callback_legacy_success_redirects_with_token(monkeypatch):
    app = create_auth_app()
    client = app.test_client()

    with client.session_transaction() as sess:
        sess["oauth_state"] = "state-1"
        sess["oauth_redirect"] = "https://example.com/callback"
        sess["oauth_app_id"] = "app_1"

    monkeypatch.setattr(
        auth_routes,
        "handle_google_oauth_callback",
        lambda _code: {
            "success": True,
            "user": {"email": "test@example.com", "name": "Test User"},
        },
    )
    monkeypatch.setattr(
        auth_routes,
        "get_user_by_email",
        lambda _email: {"email": "test@example.com", "legal_name": "Test User"},
    )
    monkeypatch.setattr(
        "models.app.get_app_by_id",
        lambda _app_id: {"id": "app_1", "is_active": True, "allow_anyone": True},
    )
    monkeypatch.setattr(auth_routes, "create_oauth_token", lambda *_args, **_kwargs: "tok_1")

    response = client.get("/auth/google/callback?state=state-1&code=abc")

    assert response.status_code == 302
    assert response.location == "https://example.com/callback?token=tok_1"


def test_auth_google_callback_default_success_redirects_home(monkeypatch):
    app = create_auth_app()
    client = app.test_client()

    with client.session_transaction() as sess:
        sess["oauth_state"] = "state-1"

    monkeypatch.setattr(
        auth_routes,
        "handle_google_oauth_callback",
        lambda _code: {
            "success": True,
            "user": {"email": "test@example.com", "name": "Test User"},
        },
    )
    monkeypatch.setattr(
        auth_routes,
        "get_user_by_email",
        lambda _email: {"email": "test@example.com", "legal_name": "Test User"},
    )

    response = client.get("/auth/google/callback?state=state-1&code=abc")

    assert response.status_code == 302
    assert response.location.endswith("/")


def test_auth_google_with_debug_disabled_still_redirects(monkeypatch):
    app = create_auth_app()
    client = app.test_client()
    monkeypatch.setattr(auth_routes, "DEBUG_MODE", False)
    monkeypatch.setattr(auth_routes, "get_google_auth_url", lambda: "https://accounts.example/oauth")

    response = client.get("/auth/google")

    assert response.status_code == 302
    assert response.location == "https://accounts.example/oauth"


def test_auth_google_callback_legacy_restricted_authorized_user_redirects_with_token(monkeypatch):
    app = create_auth_app()
    client = app.test_client()

    with client.session_transaction() as sess:
        sess["oauth_state"] = "state-1"
        sess["oauth_redirect"] = "https://example.com/callback"
        sess["oauth_app_id"] = "app_1"

    monkeypatch.setattr(
        auth_routes,
        "handle_google_oauth_callback",
        lambda _code: {
            "success": True,
            "user": {"email": "test@example.com", "name": "Test User"},
        },
    )
    monkeypatch.setattr(
        auth_routes,
        "get_user_by_email",
        lambda _email: {"email": "test@example.com", "legal_name": "Test User"},
    )
    monkeypatch.setattr(
        "models.app.get_app_by_id",
        lambda _app_id: {"id": "app_1", "is_active": True, "allow_anyone": False},
    )
    monkeypatch.setattr(auth_routes, "is_admin", lambda _email: True)
    monkeypatch.setattr(auth_routes, "has_app_permission", lambda *_args: True)
    monkeypatch.setattr(auth_routes, "create_oauth_token", lambda *_args, **_kwargs: "tok_1")

    response = client.get("/auth/google/callback?state=state-1&code=abc")

    assert response.status_code == 302
    assert response.location == "https://example.com/callback?token=tok_1"


def oauth_app(
    *, allow_anyone=True, skip_consent_screen=False, active=True, scopes='["profile", "email"]'
):
    return {
        "id": "app_1",
        "is_active": active,
        "redirect_uris": '["https://example.com/callback"]',
        "allowed_scopes": scopes,
        "allow_anyone": allow_anyone,
        "skip_consent_screen": skip_consent_screen,
    }


def test_oauth_authorize_unsupported_response_type(monkeypatch):
    app = create_auth_app()
    client = app.test_client()
    monkeypatch.setattr(auth_routes, "get_app_by_client_id", lambda _id: oauth_app())

    response = client.get(
        "/oauth/authorize?client_id=client_1&redirect_uri=https://example.com/callback&response_type=token"
    )

    assert response.status_code == 200
    assert b"Unsupported response_type" in response.data


def test_oauth_authorize_invalid_client(monkeypatch):
    app = create_auth_app()
    client = app.test_client()
    monkeypatch.setattr(auth_routes, "get_app_by_client_id", lambda _id: None)

    response = client.get(
        "/oauth/authorize?client_id=client_1&redirect_uri=https://example.com/callback"
    )

    assert response.status_code == 200
    assert b"Invalid client_id" in response.data


def test_oauth_authorize_inactive_client(monkeypatch):
    app = create_auth_app()
    client = app.test_client()
    monkeypatch.setattr(
        auth_routes, "get_app_by_client_id", lambda _id: oauth_app(active=False)
    )

    response = client.get(
        "/oauth/authorize?client_id=client_1&redirect_uri=https://example.com/callback"
    )

    assert response.status_code == 200
    assert b"currently disabled" in response.data


def test_oauth_authorize_invalid_redirect_uri(monkeypatch):
    app = create_auth_app()
    client = app.test_client()
    monkeypatch.setattr(auth_routes, "get_app_by_client_id", lambda _id: oauth_app())
    monkeypatch.setattr(auth_routes, "validate_redirect_uri", lambda *_args: False)

    response = client.get(
        "/oauth/authorize?client_id=client_1&redirect_uri=https://wrong.example/callback"
    )

    assert response.status_code == 200
    assert b"Invalid redirect_uri" in response.data


def test_oauth_authorize_invalid_scope(monkeypatch):
    app = create_auth_app()
    client = app.test_client()
    monkeypatch.setattr(auth_routes, "get_app_by_client_id", lambda _id: oauth_app())
    monkeypatch.setattr(auth_routes, "validate_redirect_uri", lambda *_args: True)

    response = client.get(
        "/oauth/authorize?client_id=client_1&redirect_uri=https://example.com/callback&scope=admin"
    )

    assert response.status_code == 200
    assert b"Invalid scope" in response.data


def test_oauth_authorize_restricted_app_permission_denied(monkeypatch):
    app = create_auth_app()
    client = app.test_client()
    login_session(client)
    monkeypatch.setattr(
        auth_routes, "get_app_by_client_id", lambda _id: oauth_app(allow_anyone=False)
    )
    monkeypatch.setattr(auth_routes, "validate_redirect_uri", lambda *_args: True)
    monkeypatch.setattr(
        auth_routes,
        "get_user_by_email",
        lambda _email: {"email": "test@example.com", "legal_name": "Legal Name"},
    )
    monkeypatch.setattr(auth_routes, "is_admin", lambda _email: False)
    monkeypatch.setattr(auth_routes, "has_app_permission", lambda *_args: False)

    response = client.get(
        "/oauth/authorize?client_id=client_1&redirect_uri=https://example.com/callback"
    )

    assert response.status_code == 200
    assert b"permission to access this app" in response.data


def test_oauth_authorize_restricted_app_authorized_user_can_continue(monkeypatch):
    app = create_auth_app()
    client = app.test_client()
    login_session(client)
    monkeypatch.setattr(
        auth_routes,
        "get_app_by_client_id",
        lambda _id: oauth_app(allow_anyone=False, skip_consent_screen=True),
    )
    monkeypatch.setattr(auth_routes, "validate_redirect_uri", lambda *_args: True)
    monkeypatch.setattr(
        auth_routes,
        "get_user_by_email",
        lambda _email: {"email": "test@example.com", "legal_name": "Legal Name"},
    )
    monkeypatch.setattr(auth_routes, "is_admin", lambda _email: True)
    monkeypatch.setattr(auth_routes, "has_app_permission", lambda *_args: True)
    monkeypatch.setattr(auth_routes, "create_authorization_code", lambda **_kwargs: "code-1")

    response = client.get(
        "/oauth/authorize?client_id=client_1&redirect_uri=https://example.com/callback&state=abc"
    )

    assert response.status_code == 302
    assert response.location == "https://example.com/callback?code=code-1&state=abc"


def test_oauth_authorize_logged_in_shows_consent_screen(monkeypatch):
    app = create_auth_app()
    client = app.test_client()
    login_session(client)
    monkeypatch.setattr(auth_routes, "get_app_by_client_id", lambda _id: oauth_app())
    monkeypatch.setattr(auth_routes, "validate_redirect_uri", lambda *_args: True)
    monkeypatch.setattr(
        auth_routes,
        "get_user_by_email",
        lambda _email: {"email": "test@example.com", "legal_name": "Legal Name"},
    )

    response = client.get(
        "/oauth/authorize?client_id=client_1&redirect_uri=https://example.com/callback"
    )

    assert response.status_code == 200
    assert b"Authorize" in response.data


def test_oauth_authorize_logged_in_without_legal_name_shows_login(monkeypatch):
    app = create_auth_app()
    client = app.test_client()
    login_session(client)
    monkeypatch.setattr(auth_routes, "get_app_by_client_id", lambda _id: oauth_app())
    monkeypatch.setattr(auth_routes, "validate_redirect_uri", lambda *_args: True)
    monkeypatch.setattr(
        auth_routes,
        "get_user_by_email",
        lambda _email: {"email": "test@example.com", "legal_name": ""},
    )

    response = client.get(
        "/oauth/authorize?client_id=client_1&redirect_uri=https://example.com/callback"
    )

    assert response.status_code == 200
    assert b"Sign in" in response.data


def test_oauth_authorize_uses_session_cached_params(monkeypatch):
    app = create_auth_app()
    client = app.test_client()
    login_session(client)
    oauth2_session(client)

    monkeypatch.setattr(
        auth_routes,
        "get_app_by_client_id",
        lambda client_id: oauth_app() if client_id == "client_1" else None,
    )
    monkeypatch.setattr(auth_routes, "validate_redirect_uri", lambda *_args: True)
    monkeypatch.setattr(
        auth_routes,
        "get_user_by_email",
        lambda _email: {"email": "test@example.com", "legal_name": "Legal Name"},
    )

    response = client.get("/oauth/authorize")

    assert response.status_code == 200
    assert b"Authorize" in response.data


def test_oauth_authorize_consent_requires_user_session():
    app = create_auth_app()
    client = app.test_client()

    response = client.post("/oauth/authorize", data={"action": "approve"})

    assert response.status_code == 200
    assert b"Session expired" in response.data


def test_oauth_authorize_consent_requires_oauth_session(login_email="test@example.com"):
    app = create_auth_app()
    client = app.test_client()
    login_session(client, email=login_email)

    response = client.post("/oauth/authorize", data={"action": "approve"})

    assert response.status_code == 200
    assert b"Invalid OAuth session" in response.data


def test_oauth_authorize_consent_inactive_app_redirects_invalid_client(monkeypatch):
    app = create_auth_app()
    client = app.test_client()
    login_session(client)
    oauth2_session(client)
    monkeypatch.setattr(auth_routes, "get_app_by_client_id", lambda _id: oauth_app(active=False))

    response = client.post("/oauth/authorize", data={"action": "approve"})

    assert response.status_code == 302
    assert response.location == "https://example.com/callback?error=invalid_client&state=abc"
    with client.session_transaction() as sess:
        assert "oauth2_client_id" not in sess
        assert "oauth2_redirect_uri" not in sess
        assert "oauth2_scope" not in sess
        assert "oauth2_state" not in sess


def test_oauth_authorize_consent_restricted_permission_denied(monkeypatch):
    app = create_auth_app()
    client = app.test_client()
    login_session(client)
    oauth2_session(client)
    monkeypatch.setattr(
        auth_routes, "get_app_by_client_id", lambda _id: oauth_app(allow_anyone=False)
    )
    monkeypatch.setattr(auth_routes, "is_admin", lambda _email: False)

    response = client.post("/oauth/authorize", data={"action": "approve"})

    assert response.status_code == 302
    assert (
        response.location
        == "https://example.com/callback?error=access_denied&error_description=insufficient_permissions&state=abc"
    )


def test_oauth_authorize_consent_restricted_authorized_user_can_deny(monkeypatch):
    app = create_auth_app()
    client = app.test_client()
    login_session(client)
    oauth2_session(client)
    monkeypatch.setattr(
        auth_routes, "get_app_by_client_id", lambda _id: oauth_app(allow_anyone=False)
    )
    monkeypatch.setattr(auth_routes, "is_admin", lambda _email: True)
    monkeypatch.setattr(auth_routes, "has_app_permission", lambda *_args: True)

    response = client.post("/oauth/authorize", data={"action": "deny"})

    assert response.status_code == 302
    assert response.location == "https://example.com/callback?error=access_denied&state=abc"


def test_oauth_authorize_consent_approve_success_generates_code_and_clears_session(
    monkeypatch,
):
    app = create_auth_app()
    client = app.test_client()
    login_session(client)
    oauth2_session(client)

    monkeypatch.setattr(auth_routes, "get_app_by_client_id", lambda _id: oauth_app())
    monkeypatch.setattr(
        auth_routes, "create_authorization_code", lambda **_kwargs: "issued-code-1"
    )

    response = client.post("/oauth/authorize", data={"action": "approve"})

    assert response.status_code == 302
    assert response.location == "https://example.com/callback?code=issued-code-1&state=abc"
    with client.session_transaction() as sess:
        assert "oauth2_client_id" not in sess


def test_oauth_token_maps_invalid_client_error(monkeypatch):
    app = create_auth_app(register_oauth=True)
    client = app.test_client()
    monkeypatch.setattr(
        auth_routes,
        "exchange_code_for_token",
        lambda *_args: {"success": False, "error": "invalid_client"},
    )

    response = client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": "code_1",
            "redirect_uri": "https://example.com/callback",
            "client_id": "client_1",
            "client_secret": "secret_1",
        },
    )

    assert response.status_code == 400
    payload = response.get_json()
    assert payload["error"] == "invalid_client"
    assert "client_secret" in payload["error_description"]


def test_oauth_token_maps_unknown_exchange_error(monkeypatch):
    app = create_auth_app(register_oauth=True)
    client = app.test_client()
    monkeypatch.setattr(
        auth_routes,
        "exchange_code_for_token",
        lambda *_args: {"success": False, "error": "server_boom"},
    )

    response = client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": "code_1",
            "redirect_uri": "https://example.com/callback",
            "client_id": "client_1",
            "client_secret": "secret_1",
        },
    )

    assert response.status_code == 400
    payload = response.get_json()
    assert payload["error"] == "server_boom"
    assert "Invalid authorization code or client credentials" in payload["error_description"]


def test_oauth_token_with_debug_disabled_success(monkeypatch):
    app = create_auth_app(register_oauth=True)
    client = app.test_client()
    monkeypatch.setattr(auth_routes, "DEBUG_MODE", False)
    monkeypatch.setattr(
        auth_routes,
        "exchange_code_for_token",
        lambda *_args: {
            "success": True,
            "access_token": "access_1",
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": "profile",
        },
    )

    response = client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": "code_1",
            "redirect_uri": "https://example.com/callback",
            "client_id": "client_1",
            "client_secret": "secret_1",
        },
    )

    assert response.status_code == 200
    assert response.get_json()["access_token"] == "access_1"


def test_oauth_revoke_invokes_revoke_function(monkeypatch):
    app = create_auth_app(register_oauth=True)
    client = app.test_client()
    revoked = {}
    monkeypatch.setattr(
        auth_routes, "revoke_access_token", lambda token: revoked.setdefault("token", token)
    )

    response = client.post("/oauth/revoke", data={"token": "tok_123"})

    assert response.status_code == 200
    assert response.get_json()["success"] is True
    assert revoked["token"] == "tok_123"


def test_oauth_legacy_inactive_app_returns_error(monkeypatch):
    app = create_auth_app()
    client = app.test_client()
    monkeypatch.setattr(
        auth_routes,
        "validate_app_redirect",
        lambda _redirect: {"id": "app_1", "is_active": False},
    )

    response = client.get("/oauth?redirect=https://example.com/callback")

    assert response.status_code == 200
    assert b"currently disabled" in response.data


def test_oauth_legacy_restricted_non_admin_denied(monkeypatch):
    app = create_auth_app()
    client = app.test_client()
    login_session(client)
    monkeypatch.setattr(
        auth_routes,
        "validate_app_redirect",
        lambda _redirect: {"id": "app_1", "is_active": True, "allow_anyone": False},
    )
    monkeypatch.setattr(
        auth_routes,
        "get_user_by_email",
        lambda _email: {"email": "test@example.com", "legal_name": "Legal Name"},
    )
    monkeypatch.setattr(auth_routes, "is_admin", lambda _email: False)

    response = client.get("/oauth?redirect=https://example.com/callback")

    assert response.status_code == 200
    assert b"Please contact an administrator" in response.data


def test_oauth_legacy_restricted_no_permission_denied(monkeypatch):
    app = create_auth_app()
    client = app.test_client()
    login_session(client)
    monkeypatch.setattr(
        auth_routes,
        "validate_app_redirect",
        lambda _redirect: {"id": "app_1", "is_active": True, "allow_anyone": False},
    )
    monkeypatch.setattr(
        auth_routes,
        "get_user_by_email",
        lambda _email: {"email": "test@example.com", "legal_name": "Legal Name"},
    )
    monkeypatch.setattr(auth_routes, "is_admin", lambda _email: True)
    monkeypatch.setattr(auth_routes, "has_app_permission", lambda *_args: False)

    response = client.get("/oauth?redirect=https://example.com/callback")

    assert response.status_code == 200
    assert b"Please contact an administrator" in response.data


def test_oauth_legacy_restricted_authorized_user_gets_token(monkeypatch):
    app = create_auth_app()
    client = app.test_client()
    login_session(client)
    monkeypatch.setattr(
        auth_routes,
        "validate_app_redirect",
        lambda _redirect: {"id": "app_1", "is_active": True, "allow_anyone": False},
    )
    monkeypatch.setattr(
        auth_routes,
        "get_user_by_email",
        lambda _email: {"email": "test@example.com", "legal_name": "Legal Name"},
    )
    monkeypatch.setattr(auth_routes, "is_admin", lambda _email: True)
    monkeypatch.setattr(auth_routes, "has_app_permission", lambda *_args: True)
    monkeypatch.setattr(auth_routes, "create_oauth_token", lambda *_args, **_kwargs: "tok_1")

    response = client.get("/oauth?redirect=https://example.com/callback")

    assert response.status_code == 302
    assert response.location == "https://example.com/callback?token=tok_1"


def test_oauth_legacy_logged_in_without_complete_profile_shows_login(monkeypatch):
    app = create_auth_app()
    client = app.test_client()
    login_session(client)
    monkeypatch.setattr(
        auth_routes,
        "validate_app_redirect",
        lambda _redirect: {"id": "app_1", "is_active": True, "allow_anyone": True},
    )
    monkeypatch.setattr(
        auth_routes, "get_user_by_email", lambda _email: {"email": "test@example.com", "legal_name": ""}
    )

    response = client.get("/oauth?redirect=https://example.com/callback")

    assert response.status_code == 200
    assert b"Sign in" in response.data


def test_oauth_legacy_success_with_existing_query_uses_ampersand(monkeypatch):
    app = create_auth_app()
    client = app.test_client()
    login_session(client)
    monkeypatch.setattr(
        auth_routes,
        "validate_app_redirect",
        lambda _redirect: {"id": "app_1", "is_active": True, "allow_anyone": True},
    )
    monkeypatch.setattr(
        auth_routes,
        "get_user_by_email",
        lambda _email: {"email": "test@example.com", "legal_name": "Legal Name"},
    )
    monkeypatch.setattr(auth_routes, "create_oauth_token", lambda *_args, **_kwargs: "tok_1")

    response = client.get("/oauth?redirect=https%3A%2F%2Fexample.com%2Fcallback%3Fnext%3D1")

    assert response.status_code == 302
    assert response.location == "https://example.com/callback?next=1&token=tok_1"


def test_send_code_json_failure(monkeypatch):
    app = create_auth_app()
    client = app.test_client()
    monkeypatch.setattr(auth_routes, "send_email_verification", lambda _email: False)

    response = client.post("/send-code", json={"email": "test@example.com"})

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["success"] is False
    assert "Failed to send magic link" in payload["error"]


def test_send_code_form_requires_email():
    app = create_auth_app()
    client = app.test_client()

    response = client.post("/send-code", data={})

    assert response.status_code == 200
    assert b"Email is required" in response.data


def test_send_code_form_success(monkeypatch):
    app = create_auth_app()
    client = app.test_client()
    monkeypatch.setattr(auth_routes, "send_email_verification", lambda _email: True)

    response = client.post("/send-code", data={"email": "test@example.com"})

    assert response.status_code == 200
    assert b"Check Your Email" in response.data


def test_send_code_form_failure(monkeypatch):
    app = create_auth_app()
    client = app.test_client()
    monkeypatch.setattr(auth_routes, "send_email_verification", lambda _email: False)

    response = client.post("/send-code", data={"email": "test@example.com"})

    assert response.status_code == 200
    assert b"Failed to send magic link" in response.data


def test_email_callback_failed_verification_renders_error(monkeypatch):
    app = create_auth_app()
    client = app.test_client()
    monkeypatch.setattr(
        auth_routes, "verify_email_code", lambda _code: {"success": False, "error": "expired"}
    )

    response = client.get("/auth/email/callback?code=bad")

    assert response.status_code == 200
    assert b"expired" in response.data


def test_email_callback_existing_user_oauth2_redirect(monkeypatch):
    app = create_auth_app()
    client = app.test_client()
    oauth2_session(client)
    monkeypatch.setattr(
        auth_routes,
        "verify_email_code",
        lambda _code: {"success": True, "email": "test@example.com", "name": "Tester"},
    )
    monkeypatch.setattr(
        auth_routes,
        "get_user_by_email",
        lambda _email: {"email": "test@example.com", "legal_name": "Legal Name"},
    )

    response = client.get("/auth/email/callback?code=good")

    assert response.status_code == 302
    assert response.location.endswith("/oauth/authorize")


def test_email_callback_existing_user_legacy_inactive_app(monkeypatch):
    app = create_auth_app()
    client = app.test_client()
    with client.session_transaction() as sess:
        sess["oauth_redirect"] = "https://example.com/callback"
        sess["oauth_app_id"] = "app_1"
    monkeypatch.setattr(
        auth_routes,
        "verify_email_code",
        lambda _code: {"success": True, "email": "test@example.com", "name": "Tester"},
    )
    monkeypatch.setattr(
        auth_routes,
        "get_user_by_email",
        lambda _email: {"email": "test@example.com", "legal_name": "Legal Name"},
    )
    monkeypatch.setattr("models.app.get_app_by_id", lambda _id: {"is_active": False})

    response = client.get("/auth/email/callback?code=good")

    assert response.status_code == 200
    assert b"no longer available" in response.data


def test_email_callback_existing_user_legacy_restricted_non_admin(monkeypatch):
    app = create_auth_app()
    client = app.test_client()
    with client.session_transaction() as sess:
        sess["oauth_redirect"] = "https://example.com/callback"
        sess["oauth_app_id"] = "app_1"
    monkeypatch.setattr(
        auth_routes,
        "verify_email_code",
        lambda _code: {"success": True, "email": "test@example.com", "name": "Tester"},
    )
    monkeypatch.setattr(
        auth_routes,
        "get_user_by_email",
        lambda _email: {"email": "test@example.com", "legal_name": "Legal Name"},
    )
    monkeypatch.setattr(
        "models.app.get_app_by_id",
        lambda _id: {"id": "app_1", "is_active": True, "allow_anyone": False},
    )
    monkeypatch.setattr(auth_routes, "is_admin", lambda _email: False)

    response = client.get("/auth/email/callback?code=good")

    assert response.status_code == 200
    assert b"permission to access this app" in response.data


def test_email_callback_existing_user_legacy_restricted_missing_permission(monkeypatch):
    app = create_auth_app()
    client = app.test_client()
    with client.session_transaction() as sess:
        sess["oauth_redirect"] = "https://example.com/callback"
        sess["oauth_app_id"] = "app_1"
    monkeypatch.setattr(
        auth_routes,
        "verify_email_code",
        lambda _code: {"success": True, "email": "test@example.com", "name": "Tester"},
    )
    monkeypatch.setattr(
        auth_routes,
        "get_user_by_email",
        lambda _email: {"email": "test@example.com", "legal_name": "Legal Name"},
    )
    monkeypatch.setattr(
        "models.app.get_app_by_id",
        lambda _id: {"id": "app_1", "is_active": True, "allow_anyone": False},
    )
    monkeypatch.setattr(auth_routes, "is_admin", lambda _email: True)
    monkeypatch.setattr(auth_routes, "has_app_permission", lambda *_args: False)

    response = client.get("/auth/email/callback?code=good")

    assert response.status_code == 200
    assert b"permission to access this app" in response.data


def test_email_callback_existing_user_legacy_success_redirects_with_token(monkeypatch):
    app = create_auth_app()
    client = app.test_client()
    with client.session_transaction() as sess:
        sess["oauth_redirect"] = "https://example.com/callback"
        sess["oauth_app_id"] = "app_1"
    monkeypatch.setattr(
        auth_routes,
        "verify_email_code",
        lambda _code: {"success": True, "email": "test@example.com", "name": "Tester"},
    )
    monkeypatch.setattr(
        auth_routes,
        "get_user_by_email",
        lambda _email: {"email": "test@example.com", "legal_name": "Legal Name"},
    )
    monkeypatch.setattr(
        "models.app.get_app_by_id",
        lambda _id: {"id": "app_1", "is_active": True, "allow_anyone": True},
    )
    monkeypatch.setattr(auth_routes, "create_oauth_token", lambda *_args, **_kwargs: "tok_1")

    response = client.get("/auth/email/callback?code=good")

    assert response.status_code == 302
    assert response.location == "https://example.com/callback?token=tok_1"


def test_email_callback_existing_user_legacy_restricted_authorized_user(monkeypatch):
    app = create_auth_app()
    client = app.test_client()
    with client.session_transaction() as sess:
        sess["oauth_redirect"] = "https://example.com/callback"
        sess["oauth_app_id"] = "app_1"
    monkeypatch.setattr(
        auth_routes,
        "verify_email_code",
        lambda _code: {"success": True, "email": "test@example.com", "name": "Tester"},
    )
    monkeypatch.setattr(
        auth_routes,
        "get_user_by_email",
        lambda _email: {"email": "test@example.com", "legal_name": "Legal Name"},
    )
    monkeypatch.setattr(
        "models.app.get_app_by_id",
        lambda _id: {"id": "app_1", "is_active": True, "allow_anyone": False},
    )
    monkeypatch.setattr(auth_routes, "is_admin", lambda _email: True)
    monkeypatch.setattr(auth_routes, "has_app_permission", lambda *_args: True)
    monkeypatch.setattr(auth_routes, "create_oauth_token", lambda *_args, **_kwargs: "tok_1")

    response = client.get("/auth/email/callback?code=good")

    assert response.status_code == 302
    assert response.location == "https://example.com/callback?token=tok_1"


def test_email_callback_new_user_sets_pending_registration(monkeypatch):
    app = create_auth_app()
    client = app.test_client()
    monkeypatch.setattr(
        auth_routes,
        "verify_email_code",
        lambda _code: {"success": True, "email": "new@example.com", "name": "New User"},
    )
    monkeypatch.setattr(auth_routes, "get_user_by_email", lambda _email: None)

    response = client.get("/auth/email/callback?code=good")

    assert response.status_code == 302
    assert response.location.endswith("/register")
    with client.session_transaction() as sess:
        assert sess["pending_registration"] is True
        assert sess["user_email"] == "new@example.com"


def test_verify_code_route_returns_magic_link_guidance():
    app = create_auth_app()
    client = app.test_client()

    response = client.post("/verify-code")

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["success"] is False
    assert "magic link" in payload["error"]


def test_verify_discord_missing_token():
    app = create_auth_app()
    client = app.test_client()

    response = client.get("/verify")

    assert response.status_code == 200
    assert b"Missing verification token" in response.data


def test_verify_discord_invalid_token(monkeypatch):
    app = create_auth_app()
    client = app.test_client()
    monkeypatch.setattr(auth_routes, "verify_discord_token", lambda _token: None)

    response = client.get("/verify?token=bad")

    assert response.status_code == 200
    assert b"Invalid or expired verification link" in response.data


def test_verify_discord_valid_token_sets_session(monkeypatch):
    app = create_auth_app()
    client = app.test_client()
    monkeypatch.setattr(
        auth_routes,
        "verify_discord_token",
        lambda _token: {"discord_id": "123", "discord_username": "tester"},
    )

    response = client.get("/verify?token=good")

    assert response.status_code == 200
    assert b"Sign in" in response.data
    with client.session_transaction() as sess:
        assert sess["verification_token"] == "good"
        assert sess["discord_id"] == "123"


def test_verify_discord_valid_token_logged_in_redirects_complete(monkeypatch):
    app = create_auth_app()
    client = app.test_client()
    login_session(client)
    monkeypatch.setattr(
        auth_routes,
        "verify_discord_token",
        lambda _token: {"discord_id": "123", "discord_username": "tester"},
    )

    response = client.get("/verify?token=good")

    assert response.status_code == 302
    assert response.location.endswith("/verify/complete")


def test_verify_complete_requires_verification_token():
    app = create_auth_app()
    client = app.test_client()

    response = client.get("/verify/complete")

    assert response.status_code == 200
    assert b"Invalid verification state" in response.data


def test_verify_complete_requires_logged_in_user():
    app = create_auth_app()
    client = app.test_client()
    with client.session_transaction() as sess:
        sess["verification_token"] = "tok_1"

    response = client.get("/verify/complete")

    assert response.status_code == 200
    assert b"Please log in first" in response.data


def test_verify_complete_success_clears_session(monkeypatch):
    app = create_auth_app()
    client = app.test_client()
    login_session(client)
    with client.session_transaction() as sess:
        sess["verification_token"] = "tok_1"
        sess["discord_id"] = "123"
        sess["discord_username"] = "tester"

    monkeypatch.setattr(
        auth_routes,
        "complete_discord_verification",
        lambda _token, _email: {
            "success": True,
            "discord_username": "tester",
            "roles_assigned": [{"event_id": "hackathon", "role_name": "Hacker"}],
            "roles_failed": [],
            "total_roles_assigned": 1,
            "total_roles_failed": 0,
        },
    )
    monkeypatch.setattr(
        auth_routes,
        "get_user_by_email",
        lambda _email: {
            "email": "test@example.com",
            "preferred_name": "Tester",
            "events": ["event-1"],
        },
    )

    response = client.get("/verify/complete")

    assert response.status_code == 200
    assert b"Discord Verification Successful" in response.data
    with client.session_transaction() as sess:
        assert "verification_token" not in sess
        assert "discord_id" not in sess


def test_verify_complete_failure_renders_error(monkeypatch):
    app = create_auth_app()
    client = app.test_client()
    login_session(client)
    with client.session_transaction() as sess:
        sess["verification_token"] = "tok_1"

    monkeypatch.setattr(
        auth_routes,
        "complete_discord_verification",
        lambda _token, _email: {"success": False, "error": "verification failed"},
    )

    response = client.get("/verify/complete")

    assert response.status_code == 200
    assert b"verification failed" in response.data


def test_register_requires_logged_in_user():
    app = create_auth_app()
    client = app.test_client()

    response = client.get("/register")

    assert response.status_code == 302
    assert response.location.endswith("/")


def test_register_existing_complete_user_redirects_home(monkeypatch):
    app = create_auth_app()
    client = app.test_client()
    login_session(client)
    monkeypatch.setattr(
        auth_routes,
        "get_user_by_email",
        lambda _email: {"email": "test@example.com", "legal_name": "Legal Name"},
    )

    response = client.get("/register")

    assert response.status_code == 302
    assert response.location.endswith("/")


def test_register_get_renders_form_when_pending(monkeypatch):
    app = create_auth_app()
    client = app.test_client()
    login_session(client)
    with client.session_transaction() as sess:
        sess["pending_registration"] = True
    monkeypatch.setattr(
        auth_routes,
        "get_user_by_email",
        lambda _email: {"email": "test@example.com", "legal_name": "Legal Name"},
    )

    response = client.get("/register")

    assert response.status_code == 200
    assert b"Complete Your Registration" in response.data


def test_register_post_validation_errors(monkeypatch):
    app = create_auth_app()
    client = app.test_client()
    login_session(client)
    monkeypatch.setattr(auth_routes, "get_user_by_email", lambda _email: None)

    response = client.post("/register", data={"legal_name": "", "dob": "", "pronouns": ""})

    assert response.status_code == 200
    assert b"Legal name is required" in response.data
    assert b"Date of birth is required" in response.data
    assert b"Pronouns are required" in response.data


def test_register_post_invalid_dob(monkeypatch):
    app = create_auth_app()
    client = app.test_client()
    login_session(client)
    monkeypatch.setattr(auth_routes, "get_user_by_email", lambda _email: None)

    response = client.post(
        "/register",
        data={"legal_name": "Legal Name", "dob": "not-a-date", "pronouns": "they/them"},
    )

    assert response.status_code == 200
    assert b"Invalid date format" in response.data


def test_register_post_update_user_value_error(monkeypatch):
    app = create_auth_app()
    client = app.test_client()
    login_session(client)
    monkeypatch.setattr(
        auth_routes,
        "get_user_by_email",
        lambda _email: {"id": "user_1", "email": "test@example.com", "legal_name": ""},
    )

    def raise_value_error(*_args, **_kwargs):
        raise ValueError("update failed")

    monkeypatch.setattr(auth_routes, "update_user", raise_value_error)

    response = client.post(
        "/register",
        data={
            "legal_name": "Legal Name",
            "preferred_name": "Nick",
            "dob": "2000-01-01",
            "pronouns": "they/them",
        },
    )

    assert response.status_code == 200
    assert b"update failed" in response.data


def test_register_post_update_redirects_verify_complete(monkeypatch):
    app = create_auth_app()
    client = app.test_client()
    login_session(client)
    with client.session_transaction() as sess:
        sess["verification_token"] = "tok_1"
    monkeypatch.setattr(
        auth_routes,
        "get_user_by_email",
        lambda _email: {"id": "user_1", "email": "test@example.com", "legal_name": ""},
    )
    monkeypatch.setattr(auth_routes, "update_user", lambda *_args, **_kwargs: None)

    response = client.post(
        "/register",
        data={"legal_name": "Legal Name", "dob": "2000-01-01", "pronouns": "they/them"},
    )

    assert response.status_code == 302
    assert response.location.endswith("/verify/complete")


def test_register_post_update_redirects_oauth_authorize(monkeypatch):
    app = create_auth_app()
    client = app.test_client()
    login_session(client)
    oauth2_session(client)
    monkeypatch.setattr(
        auth_routes,
        "get_user_by_email",
        lambda _email: {"id": "user_1", "email": "test@example.com", "legal_name": ""},
    )
    monkeypatch.setattr(auth_routes, "update_user", lambda *_args, **_kwargs: None)

    response = client.post(
        "/register",
        data={"legal_name": "Legal Name", "dob": "2000-01-01", "pronouns": "they/them"},
    )

    assert response.status_code == 302
    assert response.location.endswith("/oauth/authorize")


def test_register_post_update_legacy_inactive_app(monkeypatch):
    app = create_auth_app()
    client = app.test_client()
    login_session(client)
    with client.session_transaction() as sess:
        sess["oauth_redirect"] = "https://example.com/callback"
        sess["oauth_app_id"] = "app_1"
    monkeypatch.setattr(
        auth_routes,
        "get_user_by_email",
        lambda _email: {"id": "user_1", "email": "test@example.com", "legal_name": ""},
    )
    monkeypatch.setattr(auth_routes, "update_user", lambda *_args, **_kwargs: None)
    monkeypatch.setattr("models.app.get_app_by_id", lambda _id: {"is_active": False})

    response = client.post(
        "/register",
        data={"legal_name": "Legal Name", "dob": "2000-01-01", "pronouns": "they/them"},
    )

    assert response.status_code == 200
    assert b"no longer available" in response.data


def test_register_post_update_legacy_restricted_non_admin(monkeypatch):
    app = create_auth_app()
    client = app.test_client()
    login_session(client)
    with client.session_transaction() as sess:
        sess["oauth_redirect"] = "https://example.com/callback"
        sess["oauth_app_id"] = "app_1"
    monkeypatch.setattr(
        auth_routes,
        "get_user_by_email",
        lambda _email: {"id": "user_1", "email": "test@example.com", "legal_name": ""},
    )
    monkeypatch.setattr(auth_routes, "update_user", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        "models.app.get_app_by_id",
        lambda _id: {"id": "app_1", "is_active": True, "allow_anyone": False},
    )
    monkeypatch.setattr(auth_routes, "is_admin", lambda _email: False)

    response = client.post(
        "/register",
        data={"legal_name": "Legal Name", "dob": "2000-01-01", "pronouns": "they/them"},
    )

    assert response.status_code == 200
    assert b"permission to access this app" in response.data


def test_register_post_update_legacy_restricted_missing_permission(monkeypatch):
    app = create_auth_app()
    client = app.test_client()
    login_session(client)
    with client.session_transaction() as sess:
        sess["oauth_redirect"] = "https://example.com/callback"
        sess["oauth_app_id"] = "app_1"
    monkeypatch.setattr(
        auth_routes,
        "get_user_by_email",
        lambda _email: {"id": "user_1", "email": "test@example.com", "legal_name": ""},
    )
    monkeypatch.setattr(auth_routes, "update_user", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        "models.app.get_app_by_id",
        lambda _id: {"id": "app_1", "is_active": True, "allow_anyone": False},
    )
    monkeypatch.setattr(auth_routes, "is_admin", lambda _email: True)
    monkeypatch.setattr(auth_routes, "has_app_permission", lambda *_args: False)

    response = client.post(
        "/register",
        data={"legal_name": "Legal Name", "dob": "2000-01-01", "pronouns": "they/them"},
    )

    assert response.status_code == 200
    assert b"permission to access this app" in response.data


def test_register_post_update_legacy_success_redirects_with_token(monkeypatch):
    app = create_auth_app()
    client = app.test_client()
    login_session(client)
    with client.session_transaction() as sess:
        sess["oauth_redirect"] = "https://example.com/callback"
        sess["oauth_app_id"] = "app_1"
    monkeypatch.setattr(
        auth_routes,
        "get_user_by_email",
        lambda _email: {"id": "user_1", "email": "test@example.com", "legal_name": ""},
    )
    monkeypatch.setattr(auth_routes, "update_user", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        "models.app.get_app_by_id",
        lambda _id: {"id": "app_1", "is_active": True, "allow_anyone": True},
    )
    monkeypatch.setattr(auth_routes, "create_oauth_token", lambda *_args, **_kwargs: "tok_1")

    response = client.post(
        "/register",
        data={"legal_name": "Legal Name", "dob": "2000-01-01", "pronouns": "they/them"},
    )

    assert response.status_code == 302
    assert response.location == "https://example.com/callback?token=tok_1"


def test_register_post_update_legacy_restricted_authorized_user_redirects_with_token(
    monkeypatch,
):
    app = create_auth_app()
    client = app.test_client()
    login_session(client)
    with client.session_transaction() as sess:
        sess["oauth_redirect"] = "https://example.com/callback"
        sess["oauth_app_id"] = "app_1"
    monkeypatch.setattr(
        auth_routes,
        "get_user_by_email",
        lambda _email: {"id": "user_1", "email": "test@example.com", "legal_name": ""},
    )
    monkeypatch.setattr(auth_routes, "update_user", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        "models.app.get_app_by_id",
        lambda _id: {"id": "app_1", "is_active": True, "allow_anyone": False},
    )
    monkeypatch.setattr(auth_routes, "is_admin", lambda _email: True)
    monkeypatch.setattr(auth_routes, "has_app_permission", lambda *_args: True)
    monkeypatch.setattr(auth_routes, "create_oauth_token", lambda *_args, **_kwargs: "tok_1")

    response = client.post(
        "/register",
        data={"legal_name": "Legal Name", "dob": "2000-01-01", "pronouns": "they/them"},
    )

    assert response.status_code == 302
    assert response.location == "https://example.com/callback?token=tok_1"


def test_register_post_create_user_default_redirect_home_without_oauth_redirect(monkeypatch):
    app = create_auth_app()
    client = app.test_client()
    login_session(client, email="new2@example.com")
    monkeypatch.setattr(auth_routes, "get_user_by_email", lambda _email: None)
    monkeypatch.setattr(auth_routes, "create_user", lambda **_kwargs: None)

    response = client.post(
        "/register",
        data={
            "legal_name": "Legal Name",
            "preferred_name": "Nick",
            "dob": "2000-01-01",
            "pronouns": "they/them",
        },
    )

    assert response.status_code == 302
    assert response.location.endswith("/")


def test_register_post_create_user_and_clear_incomplete_oauth_session(monkeypatch):
    app = create_auth_app()
    client = app.test_client()
    login_session(client, email="new@example.com")
    with client.session_transaction() as sess:
        sess["oauth_redirect"] = "https://example.com/callback"

    created = {}
    monkeypatch.setattr(auth_routes, "get_user_by_email", lambda _email: None)
    monkeypatch.setattr(
        auth_routes,
        "create_user",
        lambda **kwargs: created.update(kwargs),
    )

    response = client.post(
        "/register",
        data={
            "legal_name": "Legal Name",
            "preferred_name": "Nick",
            "dob": "2000-01-01",
            "pronouns": "they/them",
        },
    )

    assert response.status_code == 302
    assert response.location.endswith("/")
    assert created["email"] == "new@example.com"
    assert created["dob"] == "01/01/2000"
    with client.session_transaction() as sess:
        assert "oauth_redirect" not in sess


def test_unlink_discord_dashboard_requires_login():
    app = create_auth_app()
    client = app.test_client()

    response = client.post("/dashboard/discord/unlink")

    assert response.status_code == 401
    assert response.get_json()["success"] is False


def test_unlink_discord_dashboard_success(monkeypatch):
    app = create_auth_app()
    client = app.test_client()
    login_session(client)
    monkeypatch.setattr(
        auth_routes,
        "unlink_discord_account",
        lambda _email: {
            "success": True,
            "total_roles_removed": 2,
            "total_roles_failed": 0,
            "role_removal_success": True,
        },
    )

    response = client.post("/dashboard/discord/unlink")

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["success"] is True
    assert payload["roles_removed"] == 2


def test_unlink_discord_dashboard_service_failure(monkeypatch):
    app = create_auth_app()
    client = app.test_client()
    login_session(client)
    monkeypatch.setattr(
        auth_routes,
        "unlink_discord_account",
        lambda _email: {"success": False, "error": "unlink failed"},
    )

    response = client.post("/dashboard/discord/unlink")

    assert response.status_code == 400
    assert response.get_json()["error"] == "unlink failed"


def test_unlink_discord_dashboard_exception_returns_500(monkeypatch):
    app = create_auth_app()
    client = app.test_client()
    login_session(client)

    def raise_exc(_email):
        raise RuntimeError("boom")

    monkeypatch.setattr(auth_routes, "unlink_discord_account", raise_exc)

    response = client.post("/dashboard/discord/unlink")

    assert response.status_code == 500
    assert response.get_json()["error"] == "Internal server error"


def test_unlink_discord_dashboard_exception_with_debug_disabled(monkeypatch):
    app = create_auth_app()
    client = app.test_client()
    login_session(client)
    monkeypatch.setattr(auth_routes, "DEBUG_MODE", False)

    def raise_exc(_email):
        raise RuntimeError("boom")

    monkeypatch.setattr(auth_routes, "unlink_discord_account", raise_exc)

    response = client.post("/dashboard/discord/unlink")

    assert response.status_code == 500
    assert response.get_json()["error"] == "Internal server error"
