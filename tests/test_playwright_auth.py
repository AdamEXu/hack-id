import os
from pathlib import Path
from threading import Thread

os.environ.setdefault("SECRET_KEY", "test-secret")

import pytest
from flask import Flask, session
from playwright.sync_api import sync_playwright
from werkzeug.serving import make_server

import routes.auth as auth_routes


@pytest.fixture
def auth_server(monkeypatch):
    """Run a minimal auth app with deterministic mocked integrations."""
    template_dir = Path(__file__).resolve().parents[1] / "templates"
    app = Flask(__name__, template_folder=str(template_dir))
    app.secret_key = "test-secret"
    app.jinja_env.globals["csrf_token"] = lambda: "test-csrf"

    monkeypatch.setattr(
        auth_routes,
        "validate_app_redirect",
        lambda _redirect: {"id": "app_1", "is_active": True, "allow_anyone": True},
    )
    monkeypatch.setattr(
        auth_routes,
        "get_user_by_email",
        lambda _email: {"email": "playwright@example.com", "legal_name": "Playwright User"},
    )
    monkeypatch.setattr(
        auth_routes,
        "create_oauth_token",
        lambda _email, expires_in_seconds: "pw_oauth_token",
    )
    monkeypatch.setattr(auth_routes, "send_email_verification", lambda _email: True)

    app.register_blueprint(auth_routes.auth_bp)

    @app.get("/_test/login")
    def _test_login():
        session["user_email"] = "playwright@example.com"
        return "ok", 200

    server = make_server("127.0.0.1", 0, app)
    port = server.server_port
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.shutdown()
        thread.join(timeout=2)


@pytest.fixture
def pw_request():
    """Playwright API request context (no browser binary required)."""
    with sync_playwright() as playwright:
        request_context = playwright.request.new_context(ignore_https_errors=True)
        try:
            yield request_context
        finally:
            request_context.dispose()


def test_playwright_login_page_renders(auth_server, pw_request):
    response = pw_request.get(f"{auth_server}/")

    assert response.status == 200
    assert "Sign in" in response.text()


def test_playwright_send_code_json_flow(auth_server, pw_request):
    response = pw_request.post(
        f"{auth_server}/send-code",
        data={"email": "playwright@example.com"},
    )

    assert response.status == 200
    payload = response.json()
    assert payload["success"] is True
    assert "Magic link sent" in payload["message"]


def test_playwright_oauth_login_and_redirect_flow(auth_server, pw_request):
    oauth_url = (
        f"{auth_server}/oauth?redirect=https://example.com/callback"
    )

    unauthenticated = pw_request.get(oauth_url)
    assert unauthenticated.status == 200
    assert "Sign in" in unauthenticated.text()

    login_response = pw_request.get(f"{auth_server}/_test/login")
    assert login_response.status == 200

    authenticated = pw_request.get(oauth_url, max_redirects=0)
    assert authenticated.status == 302
    assert authenticated.headers["location"] == "https://example.com/callback?token=pw_oauth_token"
