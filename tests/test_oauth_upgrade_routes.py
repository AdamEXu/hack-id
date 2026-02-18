import os

os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("WORKOS_API_KEY", "test-workos-key")
os.environ.setdefault("WORKOS_CLIENT_ID", "test-workos-client")

import app as app_module  # noqa: E402


def test_legacy_oauth_endpoints_return_410():
    client = app_module.app.test_client()

    oauth_response = client.get("/oauth")
    assert oauth_response.status_code == 410

    legacy_user_info_response = client.post("/api/oauth/user-info", json={"token": "abc"})
    assert legacy_user_info_response.status_code == 410


def test_admin_apps_requires_apps_read_html(monkeypatch):
    client = app_module.app.test_client()

    # Authenticated admin user, but without apps.read.
    with client.session_transaction() as flask_session:
        flask_session["user_email"] = "admin@example.com"
        flask_session["user_name"] = "Admin"

    monkeypatch.setattr(
        "models.user.get_user_by_email",
        lambda _email: {"email": "admin@example.com", "preferred_name": "Admin", "events": []},
    )
    monkeypatch.setattr("routes.admin.is_admin", lambda _email: True)
    monkeypatch.setattr(
        "routes.admin.has_page_permission",
        lambda _email, page_name, access_level="read": False,
    )

    response = client.get("/admin/apps")
    assert response.status_code == 403
    assert "text/html" in response.headers.get("Content-Type", "")
    assert b"Access denied" in response.data
