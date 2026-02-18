import os

os.environ.setdefault("SECRET_KEY", "test-secret")

from flask import Flask, jsonify
import pytest

import routes.api as api_routes


def create_api_app():
    app = Flask(__name__)
    app.secret_key = "test-secret"
    app.register_blueprint(api_routes.api_bp)
    return app


def auth_header(token="valid-key"):
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def api_client(monkeypatch):
    app = create_api_app()
    monkeypatch.setattr(
        api_routes,
        "get_key_permissions",
        lambda _key: ["users.read", "events.register", "oauth", "discord.manage"],
    )
    monkeypatch.setattr(api_routes, "log_api_key_usage", lambda *_args, **_kwargs: None)
    return app.test_client()


def test_require_api_key_rejects_invalid_api_key(monkeypatch):
    app = Flask(__name__)

    @app.route("/protected")
    @api_routes.require_api_key("users.read")
    def protected():
        return jsonify({"success": True})

    monkeypatch.setattr(api_routes, "get_key_permissions", lambda _key: [])
    client = app.test_client()

    response = client.get("/protected", headers=auth_header("bad-key"))

    assert response.status_code == 403
    assert response.get_json()["error"] == "Invalid API key"


def test_require_api_key_without_required_permissions_allows_valid_key(monkeypatch):
    app = Flask(__name__)
    calls = []

    @app.route("/open")
    @api_routes.require_api_key()
    def open_route():
        return jsonify({"success": True})

    monkeypatch.setattr(api_routes, "get_key_permissions", lambda _key: ["any.permission"])
    monkeypatch.setattr(
        api_routes,
        "log_api_key_usage",
        lambda key, action, _metadata: calls.append((key, action)),
    )
    client = app.test_client()

    response = client.get("/open", headers=auth_header("k1"))

    assert response.status_code == 200
    assert response.get_json()["success"] is True
    assert calls == [("k1", "open_route")]


def test_api_current_event_success(api_client, monkeypatch):
    monkeypatch.setattr(
        api_routes,
        "get_current_event",
        lambda: {"id": "hack-1", "name": "Hack 1", "description": "Desc", "discord-role-id": "123"},
    )

    response = api_client.get("/api/current-event")

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["success"] is True
    assert payload["current_event"]["id"] == "hack-1"


def test_api_current_event_exception_returns_500(api_client, monkeypatch):
    monkeypatch.setattr(api_routes, "DEBUG_MODE", False)

    def raise_exc():
        raise RuntimeError("boom")

    monkeypatch.setattr(api_routes, "get_current_event", raise_exc)

    response = api_client.get("/api/current-event")

    assert response.status_code == 500
    assert response.get_json()["error"] == "Internal server error"


def test_api_all_events_success(api_client, monkeypatch):
    monkeypatch.setattr(
        api_routes,
        "get_all_events",
        lambda: {
            "hack-1": {"name": "Hack 1", "description": "Desc", "discord-role-id": "123"},
            "hack-2": {"name": "Hack 2"},
        },
    )
    monkeypatch.setattr(api_routes, "get_current_event", lambda: {"id": "hack-1"})

    response = api_client.get("/api/events")

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["success"] is True
    assert len(payload["events"]) == 2
    assert any(event["is_current"] for event in payload["events"])


def test_api_all_events_exception_returns_500(api_client, monkeypatch):
    monkeypatch.setattr(api_routes, "DEBUG_MODE", False)
    monkeypatch.setattr(api_routes, "get_all_events", lambda: (_ for _ in ()).throw(RuntimeError("boom")))

    response = api_client.get("/api/events")

    assert response.status_code == 500
    assert response.get_json()["error"] == "Internal server error"


def test_api_register_event_requires_json(api_client):
    response = api_client.post(
        "/api/register-event",
        data="null",
        content_type="application/json",
        headers=auth_header(),
    )

    assert response.status_code == 400
    assert response.get_json()["error"] == "JSON data required"


def test_api_register_event_validation_failure(api_client, monkeypatch):
    monkeypatch.setattr(api_routes, "validate_api_request", lambda *_args: {"valid": False, "errors": ["bad"]})
    monkeypatch.setattr(
        api_routes,
        "handle_validation_error",
        lambda _result: (api_routes.jsonify({"success": False, "error": "validation"}), 400),
    )

    response = api_client.post("/api/register-event", json={"foo": "bar"}, headers=auth_header())

    assert response.status_code == 400
    assert response.get_json()["error"] == "validation"


def test_api_register_event_success_and_optional_fields_passed(api_client, monkeypatch):
    captured = {}

    monkeypatch.setattr(
        api_routes,
        "validate_api_request",
        lambda data, _required: {"valid": True, "data": data},
    )

    def fake_register(**kwargs):
        captured.update(kwargs)
        return {"success": True, "registered": True}

    monkeypatch.setattr(api_routes, "register_user_for_event", fake_register)

    payload = {
        "user_email": "test@example.com",
        "event_id": "hack-1",
        "phone_number": "123",
        "address": "addr",
        "emergency_contact_name": "name",
        "emergency_contact_email": "ec@example.com",
        "emergency_contact_phone": "321",
        "dietary_restrictions": "none",
        "tshirt_size": "M",
    }
    response = api_client.post("/api/register-event", json=payload, headers=auth_header())

    assert response.status_code == 200
    assert response.get_json()["registered"] is True
    assert captured["user_email"] == "test@example.com"
    assert captured["tshirt_size"] == "M"


def test_api_register_event_service_failure_returns_400(api_client, monkeypatch):
    monkeypatch.setattr(
        api_routes,
        "validate_api_request",
        lambda data, _required: {"valid": True, "data": data},
    )
    monkeypatch.setattr(
        api_routes,
        "register_user_for_event",
        lambda **_kwargs: {"success": False, "error": "failed"},
    )

    response = api_client.post(
        "/api/register-event", json={"user_email": "test@example.com"}, headers=auth_header()
    )

    assert response.status_code == 400
    assert response.get_json()["error"] == "failed"


def test_api_register_event_exception_uses_handle_api_error(api_client, monkeypatch):
    monkeypatch.setattr(
        api_routes,
        "validate_api_request",
        lambda data, _required: {"valid": True, "data": data},
    )
    monkeypatch.setattr(
        api_routes,
        "register_user_for_event",
        lambda **_kwargs: (_ for _ in ()).throw(RuntimeError("boom")),
    )
    monkeypatch.setattr(
        api_routes,
        "handle_api_error",
        lambda _exc, ctx: (api_routes.jsonify({"success": False, "error": ctx}), 500),
    )

    response = api_client.post(
        "/api/register-event", json={"user_email": "test@example.com"}, headers=auth_header()
    )

    assert response.status_code == 500
    assert response.get_json()["error"] == "api_register_event"


def test_api_user_status_requires_user_email(api_client):
    response = api_client.get("/api/user-status", headers=auth_header())

    assert response.status_code == 400
    assert "user_email parameter is required" in response.get_json()["error"]


def test_api_user_status_service_failure(api_client, monkeypatch):
    monkeypatch.setattr(
        api_routes, "get_user_event_status", lambda *_args: {"success": False, "error": "not found"}
    )

    response = api_client.get("/api/user-status?user_email=test@example.com", headers=auth_header())

    assert response.status_code == 400
    assert response.get_json()["error"] == "not found"


def test_api_user_status_exception_returns_500(api_client, monkeypatch):
    monkeypatch.setattr(api_routes, "DEBUG_MODE", False)
    monkeypatch.setattr(
        api_routes, "get_user_event_status", lambda *_args: (_ for _ in ()).throw(RuntimeError("boom"))
    )

    response = api_client.get("/api/user-status?user_email=test@example.com", headers=auth_header())

    assert response.status_code == 500
    assert response.get_json()["error"] == "Internal server error"


def test_oauth2_user_info_invalid_header(api_client):
    response = api_client.get("/api/oauth/user-info")

    assert response.status_code == 401
    assert response.get_json()["error"] == "invalid_request"


def test_oauth2_user_info_invalid_token(api_client, monkeypatch):
    monkeypatch.setattr("models.oauth.verify_access_token", lambda _token: None)

    response = api_client.get("/api/oauth/user-info", headers=auth_header("oauth-token"))

    assert response.status_code == 401
    assert response.get_json()["error"] == "invalid_token"


def test_oauth2_user_info_user_not_found(api_client, monkeypatch):
    monkeypatch.setattr(
        "models.oauth.verify_access_token",
        lambda _token: {"user_email": "test@example.com", "scope": "profile email"},
    )
    monkeypatch.setattr(api_routes, "get_user_by_email", lambda _email: None)

    response = api_client.get("/api/oauth/user-info", headers=auth_header("oauth-token"))

    assert response.status_code == 404
    assert response.get_json()["error"] == "not_found"


def test_oauth2_user_info_success_includes_scope_based_fields(api_client, monkeypatch):
    monkeypatch.setattr(
        "models.oauth.verify_access_token",
        lambda _token: {
            "user_email": "test@example.com",
            "scope": "profile email dob events discord",
        },
    )
    monkeypatch.setattr(
        api_routes,
        "get_user_by_email",
        lambda _email: {
            "email": "test@example.com",
            "legal_name": "Legal Name",
            "preferred_name": "Nick",
            "pronouns": "they/them",
            "dob": "01/01/2000",
            "events": ["hack-1"],
            "discord_id": "123",
            "discord_username": "tester",
        },
    )
    monkeypatch.setattr(api_routes, "is_admin", lambda _email: True)

    response = api_client.get("/api/oauth/user-info", headers=auth_header("oauth-token"))

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["email"] == "test@example.com"
    assert payload["discord_id"] == "123"
    assert payload["is_admin"] is True


def test_oauth2_user_info_with_no_granted_scopes_returns_is_admin_only(api_client, monkeypatch):
    monkeypatch.setattr(
        "models.oauth.verify_access_token",
        lambda _token: {"user_email": "test@example.com", "scope": ""},
    )
    monkeypatch.setattr(
        api_routes,
        "get_user_by_email",
        lambda _email: {"email": "test@example.com"},
    )
    monkeypatch.setattr(api_routes, "is_admin", lambda _email: False)

    response = api_client.get("/api/oauth/user-info", headers=auth_header("oauth-token"))

    assert response.status_code == 200
    assert response.get_json() == {"is_admin": False}


def test_oauth2_user_info_exception_returns_server_error(api_client, monkeypatch):
    monkeypatch.setattr(api_routes, "DEBUG_MODE", False)
    monkeypatch.setattr("models.oauth.verify_access_token", lambda _token: (_ for _ in ()).throw(RuntimeError("boom")))

    response = api_client.get("/api/oauth/user-info", headers=auth_header("oauth-token"))

    assert response.status_code == 500
    assert response.get_json()["error"] == "server_error"


def test_oauth_legacy_user_info_token_required(api_client):
    response = api_client.post("/api/oauth/user-info", json={}, headers=auth_header())

    assert response.status_code == 400
    assert response.get_json()["error"] == "Token is required"


def test_oauth_legacy_user_info_invalid_token(api_client, monkeypatch):
    monkeypatch.setattr(api_routes, "verify_oauth_token", lambda _token: None)

    response = api_client.post("/api/oauth/user-info", json={"token": "bad"}, headers=auth_header())

    assert response.status_code == 401
    assert response.get_json()["error"] == "Invalid or expired token"


def test_oauth_legacy_user_info_user_not_found(api_client, monkeypatch):
    monkeypatch.setattr(api_routes, "verify_oauth_token", lambda _token: "test@example.com")
    monkeypatch.setattr(api_routes, "get_user_by_email", lambda _email: None)

    response = api_client.post("/api/oauth/user-info", json={"token": "good"}, headers=auth_header())

    assert response.status_code == 404
    assert response.get_json()["error"] == "User not found"


def test_oauth_legacy_user_info_success(api_client, monkeypatch):
    monkeypatch.setattr(api_routes, "verify_oauth_token", lambda _token: "test@example.com")
    monkeypatch.setattr(
        api_routes,
        "get_user_by_email",
        lambda _email: {
            "email": "test@example.com",
            "legal_name": "Legal Name",
            "preferred_name": "Nick",
            "pronouns": "they/them",
            "dob": "01/01/2000",
        },
    )
    monkeypatch.setattr(api_routes, "is_admin", lambda _email: False)

    response = api_client.post("/api/oauth/user-info", json={"token": "good"}, headers=auth_header())

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["success"] is True
    assert payload["user"]["email"] == "test@example.com"


def test_oauth_legacy_user_info_exception_returns_500(api_client, monkeypatch):
    monkeypatch.setattr(api_routes, "DEBUG_MODE", False)
    monkeypatch.setattr(api_routes, "verify_oauth_token", lambda _token: (_ for _ in ()).throw(RuntimeError("boom")))

    response = api_client.post("/api/oauth/user-info", json={"token": "good"}, headers=auth_header())

    assert response.status_code == 500
    assert response.get_json()["error"] == "Internal server error"


def test_api_test_endpoint_success(api_client):
    response = api_client.get("/api/test", headers=auth_header())

    assert response.status_code == 200
    assert response.get_json()["success"] is True


def test_discord_user_not_found(api_client, monkeypatch):
    monkeypatch.setattr(api_routes, "get_user_by_discord_id", lambda _id: None)

    response = api_client.get("/api/discord/user/123", headers=auth_header())

    assert response.status_code == 404
    assert response.get_json()["error"] == "User not found"


def test_discord_user_success(api_client, monkeypatch):
    monkeypatch.setattr(
        api_routes,
        "get_user_by_discord_id",
        lambda _id: {
            "id": "user-1",
            "email": "test@example.com",
            "legal_name": "Legal Name",
            "preferred_name": "Nick",
            "pronouns": "they/them",
            "dob": "01/01/2000",
            "discord_id": "123",
            "events": ["hack-1"],
        },
    )
    monkeypatch.setattr("models.admin.is_admin", lambda _email: True)

    response = api_client.get("/api/discord/user/123", headers=auth_header())

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["success"] is True
    assert payload["user"]["is_admin"] is True


def test_discord_user_exception_uses_handle_api_error(api_client, monkeypatch):
    monkeypatch.setattr(
        api_routes, "get_user_by_discord_id", lambda _id: (_ for _ in ()).throw(RuntimeError("boom"))
    )
    monkeypatch.setattr(
        api_routes,
        "handle_api_error",
        lambda _exc, ctx: (api_routes.jsonify({"success": False, "error": ctx}), 500),
    )

    response = api_client.get("/api/discord/user/123", headers=auth_header())

    assert response.status_code == 500
    assert response.get_json()["error"] == "api_discord_user"


def test_create_verification_token_requires_json(api_client):
    response = api_client.post(
        "/api/discord/verification-token",
        data="null",
        content_type="application/json",
        headers=auth_header(),
    )

    assert response.status_code == 400
    assert response.get_json()["error"] == "JSON data required"


def test_create_verification_token_requires_fields(api_client):
    response = api_client.post(
        "/api/discord/verification-token",
        json={"discord_username": "tester"},
        headers=auth_header(),
    )

    assert response.status_code == 400
    assert "Missing field: discord_id" in response.get_json()["error"]


def test_create_verification_token_success(api_client, monkeypatch):
    monkeypatch.setattr(api_routes, "save_verification_token", lambda *_args: "tok_1")

    response = api_client.post(
        "/api/discord/verification-token",
        json={"discord_id": 123, "discord_username": "tester", "message_id": "m1"},
        headers=auth_header(),
    )

    assert response.status_code == 200
    assert response.get_json()["token"] == "tok_1"


def test_create_verification_token_exception(api_client, monkeypatch):
    monkeypatch.setattr(
        api_routes, "save_verification_token", lambda *_args: (_ for _ in ()).throw(RuntimeError("boom"))
    )
    monkeypatch.setattr(
        api_routes,
        "handle_api_error",
        lambda _exc, ctx: (api_routes.jsonify({"success": False, "error": ctx}), 500),
    )

    response = api_client.post(
        "/api/discord/verification-token",
        json={"discord_id": 123, "discord_username": "tester"},
        headers=auth_header(),
    )

    assert response.status_code == 500
    assert response.get_json()["error"] == "api_create_verification_token"


def test_get_verification_token_not_found(api_client, monkeypatch):
    monkeypatch.setattr(api_routes, "get_verification_token", lambda _token: None)

    response = api_client.get("/api/discord/verification-token/tok_1", headers=auth_header())

    assert response.status_code == 404


def test_get_verification_token_success(api_client, monkeypatch):
    monkeypatch.setattr(
        api_routes,
        "get_verification_token",
        lambda _token: {
            "token": "tok_1",
            "discord_id": "123",
            "discord_username": "tester",
            "message_id": "m1",
            "expires_at": "2026-01-01",
            "used": 1,
        },
    )

    response = api_client.get("/api/discord/verification-token/tok_1", headers=auth_header())

    assert response.status_code == 200
    assert response.get_json()["token_data"]["used"] is True


def test_get_verification_token_exception(api_client, monkeypatch):
    monkeypatch.setattr(
        api_routes, "get_verification_token", lambda _token: (_ for _ in ()).throw(RuntimeError("boom"))
    )
    monkeypatch.setattr(
        api_routes,
        "handle_api_error",
        lambda _exc, ctx: (api_routes.jsonify({"success": False, "error": ctx}), 500),
    )

    response = api_client.get("/api/discord/verification-token/tok_1", headers=auth_header())

    assert response.status_code == 500
    assert response.get_json()["error"] == "api_get_verification_token"


def test_mark_token_used_not_found(api_client, monkeypatch):
    monkeypatch.setattr(api_routes, "get_verification_token", lambda _token: None)

    response = api_client.delete("/api/discord/verification-token/tok_1", headers=auth_header())

    assert response.status_code == 404


def test_mark_token_used_success(api_client, monkeypatch):
    used = {}
    monkeypatch.setattr(api_routes, "get_verification_token", lambda _token: {"token": "tok_1"})
    monkeypatch.setattr(api_routes, "mark_token_used", lambda token: used.setdefault("token", token))

    response = api_client.delete("/api/discord/verification-token/tok_1", headers=auth_header())

    assert response.status_code == 200
    assert used["token"] == "tok_1"


def test_mark_token_used_exception(api_client, monkeypatch):
    monkeypatch.setattr(
        api_routes, "get_verification_token", lambda _token: (_ for _ in ()).throw(RuntimeError("boom"))
    )
    monkeypatch.setattr(
        api_routes,
        "handle_api_error",
        lambda _exc, ctx: (api_routes.jsonify({"success": False, "error": ctx}), 500),
    )

    response = api_client.delete("/api/discord/verification-token/tok_1", headers=auth_header())

    assert response.status_code == 500
    assert response.get_json()["error"] == "api_mark_token_used"


def test_discord_role_mappings_success(api_client, monkeypatch):
    monkeypatch.setattr(
        api_routes,
        "get_all_events",
        lambda: {"hack-1": {"discord-role-id": "123"}, "hack-2": {"name": "No role"}},
    )

    response = api_client.get("/api/discord/role-mappings", headers=auth_header())

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["role_mappings"] == {"hack-1": "123"}


def test_discord_role_mappings_exception(api_client, monkeypatch):
    monkeypatch.setattr(api_routes, "get_all_events", lambda: (_ for _ in ()).throw(RuntimeError("boom")))
    monkeypatch.setattr(
        api_routes,
        "handle_api_error",
        lambda _exc, ctx: (api_routes.jsonify({"success": False, "error": ctx}), 500),
    )

    response = api_client.get("/api/discord/role-mappings", headers=auth_header())

    assert response.status_code == 500
    assert response.get_json()["error"] == "api_discord_role_mappings"


def test_discord_user_roles_not_found(api_client, monkeypatch):
    monkeypatch.setattr(api_routes, "get_user_by_discord_id", lambda _id: None)

    response = api_client.get("/api/discord/user-roles/123", headers=auth_header())

    assert response.status_code == 404


def test_discord_user_roles_success(api_client, monkeypatch):
    monkeypatch.setattr(api_routes, "get_user_by_discord_id", lambda _id: {"events": ["hack-1", "hack-2"]})
    monkeypatch.setattr(
        api_routes,
        "get_all_events",
        lambda: {
            "hack-1": {"discord-role-id": "123", "name": "Hack 1"},
            "hack-2": {"name": "Hack 2"},
        },
    )

    response = api_client.get("/api/discord/user-roles/123", headers=auth_header())

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["roles_to_assign"] == [{"event_id": "hack-1", "role_id": "123", "event_name": "Hack 1"}]


def test_discord_user_roles_exception(api_client, monkeypatch):
    monkeypatch.setattr(
        api_routes, "get_user_by_discord_id", lambda _id: (_ for _ in ()).throw(RuntimeError("boom"))
    )
    monkeypatch.setattr(
        api_routes,
        "handle_api_error",
        lambda _exc, ctx: (api_routes.jsonify({"success": False, "error": ctx}), 500),
    )

    response = api_client.get("/api/discord/user-roles/123", headers=auth_header())

    assert response.status_code == 500
    assert response.get_json()["error"] == "api_discord_user_roles"


def test_discord_verified_users_success(api_client, monkeypatch):
    monkeypatch.setattr(
        api_routes,
        "get_all_users",
        lambda: [
            {"id": "1", "email": "a@example.com", "discord_id": "123", "events": [], "preferred_name": "A", "legal_name": "A"},
            {"id": "2", "email": "b@example.com", "discord_id": "", "events": []},
        ],
    )

    response = api_client.get("/api/discord/verified-users", headers=auth_header())

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["count"] == 1
    assert payload["verified_users"][0]["email"] == "a@example.com"


def test_discord_verified_users_exception(api_client, monkeypatch):
    monkeypatch.setattr(api_routes, "get_all_users", lambda: (_ for _ in ()).throw(RuntimeError("boom")))
    monkeypatch.setattr(
        api_routes,
        "handle_api_error",
        lambda _exc, ctx: (api_routes.jsonify({"success": False, "error": ctx}), 500),
    )

    response = api_client.get("/api/discord/verified-users", headers=auth_header())

    assert response.status_code == 500
    assert response.get_json()["error"] == "api_discord_verified_users"


def test_discord_complete_verification_requires_json(api_client):
    response = api_client.post(
        "/api/discord/complete-verification",
        data="null",
        content_type="application/json",
        headers=auth_header(),
    )

    assert response.status_code == 400
    assert response.get_json()["error"] == "JSON data required"


def test_discord_complete_verification_requires_fields(api_client):
    response = api_client.post(
        "/api/discord/complete-verification",
        json={"discord_id": "123"},
        headers=auth_header(),
    )

    assert response.status_code == 400
    assert "Missing field: user_email" in response.get_json()["error"]


def test_discord_complete_verification_user_not_found(api_client, monkeypatch):
    monkeypatch.setattr(api_routes, "get_user_by_email", lambda _email: None)

    response = api_client.post(
        "/api/discord/complete-verification",
        json={"discord_id": "123", "user_email": "test@example.com"},
        headers=auth_header(),
    )

    assert response.status_code == 404


def test_discord_complete_verification_rejects_id_linked_to_other_user(api_client, monkeypatch):
    monkeypatch.setattr(api_routes, "get_user_by_email", lambda _email: {"id": "user-1", "email": "test@example.com"})
    monkeypatch.setattr(api_routes, "get_user_by_discord_id", lambda _id: {"email": "other@example.com"})

    response = api_client.post(
        "/api/discord/complete-verification",
        json={"discord_id": "123", "user_email": "test@example.com"},
        headers=auth_header(),
    )

    assert response.status_code == 400
    assert "already linked" in response.get_json()["error"]


def test_discord_complete_verification_update_value_error(api_client, monkeypatch):
    monkeypatch.setattr(api_routes, "get_user_by_email", lambda _email: {"id": "user-1", "email": "test@example.com"})
    monkeypatch.setattr(api_routes, "get_user_by_discord_id", lambda _id: None)

    def raise_value_error(*_args, **_kwargs):
        raise ValueError("invalid")

    monkeypatch.setattr("models.user.update_user", raise_value_error)

    response = api_client.post(
        "/api/discord/complete-verification",
        json={"discord_id": "123", "user_email": "test@example.com"},
        headers=auth_header(),
    )

    assert response.status_code == 400
    assert response.get_json()["error"] == "invalid"


def test_discord_complete_verification_success(api_client, monkeypatch):
    monkeypatch.setattr(api_routes, "get_user_by_email", lambda _email: {"id": "user-1", "email": "test@example.com"})
    monkeypatch.setattr(api_routes, "get_user_by_discord_id", lambda _id: None)
    monkeypatch.setattr("models.user.update_user", lambda *_args, **_kwargs: None)

    response = api_client.post(
        "/api/discord/complete-verification",
        json={"discord_id": "123", "user_email": "test@example.com"},
        headers=auth_header(),
    )

    assert response.status_code == 200
    assert response.get_json()["success"] is True


def test_discord_complete_verification_exception(api_client, monkeypatch):
    monkeypatch.setattr(
        api_routes, "get_user_by_email", lambda _email: (_ for _ in ()).throw(RuntimeError("boom"))
    )
    monkeypatch.setattr(
        api_routes,
        "handle_api_error",
        lambda _exc, ctx: (api_routes.jsonify({"success": False, "error": ctx}), 500),
    )

    response = api_client.post(
        "/api/discord/complete-verification",
        json={"discord_id": "123", "user_email": "test@example.com"},
        headers=auth_header(),
    )

    assert response.status_code == 500
    assert response.get_json()["error"] == "api_discord_complete_verification"


def test_discord_remove_roles_requires_json(api_client):
    response = api_client.post(
        "/api/discord/remove-roles",
        data="null",
        content_type="application/json",
        headers=auth_header(),
    )

    assert response.status_code == 400


def test_discord_remove_roles_requires_identifier(api_client):
    response = api_client.post("/api/discord/remove-roles", json={"foo": "bar"}, headers=auth_header())

    assert response.status_code == 400
    assert "Either discord_id or user_email is required" in response.get_json()["error"]


def test_discord_remove_roles_user_email_not_found(api_client, monkeypatch):
    monkeypatch.setattr(api_routes, "get_user_by_email", lambda _email: None)

    response = api_client.post(
        "/api/discord/remove-roles",
        json={"user_email": "test@example.com"},
        headers=auth_header(),
    )

    assert response.status_code == 404


def test_discord_remove_roles_user_without_discord(api_client, monkeypatch):
    monkeypatch.setattr(api_routes, "get_user_by_email", lambda _email: {"email": "test@example.com", "discord_id": None})

    response = api_client.post(
        "/api/discord/remove-roles",
        json={"user_email": "test@example.com"},
        headers=auth_header(),
    )

    assert response.status_code == 404
    assert "no Discord account linked" in response.get_json()["error"]


def test_discord_remove_roles_success(api_client, monkeypatch):
    monkeypatch.setattr(
        "utils.discord.remove_all_event_roles",
        lambda _discord_id: {"success": True, "roles_removed": ["a"], "total_removed": 1},
    )

    response = api_client.post(
        "/api/discord/remove-roles",
        json={"discord_id": "123"},
        headers=auth_header(),
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["success"] is True
    assert payload["total_removed"] == 1


def test_discord_remove_roles_user_email_with_discord_success(api_client, monkeypatch):
    monkeypatch.setattr(
        api_routes,
        "get_user_by_email",
        lambda _email: {"email": "test@example.com", "discord_id": "123"},
    )
    monkeypatch.setattr(
        "utils.discord.remove_all_event_roles",
        lambda _discord_id: {"success": True, "roles_removed": [], "total_removed": 0},
    )

    response = api_client.post(
        "/api/discord/remove-roles",
        json={"user_email": "test@example.com"},
        headers=auth_header(),
    )

    assert response.status_code == 200
    assert response.get_json()["success"] is True


def test_discord_remove_roles_failure_returns_500(api_client, monkeypatch):
    monkeypatch.setattr(
        "utils.discord.remove_all_event_roles",
        lambda _discord_id: {
            "success": False,
            "error": "remove failed",
            "roles_removed": [],
            "roles_failed": ["a"],
        },
    )

    response = api_client.post(
        "/api/discord/remove-roles",
        json={"discord_id": "123"},
        headers=auth_header(),
    )

    assert response.status_code == 500
    assert response.get_json()["error"] == "remove failed"


def test_discord_remove_roles_exception(api_client, monkeypatch):
    monkeypatch.setattr(
        "utils.discord.remove_all_event_roles",
        lambda _discord_id: (_ for _ in ()).throw(RuntimeError("boom")),
    )
    monkeypatch.setattr(
        api_routes,
        "handle_api_error",
        lambda _exc, ctx: (api_routes.jsonify({"success": False, "error": ctx}), 500),
    )

    response = api_client.post(
        "/api/discord/remove-roles",
        json={"discord_id": "123"},
        headers=auth_header(),
    )

    assert response.status_code == 500
    assert response.get_json()["error"] == "api_discord_remove_roles"


def test_discord_unlink_requires_json(api_client):
    response = api_client.post(
        "/api/discord/unlink",
        data="null",
        content_type="application/json",
        headers=auth_header(),
    )

    assert response.status_code == 400


def test_discord_unlink_requires_identifier(api_client):
    response = api_client.post("/api/discord/unlink", json={"foo": "bar"}, headers=auth_header())

    assert response.status_code == 400


def test_discord_unlink_discord_id_not_found(api_client, monkeypatch):
    monkeypatch.setattr(api_routes, "get_user_by_discord_id", lambda _id: None)

    response = api_client.post(
        "/api/discord/unlink",
        json={"discord_id": "123"},
        headers=auth_header(),
    )

    assert response.status_code == 404
    assert "No user found" in response.get_json()["error"]


def test_discord_unlink_user_email_not_found(api_client, monkeypatch):
    monkeypatch.setattr(api_routes, "get_user_by_email", lambda _email: None)

    response = api_client.post(
        "/api/discord/unlink",
        json={"user_email": "test@example.com"},
        headers=auth_header(),
    )

    assert response.status_code == 404


def test_discord_unlink_user_without_discord(api_client, monkeypatch):
    monkeypatch.setattr(api_routes, "get_user_by_email", lambda _email: {"email": "test@example.com", "discord_id": None})

    response = api_client.post(
        "/api/discord/unlink",
        json={"user_email": "test@example.com"},
        headers=auth_header(),
    )

    assert response.status_code == 400
    assert "no Discord account linked" in response.get_json()["error"]


def test_discord_unlink_success(api_client, monkeypatch):
    monkeypatch.setattr(
        api_routes, "get_user_by_discord_id", lambda _id: {"email": "test@example.com"}
    )
    monkeypatch.setattr(
        "services.auth_service.unlink_discord_account",
        lambda _email: {
            "success": True,
            "user_email": "test@example.com",
            "previous_discord_id": "123",
            "roles_removed": [],
            "roles_failed": [],
            "total_roles_removed": 0,
            "total_roles_failed": 0,
            "role_removal_success": True,
        },
    )

    response = api_client.post(
        "/api/discord/unlink",
        json={"discord_id": "123"},
        headers=auth_header(),
    )

    assert response.status_code == 200
    assert response.get_json()["success"] is True


def test_discord_unlink_success_by_user_email(api_client, monkeypatch):
    monkeypatch.setattr(
        api_routes,
        "get_user_by_email",
        lambda _email: {"email": "test@example.com", "discord_id": "123"},
    )
    monkeypatch.setattr(
        "services.auth_service.unlink_discord_account",
        lambda _email: {
            "success": True,
            "user_email": "test@example.com",
            "previous_discord_id": "123",
            "roles_removed": [],
            "roles_failed": [],
            "total_roles_removed": 0,
            "total_roles_failed": 0,
            "role_removal_success": True,
        },
    )

    response = api_client.post(
        "/api/discord/unlink",
        json={"user_email": "test@example.com"},
        headers=auth_header(),
    )

    assert response.status_code == 200
    assert response.get_json()["success"] is True


def test_discord_unlink_service_failure(api_client, monkeypatch):
    monkeypatch.setattr(
        api_routes, "get_user_by_discord_id", lambda _id: {"email": "test@example.com"}
    )
    monkeypatch.setattr(
        "services.auth_service.unlink_discord_account",
        lambda _email: {"success": False, "error": "unlink failed"},
    )

    response = api_client.post(
        "/api/discord/unlink",
        json={"discord_id": "123"},
        headers=auth_header(),
    )

    assert response.status_code == 400
    assert response.get_json()["error"] == "unlink failed"


def test_discord_unlink_exception(api_client, monkeypatch):
    monkeypatch.setattr(
        api_routes, "get_user_by_discord_id", lambda _id: (_ for _ in ()).throw(RuntimeError("boom"))
    )
    monkeypatch.setattr(
        api_routes,
        "handle_api_error",
        lambda _exc, ctx: (api_routes.jsonify({"success": False, "error": ctx}), 500),
    )

    response = api_client.post(
        "/api/discord/unlink",
        json={"discord_id": "123"},
        headers=auth_header(),
    )

    assert response.status_code == 500
    assert response.get_json()["error"] == "api_discord_unlink"
