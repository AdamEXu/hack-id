import os

os.environ.setdefault("SECRET_KEY", "test-secret")

from flask import Flask, jsonify
import routes.api as api_routes


def create_test_app():
    app = Flask(__name__)
    app.register_blueprint(api_routes.api_bp)
    return app


def test_require_api_key_rejects_missing_authorization_header():
    app = Flask(__name__)

    @app.route("/protected")
    @api_routes.require_api_key("users.read")
    def protected():
        return jsonify({"success": True})

    client = app.test_client()
    response = client.get("/protected")

    assert response.status_code == 401
    assert response.get_json()["error"] == "Missing or invalid Authorization header"


def test_require_api_key_rejects_insufficient_permissions(monkeypatch):
    app = Flask(__name__)

    @app.route("/protected")
    @api_routes.require_api_key("users.read")
    def protected():
        return jsonify({"success": True})

    monkeypatch.setattr(api_routes, "get_key_permissions", lambda _api_key: ["events.register"])

    client = app.test_client()
    response = client.get(
        "/protected", headers={"Authorization": "Bearer test-key"}
    )

    assert response.status_code == 403
    assert response.get_json()["error"] == "Insufficient permissions"


def test_require_api_key_allows_valid_key_and_logs_usage(monkeypatch):
    app = Flask(__name__)

    @app.route("/protected")
    @api_routes.require_api_key("users.read")
    def protected():
        return jsonify({"success": True})

    log_calls = []

    monkeypatch.setattr(api_routes, "get_key_permissions", lambda _api_key: ["users.read"])
    monkeypatch.setattr(
        api_routes,
        "log_api_key_usage",
        lambda api_key, action, metadata: log_calls.append(
            {"api_key": api_key, "action": action, "metadata": metadata}
        ),
    )

    client = app.test_client()
    response = client.get(
        "/protected", headers={"Authorization": "Bearer test-key"}
    )

    assert response.status_code == 200
    assert response.get_json()["success"] is True
    assert len(log_calls) == 1
    assert log_calls[0]["action"] == "protected"


def test_api_current_event_returns_404_when_no_current_event(monkeypatch):
    app = create_test_app()
    monkeypatch.setattr(api_routes, "get_current_event", lambda: None)

    client = app.test_client()
    response = client.get("/api/current-event")

    assert response.status_code == 404
    payload = response.get_json()
    assert payload["success"] is False


def test_api_user_status_returns_data_for_valid_request(monkeypatch):
    app = create_test_app()

    monkeypatch.setattr(api_routes, "get_key_permissions", lambda _api_key: ["users.read"])
    monkeypatch.setattr(api_routes, "log_api_key_usage", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        api_routes,
        "get_user_event_status",
        lambda user_email, event_id: {
            "success": True,
            "user_email": user_email,
            "event_id": event_id,
            "registered": True,
        },
    )

    client = app.test_client()
    response = client.get(
        "/api/user-status?user_email=test@example.com&event_id=hackathon-1",
        headers={"Authorization": "Bearer valid-key"},
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["success"] is True
    assert payload["registered"] is True
