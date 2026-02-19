import os

os.environ.setdefault("SECRET_KEY", "test-secret")

from services.app_access_service import (  # noqa: E402
    AppAclEvaluationError,
    evaluate_app_acl_with_fail_open,
)


def test_fail_open_allows_with_valid_snapshot(monkeypatch):
    app = {"id": "app_123", "allow_anyone": False}
    session_data = {"uw_admin": True, "uw_admin_verified_at": 1_700_000_000}

    def raise_eval_error(*_args, **_kwargs):
        raise AppAclEvaluationError("teable unavailable")

    monkeypatch.setattr(
        "services.app_access_service.evaluate_app_acl_strict",
        raise_eval_error,
    )
    monkeypatch.setattr("services.universal_admin_snapshot.time.time", lambda: 1_700_000_100)

    result = evaluate_app_acl_with_fail_open(
        app=app,
        user_email="admin@example.com",
        path="/oauth/authorize",
        sess=session_data,
    )

    assert result["allowed"] is True
    assert result["fail_open_used"] is True
    assert session_data["acl_fail_open_used"] is True


def test_fail_open_denies_with_missing_snapshot(monkeypatch):
    app = {"id": "app_123", "allow_anyone": False}
    session_data = {}

    def raise_eval_error(*_args, **_kwargs):
        raise AppAclEvaluationError("teable unavailable")

    monkeypatch.setattr(
        "services.app_access_service.evaluate_app_acl_strict",
        raise_eval_error,
    )

    result = evaluate_app_acl_with_fail_open(
        app=app,
        user_email="admin@example.com",
        path="/oauth/authorize",
        sess=session_data,
    )

    assert result["allowed"] is False
    assert result["reason"] == "acl_eval_error_no_snapshot"

