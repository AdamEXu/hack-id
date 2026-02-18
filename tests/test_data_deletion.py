import os

os.environ.setdefault("SECRET_KEY", "test-secret")

import services.data_deletion as data_deletion


class FakeCursor:
    def __init__(self, rowcount):
        self.rowcount = rowcount


class FakeConnection:
    def __init__(self, rowcount=0):
        self.rowcount = rowcount
        self.committed = False
        self.closed = False

    def execute(self, _query, _params):
        return FakeCursor(self.rowcount)

    def commit(self):
        self.committed = True

    def close(self):
        self.closed = True


def test_delete_user_data_returns_error_when_user_not_found(monkeypatch):
    monkeypatch.setattr(
        data_deletion,
        "get_user_data_summary",
        lambda _email: {"user_found": False, "discord_linked": False},
    )

    result = data_deletion.delete_user_data("missing@example.com")

    assert result["success"] is False
    assert "User not found" in result["errors"]


def test_delete_user_data_deletes_opt_out_and_user_record(monkeypatch):
    fake_conn = FakeConnection(rowcount=2)
    deleted_user_ids = []

    monkeypatch.setattr(
        data_deletion,
        "get_user_data_summary",
        lambda _email: {"user_found": True, "discord_linked": False},
    )
    monkeypatch.setattr(data_deletion, "get_db_connection", lambda: fake_conn)
    monkeypatch.setattr(
        data_deletion,
        "delete_subscriber_by_email",
        lambda _email: {"success": True},
    )
    monkeypatch.setattr(
        data_deletion,
        "get_user_by_email",
        lambda _email: {"id": "user_123", "email": "test@example.com"},
    )

    import models.user as user_model

    monkeypatch.setattr(
        user_model, "delete_user", lambda user_id: deleted_user_ids.append(user_id)
    )

    result = data_deletion.delete_user_data(
        "test@example.com", include_discord=False, include_listmonk=True
    )

    assert result["success"] is True
    assert result["deletion_counts"]["opt_out_tokens"] == 2
    assert result["deletion_counts"]["users"] == 1
    assert result["total_records_deleted"] == 3
    assert deleted_user_ids == ["user_123"]
    assert fake_conn.committed is True
    assert fake_conn.closed is True
