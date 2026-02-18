import os

os.environ.setdefault("SECRET_KEY", "test-secret")

import builtins

import services.data_deletion as data_deletion


class FakeCursor:
    def __init__(self, rowcount=0, row=None):
        self.rowcount = rowcount
        self._row = row

    def fetchone(self):
        return self._row


class FakeConnection:
    def __init__(self, execute_impl):
        self._execute_impl = execute_impl
        self.committed = False
        self.closed = False

    def execute(self, query, params):
        return self._execute_impl(query, params)

    def commit(self):
        self.committed = True

    def close(self):
        self.closed = True


def test_get_user_data_summary_user_not_found(monkeypatch):
    conn = FakeConnection(lambda _query, _params: FakeCursor(row=({"count": 0})))
    monkeypatch.setattr(data_deletion, "get_db_connection", lambda: conn)
    monkeypatch.setattr(data_deletion, "get_user_by_email", lambda _email: None)

    summary = data_deletion.get_user_data_summary("missing@example.com")

    assert summary["user_found"] is False
    assert summary["tables_with_data"] == []
    assert conn.closed is True


def test_get_user_data_summary_with_opt_out_tokens(monkeypatch):
    conn = FakeConnection(
        lambda _query, _params: FakeCursor(row={"count": 3})
    )
    monkeypatch.setattr(data_deletion, "get_db_connection", lambda: conn)
    monkeypatch.setattr(
        data_deletion,
        "get_user_by_email",
        lambda _email: {"id": "user_1", "discord_id": "123"},
    )

    summary = data_deletion.get_user_data_summary("test@example.com")

    assert summary["user_found"] is True
    assert summary["discord_linked"] is True
    assert summary["opt_out_tokens"] == 3
    assert "users" in summary["tables_with_data"]
    assert "opt_out_tokens" in summary["tables_with_data"]
    assert conn.closed is True


def test_get_user_data_summary_user_with_no_opt_out_tokens(monkeypatch):
    conn = FakeConnection(lambda _query, _params: FakeCursor(row={"count": 0}))
    monkeypatch.setattr(data_deletion, "get_db_connection", lambda: conn)
    monkeypatch.setattr(
        data_deletion,
        "get_user_by_email",
        lambda _email: {"id": "user_1", "discord_id": None},
    )

    summary = data_deletion.get_user_data_summary("test@example.com")

    assert summary["user_found"] is True
    assert summary["opt_out_tokens"] == 0
    assert summary["tables_with_data"] == ["users"]


def test_remove_discord_roles_when_no_discord_account(monkeypatch):
    monkeypatch.setattr(
        data_deletion, "get_user_by_email", lambda _email: {"email": "test@example.com", "discord_id": None}
    )

    result = data_deletion.remove_discord_roles("test@example.com")

    assert result["success"] is False
    assert result["error"] == "No Discord account linked"


def test_remove_discord_roles_success(monkeypatch):
    monkeypatch.setattr(data_deletion, "DEBUG_MODE", False)
    monkeypatch.setattr(
        data_deletion, "get_user_by_email", lambda _email: {"email": "test@example.com", "discord_id": "123"}
    )
    monkeypatch.setattr(
        "utils.discord.remove_all_event_roles",
        lambda _discord_id: {"success": True, "roles_removed": ["a"], "total_removed": 1},
    )

    result = data_deletion.remove_discord_roles("test@example.com")

    assert result["success"] is True
    assert result["total_removed"] == 1
    assert result["roles_removed"] == ["a"]


def test_remove_discord_roles_partial_failure(monkeypatch):
    monkeypatch.setattr(data_deletion, "DEBUG_MODE", False)
    monkeypatch.setattr(
        data_deletion, "get_user_by_email", lambda _email: {"email": "test@example.com", "discord_id": "123"}
    )
    monkeypatch.setattr(
        "utils.discord.remove_all_event_roles",
        lambda _discord_id: {
            "success": False,
            "error": "remove failed",
            "roles_removed": ["a"],
            "roles_failed": ["b"],
        },
    )

    result = data_deletion.remove_discord_roles("test@example.com")

    assert result["success"] is False
    assert result["error"] == "remove failed"
    assert result["roles_failed"] == ["b"]


def test_remove_discord_roles_handles_unexpected_exception(monkeypatch):
    monkeypatch.setattr(
        data_deletion, "get_user_by_email", lambda _email: {"email": "test@example.com", "discord_id": "123"}
    )
    monkeypatch.setattr(
        "utils.discord.remove_all_event_roles",
        lambda _discord_id: (_ for _ in ()).throw(RuntimeError("boom")),
    )

    result = data_deletion.remove_discord_roles("test@example.com")

    assert result["success"] is False
    assert "Discord role removal failed" in result["error"]


def test_remove_discord_roles_handles_import_error(monkeypatch):
    monkeypatch.setattr(
        data_deletion, "get_user_by_email", lambda _email: {"email": "test@example.com", "discord_id": "123"}
    )

    original_import = builtins.__import__

    def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "utils.discord":
            raise ImportError("missing discord utilities")
        return original_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    result = data_deletion.remove_discord_roles("test@example.com")

    assert result["success"] is False
    assert result["error"] == "Discord utilities not available"


def test_remove_discord_roles_handles_user_lookup_exception(monkeypatch):
    monkeypatch.setattr(
        data_deletion,
        "get_user_by_email",
        lambda _email: (_ for _ in ()).throw(RuntimeError("lookup boom")),
    )

    result = data_deletion.remove_discord_roles("test@example.com")

    assert result["success"] is False
    assert "Error accessing user data" in result["error"]


def test_delete_user_data_adds_discord_and_listmonk_errors(monkeypatch):
    conn = FakeConnection(lambda _query, _params: FakeCursor(rowcount=0))

    monkeypatch.setattr(
        data_deletion,
        "get_user_data_summary",
        lambda _email: {"user_found": True, "discord_linked": True},
    )
    monkeypatch.setattr(
        data_deletion,
        "remove_discord_roles",
        lambda _email: {"success": False, "error": "discord failed"},
    )
    monkeypatch.setattr(
        data_deletion,
        "delete_subscriber_by_email",
        lambda _email: {"success": False, "error": "listmonk failed", "skipped": False},
    )
    monkeypatch.setattr(data_deletion, "get_db_connection", lambda: conn)
    monkeypatch.setattr(data_deletion, "get_user_by_email", lambda _email: None)

    result = data_deletion.delete_user_data("test@example.com")

    assert result["success"] is False
    assert "Discord: discord failed" in result["errors"]
    assert "Listmonk: listmonk failed" in result["errors"]
    assert conn.committed is True
    assert conn.closed is True


def test_delete_user_data_discord_success_does_not_add_discord_error(monkeypatch):
    conn = FakeConnection(lambda _query, _params: FakeCursor(rowcount=0))
    monkeypatch.setattr(
        data_deletion,
        "get_user_data_summary",
        lambda _email: {"user_found": True, "discord_linked": True},
    )
    monkeypatch.setattr(
        data_deletion,
        "remove_discord_roles",
        lambda _email: {"success": True, "error": None},
    )
    monkeypatch.setattr(
        data_deletion,
        "delete_subscriber_by_email",
        lambda _email: {"success": True},
    )
    monkeypatch.setattr(data_deletion, "get_db_connection", lambda: conn)
    monkeypatch.setattr(data_deletion, "get_user_by_email", lambda _email: None)

    result = data_deletion.delete_user_data("test@example.com")

    assert result["success"] is True
    assert all(not err.startswith("Discord:") for err in result["errors"])


def test_delete_user_data_skipped_listmonk_does_not_add_error(monkeypatch):
    conn = FakeConnection(lambda _query, _params: FakeCursor(rowcount=0))
    monkeypatch.setattr(
        data_deletion,
        "get_user_data_summary",
        lambda _email: {"user_found": True, "discord_linked": False},
    )
    monkeypatch.setattr(
        data_deletion,
        "delete_subscriber_by_email",
        lambda _email: {"success": False, "skipped": True},
    )
    monkeypatch.setattr(data_deletion, "get_db_connection", lambda: conn)
    monkeypatch.setattr(data_deletion, "get_user_by_email", lambda _email: None)

    result = data_deletion.delete_user_data("test@example.com")

    assert result["success"] is True
    assert result["errors"] == []


def test_delete_user_data_with_listmonk_disabled_skips_external_delete(monkeypatch):
    conn = FakeConnection(lambda _query, _params: FakeCursor(rowcount=0))
    monkeypatch.setattr(
        data_deletion,
        "get_user_data_summary",
        lambda _email: {"user_found": True, "discord_linked": False},
    )
    monkeypatch.setattr(data_deletion, "get_db_connection", lambda: conn)
    monkeypatch.setattr(data_deletion, "get_user_by_email", lambda _email: None)

    result = data_deletion.delete_user_data(
        "test@example.com", include_discord=False, include_listmonk=False
    )

    assert result["success"] is True
    assert result["listmonk_result"] is None


def test_delete_user_data_handles_sqlite_delete_error(monkeypatch):
    def execute_impl(_query, _params):
        raise RuntimeError("sqlite failed")

    conn = FakeConnection(execute_impl)
    monkeypatch.setattr(
        data_deletion,
        "get_user_data_summary",
        lambda _email: {"user_found": True, "discord_linked": False},
    )
    monkeypatch.setattr(
        data_deletion,
        "delete_subscriber_by_email",
        lambda _email: {"success": True},
    )
    monkeypatch.setattr(data_deletion, "get_db_connection", lambda: conn)
    monkeypatch.setattr(data_deletion, "get_user_by_email", lambda _email: None)

    result = data_deletion.delete_user_data("test@example.com")

    assert result["success"] is False
    assert any("Error deleting from opt_out_tokens" in err for err in result["errors"])


def test_delete_user_data_handles_teable_delete_error(monkeypatch):
    conn = FakeConnection(lambda _query, _params: FakeCursor(rowcount=0))
    monkeypatch.setattr(
        data_deletion,
        "get_user_data_summary",
        lambda _email: {"user_found": True, "discord_linked": False},
    )
    monkeypatch.setattr(
        data_deletion,
        "delete_subscriber_by_email",
        lambda _email: {"success": True},
    )
    monkeypatch.setattr(data_deletion, "get_db_connection", lambda: conn)
    monkeypatch.setattr(
        data_deletion, "get_user_by_email", lambda _email: {"id": "user_1", "email": "test@example.com"}
    )

    def raise_delete(_user_id):
        raise RuntimeError("teable failed")

    monkeypatch.setattr("models.user.delete_user", raise_delete)

    result = data_deletion.delete_user_data("test@example.com")

    assert result["success"] is False
    assert any("Error deleting from Teable users" in err for err in result["errors"])


def test_delete_user_data_outer_exception_is_captured(monkeypatch):
    monkeypatch.setattr(
        data_deletion,
        "get_user_data_summary",
        lambda _email: (_ for _ in ()).throw(RuntimeError("critical")),
    )

    result = data_deletion.delete_user_data("test@example.com")

    assert result["success"] is False
    assert any("Critical error during data deletion" in err for err in result["errors"])


def test_verify_user_deletion_when_fully_deleted(monkeypatch):
    conn = FakeConnection(lambda _query, _params: FakeCursor(row={"count": 0}))
    monkeypatch.setattr(data_deletion, "get_db_connection", lambda: conn)
    monkeypatch.setattr(data_deletion, "get_user_by_email", lambda _email: None)

    verification = data_deletion.verify_user_deletion("test@example.com")

    assert verification["completely_deleted"] is True
    assert verification["remaining_data"] == {}
    assert "opt_out_tokens" in verification["tables_checked"]
    assert "users" in verification["tables_checked"]
    assert conn.closed is True


def test_verify_user_deletion_detects_remaining_data(monkeypatch):
    conn = FakeConnection(lambda _query, _params: FakeCursor(row={"count": 2}))
    monkeypatch.setattr(data_deletion, "get_db_connection", lambda: conn)
    monkeypatch.setattr(data_deletion, "get_user_by_email", lambda _email: {"id": "user_1"})

    verification = data_deletion.verify_user_deletion("test@example.com")

    assert verification["completely_deleted"] is False
    assert verification["remaining_data"]["opt_out_tokens"] == 2
    assert verification["remaining_data"]["users"] == 1


def test_verify_user_deletion_handles_user_lookup_exception(monkeypatch):
    conn = FakeConnection(lambda _query, _params: FakeCursor(row={"count": 0}))
    monkeypatch.setattr(data_deletion, "get_db_connection", lambda: conn)
    monkeypatch.setattr(
        data_deletion,
        "get_user_by_email",
        lambda _email: (_ for _ in ()).throw(RuntimeError("teable lookup failed")),
    )

    verification = data_deletion.verify_user_deletion("test@example.com")

    assert verification["completely_deleted"] is True
    assert "users" not in verification["remaining_data"]


def test_verify_user_deletion_continues_when_sqlite_check_fails(monkeypatch):
    def execute_impl(_query, _params):
        raise RuntimeError("query failed")

    conn = FakeConnection(execute_impl)
    monkeypatch.setattr(data_deletion, "get_db_connection", lambda: conn)
    monkeypatch.setattr(data_deletion, "get_user_by_email", lambda _email: None)

    verification = data_deletion.verify_user_deletion("test@example.com")

    assert verification["completely_deleted"] is True
    assert verification["remaining_data"] == {}


def test_get_deletion_preview_user_not_found(monkeypatch):
    monkeypatch.setattr(data_deletion, "get_user_data_summary", lambda _email: {"user_found": False})

    preview = data_deletion.get_deletion_preview("missing@example.com")

    assert preview["user_found"] is False
    assert "No account found" in preview["message"]


def test_get_deletion_preview_for_discord_linked_user(monkeypatch):
    monkeypatch.setattr(
        data_deletion,
        "get_user_data_summary",
        lambda _email: {"user_found": True, "discord_linked": True},
    )

    preview = data_deletion.get_deletion_preview("test@example.com")

    assert preview["user_found"] is True
    assert preview["discord_warning"] is True
    assert any("Discord verification status and roles" in item for item in preview["items_to_delete"])


def test_get_deletion_preview_for_non_discord_user(monkeypatch):
    monkeypatch.setattr(
        data_deletion,
        "get_user_data_summary",
        lambda _email: {"user_found": True, "discord_linked": False},
    )

    preview = data_deletion.get_deletion_preview("test@example.com")

    assert preview["user_found"] is True
    assert preview["discord_warning"] is False
    assert all("Discord verification status and roles" not in item for item in preview["items_to_delete"])
