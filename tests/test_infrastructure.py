"""Infrastructure layer tests."""

from unittest.mock import MagicMock, patch

import pytest

from src.infrastructure.config import ConfigManager
from src.infrastructure.database import Database, StatusRepository
from src.infrastructure.message_store import MessageStore
from src.infrastructure.unsubscribe import UnsubscribeClient


@pytest.fixture
def tmp_config_path(tmp_path):
    return str(tmp_path / "config.json")


@pytest.fixture
def tmp_db_path(tmp_path):
    return str(tmp_path / "test.db")


@pytest.fixture
def tmp_config_with_db(tmp_path):
    config = ConfigManager(config_path=str(tmp_path / "config.json"))
    config.set("db_path", str(tmp_path / "test.db"))
    config.set("credentials_dir", str(tmp_path / "credentials"))
    config.set("token_dir", str(tmp_path / "tokens"))
    return config


# --- ConfigManager ---

def test_config_manager_creates_empty_config(tmp_config_path):
    config = ConfigManager(config_path=tmp_config_path)
    assert config.get("missing") is None


def test_config_manager_set_and_get(tmp_config_path):
    config = ConfigManager(config_path=tmp_config_path)
    config.set("key", "value")
    assert config.get("key") == "value"


def test_config_manager_default_value(tmp_config_path):
    config = ConfigManager(config_path=tmp_config_path)
    assert config.get("missing", "default") == "default"


def test_config_manager_persists(tmp_config_path):
    config = ConfigManager(config_path=tmp_config_path)
    config.set("persistent", 42)
    config2 = ConfigManager(config_path=tmp_config_path)
    assert config2.get("persistent") == 42


# --- ConfigManager multi-account ---

def test_add_account_first_becomes_default(tmp_config_path):
    cfg = ConfigManager(config_path=tmp_config_path)
    cfg.add_account("a@example.com")
    assert cfg.get_accounts()["a@example.com"]["is_default"] is True


def test_add_account_second_not_default(tmp_config_path):
    cfg = ConfigManager(config_path=tmp_config_path)
    cfg.add_account("a@example.com")
    cfg.add_account("b@example.com")
    assert cfg.get_accounts()["b@example.com"]["is_default"] is False
    assert cfg.get_accounts()["a@example.com"]["is_default"] is True


def test_add_account_set_default_demotes_others(tmp_config_path):
    cfg = ConfigManager(config_path=tmp_config_path)
    cfg.add_account("a@example.com")
    cfg.add_account("b@example.com", set_default=True)
    assert cfg.get_accounts()["b@example.com"]["is_default"] is True
    assert cfg.get_accounts()["a@example.com"]["is_default"] is False


def test_get_default_account_explicit_flag(tmp_config_path):
    cfg = ConfigManager(config_path=tmp_config_path)
    cfg.add_account("a@example.com")
    cfg.add_account("b@example.com", set_default=True)
    assert cfg.get_default_account() == "b@example.com"


def test_get_default_account_single_account_no_flag(tmp_config_path):
    """Single account with no is_default flag still returns that account."""
    cfg = ConfigManager(config_path=tmp_config_path)
    cfg.config["accounts"] = {"a@example.com": {}}
    assert cfg.get_default_account() == "a@example.com"


def test_get_default_account_two_accounts_neither_default_returns_none(tmp_config_path):
    cfg = ConfigManager(config_path=tmp_config_path)
    cfg.config["accounts"] = {
        "a@example.com": {"is_default": False},
        "b@example.com": {"is_default": False},
    }
    assert cfg.get_default_account() is None


def test_set_default_account(tmp_config_path):
    cfg = ConfigManager(config_path=tmp_config_path)
    cfg.add_account("a@example.com")
    cfg.add_account("b@example.com")
    cfg.set_default_account("b@example.com")
    assert cfg.get_default_account() == "b@example.com"
    assert cfg.get_accounts()["a@example.com"]["is_default"] is False


def test_resolve_user_explicit_overrides_default(tmp_config_path):
    cfg = ConfigManager(config_path=tmp_config_path)
    cfg.add_account("a@example.com")
    assert cfg.resolve_user("b@example.com") == "b@example.com"


def test_resolve_user_falls_back_to_default(tmp_config_path):
    cfg = ConfigManager(config_path=tmp_config_path)
    cfg.add_account("a@example.com")
    assert cfg.resolve_user(None) == "a@example.com"


def test_get_token_path_with_user(tmp_config_path, tmp_path):
    cfg = ConfigManager(config_path=tmp_config_path, user="me@example.com")
    cfg.set("token_dir", str(tmp_path / "tokens"))
    assert cfg.get_token_path().endswith("me@example.com.json")


def test_get_token_path_without_user(tmp_config_path, tmp_path):
    cfg = ConfigManager(config_path=tmp_config_path)
    cfg.set("token_dir", str(tmp_path / "tokens"))
    assert cfg.get_token_path().endswith("token.json")


def test_get_db_path_with_user(tmp_config_path):
    cfg = ConfigManager(config_path=tmp_config_path, user="me@example.com")
    assert cfg.get_db_path().endswith("me@example.com.db")


def test_get_db_path_without_user_uses_config(tmp_config_path, tmp_path):
    cfg = ConfigManager(config_path=tmp_config_path)
    custom = str(tmp_path / "custom.db")
    cfg.set("db_path", custom)
    assert cfg.get_db_path() == custom


# --- MessageStore exclusions and ignored senders ---

@pytest.fixture
def store(tmp_path):
    return MessageStore(Database(str(tmp_path / "test.db")))


def test_get_missing_ids_excludes_already_excluded(store):
    store.add_excluded_ids(["m1", "m2"])
    result = store.get_missing_ids(["m1", "m2", "m3"])
    assert result == ["m3"]


def test_get_missing_ids_excludes_already_stored(store):
    store.store_raw_messages({"m1": _raw_message("m1")})
    result = store.get_missing_ids(["m1", "m2"])
    assert result == ["m2"]


def test_get_missing_ids_empty_input(store):
    assert store.get_missing_ids([]) == []


def test_delete_messages_removes_from_store(store):
    store.store_raw_messages({"m1": _raw_message("m1"), "m2": _raw_message("m2")})
    assert store.count() == 2
    store.delete_messages(["m1"])
    assert store.count() == 1


def test_delete_messages_empty_list_is_noop(store):
    store.store_raw_messages({"m1": _raw_message("m1")})
    store.delete_messages([])
    assert store.count() == 1


def test_count(store):
    assert store.count() == 0
    store.store_raw_messages({"m1": _raw_message("m1"), "m2": _raw_message("m2")})
    assert store.count() == 2


def test_get_ignored_senders_by_email(store):
    store.add_excluded_ids(["m1", "m2"], sender_email="news@example.com", domain="example.com")
    senders = store.get_ignored_senders()
    assert len(senders) == 1
    assert senders[0]["group_key"] == "news@example.com"
    assert senders[0]["count"] == 2


def test_get_ignored_senders_by_domain_fallback(store):
    store.add_excluded_ids(["m1"], sender_email="", domain="example.com")
    senders = store.get_ignored_senders()
    assert senders[0]["group_key"] == "example.com"


def test_get_ignored_senders_unknown_fallback(store):
    store.add_excluded_ids(["m1"], sender_email="", domain="")
    senders = store.get_ignored_senders()
    assert senders[0]["group_key"] == "(unknown)"


def test_remove_ignored_sender_by_email(store):
    store.add_excluded_ids(["m1"], sender_email="news@example.com", domain="example.com")
    store.remove_ignored_sender("news@example.com")
    assert store.get_ignored_senders() == []


def test_remove_ignored_sender_by_domain(store):
    store.add_excluded_ids(["m1"], sender_email="", domain="example.com")
    store.remove_ignored_sender("example.com")
    assert store.get_ignored_senders() == []


def test_remove_ignored_sender_unknown(store):
    store.add_excluded_ids(["m1"], sender_email="", domain="")
    store.remove_ignored_sender("(unknown)")
    assert store.get_ignored_senders() == []


def test_remove_ignored_sender_does_not_affect_others(store):
    store.add_excluded_ids(["m1"], sender_email="a@example.com", domain="example.com")
    store.add_excluded_ids(["m2"], sender_email="b@example.com", domain="example.com")
    store.remove_ignored_sender("a@example.com")
    senders = store.get_ignored_senders()
    assert len(senders) == 1
    assert senders[0]["group_key"] == "b@example.com"


def test_clear_messages_preserves_exclusions(store):
    store.store_raw_messages({"m1": _raw_message("m1")})
    store.add_excluded_ids(["m2"], sender_email="x@x.com")
    store.clear_messages()
    assert store.count() == 0
    assert store.get_ignored_senders() != []  # exclusion survived


# --- MessageStore sync-state ---

def test_get_last_sync_at_returns_none_when_unset(store):
    assert store.get_last_sync_at() is None


def test_set_last_sync_at_round_trip(store):
    ts = 1700000000.5
    store.set_last_sync_at(ts)
    assert store.get_last_sync_at() == pytest.approx(ts)


def test_set_last_sync_at_overwrites(store):
    store.set_last_sync_at(1000.0)
    store.set_last_sync_at(2000.0)
    assert store.get_last_sync_at() == pytest.approx(2000.0)


def test_get_dismissed_reappeared_empty(store):
    assert store.get_dismissed_reappeared() == {}


def test_set_dismissed_reappeared_round_trip(store):
    data = {"news@example.com": 3, "other@x.com": 1}
    store.set_dismissed_reappeared(data)
    assert store.get_dismissed_reappeared() == data


def test_set_dismissed_reappeared_overwrites(store):
    store.set_dismissed_reappeared({"a@x.com": 1})
    store.set_dismissed_reappeared({"b@x.com": 2})
    assert store.get_dismissed_reappeared() == {"b@x.com": 2}


def test_has_seen_help_false_by_default(store):
    assert store.has_seen_help() is False


def test_mark_help_seen_persists(store):
    store.mark_help_seen()
    assert store.has_seen_help() is True


def test_mark_help_seen_idempotent(store):
    store.mark_help_seen()
    store.mark_help_seen()
    assert store.has_seen_help() is True


# --- Database and StatusRepository ---

def test_status_repository_get_seen_domains_empty(tmp_config_with_db):
    repo = StatusRepository(tmp_config_with_db)
    assert repo.get_seen_domains() == set()


def test_status_repository_mark_and_get(tmp_config_with_db):
    repo = StatusRepository(tmp_config_with_db)
    repo.mark_domain_seen("example.com")
    assert "example.com" in repo.get_seen_domains()


def test_status_repository_mark_idempotent(tmp_config_with_db):
    repo = StatusRepository(tmp_config_with_db)
    repo.mark_domain_seen("example.com")
    repo.mark_domain_seen("example.com")
    assert repo.get_seen_domains() == {"example.com"}


# --- UnsubscribeClient ---

def test_unsubscribe_client_process_success():
    client = UnsubscribeClient()
    with patch.object(client._session, "get") as mock_get:
        mock_get.return_value = MagicMock(status_code=200)
        result = client.process_unsubscribe("https://example.com/unsub")
    assert result is True


def test_unsubscribe_client_process_failure():
    client = UnsubscribeClient()
    with patch.object(client._session, "get") as mock_get:
        mock_get.return_value = MagicMock(status_code=500)
        result = client.process_unsubscribe("https://example.com/unsub")
    assert result is False


def test_unsubscribe_client_verify_always_true():
    client = UnsubscribeClient()
    assert client.verify_unsubscribe("https://example.com/unsub") is True


# --- StatusRepository unsubscribe history ---

def test_record_unsubscribe_persists(tmp_config_with_db):
    repo = StatusRepository(tmp_config_with_db)
    repo.record_unsubscribe("example.com", "news@example.com", "https://example.com/unsub")
    history = repo.get_unsubscribe_history()
    assert "example.com" in history
    assert history["example.com"]["sender_email"] == "news@example.com"
    assert history["example.com"]["unsubscribe_url"] == "https://example.com/unsub"
    assert history["example.com"]["attempted_at"] > 0


def test_get_unsubscribe_history_empty(tmp_config_with_db):
    repo = StatusRepository(tmp_config_with_db)
    assert repo.get_unsubscribe_history() == {}


def test_forget_unsubscribe_removes_entry(tmp_config_with_db):
    repo = StatusRepository(tmp_config_with_db)
    repo.record_unsubscribe("example.com", "news@example.com", "https://example.com/unsub")
    repo.forget_unsubscribe("news@example.com")
    assert repo.get_unsubscribe_history() == {}


def test_forget_unsubscribe_does_not_affect_others(tmp_config_with_db):
    repo = StatusRepository(tmp_config_with_db)
    repo.record_unsubscribe("a.com", "a@a.com", "https://a.com/unsub")
    repo.record_unsubscribe("b.com", "b@b.com", "https://b.com/unsub")
    repo.forget_unsubscribe("a@a.com")
    history = repo.get_unsubscribe_history()
    assert "a.com" not in history
    assert "b.com" in history


# --- MessageStore delivered_to ---

def _raw_message(msg_id: str, to: str = "", delivered_to: str = "") -> dict:
    headers = [
        {"name": "From", "value": "sender@newsletter.com"},
        {"name": "Subject", "value": "Hello"},
    ]
    if to:
        headers.append({"name": "To", "value": to})
    if delivered_to:
        headers.append({"name": "Delivered-To", "value": delivered_to})
    return {
        "id": msg_id,
        "labelIds": ["INBOX"],
        "internalDate": "1704067200000",
        "payload": {"headers": headers},
    }


def test_delivered_to_preferred_over_to(tmp_path):
    """Delivered-To header should be used when both Delivered-To and To are present."""
    db = Database(str(tmp_path / "test.db"))
    store = MessageStore(db)
    store.store_raw_messages({"m1": _raw_message("m1", to="other@gmail.com", delivered_to="alias@gmail.com")})
    msgs = store.get_all_messages()
    assert msgs[0].delivered_to == "alias@gmail.com"


def test_falls_back_to_to_header_when_no_delivered_to(tmp_path):
    db = Database(str(tmp_path / "test.db"))
    store = MessageStore(db)
    store.store_raw_messages({"m1": _raw_message("m1", to="user@gmail.com")})
    msgs = store.get_all_messages()
    assert msgs[0].delivered_to == "user@gmail.com"


def test_delivered_to_empty_when_no_headers(tmp_path):
    db = Database(str(tmp_path / "test.db"))
    store = MessageStore(db)
    store.store_raw_messages({"m1": _raw_message("m1")})
    msgs = store.get_all_messages()
    assert msgs[0].delivered_to == ""
