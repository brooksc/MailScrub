"""Tests for GmailSyncer sync logic."""

from unittest.mock import MagicMock, call, patch

import pytest

from src.infrastructure.database import Database
from src.infrastructure.message_store import SYNC_QUERY, GmailSyncer, MessageStore


@pytest.fixture
def store(tmp_path):
    return MessageStore(Database(str(tmp_path / "test.db")))


@pytest.fixture
def repo():
    return MagicMock()


@pytest.fixture
def syncer(repo, store):
    return GmailSyncer(repo, store)


def _raw(msg_id: str) -> dict:
    return {
        "id": msg_id,
        "labelIds": ["INBOX"],
        "internalDate": "1704067200000",
        "payload": {"headers": [{"name": "From", "value": "x@x.com"}]},
    }


# --- incremental sync builds after: query ---

def test_incremental_sync_appends_after_timestamp(syncer, repo, store):
    store.set_last_sync_at(1700000000.0)
    repo.list_message_ids.return_value = []

    syncer.sync()

    query_used = repo.list_message_ids.call_args[0][0]
    assert "after:1700000000" in query_used
    assert query_used.startswith(SYNC_QUERY)


def test_full_sync_ignores_last_sync_at(syncer, repo, store):
    store.set_last_sync_at(1700000000.0)
    repo.list_message_ids.return_value = []

    syncer.sync(full_sync=True)

    query_used = repo.list_message_ids.call_args[0][0]
    assert "after:" not in query_used


# --- full_sync=True clears messages ---

def test_full_sync_clears_store_before_fetching(syncer, repo, store, tmp_path):
    store.store_raw_messages({"existing": _raw("existing")})
    repo.list_message_ids.return_value = []

    syncer.sync(full_sync=True)

    assert store.count() == 0


# --- empty ID list still writes last_sync_at ---

def test_empty_id_list_writes_last_sync_at(syncer, repo, store):
    assert store.get_last_sync_at() is None
    repo.list_message_ids.return_value = []

    syncer.sync()

    assert store.get_last_sync_at() is not None


def test_all_ids_already_stored_writes_last_sync_at(syncer, repo, store):
    store.store_raw_messages({"m1": _raw("m1")})
    repo.list_message_ids.return_value = ["m1"]

    syncer.sync()

    assert store.get_last_sync_at() is not None


# --- successful sync stores messages and writes last_sync_at ---

def test_sync_stores_new_messages(syncer, repo, store):
    repo.list_message_ids.return_value = ["m1", "m2"]
    repo.fetch_message_headers.return_value = {"m1": _raw("m1"), "m2": _raw("m2")}

    with patch("src.infrastructure.message_store.time.sleep"):
        result = syncer.sync()

    assert result.fetched == 2
    assert result.total_new == 2
    assert result.interrupted is False
    assert store.count() == 2
    assert store.get_last_sync_at() is not None


# --- KeyboardInterrupt sets interrupted, does NOT write last_sync_at ---

def test_keyboard_interrupt_sets_interrupted_flag(syncer, repo, store):
    repo.list_message_ids.return_value = ["m1"]
    repo.fetch_message_headers.side_effect = KeyboardInterrupt

    result = syncer.sync()

    assert result.interrupted is True
    assert store.get_last_sync_at() is None


def test_keyboard_interrupt_does_not_write_last_sync_at(syncer, repo, store):
    store.set_last_sync_at(1000.0)
    repo.list_message_ids.return_value = ["m1"]
    repo.fetch_message_headers.side_effect = KeyboardInterrupt

    syncer.sync()

    assert store.get_last_sync_at() == pytest.approx(1000.0)


# --- on_progress callback ---

def test_on_progress_called_after_each_batch(syncer, repo, store):
    repo.list_message_ids.return_value = ["m1", "m2"]
    repo.fetch_message_headers.return_value = {"m1": _raw("m1"), "m2": _raw("m2")}
    progress_calls = []

    with patch("src.infrastructure.message_store.time.sleep"):
        syncer.sync(on_progress=lambda f, t: progress_calls.append((f, t)))

    assert len(progress_calls) >= 1
    assert progress_calls[-1] == (2, 2)
