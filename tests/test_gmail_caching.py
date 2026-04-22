"""Tests for GmailRepository cache integration and pagination."""

import os
import time
from unittest.mock import MagicMock

import pytest

from src.domain.models.message import EmailMessage
from src.infrastructure.config import ConfigManager
from src.infrastructure.database import Database, MessageCache
from src.infrastructure.gmail import GmailRepository


@pytest.fixture
def mock_config():
    config = MagicMock(spec=ConfigManager)
    config.get_credentials_path.return_value = os.path.join(
        os.path.dirname(__file__), "test_credentials.json"
    )
    config.get_token_path.return_value = os.path.join(
        os.path.dirname(__file__), "test_token.json"
    )
    return config


@pytest.fixture
def db(tmp_path):
    return Database(str(tmp_path / "test.db"))


@pytest.fixture
def cache(db):
    return MessageCache(db, ttl_seconds=3600)


@pytest.fixture
def repo(mock_config, cache):
    return GmailRepository(mock_config, cache=cache)


@pytest.fixture
def repo_no_cache(mock_config):
    return GmailRepository(mock_config, cache=None)


def _raw_message(msg_id: str, subject: str = "Test", unread: bool = True) -> dict:
    """Build a minimal Gmail API message dict."""
    return {
        "id": msg_id,
        "threadId": f"thread-{msg_id}",
        "labelIds": ["INBOX", "UNREAD"] if unread else ["INBOX"],
        "internalDate": "1704067200000",
        "payload": {
            "headers": [
                {"name": "From", "value": "Test Sender <sender@example.com>"},
                {"name": "Subject", "value": subject},
                {"name": "Date", "value": "Mon, 01 Jan 2024 00:00:00 +0000"},
                {"name": "List-Unsubscribe", "value": "<https://example.com/unsub>"},
                {"name": "List-Unsubscribe-Post", "value": "List-Unsubscribe=One-Click"},
            ]
        },
    }


def _make_mock_service(page_ids: list[list[str]], raw_msgs: dict[str, dict]):
    """Return a mock Gmail service that pages through page_ids and serves raw_msgs via batch."""
    mock_service = MagicMock()

    # Set up paginated list responses
    list_responses = []
    for i, page in enumerate(page_ids):
        resp = {"messages": [{"id": mid} for mid in page]}
        if i < len(page_ids) - 1:
            resp["nextPageToken"] = f"token{i}"
        list_responses.append(resp)
    mock_service.users().messages().list().execute.side_effect = list_responses

    # Set up batch execution
    def make_batch_execute(batch_mock):
        def execute():
            callback = mock_service.new_batch_http_request.call_args[1]["callback"]
            for mid, raw in raw_msgs.items():
                callback(mid, raw, None)
        return execute

    mock_batch = MagicMock()
    mock_batch.execute.side_effect = make_batch_execute(mock_batch)
    mock_service.new_batch_http_request.return_value = mock_batch

    return mock_service, mock_batch


# ---------------------------------------------------------------------------
# _message_to_cache_dict
# ---------------------------------------------------------------------------

class TestMessageToCacheDict:
    def test_extracts_all_fields(self, repo):
        raw = _raw_message("msg1", subject="Hi", unread=True)
        data = repo._message_to_cache_dict(raw)
        assert data["from"] == "Test Sender <sender@example.com>"
        assert data["subject"] == "Hi"
        assert data["internalDate"] == "1704067200000"
        assert data["is_unread"] is True
        assert data["unsubscribe_link"] == "<https://example.com/unsub>"
        assert data["unsubscribe_post"] is True

    def test_unread_false_when_no_unread_label(self, repo):
        raw = _raw_message("msg1", unread=False)
        data = repo._message_to_cache_dict(raw)
        assert data["is_unread"] is False

    def test_unsubscribe_link_none_when_missing(self, repo):
        raw = {
            "id": "msg1", "threadId": "t1", "labelIds": ["INBOX"],
            "internalDate": "1704067200000",
            "payload": {"headers": [
                {"name": "From", "value": "a@b.com"},
                {"name": "Subject", "value": "X"},
            ]},
        }
        data = repo._message_to_cache_dict(raw)
        assert data["unsubscribe_link"] is None
        assert data["unsubscribe_post"] is False


# ---------------------------------------------------------------------------
# _parse_cached
# ---------------------------------------------------------------------------

class TestParseCached:
    def test_reconstructs_email_message(self, repo):
        data = {
            "from": "Alice <alice@example.com>",
            "subject": "Hello",
            "internalDate": "1704067200000",
            "is_unread": True,
            "unsubscribe_link": "<https://example.com/unsub>",
            "unsubscribe_post": True,
        }
        msg = repo._parse_cached("msgX", data)
        assert isinstance(msg, EmailMessage)
        assert msg.id == "msgX"
        assert msg.sender.email == "alice@example.com"
        assert msg.subject == "Hello"
        assert msg.is_unread is True
        assert msg.unsubscribe_link == "<https://example.com/unsub>"
        assert msg.unsubscribe_post is True

    def test_handles_none_unsubscribe(self, repo):
        data = {
            "from": "a@b.com", "subject": "X", "internalDate": "0",
            "is_unread": False, "unsubscribe_link": None, "unsubscribe_post": False,
        }
        msg = repo._parse_cached("msg1", data)
        assert msg.has_unsubscribe is False

    def test_parse_cached_roundtrip_matches_parse_message(self, repo):
        """_parse_cached should produce an identical EmailMessage to _parse_message."""
        raw = _raw_message("msg1", subject="Roundtrip", unread=True)
        from_parse = repo._parse_message(raw)
        data = repo._message_to_cache_dict(raw)
        from_cache = repo._parse_cached("msg1", data)

        assert from_cache.id == from_parse.id
        assert from_cache.sender.email == from_parse.sender.email
        assert from_cache.subject == from_parse.subject
        assert from_cache.is_unread == from_parse.is_unread
        assert from_cache.unsubscribe_link == from_parse.unsubscribe_link
        assert from_cache.unsubscribe_post == from_parse.unsubscribe_post


# ---------------------------------------------------------------------------
# get_messages — pagination (no cap)
# ---------------------------------------------------------------------------

class TestGetMessagesPagination:
    def test_fetches_single_page(self, repo):
        raw = _raw_message("msg1")
        mock_service, mock_batch = _make_mock_service([["msg1"]], {"msg1": raw})
        repo._service = mock_service
        msgs = repo.get_messages("label:test")
        assert len(msgs) == 1

    def test_follows_next_page_token(self, repo):
        """Should collect IDs from all pages before batch-fetching."""
        raw1 = _raw_message("msg1")
        raw2 = _raw_message("msg2")
        mock_service, mock_batch = _make_mock_service(
            [["msg1"], ["msg2"]],
            {"msg1": raw1, "msg2": raw2},
        )
        repo._service = mock_service
        msgs = repo.get_messages("label:test")
        assert len(msgs) == 2
        assert {m.id for m in msgs} == {"msg1", "msg2"}

    def test_fetches_three_pages(self, repo):
        pages = [[f"msg{i}"] for i in range(3)]
        raws = {f"msg{i}": _raw_message(f"msg{i}") for i in range(3)}
        mock_service, _ = _make_mock_service(pages, raws)
        repo._service = mock_service
        msgs = repo.get_messages()
        assert len(msgs) == 3

    def test_returns_empty_list_when_no_messages(self, repo):
        mock_service = MagicMock()
        mock_service.users().messages().list().execute.return_value = {"messages": []}
        repo._service = mock_service
        assert repo.get_messages() == []
        mock_service.new_batch_http_request.assert_not_called()


# ---------------------------------------------------------------------------
# get_messages — cache hit / miss / partial
# ---------------------------------------------------------------------------

class TestGetMessagesCache:
    def test_full_cache_hit_skips_batch(self, repo, cache):
        raw = _raw_message("msg1")
        cache.store({"msg1": repo._message_to_cache_dict(raw)})

        mock_service = MagicMock()
        mock_service.users().messages().list().execute.return_value = {
            "messages": [{"id": "msg1"}]
        }
        repo._service = mock_service

        msgs = repo.get_messages()
        assert len(msgs) == 1
        assert msgs[0].id == "msg1"
        mock_service.new_batch_http_request.assert_not_called()

    def test_full_cache_miss_fetches_all(self, repo, cache):
        raw = _raw_message("msg1")
        mock_service, mock_batch = _make_mock_service([["msg1"]], {"msg1": raw})
        repo._service = mock_service

        msgs = repo.get_messages()
        assert len(msgs) == 1
        mock_service.new_batch_http_request.assert_called_once()

    def test_partial_cache_hit_fetches_only_uncached(self, repo, cache):
        raw1 = _raw_message("msg1", subject="Cached")
        raw2 = _raw_message("msg2", subject="Uncached")

        # Pre-cache msg1
        cache.store({"msg1": repo._message_to_cache_dict(raw1)})

        mock_service = MagicMock()
        mock_service.users().messages().list().execute.return_value = {
            "messages": [{"id": "msg1"}, {"id": "msg2"}]
        }
        fetched_ids = []

        def make_execute():
            callback = mock_service.new_batch_http_request.call_args[1]["callback"]
            callback("msg2", raw2, None)

        mock_batch = MagicMock()
        mock_batch.execute.side_effect = make_execute
        mock_batch.add.side_effect = lambda req, request_id: fetched_ids.append(request_id)
        mock_service.new_batch_http_request.return_value = mock_batch
        repo._service = mock_service

        msgs = repo.get_messages()
        assert len(msgs) == 2
        # Only msg2 should have been fetched via API
        assert fetched_ids == ["msg2"]

    def test_newly_fetched_messages_stored_in_cache(self, repo, cache):
        raw = _raw_message("msg1")
        mock_service, _ = _make_mock_service([["msg1"]], {"msg1": raw})
        repo._service = mock_service

        repo.get_messages()

        # msg1 should now be in cache
        cached = cache.get_cached(["msg1"])
        assert "msg1" in cached
        assert cached["msg1"]["subject"] == "Test"

    def test_cache_preserves_message_order(self, repo, cache):
        """Messages must come back in the same order Gmail's list returned them."""
        raws = {f"msg{i}": _raw_message(f"msg{i}", subject=f"Sub {i}") for i in range(4)}
        # Pre-cache even-indexed messages
        cache.store({
            "msg0": repo._message_to_cache_dict(raws["msg0"]),
            "msg2": repo._message_to_cache_dict(raws["msg2"]),
        })

        mock_service = MagicMock()
        mock_service.users().messages().list().execute.return_value = {
            "messages": [{"id": f"msg{i}"} for i in range(4)]
        }

        def make_execute():
            callback = mock_service.new_batch_http_request.call_args[1]["callback"]
            callback("msg1", raws["msg1"], None)
            callback("msg3", raws["msg3"], None)

        mock_batch = MagicMock()
        mock_batch.execute.side_effect = make_execute
        mock_service.new_batch_http_request.return_value = mock_batch
        repo._service = mock_service

        msgs = repo.get_messages()
        assert [m.id for m in msgs] == ["msg0", "msg1", "msg2", "msg3"]

    def test_works_without_cache(self, repo_no_cache):
        raw = _raw_message("msg1")
        mock_service, _ = _make_mock_service([["msg1"]], {"msg1": raw})
        repo_no_cache._service = mock_service
        msgs = repo_no_cache.get_messages()
        assert len(msgs) == 1
        assert msgs[0].id == "msg1"

    def test_expired_cache_entry_refetched(self, repo, db, cache):
        raw = _raw_message("msg1", subject="Fresh")
        cache.store({"msg1": repo._message_to_cache_dict(raw)})
        # Expire the entry
        db._conn.execute(
            "UPDATE message_cache SET cached_at = ? WHERE message_id = ?",
            (time.time() - 9999, "msg1"),
        )
        db._conn.commit()

        updated_raw = _raw_message("msg1", subject="Updated")
        mock_service, _ = _make_mock_service([["msg1"]], {"msg1": updated_raw})
        repo._service = mock_service

        msgs = repo.get_messages()
        assert msgs[0].subject == "Updated"
        mock_service.new_batch_http_request.assert_called_once()


# ---------------------------------------------------------------------------
# Cache invalidation on write operations
# ---------------------------------------------------------------------------

class TestCacheInvalidation:
    def _pre_cache(self, repo, cache, msg_id: str):
        raw = _raw_message(msg_id)
        cache.store({msg_id: repo._message_to_cache_dict(raw)})
        assert msg_id in cache.get_cached([msg_id])

    def test_update_labels_invalidates_cache(self, repo, cache):
        self._pre_cache(repo, cache, "msg1")

        mock_service = MagicMock()
        mock_service.users().labels().list().execute.return_value = {"labels": []}
        mock_service.users().labels().create().execute.return_value = {"id": "Label_1", "name": "test/label"}
        mock_service.users().messages().modify().execute.return_value = {}
        repo._service = mock_service

        repo.update_labels("msg1", add_labels=["test/label"], remove_labels=[])
        assert cache.get_cached(["msg1"]) == {}

    def test_trash_message_invalidates_cache(self, repo, cache):
        self._pre_cache(repo, cache, "msg1")

        mock_service = MagicMock()
        mock_service.users().messages().trash().execute.return_value = {}
        repo._service = mock_service

        repo.trash_message("msg1")
        assert cache.get_cached(["msg1"]) == {}

    def test_update_labels_does_not_invalidate_other_messages(self, repo, cache):
        self._pre_cache(repo, cache, "msg1")
        self._pre_cache(repo, cache, "msg2")

        mock_service = MagicMock()
        mock_service.users().labels().list().execute.return_value = {"labels": []}
        mock_service.users().labels().create().execute.return_value = {"id": "Label_1", "name": "test/label"}
        mock_service.users().messages().modify().execute.return_value = {}
        repo._service = mock_service

        repo.update_labels("msg1", add_labels=["test/label"], remove_labels=[])
        assert "msg2" in cache.get_cached(["msg2"])

    def test_trash_does_not_invalidate_other_messages(self, repo, cache):
        self._pre_cache(repo, cache, "msg1")
        self._pre_cache(repo, cache, "msg2")

        mock_service = MagicMock()
        mock_service.users().messages().trash().execute.return_value = {}
        repo._service = mock_service

        repo.trash_message("msg1")
        assert "msg2" in cache.get_cached(["msg2"])

    def test_no_cache_update_labels_does_not_crash(self, repo_no_cache):
        mock_service = MagicMock()
        mock_service.users().labels().list().execute.return_value = {"labels": []}
        mock_service.users().labels().create().execute.return_value = {"id": "L1", "name": "x"}
        mock_service.users().messages().modify().execute.return_value = {}
        repo_no_cache._service = mock_service
        result = repo_no_cache.update_labels("msg1", add_labels=["x"], remove_labels=[])
        assert result is True

    def test_no_cache_trash_does_not_crash(self, repo_no_cache):
        mock_service = MagicMock()
        mock_service.users().messages().trash().execute.return_value = {}
        repo_no_cache._service = mock_service
        assert repo_no_cache.trash_message("msg1") is True
