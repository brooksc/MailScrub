"""Comprehensive tests for MessageCache."""

import time

import pytest

from src.infrastructure.database import Database, MessageCache


@pytest.fixture
def db(tmp_path):
    return Database(str(tmp_path / "test.db"))


@pytest.fixture
def cache(db):
    return MessageCache(db, ttl_seconds=3600)


@pytest.fixture
def sample_data():
    return {
        "from": "Test Sender <test@example.com>",
        "subject": "Hello world",
        "internalDate": "1704067200000",
        "is_unread": True,
        "unsubscribe_link": "<https://example.com/unsub>",
        "unsubscribe_post": True,
    }


# ---------------------------------------------------------------------------
# get_cached
# ---------------------------------------------------------------------------

class TestGetCached:
    def test_returns_empty_dict_for_empty_input(self, cache):
        assert cache.get_cached([]) == {}

    def test_returns_empty_dict_when_nothing_stored(self, cache):
        assert cache.get_cached(["msg1", "msg2"]) == {}

    def test_returns_cached_entry(self, cache, sample_data):
        cache.store({"msg1": sample_data})
        result = cache.get_cached(["msg1"])
        assert "msg1" in result
        assert result["msg1"]["subject"] == "Hello world"

    def test_returns_only_requested_ids(self, cache, sample_data):
        cache.store({"msg1": sample_data, "msg2": {**sample_data, "subject": "Other"}})
        result = cache.get_cached(["msg1"])
        assert "msg1" in result
        assert "msg2" not in result

    def test_returns_multiple_ids(self, cache, sample_data):
        cache.store({"msg1": sample_data, "msg2": {**sample_data, "subject": "Two"}})
        result = cache.get_cached(["msg1", "msg2"])
        assert set(result.keys()) == {"msg1", "msg2"}

    def test_excludes_expired_entries(self, db, sample_data):
        short_cache = MessageCache(db, ttl_seconds=1)
        short_cache.store({"msg1": sample_data})
        # Expire by backdating the cached_at
        db._conn.execute(
            "UPDATE message_cache SET cached_at = ? WHERE message_id = ?",
            (time.time() - 2, "msg1"),
        )
        db._conn.commit()
        result = short_cache.get_cached(["msg1"])
        assert result == {}

    def test_non_expired_entries_returned(self, db, sample_data):
        long_cache = MessageCache(db, ttl_seconds=9999)
        long_cache.store({"msg1": sample_data})
        result = long_cache.get_cached(["msg1"])
        assert "msg1" in result

    def test_mix_of_cached_expired_and_missing(self, db, sample_data):
        cache = MessageCache(db, ttl_seconds=3600)
        cache.store({"fresh": sample_data, "stale": {**sample_data, "subject": "Old"}})
        db._conn.execute(
            "UPDATE message_cache SET cached_at = ? WHERE message_id = ?",
            (time.time() - 9999, "stale"),
        )
        db._conn.commit()
        result = cache.get_cached(["fresh", "stale", "missing"])
        assert "fresh" in result
        assert "stale" not in result
        assert "missing" not in result

    def test_data_round_trips_correctly(self, cache, sample_data):
        cache.store({"msg1": sample_data})
        result = cache.get_cached(["msg1"])
        assert result["msg1"] == sample_data


# ---------------------------------------------------------------------------
# store
# ---------------------------------------------------------------------------

class TestStore:
    def test_stores_single_entry(self, cache, sample_data):
        cache.store({"msg1": sample_data})
        assert "msg1" in cache.get_cached(["msg1"])

    def test_stores_multiple_entries(self, cache, sample_data):
        entries = {f"msg{i}": {**sample_data, "subject": f"Sub {i}"} for i in range(5)}
        cache.store(entries)
        result = cache.get_cached(list(entries.keys()))
        assert len(result) == 5

    def test_upserts_existing_entry(self, cache, sample_data):
        cache.store({"msg1": sample_data})
        updated = {**sample_data, "subject": "Updated"}
        cache.store({"msg1": updated})
        result = cache.get_cached(["msg1"])
        assert result["msg1"]["subject"] == "Updated"

    def test_store_empty_dict_is_noop(self, cache):
        cache.store({})  # must not raise
        assert cache.get_cached([]) == {}

    def test_preserves_none_fields(self, cache, sample_data):
        data = {**sample_data, "unsubscribe_link": None}
        cache.store({"msg1": data})
        result = cache.get_cached(["msg1"])
        assert result["msg1"]["unsubscribe_link"] is None


# ---------------------------------------------------------------------------
# invalidate
# ---------------------------------------------------------------------------

class TestInvalidate:
    def test_removes_existing_entry(self, cache, sample_data):
        cache.store({"msg1": sample_data})
        cache.invalidate("msg1")
        assert cache.get_cached(["msg1"]) == {}

    def test_noop_for_nonexistent_id(self, cache):
        cache.invalidate("nonexistent")  # must not raise

    def test_does_not_remove_other_entries(self, cache, sample_data):
        cache.store({"msg1": sample_data, "msg2": {**sample_data, "subject": "Keep"}})
        cache.invalidate("msg1")
        result = cache.get_cached(["msg1", "msg2"])
        assert "msg1" not in result
        assert "msg2" in result


# ---------------------------------------------------------------------------
# purge_expired
# ---------------------------------------------------------------------------

class TestPurgeExpired:
    def test_removes_expired_entries(self, db, sample_data):
        cache = MessageCache(db, ttl_seconds=3600)
        cache.store({"msg1": sample_data, "msg2": {**sample_data, "subject": "Two"}})
        # Expire both
        db._conn.execute("UPDATE message_cache SET cached_at = ?", (time.time() - 9999,))
        db._conn.commit()
        removed = cache.purge_expired()
        assert removed == 2
        assert cache.get_cached(["msg1", "msg2"]) == {}

    def test_keeps_non_expired_entries(self, db, sample_data):
        cache = MessageCache(db, ttl_seconds=3600)
        cache.store({"fresh": sample_data, "stale": {**sample_data, "subject": "Old"}})
        db._conn.execute(
            "UPDATE message_cache SET cached_at = ? WHERE message_id = ?",
            (time.time() - 9999, "stale"),
        )
        db._conn.commit()
        removed = cache.purge_expired()
        assert removed == 1
        assert "fresh" in cache.get_cached(["fresh"])

    def test_returns_zero_when_nothing_expired(self, cache, sample_data):
        cache.store({"msg1": sample_data})
        assert cache.purge_expired() == 0

    def test_returns_zero_on_empty_table(self, cache):
        assert cache.purge_expired() == 0


# ---------------------------------------------------------------------------
# TTL boundary
# ---------------------------------------------------------------------------

class TestTTLBoundary:
    def test_entry_exactly_at_ttl_boundary_is_expired(self, db, sample_data):
        cache = MessageCache(db, ttl_seconds=60)
        cache.store({"msg1": sample_data})
        # Set cached_at to exactly ttl seconds ago (expired)
        db._conn.execute(
            "UPDATE message_cache SET cached_at = ? WHERE message_id = ?",
            (time.time() - 60, "msg1"),
        )
        db._conn.commit()
        assert cache.get_cached(["msg1"]) == {}

    def test_entry_just_within_ttl_is_valid(self, db, sample_data):
        cache = MessageCache(db, ttl_seconds=60)
        cache.store({"msg1": sample_data})
        # 1 second inside the TTL window
        db._conn.execute(
            "UPDATE message_cache SET cached_at = ? WHERE message_id = ?",
            (time.time() - 59, "msg1"),
        )
        db._conn.commit()
        assert "msg1" in cache.get_cached(["msg1"])
